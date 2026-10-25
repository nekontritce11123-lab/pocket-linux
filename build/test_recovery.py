import hashlib
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import recovery

PROJECT = HERE.parents[1]
SCRIPT = HERE.parent / 'scripts/Prepare-Dependencies.ps1'
TEMP = PROJECT / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/desktop-build/recovery-tests'
POWERSHELL = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        TEMP.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='fake-', dir=TEMP)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.files = {name: ('fixture:' + name).encode() for name in recovery.ESSENTIAL}
        for name, content in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.keep = {'linux.qcow2': b'NOT A REAL DISK', 'config/profile.json': b'private fixture'}
        for name, content in self.keep.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.result = recovery.build_recovery(self.root)
        self.archive = Path(self.result['archive'])
        self.manifest = Path(self.result['manifest'])
        for name in self.files:
            (self.root / name).unlink()

    def setup_runtime(self):
        result = subprocess.run([str(POWERSHELL), '-NoProfile', '-NonInteractive', '-File', str(SCRIPT),
                                 '-Project', str(self.root)], capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout.decode('utf-8-sig'))

    def replace_package(self, entries=None, symlink=None):
        with zipfile.ZipFile(self.archive, 'w') as packed:
            for name, content in (entries or self.files).items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (0o120777 if name == symlink else 0o100644) << 16
                packed.writestr(info, content)

    def assert_no_components_published(self):
        for name in self.files:
            self.assertFalse((self.root / name).exists(), name)
        self.assertEqual(list((self.root / 'runtime').glob('.repair-*')), [])
        for name, content in self.keep.items():
            self.assertEqual((self.root / name).read_bytes(), content)

    def test_builder_only_includes_allowed_components_and_validates_written_zip(self):
        data = json.loads(self.manifest.read_text())
        self.assertEqual(set(data), {'schema', 'files'})
        self.assertEqual({record['path'] for record in data['files']}, set(self.files))
        with zipfile.ZipFile(self.archive) as packed:
            self.assertIsNone(packed.testzip())
            self.assertEqual(set(packed.namelist()), set(self.files))
        self.assertEqual(self.result['archive_sha256'], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        for name in ('../outside', 'PocketNet.exe:stream', 'config/profile.json', 'runtime/python-3.12.14/../../outside',
                     'runtime/qemu-11.1.0/CON', 'runtime/host-files/bad.', 'runtime/host-files/name '):
            self.assertFalse(recovery.valid_name(name), name)

    def test_repaired_then_ready_without_rewriting_files_or_user_data(self):
        report = self.setup_runtime()
        self.assertTrue(report['ok'], report)
        self.assertEqual(report['code'], 'repaired')
        self.assertEqual(report['checked_files'], len(self.files))
        self.assertEqual(report['repaired_files'], len(self.files))
        before = {name: (self.root / name).stat().st_mtime_ns for name in self.files}
        for name, content in self.files.items():
            self.assertEqual((self.root / name).read_bytes(), content)
        report = self.setup_runtime()
        self.assertEqual(report['code'], 'ready')
        self.assertEqual(report['repaired_files'], 0)
        self.assertEqual(before, {name: (self.root / name).stat().st_mtime_ns for name in self.files})
        damaged = self.root / 'PocketNet.exe'
        damaged.write_bytes(b'x' * len(self.files['PocketNet.exe']))
        report = self.setup_runtime()
        self.assertEqual(report['code'], 'repaired')
        self.assertEqual(report['repaired_files'], 1)
        self.assertEqual(damaged.read_bytes(), self.files['PocketNet.exe'])
        for name, content in self.keep.items():
            self.assertEqual((self.root / name).read_bytes(), content)

    def test_hash_failure_verifies_whole_stage_before_first_replacement(self):
        entries = dict(self.files)
        damaged = 'runtime/qemu-11.1.0/qemu-system-x86_64.exe'
        entries[damaged] = b'x' * len(entries[damaged])
        self.replace_package(entries)
        self.assertEqual(self.setup_runtime()['code'], 'invalid_package')
        self.assert_no_components_published()

    def test_manifest_traversal_and_nonregular_zip_are_rejected(self):
        data = json.loads(self.manifest.read_text())
        unsafe = {'path': '../outside.txt', 'bytes': 3, 'sha256': hashlib.sha256(b'bad').hexdigest()}
        data['files'].append(unsafe)
        self.manifest.write_text(json.dumps(data))
        self.replace_package({**self.files, unsafe['path']: b'bad'})
        self.assertEqual(self.setup_runtime()['code'], 'invalid_package')
        self.assert_no_components_published()
        data['files'].pop()
        self.manifest.write_text(json.dumps(data))
        self.replace_package(symlink='runtime/python-3.12.14/python.exe')
        self.assertEqual(self.setup_runtime()['code'], 'invalid_package')
        self.assert_no_components_published()

    def test_case_duplicates_in_archive_are_rejected(self):
        self.replace_package({**self.files, 'runtime/python-3.12.14/PYTHON.exe': b'bad'})
        self.assertEqual(self.setup_runtime()['code'], 'invalid_package')
        self.assert_no_components_published()

    def test_supervisor_operation_and_linux_locks_block_recovery(self):
        state = self.root / 'state'
        state.mkdir()
        for name in ('operation.lock', 'linux.lock'):
            with self.subTest(lock=name):
                with (state / name).open('w+b') as handle:
                    handle.write(b'\0')
                    handle.flush()
                    if name == 'linux.lock':
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    try:
                        self.assertEqual(self.setup_runtime()['code'], 'runtime_busy')
                        self.assert_no_components_published()
                    finally:
                        if name == 'linux.lock':
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    def test_missing_package_and_fractional_manifest_size_are_rejected(self):
        self.archive.unlink()
        self.assertEqual(self.setup_runtime()['code'], 'package_missing')
        self.replace_package()
        data = json.loads(self.manifest.read_text())
        data['files'][0]['bytes'] = 1.5
        self.manifest.write_text(json.dumps(data))
        self.assertEqual(self.setup_runtime()['code'], 'invalid_package')
        self.assert_no_components_published()

    def test_builder_refuses_existing_outputs_and_missing_essential_files(self):
        for name, content in self.files.items():
            (self.root / name).write_bytes(content)
        with self.assertRaises(ValueError):
            recovery.build_recovery(self.root)
        self.archive.unlink()
        self.manifest.unlink()
        (self.root / recovery.ESSENTIAL[0]).unlink()
        with self.assertRaises(ValueError):
            recovery.build_recovery(self.root)

    def test_junction_target_is_not_written(self):
        outside = self.root / 'outside'
        outside.mkdir()
        sentinel = outside / 'python.exe'
        sentinel.write_bytes(b'keep outside')
        link = self.root / 'runtime/python-3.12.14'
        link.rmdir()
        # This is a new test-owned junction, never a user path or a deletion command.
        created = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True, timeout=10)
        self.assertEqual(created.returncode, 0, created.stderr.decode(errors='replace'))
        try:
            self.assertFalse(self.setup_runtime()['ok'])
            self.assertEqual(sentinel.read_bytes(), b'keep outside')
        finally:
            os.rmdir(link)


if __name__ == '__main__':
    unittest.main()
