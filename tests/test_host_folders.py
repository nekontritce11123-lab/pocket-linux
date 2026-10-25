import importlib.util
from contextlib import nullcontext
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import host_folders as folders


class FolderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = ROOT.parent / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/folder-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix='host-', dir=scratch)
        cls.base = Path(cls.temporary.name)
        cls.root = cls.base / 'package'
        cls.share = cls.base / 'shared-кириллица'
        cls.private = cls.root / 'state/session-test'
        cls.root.mkdir()
        cls.share.mkdir()
        cls.private.mkdir(parents=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.system_paths = mock.patch.object(folders, 'system_protected_paths', return_value=[]).start()
        self.addCleanup(mock.patch.stopall)

    def test_drive_enumeration_uses_only_fixed_and_removable_flags(self):
        kernel = mock.Mock()
        kernel.GetLogicalDrives.return_value = sum(1 << index for index in (2, 3, 4, 5))
        kernel.GetDriveTypeW.side_effect = lambda path: {'C:\\': 3, 'D:\\': 2, 'E:\\': 4, 'F:\\': 5}[path]
        with mock.patch.object(folders.ctypes, 'WinDLL', return_value=kernel):
            self.assertEqual(folders.local_drives(), ['C:\\', 'D:\\'])

    def test_all_mode_keeps_drive_ancestor_and_protects_runtime_and_startup(self):
        executable = self.root / 'runtime/host-files/HostFiles.exe'
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.touch()
        process, request = mock.Mock(), {}
        process.poll.return_value = None
        process.stdin.write.side_effect = lambda data: request.update(json.loads(data))
        process.stdout.readline.side_effect = lambda limit: json.dumps(
            {'schema': 1, 'ok': True, 'session_nonce': request['session_nonce'], 'port': 50001,
             'share_count': len(request['shares'])}).encode() + b'\n'
        startup = self.base / 'fake-startup'
        self.system_paths.return_value = [startup]
        # No drive-root or personal-directory I/O: all OS discovery and pins are mocked.
        with mock.patch.object(folders, 'local_drives', return_value=[self.root.anchor]), \
                mock.patch.object(folders, 'canonical_directory', side_effect=Path), \
                mock.patch.object(folders, '_pinned_directory', side_effect=lambda *args, **kwargs: nullcontext()), \
                mock.patch.object(folders.subprocess, 'Popen', return_value=process):
            channel = folders.start(self.root, {'mode': 'all'}, self.private, lambda path: str(path))
            self.assertEqual(request['shares'], [{'name': 'PC_' + self.root.drive[0], 'path': self.root.anchor}])
            self.assertIn(str(self.root), request['protected'])
            self.assertIn(str(self.private), request['protected'])
            self.assertIn(str(startup), request['protected'])
            self.assertIn('restrict=on', str(channel.qemu_args))
            channel.close()

    def test_selected_folder_is_canonical_and_invalid_modes_are_refused(self):
        value = folders.normalize_folders(self.root, {'mode': 'selected', 'folders': [str(self.share)]})
        self.assertEqual(value, {'schema': 1, 'mode': 'selected', 'folders': [str(self.share.resolve())]})
        self.assertEqual(folders.normalize_folders(self.root, {})['mode'], 'off')
        for settings in ({'mode': 'invalid'}, {'mode': 'selected', 'folders': []},
                         {'mode': 'selected', 'folders': [str(self.share)] * 17},
                         {'mode': 'selected', 'folders': [str(self.share), str(self.share)]},
                         {'schema': True}, {'unknown': 'no'}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                folders.normalize_folders(self.root, settings)

    def test_all_mode_normalization_does_not_probe_disks(self):
        with mock.patch.object(Path, 'lstat', side_effect=AssertionError('No disk probe during settings validation')):
            self.assertEqual(folders.normalize_folders(self.root, {'mode': 'all'}),
                             {'schema': 1, 'mode': 'all', 'folders': []})

    def test_package_ancestors_and_children_are_never_shared(self):
        for path in (self.root, self.base, self.private, self.root / 'state'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                folders.normalize_folders(self.root, {'mode': 'selected', 'folders': [str(path)]})
        for path in ('relative', 'C:relative', '//server/share', r'\\?\C:\Windows', 'C:/'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                folders.normalize_folders(self.root, {'mode': 'selected', 'folders': [path]})

    def test_reparse_component_is_refused(self):
        fake = mock.Mock(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        with mock.patch.object(Path, 'lstat', return_value=fake):
            with self.assertRaises(ValueError):
                folders.canonical_directory(self.share)

    def test_disabled_folders_do_not_probe_a_missing_drive(self):
        with mock.patch.object(Path, 'lstat', side_effect=AssertionError('No disk access while off')):
            value = folders.normalize_folders(self.root, {'mode': 'off', 'folders': ['Z:/missing-project']})
        self.assertEqual(value['mode'], 'off')
        self.assertEqual(len(value['folders']), 1)

    def test_ready_requires_exact_nonce_share_count_and_loopback_port_range(self):
        ready = {'schema': 1, 'ok': True, 'session_nonce': '1' * 32, 'port': 50001, 'share_count': 2}
        self.assertEqual(folders.parse_ready(json.dumps(ready).encode(), '1' * 32, 2)['port'], 50001)
        for changed in ({'session_nonce': '2' * 32}, {'share_count': 1}, {'share_count': True},
                        {'port': 445}, {'port': True}, {'schema': True}, {'ok': False}, {'extra': 1}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                folders.parse_ready(json.dumps(ready | changed).encode(), '1' * 32, 2)
        with self.assertRaises(ValueError):
            folders.parse_ready(b'x' * 4097, '1' * 32, 2)

    def test_start_uses_confined_helper_stdin_and_secret_free_qemu_args(self):
        executable = self.root / 'runtime/host-files/HostFiles.exe'
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.touch()
        process = mock.Mock()
        process.poll.return_value = None
        request = {}

        def receive(data):
            request.update(json.loads(data))

        process.stdin.write.side_effect = receive
        process.stdout.readline.side_effect = lambda limit: json.dumps(
            {'schema': 1, 'ok': True, 'session_nonce': request['session_nonce'], 'port': 50001,
             'share_count': len(request['shares'])}).encode() + b'\n'
        with mock.patch.object(folders.subprocess, 'Popen', return_value=process) as launched:
            channel = folders.start(self.root, [str(self.share)], self.private, lambda path: str(path))
            args = channel.qemu_args
            self.assertEqual(request['shares'], [{'name': 'PC_01', 'path': str(self.share.resolve())}])
            self.assertIn(str(self.root.resolve()), request['protected'])
            self.assertIn(str(self.private.resolve()), request['protected'])
            self.assertIn('restrict=on', args[args.index('-netdev') + 1])
            self.assertIn('ipv6=off', args[args.index('-netdev') + 1])
            self.assertIn('guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:50001', args[args.index('-netdev') + 1])
            self.assertNotIn(request['password'], str(args))
            self.assertNotIn(request['username'], str(args))
            self.assertNotIn('hostfwd=', str(args))
            config_path = channel.config_path
            config = json.loads(config_path.read_text())
            self.assertEqual(config['shares'], ['PC_01'])
            self.assertNotIn('path', config)
            channel.close()
            channel.close()
        self.assertFalse(config_path.exists())
        process.stdin.close.assert_called()
        self.assertEqual(launched.call_args.args[0], [str(executable)])

    def test_no_selected_folders_start_nothing(self):
        with mock.patch.object(folders.subprocess, 'Popen') as launched:
            channel = folders.start(self.root, [], self.private, lambda path: str(path))
            self.assertEqual(channel.qemu_args, [])
            channel.close()
        launched.assert_not_called()

    def test_wrong_ready_nonce_closes_only_owned_helper_and_cleans_private_file(self):
        executable = self.root / 'runtime/host-files/HostFiles.exe'
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.touch()
        process = mock.Mock()
        process.poll.return_value = None
        process.stdout.readline.return_value = json.dumps(
            {'schema': 1, 'ok': True, 'session_nonce': 'wrong', 'port': 50001, 'share_count': 1}).encode()
        with mock.patch.object(folders.subprocess, 'Popen', return_value=process):
            with self.assertRaises(ValueError):
                folders.start(self.root, [str(self.share)], self.private, lambda path: str(path))
        process.stdin.close.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)
        self.assertEqual(list(self.private.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
