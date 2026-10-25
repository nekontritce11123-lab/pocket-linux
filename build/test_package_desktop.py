import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import zipfile

spec = importlib.util.spec_from_file_location('package_desktop', Path(__file__).with_name('package_desktop.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def test_allowlisted_directory_itself_cannot_be_a_junction(self):
        root = Path(__file__).resolve().parents[1]
        original = Path.lstat
        def metadata(path):
            if path == root / package.DIRECTORIES[0]:
                return SimpleNamespace(st_file_attributes=package.stat.FILE_ATTRIBUTE_REPARSE_POINT)
            return original(path)
        with mock.patch.object(Path, 'lstat', metadata), self.assertRaisesRegex(ValueError, 'Reparse'):
            package.payload(root)

    def test_allowlist_excludes_personal_profile_and_verifies_extraction(self):
        test_root = Path(__file__).resolve().parents[2] / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/desktop-build/package-tests'
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as scratch:
            base = Path(scratch)
            root = base / 'payload'
            for relative in package.FILES + tuple(name + '/sample.txt' for name in package.DIRECTORIES):
                file = root / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(relative.encode())
            for relative in ('profiles/profiles.json', 'state/proxy.json', 'config/personal.json', 'unexpected.txt'):
                file = root / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('never ship this')
            result = package.package(root, base / 'test.zip', base / 'extracted')
            self.assertTrue(result['crc_and_all_extracted_sha256'])
            with zipfile.ZipFile(base / 'test.zip') as archive:
                self.assertFalse(any(part in name for name in archive.namelist()
                                     for part in ('profiles/', 'state/', 'config/', 'unexpected')))
            manifest = json.loads((base / 'extracted/Pocket-Linux/SHA256SUMS.json').read_text())
            self.assertEqual(len(manifest), len(package.FILES) + len(package.DIRECTORIES))


if __name__ == '__main__':
    unittest.main()
