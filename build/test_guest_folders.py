import importlib.util
import json
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('guest_folders', Path(__file__).with_name('guest_folders.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


def config():
    return {'schema': 1, 'session_nonce': '1' * 32, 'server': '192.168.234.4',
            'username': 'WCP_test', 'password': 'a' * 64, 'shares': ['PC_01', 'PC_02']}


class GuestFolderTests(unittest.TestCase):
    def test_old_mountpoints_are_removed_without_touching_mounts_or_user_data(self):
        scratch = Path(tempfile.gettempdir()) / 'pocket-linux-folder-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            for name in ('PC_01', 'PC_C', 'PC_02', 'PC_03', 'PC_04', 'personal'):
                (root / name).mkdir()
            (root / 'PC_02/keep.txt').write_text('user data')
            original = Path.lstat
            def metadata(path):
                if path == root / 'PC_03':
                    return SimpleNamespace(st_mode=stat.S_IFDIR, st_uid=1000)
                if path == root / 'PC_04':
                    return SimpleNamespace(st_mode=stat.S_IFLNK, st_uid=0)
                return original(path)
            with mock.patch.object(guest, 'MOUNT_ROOT', root), \
                    mock.patch.object(guest, 'mount_table', return_value={str(root / 'PC_C'): ('cifs', '//server/PC_C')}), \
                    mock.patch.object(Path, 'lstat', metadata):
                guest.remove_empty_mountpoints()
            self.assertFalse((root / 'PC_01').exists())
            self.assertEqual({p.name for p in root.iterdir()}, {'PC_C', 'PC_02', 'PC_03', 'PC_04', 'personal'})
            self.assertEqual((root / 'PC_02/keep.txt').read_text(), 'user data')

    def test_server_limit_of_64_distinct_shares_is_supported(self):
        value = config() | {'shares': ['PC_' + str(index) for index in range(64)]}
        self.assertEqual(len(guest.parse_config(json.dumps(value).encode())['shares']), 64)
        with self.assertRaises(ValueError):
            guest.parse_config(json.dumps(value | {'shares': value['shares'] + ['PC_64']}).encode())

    def test_firmware_shape_and_size_are_bounded(self):
        self.assertEqual(guest.parse_config(json.dumps(config()).encode()), config())
        for changed in ({'schema': True}, {'server': '1.1.1.1'}, {'password': 'bad\nvalue'},
                        {'username': 'WindowsUser'}, {'shares': ['../escape']},
                        {'shares': ['PC_A', 'PC_a']}, {'shares': []}, {'shares': ['PC_1'] * 17},
                        {'proxy': {'password': 'never'}}, {'uid': 0}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                guest.parse_config(json.dumps(config() | changed).encode())
        with self.assertRaises(ValueError):
            guest.parse_config(b'x' * (guest.MAX_CONFIG_BYTES + 1))

    def test_cifs_args_use_credentials_file_and_unicode_signing(self):
        args = guest.mount_arguments(config(), 'PC_01', Path('/run/pocket-files/credentials-abc'), 1000, 1000)
        options = args[args.index('-o') + 1].split(',')
        self.assertIn('credentials=/run/pocket-files/credentials-abc', options)
        self.assertIn('sign', options)
        self.assertIn('iocharset=utf8', options)
        self.assertIn('mapchars', options)
        self.assertIn('uid=1000', options)
        self.assertIn('gid=1000', options)
        self.assertNotIn(config()['password'], str(args))
        self.assertNotIn(config()['username'], str(args))
        self.assertEqual(args[1], '//192.168.234.4/PC_01')
        for key in ('gateway', 'dns', 'route'):
            self.assertNotIn(key, str(args))

    def test_retry_is_bounded_and_never_opens_other_connection(self):
        with mock.patch.object(guest.time, 'monotonic', return_value=0), \
                mock.patch.object(guest.time, 'sleep'), \
                mock.patch.object(guest.subprocess, 'run', return_value=mock.Mock(returncode=1)) as invoked:
            self.assertFalse(guest.mount_with_retry(['mount.cifs', 'test'], 90))
        self.assertEqual(invoked.call_count, 3)
        self.assertTrue(all(call.kwargs['timeout'] <= 15 for call in invoked.call_args_list))

    def test_windows_is_refused_before_any_system_command(self):
        with mock.patch.object(guest.sys, 'platform', 'win32'), \
                mock.patch.object(guest.subprocess, 'run') as invoked:
            with self.assertRaises(RuntimeError):
                guest.guard_guest()
        invoked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
