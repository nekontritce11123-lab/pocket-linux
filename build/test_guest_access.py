import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location('guest_access', Path(__file__).with_name('guest_access.py'))
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
TEMP = Path(__file__).resolve().parents[2] / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/desktop-build/access-tests'


class AccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TEMP.mkdir(parents=True, exist_ok=True)

    def test_windows_is_refused_before_files_or_commands(self):
        with mock.patch.object(access.sys, 'platform', 'win32'), \
                mock.patch.object(Path, 'open') as opened, \
                mock.patch.object(access.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                access.guard_guest()
        opened.assert_not_called()
        run.assert_not_called()

    def test_non_root_setup_is_refused(self):
        with mock.patch.object(access.sys, 'platform', 'linux'), \
                mock.patch.object(access.os, 'geteuid', return_value=1000, create=True), \
                mock.patch.object(Path, 'open') as opened:
            with self.assertRaises(RuntimeError):
                access.guard_guest()
        opened.assert_not_called()

    def test_scalar_build_marker_is_refused_before_commands(self):
        with mock.patch.object(access.sys, 'platform', 'linux'), \
                mock.patch.object(access.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(Path, 'is_symlink', return_value=False), \
                mock.patch.object(Path, 'is_file', return_value=True), \
                mock.patch.object(Path, 'open', return_value=io.BytesIO(b'42')), \
                mock.patch.object(access.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'build marker'):
                access.guard_guest()
        run.assert_not_called()

    def test_existing_encrypted_keyring_is_preserved(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as folder:
            home = Path(folder)
            rings = home / '.local/share/keyrings'
            rings.mkdir(parents=True)
            encrypted = rings / 'login.keyring'
            content = b'GnomeKeyring\n\r\0\n' + b'sensitive-test-marker'
            encrypted.write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, 'existing keyring'):
                access.check_keyrings(home)
            self.assertEqual(encrypted.read_bytes(), content)

    def test_plain_login_and_alias_are_allowed_without_modifying_items(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as folder:
            home = Path(folder)
            rings = home / '.local/share/keyrings'
            rings.mkdir(parents=True)
            content = b'[keyring]\ndisplay-name=Login\n\n[1]\nsecret=synthetic-value\n'
            (rings / 'login.keyring').write_bytes(content)
            (rings / 'default').write_text('login', encoding='utf-8')
            access.check_keyrings(home)
            self.assertEqual((rings / 'login.keyring').read_bytes(), content)

    def test_other_default_or_wallet_is_preserved(self):
        for name, content in (('.local/share/keyrings/default', b'personal'),
                              ('.local/share/keyrings/personal.keyring', b'[keyring]\n'),
                              ('.local/share/kwalletd/kdewallet.kwl', b'wallet')):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=TEMP) as folder:
                home = Path(folder)
                existing = home / name
                existing.parent.mkdir(parents=True)
                existing.write_bytes(content)
                with self.assertRaises(RuntimeError):
                    access.check_keyrings(home)
                self.assertEqual(existing.read_bytes(), content)

    def test_empty_password_uses_nul_not_eof_and_checks_unlocked_alias(self):
        completed = [mock.Mock(stdout=b''),
                     mock.Mock(stdout=b"(objectpath '/org/freedesktop/secrets/collection/login',)\n"),
                     mock.Mock(stdout=b'(<false>,)\n')]
        with mock.patch.object(access.subprocess, 'run', side_effect=completed) as run:
            access.unlock_keyring()
        self.assertEqual(run.call_args_list[0].kwargs['input'], b'\0')
        self.assertNotIn('--start', run.call_args_list[0].args[0])
        self.assertIn('org.freedesktop.DBus.Properties.Get', run.call_args_list[2].args[0])

    def test_locked_or_missing_default_is_failure_without_creating_collection_prompt(self):
        for alias, locked in ((b"(objectpath '/',)\n", b'(<false>,)\n'),
                              (b"(objectpath '/org/freedesktop/secrets/collection/login',)\n", b'(<true>,)\n')):
            with self.subTest(alias=alias, locked=locked), \
                    mock.patch.object(access.subprocess, 'run', side_effect=[
                        mock.Mock(stdout=b''), mock.Mock(stdout=alias), mock.Mock(stdout=locked)]) as run:
                with self.assertRaises(RuntimeError):
                    access.unlock_keyring()
                self.assertFalse(any('CreateCollection' in str(call) for call in run.call_args_list))

    def test_fresh_locked_account_is_emptied_without_changing_root(self):
        with mock.patch.object(access.subprocess, 'run', side_effect=[
                mock.Mock(stdout='pocket L 2026-10-25 0 99999 7 -1\n'),
                mock.Mock(stdout='pocket:!:20386:0:99999:7:::\n'), mock.Mock()]) as run:
            access.empty_fresh_account()
        self.assertEqual(run.call_args_list[2].args[0], ['/usr/bin/passwd', '--delete', 'pocket'])

    def test_locked_real_password_hash_is_preserved(self):
        with mock.patch.object(access.subprocess, 'run', side_effect=[
                mock.Mock(stdout='pocket L 2026-10-25 0 99999 7 -1\n'),
                mock.Mock(stdout='pocket:!$6$synthetic$test:20386:0:99999:7:::\n')]) as run:
            with self.assertRaisesRegex(RuntimeError, 'existing locked password'):
                access.empty_fresh_account()
        self.assertEqual(run.call_count, 2)

    def test_existing_password_is_never_deleted(self):
        with mock.patch.object(access.subprocess, 'run', return_value=mock.Mock(
                stdout='pocket P 2026-10-25 0 99999 7 -1\n')) as run:
            with self.assertRaisesRegex(RuntimeError, 'existing user password'):
                access.empty_fresh_account()
        self.assertEqual(run.call_count, 1)

    def test_root_fresh_lock_is_emptied_and_existing_hash_is_preserved(self):
        with mock.patch.object(access.subprocess, 'run', side_effect=[
                mock.Mock(stdout='root L 2026-10-25 0 99999 7 -1\n'),
                mock.Mock(stdout='root:*:20386:0:99999:7:::\n'), mock.Mock()]) as run:
            access.empty_fresh_account('root')
        self.assertEqual(run.call_args_list[2].args[0], ['/usr/bin/passwd', '--delete', 'root'])
        with mock.patch.object(access.subprocess, 'run', side_effect=[
                mock.Mock(stdout='root L 2026-10-25 0 99999 7 -1\n'),
                mock.Mock(stdout='root:!$6$synthetic$test:20386:0:99999:7:::\n')]) as run:
            with self.assertRaises(RuntimeError):
                access.empty_fresh_account('root')
        self.assertEqual(run.call_count, 2)

    def test_other_accounts_are_never_changed(self):
        with mock.patch.object(access.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                access.empty_fresh_account('daemon')
        run.assert_not_called()

    def test_admin_policy_applies_only_to_local_active_pocket(self):
        self.assertIn('subject.user === "pocket" && subject.local && subject.active', access.POLKIT)
        self.assertEqual(access.SUDOERS, 'pocket ALL=(ALL:ALL) NOPASSWD: ALL\n')


if __name__ == '__main__':
    unittest.main()
