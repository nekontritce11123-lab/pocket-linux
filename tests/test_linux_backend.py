import importlib.util
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'scripts'))
import portable_app as app
import runtime_supervisor as runtime


class BackendTests(unittest.TestCase):
    def test_request_limit_duplicates_and_shape(self):
        self.assertEqual(app.read_request(io.BytesIO(b'{"a":1}')), {'a': 1})
        self.assertEqual(app.read_request(io.BytesIO(b''), allow_empty=True), {})
        for payload in (b'x' * 65537, b'{"a":1,"a":2}', b'[]', b'{"a":NaN}', b'\xff', b''):
            with self.subTest(payload=payload[:32]), self.assertRaises(ValueError):
                app.read_request(io.BytesIO(payload))

    def test_settings_validate_and_preserve_defaults(self):
        value = app.validate_settings({'work_memory_mib': 2048, 'vcpus': 3,
                                       'viewer': {'start_fullscreen': True},
                                       'windows': {'width': 1920, 'height': 1080}})
        self.assertEqual(value['work_memory_mib'], 2048)
        self.assertEqual(value['vcpus'], 3)
        self.assertTrue(value['viewer']['start_fullscreen'])
        self.assertTrue(value['viewer']['share_clipboard'])
        self.assertEqual(app.validate_settings({})['windows']['width'], 1280)
        for changed in ({'work_memory_mib': True}, {'vcpus': 0}, {'secret': 'no'},
                        {'accel': 'install'}, {'windows': {'width': 99999}},
                        {'windows': {'height': False}}, {'viewer': {'share_clipboard': 'true'}},
                        {'files': {'mode': 'unknown'}}, {'windows': {'fit': True}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                app.validate_settings(changed)

    def test_settings_are_applied_to_qemu_without_nat(self):
        spec = importlib.util.spec_from_file_location('desktop_start_for_test', SOURCE / 'desktop/start.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        settings = app.validate_settings({'work_memory_mib': 2048, 'vcpus': 3,
                                          'viewer': {'start_fullscreen': True},
                                          'windows': {'width': 1920, 'height': 1080}})
        with mock.patch.object(helper, 'qemu_path', side_effect=lambda p: str(p)):
            argv = runtime.make_qemu_args(Path('C:/Pocket'), settings, None,
                                         '1' * 32, 12345, helper)
        self.assertEqual(argv[argv.index('-m')+1], '2048')
        self.assertEqual(argv[argv.index('-smp')+1], '3')
        self.assertIn('-full-screen', argv)
        self.assertIn('VGA,vgamem_mb=64,xres=1920,yres=1080', argv)
        self.assertIn('-S', argv)
        self.assertEqual(argv[argv.index('-nic')+1], 'none')
        self.assertFalse(any('user,' in item for item in argv))

    def test_proxy_requires_supported_pinned_ipv4(self):
        config = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080,
                  'credentials': {'username': 'sample', 'password': 'test-only-secret'}}
        net = runtime.profile_to_network(config)
        self.assertEqual(net['proxy']['server'], config['host'])
        self.assertEqual(net['proxy']['password'], 'test-only-secret')
        self.assertEqual(net['listen'], '127.0.0.1:0')
        for changed in ({'protocol': 'hysteria2'}, {'protocol': 'other'},
                        {'host': 'bad\nname'}, {'host': '0.0.0.0'}, {'port': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runtime.profile_to_network(config | changed)

    def test_hysteria_preserves_tls_and_keeps_credentials_out_of_guest(self):
        profile = {'protocol': 'hysteria2', 'host': '203.0.113.8', 'port': 443,
                   'tls_server_name': 'proxy.example', 'credentials': {'auth': 'test-only-secret'}}
        config = runtime.profile_to_network(profile)
        self.assertEqual(config['proxy']['type'], 'hysteria2')
        self.assertEqual(config['proxy']['password'], 'test-only-secret')
        self.assertEqual(config['proxy']['tls_server_name'], 'proxy.example')
        for changed in ({'tls_verify': False}, {'credentials': {}}, {'tls_server_name': 'bad\nname'},
                        {'obfs': 'unknown'}, {'host': 'bad\nname'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runtime.profile_to_network(profile | changed)

    def test_proxy_hostname_is_resolved_once_only_for_launch_and_tls_keeps_name(self):
        profile = {'protocol': 'https', 'host': 'proxy.example', 'port': 443}
        with mock.patch.object(runtime.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('203.0.113.7', 443))]) as resolve:
            pending = runtime.profile_to_network(profile, resolve_host=False)
            resolve.assert_not_called()
            self.assertEqual(pending['proxy']['server'], 'proxy.example')
            config = runtime.profile_to_network(profile)
            resolve.assert_called_once_with('proxy.example', 443, runtime.socket.AF_INET, runtime.socket.SOCK_STREAM)
        self.assertEqual(config['proxy']['server'], '203.0.113.7')
        self.assertEqual(config['proxy']['tls_server_name'], 'proxy.example')
        for protocol in ('http', 'https'):
            self.assertEqual(runtime.profile_to_network(profile | {'protocol': protocol, 'host': '203.0.113.7'})['proxy']['type'], protocol)

    def test_proxy_hostname_failure_never_returns_direct_config(self):
        with mock.patch.object(runtime.socket, 'getaddrinfo', side_effect=OSError('not in public error')):
            with self.assertRaises(runtime.BackendError) as error:
                runtime.profile_to_network({'protocol': 'http', 'host': 'proxy.example', 'port': 80})
        self.assertNotIn('not in public error', str(error.exception))

    def test_default_acceleration_uses_only_existing_host_capability(self):
        with mock.patch.object(Path, 'exists', return_value=False):
            self.assertEqual(app.load_settings(Path('C:/Pocket'))['accel'], 'auto')
            for present, expected in ((True, 'whpx'), (False, 'tcg')):
                with mock.patch.object(app, 'host_facts', return_value={'whpx': present}):
                    helper = mock.Mock()
                    helper.build_qemu.return_value = []
                    runtime.make_qemu_args(Path('C:/Pocket'), app.validate_settings({}), None, '1'*32, 12345, helper)
                    self.assertEqual(helper.build_qemu.call_args.args[1], expected)

    def test_probe_deletes_secret_and_rejects_false_receipts(self):
        profile = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080}
        store = mock.Mock()
        store.selected_summary.return_value = {'profile_id': '1' * 32}
        store.secret_config.return_value = profile
        for payload, passed in ((b'{"ok":true,"protocol":"socks5"}', True),
                                (b'{"ok":true,"protocol":"other"}', False), (b'{}', False)):
            with mock.patch.object(app, 'ProfileStore', return_value=store), \
                    mock.patch.object(runtime, '_pinned_directory', return_value=nullcontext()), \
                    mock.patch.object(runtime, 'create_private_directory'), \
                    mock.patch.object(runtime, 'write_json'), \
                    mock.patch.object(app.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=payload)), \
                    mock.patch.object(Path, 'unlink') as deleted, mock.patch.object(Path, 'rmdir'):
                self.assertEqual(app.test_profile(Path('C:/Pocket'), {})['ok'], passed)
                deleted.assert_called_once()

    def test_status_distinguishes_selected_profile_from_running_session(self):
        selected = {'profile_id': '2'*32, 'revision_id': '3'*32}
        store = mock.Mock()
        store.selected_summary.return_value = selected
        store.secret_config.return_value = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080}
        host = {'windows': True, 'x64': True, 'ram_available_mib': 8000, 'whpx': True}
        for applied, revision in ((None, None), ('1'*32, '1'*32), ('2'*32, '4'*32), ('2'*32, '3'*32)):
            view = {'state': {'phase': 'running', 'profile_id': applied, 'profile_revision_id': revision},
                    'work': 'running', 'gateway': 'running' if applied else 'stopped',
                    'active': True, 'uncertain': False, 'control_available': True}
            with mock.patch.object(app, 'host_facts', return_value=host), \
                    mock.patch.object(app, 'load_settings', return_value=app.DEFAULTS), \
                    mock.patch.object(app, 'settings_reply', return_value={}), \
                    mock.patch.object(runtime, 'snapshot', return_value=view), \
                    mock.patch.object(app, 'ProfileStore', return_value=store), \
                    mock.patch.object(app, 'image_ready', return_value=True), \
                    mock.patch.object(Path, 'is_file', return_value=True):
                result = app.report(Path('C:/Pocket'))
            self.assertEqual(result['connection']['selected_applied'], applied == '2'*32 and revision == '3'*32)
            if applied is None:
                self.assertIn('без интернета', result['network_warning'])

    def test_process_identity_checks_creation_time_and_image(self):
        first = {'pid': 1234, 'created': '1337000', 'image': 'C:/Pocket/qemu.exe'}
        self.assertTrue(runtime.same_identity(first, dict(first)))
        for changed in ({'pid': 1235}, {'created': '1337001'}, {'image': 'C:/Other/qemu.exe'}):
            self.assertFalse(runtime.same_identity(first, first | changed))
        self.assertFalse(runtime.same_identity(first, None))

    def test_guest_readiness_expires_and_display_requires_requested_resolution(self):
        store = mock.Mock()
        store.selected_summary.return_value = {'profile_id': '1'*32, 'revision_id': '2'*32}
        store.secret_config.return_value = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080}
        host = {'windows': True, 'x64': True, 'ram_available_mib': 8000, 'whpx': True}
        for age, gateway, width, verified, display in (
                (1, 'running', 1280, True, 'ready'), (61, 'running', 1280, False, 'unconfirmed'),
                (1, 'stopped', 1280, False, 'ready'), (1, 'running', 1920, True, 'failed')):
            state = {'phase': 'running', 'profile_id': '1'*32, 'profile_revision_id': '2'*32,
                     'guest_status': {'received_at': 1000-age, 'status': {'network': 'ready',
                                      'dns': True, 'https': True, 'width': width, 'height': 800}}}
            view = {'state': state, 'work': 'running', 'gateway': gateway, 'active': True,
                    'uncertain': False, 'control_available': True, 'identities': {}}
            with mock.patch.object(app, 'host_facts', return_value=host), \
                    mock.patch.object(app, 'load_settings', return_value=app.DEFAULTS), \
                    mock.patch.object(app, 'settings_reply', return_value={}), \
                    mock.patch.object(runtime, 'snapshot', return_value=view), \
                    mock.patch.object(app, 'ProfileStore', return_value=store), \
                    mock.patch.object(app, 'image_ready', return_value=True), \
                    mock.patch.object(Path, 'is_file', return_value=True), \
                    mock.patch.object(app.time, 'time', return_value=1000):
                result = app.report(Path('C:/Pocket'))
            self.assertEqual(result['network_verified'], verified)
            self.assertEqual(result['windows_display']['status'], display)

    def test_control_requires_nonce_and_supported_action(self):
        nonce = '1' * 32
        token = '3' * 64
        self.assertEqual(runtime.decode_control(json.dumps({'nonce': nonce, 'token': token, 'action': 'stop'}).encode(), nonce, token), 'stop')
        for value in ({'nonce': '2' * 32, 'token': token, 'action': 'stop'},
                      {'nonce': nonce, 'token': '4' * 64, 'action': 'stop'},
                      {'nonce': nonce, 'token': token, 'action': 'quit'},
                      {'nonce': nonce, 'token': token, 'action': 'stop', 'extra': True}):
            with self.assertRaises(ValueError):
                runtime.decode_control(json.dumps(value).encode(), nonce, token)

    def test_native_process_identity_reads_only_current_process(self):
        identity = runtime.process_identity(os.getpid())
        self.assertEqual(identity['pid'], os.getpid())
        self.assertTrue(identity['created'].isdigit())
        self.assertEqual(Path(identity['image']).resolve(), Path(sys.executable).resolve())

    def test_proxy_failure_has_no_direct_fallback(self):
        store = mock.Mock()
        store.selected_summary.return_value = {'profile_id': '1' * 32}
        store.secret_config.return_value = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080,
                                           'credentials': {'username': 'sample', 'password': 'test-only-secret'}}
        with mock.patch.object(app, 'ProfileStore', return_value=store), \
                mock.patch.object(runtime, '_pinned_directory', return_value=nullcontext()), \
                mock.patch.object(runtime, 'create_private_directory'), \
                mock.patch.object(runtime, 'write_json'), \
                mock.patch.object(app.subprocess, 'run', side_effect=subprocess.TimeoutExpired('PocketNet', 20)) as probe, \
                mock.patch.object(Path, 'unlink') as deleted, mock.patch.object(Path, 'rmdir'):
            reply = app.test_profile(Path('C:/Pocket'), {})
        self.assertFalse(reply['ok'])
        self.assertFalse(reply['verified'])
        probe.assert_called_once()
        self.assertEqual(probe.call_args.args[0][-1], '--probe')
        deleted.assert_called_once()
        self.assertNotIn('test-only-secret', json.dumps(reply))

    def test_recovery_never_touches_unidentified_processes(self):
        view = {'state': {'nonce': '1' * 32}, 'uncertain': True, 'identities': {'work': 'unknown'}}
        with mock.patch.object(runtime, 'snapshot', return_value=view), \
                mock.patch.object(runtime, 'helper_module') as helper, \
                mock.patch.object(runtime.subprocess, 'Popen') as launched:
            with self.assertRaises(ValueError):
                runtime.recover_session(Path('C:/Pocket'))
        helper.assert_not_called()
        launched.assert_not_called()

    def test_proxy_secret_directory_refuses_filesystems_without_acls(self):
        with mock.patch.object(runtime, 'volume_persistent_acls', return_value=False), \
                mock.patch.object(Path, 'open') as opened, \
                mock.patch.object(runtime.ctypes, 'WinDLL') as dll:
            with self.assertRaisesRegex(ValueError, 'FAT/exFAT'):
                runtime.create_private_directory(Path('C:/Pocket/state/private'))
        opened.assert_not_called()
        dll.assert_not_called()

    def test_supervisor_keeps_only_safe_backend_error_messages(self):
        safe_message = 'FAT/exFAT не защищают пароль; выбери папку на NTFS.'
        for error in (runtime.BackendError(safe_message), OSError('test-only-secret')):
            with self.subTest(error_type=type(error).__name__):
                state = {'schema': 1, 'nonce': '1' * 32, 'phase': 'launching', 'profile_id': '2' * 32}
                helper = mock.Mock()
                helper.disk_lock.return_value = nullcontext()
                written = []
                with mock.patch.object(runtime, 'helper_module', return_value=helper), \
                        mock.patch.object(runtime, 'read_state', return_value=state), \
                        mock.patch.object(runtime, '_plain'), \
                        mock.patch.object(runtime, 'process_identity', return_value=None), \
                        mock.patch.object(runtime, 'create_private_directory', side_effect=error), \
                        mock.patch.object(runtime, 'write_json', side_effect=lambda path, value: written.append(dict(value))), \
                        mock.patch.object(app, 'load_settings', return_value=app.validate_settings({})), \
                        mock.patch.object(Path, 'exists', return_value=False), \
                        mock.patch.object(runtime.subprocess, 'Popen') as launched:
                    runtime.supervise(Path('C:/Pocket'), '1' * 32)
                self.assertEqual(written[-1]['phase'], 'failed')
                if isinstance(error, runtime.BackendError):
                    self.assertEqual(written[-1]['message'], safe_message)
                else:
                    self.assertNotIn('test-only-secret', json.dumps(written))
                    self.assertIn('Linux не запущен', written[-1]['message'])
                launched.assert_not_called()

    def test_qmp_handshake_checks_uuid_and_sends_only_powerdown(self):
        nonce = '1' * 32
        connection = mock.Mock()
        stream = connection.makefile.return_value
        stream.readline.side_effect = [b'{"QMP":{"version":{}}}\n', b'{"event":"TEST_EVENT"}\n',
            b'{"return":{},"id":1}\n',
            json.dumps({'return': {'UUID': str(uuid.UUID(hex=nonce))}, 'id': 2}).encode() + b'\n',
            b'{"return":{},"id":3}\n']
        qmp = runtime.QMP(connection, nonce)
        qmp.execute('system_powerdown')
        qmp.close()
        requests = [json.loads(call.args[0])['execute'] for call in stream.write.call_args_list]
        self.assertEqual(requests, ['qmp_capabilities', 'query-uuid', 'system_powerdown'])
        stream.close.assert_called_once()
        connection.close.assert_called_once()


class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = SOURCE.parent / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/backend-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix='fake-', dir=scratch)
        cls.root = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def call(self, action, payload=None):
        process = subprocess.run([sys.executable, '-X', 'utf8', '-I', '-S', '-B',
                                  str(SOURCE / 'scripts/portable_app.py'), '--root', str(self.root),
                                  '--action', action], input=b'' if payload is None else json.dumps(payload).encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(process.stderr, b'')
        self.assertEqual(len(process.stdout.splitlines()), 1)
        value = json.loads(process.stdout)
        self.assertIs(type(value['ok']), bool)
        self.assertEqual(process.returncode, 0 if value['ok'] else 1)
        self.assertNotIn('test-only-secret', process.stdout.decode())
        return value

    def test_routes_without_guest_or_installations(self):
        for action in ('diagnose', 'status', 'get-settings', 'list-profiles',
                       'show-desktop', 'stop', 'recover-session', 'prepare-host',
                       'prepare-components', 'repair-gateway', 'not-an-action'):
            with self.subTest(action=action):
                value = self.call(action)
                if action in ('diagnose', 'status'):
                    self.assertIn('checks', value)
                    self.assertFalse(value['network_verified'])
                if action in ('prepare-host', 'prepare-components', 'repair-gateway', 'not-an-action'):
                    self.assertFalse(value['ok'])

    def test_save_and_reload_clipboard_and_memory_settings(self):
        saved = self.call('save-settings', {'work_memory_mib': 2048, 'vcpus': 1})
        self.assertTrue(saved['ok'])
        self.assertEqual(self.call('get-settings')['settings']['work_memory_mib'], 2048)
        self.assertTrue(self.call('save-settings', {'viewer': {'share_clipboard': True}})['ok'])
        self.assertTrue(self.call('get-settings')['viewer_settings']['share_clipboard'])
        self.assertFalse(self.call('save-settings', {'files': {'mode': 'selected', 'folders': ['C:/']}})['ok'])

    def test_running_settings_remain_unchanged(self):
        path = self.root / 'config/linux.json'
        before = path.read_bytes() if path.exists() else None
        with mock.patch.object(runtime, 'snapshot', return_value={'active': True}):
            with self.assertRaises(ValueError):
                app.save_settings(self.root, {'work_memory_mib': 8192})
        self.assertEqual(path.read_bytes() if path.exists() else None, before)

    def test_probe_in_fresh_folder_creates_state_and_removes_secret(self):
        fresh = self.root / ('fresh-' + uuid.uuid4().hex)
        fresh.mkdir()
        store = mock.Mock()
        store.selected_summary.return_value = {'profile_id': '1'*32}
        store.secret_config.return_value = {'protocol': 'socks5', 'host': '203.0.113.8', 'port': 1080}
        def probe(args, **unused):
            self.assertTrue(Path(args[2]).is_file())
            return mock.Mock(returncode=0, stdout=b'{"ok":true,"protocol":"socks5"}')
        with mock.patch.object(app, 'ProfileStore', return_value=store), \
                mock.patch.object(app.subprocess, 'run', side_effect=probe):
            self.assertTrue(app.test_profile(fresh, {})['ok'])
        self.assertTrue((fresh / 'state').is_dir())
        self.assertEqual(list((fresh / 'state').iterdir()), [])

    def test_private_session_directory_has_protected_current_user_acl(self):
        import ctypes
        from ctypes import wintypes
        path = self.root / ('private-' + uuid.uuid4().hex)
        runtime.create_private_directory(path)
        (path / 'canary.txt').write_text('non-secret-test', encoding='utf-8')
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        descriptor = ctypes.c_void_p()
        text = wintypes.LPWSTR()
        advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        try:
            self.assertEqual(advapi.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None,
                                                       ctypes.byref(descriptor)), 0)
            self.assertTrue(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, 4, ctypes.byref(text), None))
            self.assertTrue(text.value.startswith('D:P'))
            self.assertEqual(text.value.count('(A;'), 1)
            self.assertIn('FA;;;S-1-5-21-', text.value)
        finally:
            if text:
                kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            if descriptor:
                kernel.LocalFree(descriptor)

    def test_profile_metadata_roundtrip_with_secret_staying_private(self):
        saved = self.call('save-profile', {'profile': {'protocol': 'socks5', 'host': '203.0.113.8',
                           'port': 1080, 'credentials': {'username': 'sample', 'password': 'test-only-secret'}}})
        self.assertTrue(saved['ok'], saved)
        profile_id = saved['profile']['profile_id']
        self.assertTrue(self.call('select-profile', {'profile_id': profile_id})['ok'])
        self.assertTrue(self.call('get-profile-view', {'profile_id': profile_id})['ok'])
        self.assertGreaterEqual(len(self.call('list-profiles')['profiles']), 1)


if __name__ == '__main__':
    unittest.main()
