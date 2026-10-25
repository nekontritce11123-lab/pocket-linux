import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_files_probe
import guest_files_probe


class FilesProbeTests(unittest.TestCase):
    def test_cli_imports_under_isolated_python(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).with_name('run_files_probe.py')), '--help'],
                                capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'--host-files', result.stdout)

    def test_guest_configuration_has_only_restricted_files_network(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            base, qemu = root / 'base.qcow2', root / 'qemu-system-x86_64.exe'
            base.touch()
            qemu.touch()
            request = run_files_probe.host_request(root / 'share')
            with patch.object(run_files_probe, 'qemu_path', side_effect=lambda path: str(path)):
                commands = run_files_probe.prepare_files_guest(root / 'guest', base, qemu, 60000, request)
            args = commands['qemu_argv']
            self.assertEqual(args.count('-netdev'), 1)
            net = args[args.index('-netdev') + 1]
            self.assertIn('user,id=plnet,restrict=on,ipv6=off,net=192.168.234.0/24,', net)
            self.assertIn('guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:60000', net)
            self.assertNotIn('hostfwd=', net)
            self.assertIn('virtio-blk-pci,drive=plseed,bootindex=2', args)
            self.assertFalse(any('usb' in arg for arg in args))
            blocks = [json.loads(args[i + 1]) for i, item in enumerate(args) if item == '-blockdev']
            self.assertNotIn(str(base), json.dumps(blocks))
            self.assertIn(str(base), commands['overlay_argv'])
            self.assertEqual(blocks[1]['label'], 'CIDATA')
            self.assertTrue(blocks[1]['read-only'])
            network = json.loads((root / 'guest/seed/network-config').read_text())
            nic = network['ethernets']['lan0']
            self.assertEqual(nic['addresses'], ['192.168.234.15/24'])
            self.assertNotIn('gateway4', nic)
            self.assertNotIn('nameservers', nic)
            user = json.loads((root / 'guest/seed/user-data').read_text().split('\n', 1)[1])
            self.assertEqual(user['users'], [])
            compile(user['write_files'][0]['content'], 'guest_files_probe', 'exec')

    def test_host_contract_and_bounded_current_receipt(self):
        request = run_files_probe.host_request(Path('C:/new/share'))
        self.assertRegex(request['session_nonce'], '^[a-f0-9]{32}$')
        self.assertRegex(request['username'], '^WCP_[A-Za-z0-9_]{1,32}$')
        self.assertRegex(request['password'], '^[a-f0-9]{64}$')
        self.assertEqual(request['protected'], [])
        self.assertEqual(request['shares'], [{'name': 'PC_SPIKE', 'path': str(Path('C:/new/share'))}])
        ready = {'schema': 1, 'ok': True, 'session_nonce': request['session_nonce'],
                 'port': 60000, 'share_count': 1}
        process = Mock(stdout=io.BytesIO(json.dumps(ready).encode() + b'\n'))
        self.assertEqual(run_files_probe.read_host_ready(process, request), ready)
        for value in [dict(ready, session_nonce='0' * 32), dict(ready, port=445),
                      dict(ready, share_count=2), dict(ready, ok=False)]:
            process.stdout = io.BytesIO(json.dumps(value).encode() + b'\n')
            with self.assertRaises(ValueError):
                run_files_probe.read_host_ready(process, request)
        process.stdout = io.BytesIO(b'x' * 5000)
        with self.assertRaises(ValueError):
            run_files_probe.read_host_ready(process, request)

    def test_guest_mount_options_and_errors_hide_credentials(self):
        config = {'session_nonce': 'a' * 32, 'username': 'WCP_test', 'password': 'b' * 64}
        args = guest_files_probe.mount_arguments(config)
        self.assertEqual(args[:6], ['mount', '-i', '-t', 'cifs', '//192.168.234.4/PC_SPIKE', '/mnt/hosttest'])
        for option in ('vers=2.1', 'sec=ntlmssp', 'sign'):
            self.assertIn(option, args[-1].split(','))
        redacted = guest_files_probe.safe_error('user WCP_test password=' + 'b' * 64, config)
        self.assertNotIn(config['username'], redacted)
        self.assertNotIn(config['password'], redacted)

    def test_receipt_rejects_wrong_session_and_limits_output(self):
        data = {'schema': 1, 'session_nonce': 'a' * 32, 'ok': False, 'stage': 'mount',
                'detail': 'CIFS unsupported', 'read_ok': False, 'write_ok': False,
                'rename_ok': False, 'delete_ok': False, 'unmount_ok': False}
        line = 'PL_FILES ' + json.dumps(data)
        self.assertEqual(run_files_probe.parse_files_receipt(line, 'a' * 32), data)
        for invalid in [line.replace('a' * 32, 'b' * 32), 'PL_FILES []', 'PL_FILES ' + 'x' * 2048]:
            with self.assertRaises(ValueError):
                run_files_probe.parse_files_receipt(invalid, 'a' * 32)
        self.assertIsNone(run_files_probe.parse_files_receipt('ordinary boot message', 'a' * 32))

    def test_guest_file_operations_with_mocked_mount(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            share = root / 'mount'
            share.mkdir()
            (share / 'windows-sentinel.txt').write_text(guest_files_probe.WINDOWS_TEXT, encoding='utf-8')
            config = {'session_nonce': 'a' * 32, 'username': 'WCP_test', 'password': 'b' * 64}
            config_path = root / 'config.json'
            config_path.write_text(json.dumps(config))
            serial = io.StringIO()

            class Serial:
                def __enter__(self):
                    return serial

                def __exit__(self, *args):
                    return False

            def guest_path(value):
                return {'/opt/pl-files-config.json': config_path, '/mnt/hosttest': share}[value]

            with patch.object(guest_files_probe, 'Path', side_effect=guest_path), \
                    patch.object(guest_files_probe.subprocess, 'run', return_value=Mock(returncode=0, stderr=b'')) as run, \
                    patch('builtins.open', return_value=Serial()):
                guest_files_probe.main()
            receipt = run_files_probe.parse_files_receipt(serial.getvalue(), config['session_nonce'])
            self.assertTrue(receipt['ok'])
            self.assertEqual((share / guest_files_probe.FINAL_NAME).read_text(encoding='utf-8'), guest_files_probe.LINUX_TEXT)
            self.assertFalse((share / guest_files_probe.DELETE_NAME).exists())
            self.assertFalse((share / 'linux-write.tmp').exists())
            self.assertEqual([entry.args[0][0] for entry in run.call_args_list], ['modprobe', 'mount', 'umount', 'systemctl'])

    def test_controller_uses_only_mocked_children_and_scrubs_logs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            base, qemu, host = (root / name for name in ('base.qcow2', 'qemu-system-x86_64.exe', 'HostFiles.exe'))
            for path in (base, qemu, host):
                path.touch()
            output = root / 'run'
            request = run_files_probe.host_request(output / 'share')
            ready = {'schema': 1, 'ok': True, 'session_nonce': request['session_nonce'], 'port': 60000, 'share_count': 1}
            helper = Mock(stdin=io.BytesIO(), stdout=io.BytesIO(json.dumps(ready).encode()), stderr=None)
            helper.poll.return_value = None
            overlay = Mock(stdin=None, stdout=None, stderr=None, returncode=0)
            overlay.poll.return_value = 0
            vm = Mock(pid=123, stdin=None, stdout=None, stderr=None, returncode=0)
            vm.poll.return_value = 0

            def guest_finished(timeout):
                self.assertEqual(timeout, 120)
                self.assertFalse(helper.stdin.closed)
                receipt = {'schema': 1, 'session_nonce': request['session_nonce'], 'ok': True,
                           'stage': 'done', 'detail': '', **{key: True for key in run_files_probe.FLAGS}}
                (output / 'guest/serial.log').write_text(request['password'] + '\nPL_FILES ' + json.dumps(receipt))
                (output / 'share' / guest_files_probe.FINAL_NAME).write_text(guest_files_probe.LINUX_TEXT, encoding='utf-8')
                return 0

            vm.wait.side_effect = guest_finished
            with patch.object(run_files_probe, 'launch', side_effect=[helper, overlay, vm]) as launch, \
                    patch.object(run_files_probe, 'qemu_path', side_effect=lambda path: str(path)), \
                    patch.object(run_files_probe, 'host_request', return_value=request), \
                    patch('builtins.print'):
                self.assertTrue(run_files_probe.run(output, base, qemu, host))
            self.assertEqual(launch.call_count, 3)
            report_text = (output / 'result.json').read_text()
            self.assertEqual(json.loads(report_text)['verdict'], 'passed')
            for text in (report_text, (output / 'guest/serial.log').read_text()):
                self.assertNotIn(request['password'], text)
                self.assertNotIn(request['username'], text)


if __name__ == '__main__':
    unittest.main()
