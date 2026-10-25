import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_files_probe
import integration
import guest_files_probe


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temporary.name)
        self.helper = Mock(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=None)
        self.helper.poll.return_value = None
        self.launch = patch.object(run_files_probe, 'launch', return_value=self.helper).start()
        self.read_ready = patch.object(run_files_probe, 'read_host_ready', side_effect=lambda process, request: {
            'schema': 1, 'ok': True, 'session_nonce': request['session_nonce'], 'port': 60000, 'share_count': 1}).start()
        self.stop = patch.object(run_files_probe, 'stop_owned').start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.temporary.cleanup)
        self.channel = integration.FileChannel(self.root)
        self.addCleanup(self.channel.close)

    def test_attach_preserves_proxy_nic_and_network(self):
        base, qemu = self.root / 'base.qcow2', self.root / 'qemu.exe'
        base.touch()
        qemu.touch()
        commands = run_files_probe.prepare(self.root / 'guest', base, qemu, 19000)
        original_args = commands['qemu_argv'][:]
        path = self.root / 'guest/seed/network-config'
        original_network = json.loads(path.read_text())
        self.channel.attach(commands)
        self.assertEqual(commands['qemu_argv'][:len(original_args)], original_args)
        args = commands['qemu_argv']
        self.assertEqual(args.count('-netdev'), 2)
        self.assertEqual(json.loads(args[args.index('-netdev') + 1])['type'], 'stream')
        net = args[len(original_args) + 1]
        self.assertIn('user,id=plfiles,restrict=on,ipv6=off,net=192.168.234.0/24,', net)
        self.assertIn('guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:60000', net)
        self.assertIn('virtio-net-pci,netdev=plfiles,mac=52:54:00:50:4c:03', args)
        network = json.loads(path.read_text())
        self.assertEqual(network['ethernets']['lan0'], original_network['ethernets']['lan0'])
        files = network['ethernets']['files0']
        self.assertEqual(files['addresses'], ['192.168.234.15/24'])
        self.assertFalse(files['dhcp4'])
        self.assertFalse(files['dhcp6'])
        self.assertFalse(files['accept-ra'])
        self.assertNotIn('gateway4', files)
        self.assertNotIn('routes', files)
        self.assertNotIn('nameservers', files)
        user = json.loads((self.root / 'guest/seed/user-data').read_text().split('\n', 1)[1])
        scripts = {item['path']: item['content'] for item in user['write_files']}
        self.assertIn('/opt/pl-probe.py', scripts)
        combined = scripts['/opt/pl-combined.py']
        compile(combined, 'combined', 'exec')
        self.assertIn('time.sleep(30)', combined)
        self.assertIn('main(poweroff=False)', combined)
        self.assertEqual(user['runcmd'], [['python3', '-I', '-B', '/opt/pl-combined.py']])
        with self.assertRaises(ValueError):
            self.channel.attach(commands)

    def test_checks_require_proxy_down_and_host_content_without_secrets(self):
        request = json.loads(self.helper.stdin.getvalue())
        data = {'schema': 1, 'session_nonce': request['session_nonce'], 'ok': True,
                'stage': 'done', 'detail': '', **{key: True for key in run_files_probe.FLAGS}}
        (self.root / 'files/share' / run_files_probe.FINAL_NAME).write_text(run_files_probe.LINUX_TEXT, encoding='utf-8', newline='')
        line = 'PL_FILES ' + json.dumps(data)
        self.assertTrue(self.channel.accept(line, 'proxy_down'))
        self.assertTrue(all(self.channel.checks().values()))
        report = self.channel.safe_text(json.dumps({'receipts': self.channel.receipts, 'ready': self.channel.ready}))
        self.assertNotIn(request['password'], report)
        self.assertNotIn(request['username'], report)
        self.assertEqual(self.channel.safe_text(request['username'] + ' ' + request['password']), '[redacted] [redacted]')
        self.assertFalse(self.channel.accept('ordinary boot message', 'healthy'))
        wrong = copy.copy(data)
        wrong['session_nonce'] = '0' * 32
        self.assertFalse(self.channel.accept('PL_FILES ' + json.dumps(wrong), 'proxy_down'))
        self.channel.receipts[0]['phase'] = 'healthy'
        self.assertFalse(self.channel.checks()['files_during_proxy_down'])

    def test_close_stops_only_owned_helper_and_is_idempotent(self):
        self.channel.close()
        self.channel.close()
        self.stop.assert_called_once_with(self.helper, graceful=True)
        argv = self.launch.call_args.args[0]
        self.assertEqual(len(argv), 1)
        self.assertTrue(argv[0].endswith('Pocket Linux\\runtime\\host-files\\HostFiles.exe'))

    def test_file_probe_can_leave_shutdown_to_combined_runner(self):
        config = {'session_nonce': 'a' * 32, 'username': 'WCP_test', 'password': 'b' * 64}
        serial = mock_open()
        with patch.object(guest_files_probe.Path, 'read_text', return_value=json.dumps(config)), \
                patch.object(guest_files_probe.subprocess, 'run', return_value=Mock(
                    returncode=1, stderr=b'cifs unavailable')) as run, \
                patch('builtins.open', serial):
            guest_files_probe.main(poweroff=False)
        self.assertEqual([entry.args[0] for entry in run.call_args_list], [['modprobe', 'cifs']])
        line = serial().write.call_args.args[0]
        self.assertFalse(run_files_probe.parse_files_receipt(line, config['session_nonce'])['ok'])


if __name__ == '__main__':
    unittest.main()
