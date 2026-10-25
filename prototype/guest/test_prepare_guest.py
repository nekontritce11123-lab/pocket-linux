import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_guest
import guest_probe


class PrepareGuestTests(unittest.TestCase):
    def test_public_canary_only_reports_a_connection_and_sends_no_payload(self):
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        with patch.object(guest_probe.socket, 'socket', return_value=sock):
            self.assertEqual(guest_probe.forbidden_public_probe(), {'connected': True})
        sock.connect.assert_called_once_with(('1.1.1.1', 443))
        sock.send.assert_not_called()
        sock.sendall.assert_not_called()

    def test_commands_and_cloud_init_are_isolated(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            base = root / 'base, $(literal) диск.qcow2'
            qemu = root / 'qemu-system-x86_64.exe'
            base.touch()
            qemu.touch()
            output = root / 'new, run'
            manifest = prepare_guest.prepare(output, base, qemu, 19000, 1024, 'probe')
            args = manifest['qemu_argv']
            self.assertEqual(args[args.index('-accel') + 1], 'whpx')
            self.assertEqual(args.count('-netdev'), 1)
            net = json.loads(args[args.index('-netdev') + 1])
            self.assertEqual(net, {'type': 'stream', 'id': 'plnet', 'server': False,
                                  'addr': {'type': 'inet', 'host': '127.0.0.1', 'port': '19000'}})
            self.assertNotIn('user', args)
            self.assertIn('virtio-net-pci,netdev=plnet,mac=52:54:00:50:4c:01', args)
            blocks = [json.loads(args[i+1]) for i, arg in enumerate(args) if arg == '-blockdev']
            self.assertEqual(blocks[1]['label'], 'CIDATA')
            self.assertTrue(blocks[1]['read-only'])
            self.assertEqual(blocks[1]['dir'], str(output / 'seed'))
            self.assertIn(str(base), manifest['overlay_argv'])
            self.assertFalse((output / 'overlay.qcow2').exists())
            config = json.loads((output / 'seed' / 'network-config').read_text())
            nic = config['ethernets']['lan0']
            self.assertEqual(nic['addresses'], ['192.168.127.2/24'])
            self.assertEqual(nic['nameservers']['addresses'], ['192.168.127.1'])
            user = (output / 'seed' / 'user-data').read_text()
            data = json.loads(user.split('\n', 1)[1])
            self.assertEqual(data['users'], [])
            self.assertEqual(data['runcmd'][0][:2], ['python3', '-I'])
            compile(data['write_files'][0]['content'], 'probe', 'exec')
            with self.assertRaises(FileExistsError):
                prepare_guest.prepare(output, base, qemu, 19000, 1024, 'probe')

    def test_reject_invalid_input_before_creating_output(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            output = Path(temporary) / 'new'
            with self.assertRaises(ValueError):
                prepare_guest.prepare(output, Path('relative'), Path('qemu.exe'), 0, 1024, 'probe')
            self.assertFalse(output.exists())

    def test_receipts_are_bounded_and_filtered(self):
        self.assertEqual(prepare_guest.parse_receipt('PL_PROBE {"ok":true}\r\n'),
                         ('PL_PROBE', {'ok': True}))
        self.assertIsNone(prepare_guest.parse_receipt('boot noise'))
        for line in ['PL_PROBE []', 'PL_BAD {}', 'PL_PROBE nope', 'PL_PROBE ' + 'x' * 8193]:
            with self.assertRaises(ValueError):
                prepare_guest.parse_receipt(line)

    def test_guest_probes_validate_fixture_responses(self):
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        with patch.object(guest_probe.socket, 'socket', return_value=sock):
            sock.recv.return_value = b'HTTP/1.0 200 OK\r\n\r\nPL_OK'
            self.assertGreater(guest_probe.tcp_probe()['bytes'], 0)
            sock.connect.assert_called_with(('198.18.0.10', 18080))
            sock.settimeout.assert_called_with(0.7)
            sock.recv.return_value = b'PL_UDP_ECHO'
            self.assertEqual(guest_probe.udp_probe()['bytes'], 11)
            sock.recv.return_value = guest_probe.struct.pack('!6H', 0x504c, 0x8180, 1, 1, 0, 0)
            self.assertEqual(guest_probe.dns_query('192.168.127.1')['answers'], 1)
            sock.recv.return_value = b'invalid'
            for probe in [guest_probe.tcp_probe, guest_probe.udp_probe,
                          lambda: guest_probe.dns_query('192.168.127.1')]:
                with self.assertRaises(ValueError):
                    probe()

    def test_oversize_receipt_remains_valid_json(self):
        serial = mock_open()
        with patch('builtins.open', serial):
            guest_probe.emit('PL_INVENTORY', huge='x' * 10000)
        line = serial().write.call_args.args[0]
        kind, data = prepare_guest.parse_receipt(line)
        self.assertEqual(kind, 'PL_ERROR')
        self.assertEqual(data['error'], 'ReceiptTooLarge')

    def test_inventory_is_compact_and_uses_bounded_df(self):
        expected = {'mem_total_kib': 2024000, 'mem_available_kib': 1800000,
                    'root_size_bytes': 3145728000, 'root_used_bytes': 800000000}
        with patch.object(guest_probe.Path, 'read_text', return_value=
                          'MemTotal: 2024000 kB\nMemFree: 1000 kB\nMemAvailable: 1800000 kB\n'), \
                patch.object(guest_probe.subprocess, 'run', return_value=Mock(
                    stdout='1B-blocks Used\n3145728000 800000000\n')) as run:
            data = guest_probe.inventory()
        self.assertEqual(data, expected)
        run.assert_called_once_with(['df', '-B1', '--output=size,used', '/'],
                                    capture_output=True, text=True, timeout=3, check=True)
        serial = mock_open()
        with patch('builtins.open', serial):
            guest_probe.emit('PL_INVENTORY', **data)
        serial().write.assert_called_once()
        line = serial().write.call_args.args[0]
        self.assertLess(len(line), 1000)
        self.assertEqual(prepare_guest.parse_receipt(line), ('PL_INVENTORY', expected))

    def test_inventory_rejects_invalid_df_values(self):
        with patch.object(guest_probe.Path, 'read_text', return_value=
                          'MemTotal: 1000 kB\nMemAvailable: 500 kB\n'), \
                patch.object(guest_probe.subprocess, 'run', return_value=Mock(
                    stdout='1B-blocks Used\n100 101\n')):
            with self.assertRaises(ValueError):
                guest_probe.inventory()

    def test_inventory_mode_emits_inventory_without_network_sockets(self):
        data = {'mem_total_kib': 1000, 'mem_available_kib': 500,
                'root_size_bytes': 100, 'root_used_bytes': 50}
        with patch.object(guest_probe.sys, 'argv', ['pl-probe.py', 'inventory']), \
                patch.object(guest_probe.Path, 'read_text', return_value='13.2\n'), \
                patch.object(guest_probe, 'inventory', return_value=data), \
                patch.object(guest_probe, 'command', return_value={}), \
                patch.object(guest_probe, 'emit') as emit, \
                patch.object(guest_probe.socket, 'socket') as socket_factory:
            guest_probe.main()
        socket_factory.assert_not_called()
        self.assertEqual([entry for entry in emit.call_args_list if entry.args[0] == 'PL_INVENTORY'],
                         [call('PL_INVENTORY', **data)])

    def test_dns_burst_sends_both_before_reading_and_accepts_reordering(self):
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        replies = [guest_probe.struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0)
                   for ident in (0x504d, 0x504c)]
        sock.recv.side_effect = replies
        with patch.object(guest_probe.socket, 'socket', return_value=sock) as factory:
            self.assertEqual(guest_probe.dns_burst(), {'bytes': 24, 'replies': 2})
        factory.assert_called_once_with(guest_probe.socket.AF_INET, guest_probe.socket.SOCK_DGRAM)
        sock.connect.assert_called_once_with(('192.168.127.1', 53))
        sock.settimeout.assert_called_once_with(0.7)
        packets = [entry.args[0] for entry in sock.send.call_args_list]
        self.assertEqual([guest_probe.struct.unpack('!H', packet[:2])[0] for packet in packets],
                         [0x504c, 0x504d])
        relevant = [entry for entry in sock.mock_calls if entry[0] in ('send', 'recv')]
        self.assertEqual(relevant, [call.send(packets[0]), call.send(packets[1]),
                                    call.recv(512), call.recv(512)])

    def test_dns_burst_requires_two_distinct_successful_replies(self):
        valid = guest_probe.struct.pack('!6H', 0x504c, 0x8180, 1, 1, 0, 0)
        for second, error in [(valid, ValueError), (b'bad', ValueError),
                              (guest_probe.socket.timeout(), guest_probe.socket.timeout),
                              (guest_probe.struct.pack('!6H', 0x504d, 0x8183, 1, 0, 0, 0), ValueError)]:
            with self.subTest(second=second):
                sock = Mock()
                sock.__enter__ = Mock(return_value=sock)
                sock.__exit__ = Mock(return_value=False)
                sock.recv.side_effect = [valid, second]
                with patch.object(guest_probe.socket, 'socket', return_value=sock):
                    with self.assertRaises(error):
                        guest_probe.dns_burst()


if __name__ == '__main__':
    unittest.main()
