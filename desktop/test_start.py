import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location('desktop_start', Path(__file__).with_name('start.py'))
start = importlib.util.module_from_spec(spec)
spec.loader.exec_module(start)


class StartTests(unittest.TestCase):
    root = Path('C:/Pocket Linux')

    def argv(self, address=None, accel='tcg'):
        return start.build_qemu(self.root, accel, address, path_fn=lambda p: p.as_posix())

    def test_offline_has_no_network_or_seed(self):
        argv = self.argv()
        self.assertIn('-nodefaults', argv)
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertNotIn('-netdev', argv)
        self.assertFalse(any('user,' in item or 'CIDATA' in item for item in argv))
        self.assertEqual(argv[argv.index('-accel') + 1], 'tcg,thread=multi')
        self.assertEqual(argv[argv.index('-cpu') + 1], 'max')
        self.assertEqual(argv[argv.index('-m') + 1], '2048')
        self.assertEqual(argv[argv.index('-display') + 1], 'sdl,gl=off,window-close=off')
        self.assertIn('VGA,vgamem_mb=64,xres=1280,yres=800', argv)

    def test_proxy_uses_only_loopback_stream(self):
        argv = self.argv('127.0.0.1:43210')
        net = json.loads(argv[argv.index('-netdev') + 1])
        self.assertEqual(net, {'type': 'stream', 'id': 'plnet', 'server': False,
                              'addr': {'type': 'inet', 'host': '127.0.0.1', 'port': '43210'}})
        self.assertIn('virtio-net-pci,netdev=plnet,mac=52:54:00:50:4c:01', argv)
        self.assertNotIn('-nic', argv)
        self.assertFalse(any('user,' in item for item in argv))

    def test_whpx_is_explicit(self):
        argv = self.argv(accel='whpx')
        self.assertEqual(argv[argv.index('-accel') + 1], 'whpx')
        self.assertIn('sse4.2=on', argv[argv.index('-cpu') + 1])
        with self.assertRaises(ValueError):
            self.argv(accel='unknown')

    def test_ready_requires_safe_loopback_and_no_fallback(self):
        ready = {'event': 'READY', 'listen': '127.0.0.1:43210', 'direct_fallback': False}
        self.assertEqual(start.ready_address(json.dumps(ready)), ready['listen'])
        for address in ('0.0.0.0:123', '127.0.0.2:123', '[::1]:123', 'localhost:123',
                        '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:123\n-no-reboot'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                start.ready_address(json.dumps({**ready, 'listen': address}))
            with self.assertRaises(ValueError):
                self.argv(address)
        for changed in ({'event': 'other'}, {'direct_fallback': True}, {'direct_fallback': 0}):
            with self.assertRaises(ValueError):
                start.ready_address(json.dumps({**ready, **changed}))
        for text in ('not JSON', '[]', 'x' * 8193):
            with self.assertRaises(ValueError):
                start.ready_address(text)

    def test_absent_proxy_is_offline_without_creating_config(self):
        with mock.patch.object(Path, 'is_file', return_value=False), \
                mock.patch.object(Path, 'open') as opened, \
                mock.patch.object(start.subprocess, 'Popen') as launched, \
                mock.patch('builtins.print'):
            self.assertEqual(start.start_network(self.root), (None, None))
        opened.assert_not_called()
        launched.assert_not_called()

    def test_invalid_ready_stops_owned_child_without_offline_fallback(self):
        process = mock.Mock()
        process.stdout.readline.return_value = json.dumps(
            {'event': 'READY', 'listen': '0.0.0.0:12345', 'direct_fallback': False})
        process.poll.return_value = None
        with mock.patch.object(Path, 'is_file', return_value=True), \
                mock.patch.object(start.subprocess, 'Popen', return_value=process):
            with self.assertRaises(ValueError):
                start.start_network(self.root)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)
        process.stdout.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
