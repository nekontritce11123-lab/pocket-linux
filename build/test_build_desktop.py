import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('build_desktop', Path(__file__).with_name('build_desktop.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildTests(unittest.TestCase):
    def test_unknown_desktop_rejected_before_creating_files(self):
        with self.assertRaisesRegex(ValueError, 'Unknown desktop'):
            build.run(Path('must-not-be-created'), desktop='unsupported')

    def test_mirror_allows_only_named_repositories(self):
        self.assertEqual(build.upstream('/debian/pool/main/a/abc_1+2_amd64.deb'),
                         'https://deb.debian.org/debian/pool/main/a/abc_1+2_amd64.deb')
        self.assertEqual(build.upstream('/debian/pool/main/a/abc_1%2b2_amd64.deb'),
                         'https://deb.debian.org/debian/pool/main/a/abc_1+2_amd64.deb')
        for path in ('http://example.com/a', '//example.com/a', '/debian/../x',
                     '/debian/%2e%2e/x', '/debian/pool/a?url=x', '/private/a', '/debian/pool/a\\b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                build.upstream(path)

    def test_newest_official_package_and_hash_required(self):
        template = ('Package: claude-code\nVersion: {}\nArchitecture: amd64\n'
                    'Filename: pool/main/c/claude-code/test.deb\nSize: 10\nSHA256: {}\n')
        records = template.format('2.1.9-1', 'a' * 64) + '\n' + template.format('2.1.10-1', 'b' * 64)
        self.assertEqual(build.select_package(records, 'claude-code')['Version'], '2.1.10-1')
        with self.assertRaises(ValueError):
            build.select_package(template.format('2.1.10-1', 'invalid'), 'claude-code')

    def test_build_network_only_reaches_proxy_process(self):
        network = build.seed_network()
        iface = network['ethernets']['build0']
        self.assertFalse(iface['dhcp4'])
        self.assertEqual(iface['gateway4'], '192.168.127.1')
        self.assertNotIn('nameservers', iface)
        args = build.build_network_args(12345)
        import json
        net = json.loads(args[1])
        self.assertEqual(net['type'], 'stream')
        self.assertEqual(net['addr']['host'], '127.0.0.1')
        self.assertEqual(net['addr']['port'], '12345')


if __name__ == '__main__':
    unittest.main()
