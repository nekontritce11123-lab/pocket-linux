import importlib.util
import io
import json
from pathlib import Path
import socket
import stat
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


host = module('host_status', 'scripts/guest_status.py')
guest = module('guest_status_helper', 'build/guest_status.py')
NONCE, FILE_NONCE = 'a' * 32, 'b' * 32


def status(**changes):
    value = dict(schema=1, session_nonce=NONCE, network='ready', dns=True, https=True, width=1280, height=800)
    value.update(changes)
    return value


def line(value, kind='POCKET_STATUS'):
    return kind.encode() + b' ' + json.dumps(value).encode() + b'\n'


class HostStatusTests(unittest.TestCase):
    def channel(self, **kwargs):
        channel = host.Channel(NONCE, **kwargs)
        self.addCleanup(channel.close)
        return channel

    def test_nonce_fields_and_expiry(self):
        for value in (status(session_nonce=FILE_NONCE), status(schema=True), status(extra='secret'),
                      status(network='ready', dns=False), status(width=True), status(height=None),
                      status(width=99999), status(network='off')):
            channel = self.channel()
            channel._feed(line(value))
            self.assertIsNone(channel.snapshot()['status'])
        channel = self.channel()
        with mock.patch.object(host.time, 'time', return_value=100):
            channel._feed(line(status()))
        for now, fresh in ((100, True), (160, True), (161, False), (99, False)):
            with mock.patch.object(host.time, 'time', return_value=now):
                snapshot = channel.snapshot()
            self.assertEqual(snapshot['fresh'], fresh)
            self.assertEqual(snapshot['received_at'], 100)
            self.assertEqual(snapshot['status'] is not None, fresh)

    def test_split_lines_noise_duplicates_and_oversize(self):
        channel = self.channel()
        channel._feed(b'Linux boot log\nPOCKET_STATUS {"schema":1,"schema":1}\n')
        data = line(status())
        channel._feed(b'x' * (host.MAX_LINE + 1))
        self.assertLessEqual(len(channel._buffer), host.MAX_LINE)
        channel._feed(data)  # Oversized line's remainder must not become a receipt.
        self.assertIsNone(channel.snapshot()['status'])
        channel._feed(data[:13])
        self.assertIsNone(channel.snapshot()['status'])
        channel._feed(data[13:])
        self.assertEqual(channel.snapshot()['status'], status())

    def test_files_exact_expected_names_and_nonce(self):
        value = dict(schema=1, session_nonce=FILE_NONCE, status='ready', mounted=['PC_One', 'PC_Two'], failed=[], code='mounted')
        for changes in ({'session_nonce': NONCE}, {'mounted': ['PC_One']},
                        {'mounted': ['PC_One', 'PC_One']}, {'mounted': ['PC_One', 'PC_Other']},
                        {'failed': ['PC_Two']}, {'schema': True}, {'code': 'secret-value'}):
            channel = self.channel(file_nonce=FILE_NONCE, expected_shares=['PC_One', 'PC_Two'])
            channel._feed(line(dict(value, **changes), 'POCKET_FILES'))
            self.assertIsNone(channel.snapshot()['files'])
        channel = self.channel(file_nonce=FILE_NONCE, expected_shares=['PC_One', 'PC_Two'])
        channel._feed(line(value, 'POCKET_FILES'))
        self.assertEqual(channel.snapshot()['files'], value)
        value.update(status='failed', mounted=['PC_One'], failed=['PC_Two'], code='mount_failed')
        channel._feed(line(value, 'POCKET_FILES'))
        self.assertEqual(channel.snapshot()['files'], value)
        disabled = self.channel()
        disabled._feed(line(value, 'POCKET_FILES'))
        self.assertIsNone(disabled.snapshot()['files'])

    def test_bound_listener_and_nonblocking_poll(self):
        channel = self.channel()
        channel.poll()
        self.assertIn('host=127.0.0.1,port=' + str(channel.port), channel.qemu_args[1])
        competitor = socket.socket()
        self.addCleanup(competitor.close)
        with self.assertRaises(OSError):
            competitor.bind(('127.0.0.1', channel.port))
        peer = socket.create_connection(('127.0.0.1', channel.port), timeout=2)
        self.addCleanup(peer.close)
        channel.poll()
        peer.sendall(line(status(network='off', dns=False, https=False)))
        for _ in range(16):
            channel.poll()
            if channel.snapshot()['status']:
                break
        self.assertEqual(channel.snapshot()['status']['network'], 'off')

    def test_up_to_64_shares(self):
        names = ['PC_Drive' + str(i) for i in range(64)]
        channel = self.channel(file_nonce=FILE_NONCE, expected_shares=names)
        value = dict(schema=1, session_nonce=FILE_NONCE, status='ready', mounted=names, failed=[], code='mounted')
        channel._feed(line(value, 'POCKET_FILES'))
        self.assertEqual(channel.snapshot()['files'], value)
        with self.assertRaises(ValueError):
            self.channel(file_nonce=FILE_NONCE, expected_shares=names + ['PC_Extra'])


class GuestStatusTests(unittest.TestCase):
    def test_strict_config(self):
        valid = dict(schema=1, session_nonce=NONCE, network=False)
        self.assertEqual(guest.parse_config(json.dumps(valid).encode()), valid)
        for value in ({}, dict(valid, network=1), dict(valid, schema=True), dict(valid, session_nonce=''), dict(valid, secret='x')):
            with self.assertRaises(ValueError):
                guest.parse_config(json.dumps(value).encode())
        for raw in (b'x'*1025, b'{"schema":1,"schema":1}', b'{}{}'):
            with self.assertRaises(ValueError):
                guest.parse_config(raw)

    def test_network_off_has_no_network_commands(self):
        with mock.patch.object(guest.subprocess, 'run') as run:
            self.assertEqual(guest.network_status(False), ('off', False, False))
        run.assert_not_called()

    def test_network_requires_dns_and_verified_https(self):
        with mock.patch.object(guest.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(guest.network_status(True), ('ready', True, True))
        dns, https = run.call_args_list
        self.assertEqual(dns.args[0], ['/usr/bin/getent', 'ahostsv4', 'www.debian.org'])
        self.assertEqual(https.args[0][-1], 'https://www.debian.org/')
        self.assertIn('--head', https.args[0])
        self.assertEqual(https.args[0][1], '--disable')
        self.assertNotIn('--insecure', https.args[0])
        self.assertEqual(https.kwargs['timeout'], 5)
        with mock.patch.object(guest.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('getent', 5), mock.Mock(returncode=0)]):
            self.assertEqual(guest.network_status(True), ('failed', False, True))

    def test_collect_only_fixed_fields(self):
        with mock.patch.object(guest, 'network_status', return_value=('off', False, False)), mock.patch.object(guest, 'display_status', return_value=(1920, 1080)):
            self.assertEqual(guest.collect(dict(network=False, session_nonce=NONCE)),
                             status(network='off', dns=False, https=False, width=1920, height=1080))

    def test_actual_session_display(self):
        comm = mock.MagicMock()
        comm.parent.stat.return_value.st_uid = 1000
        comm.read_text.return_value = 'lxqt-session\n'
        comm.parent.__truediv__.return_value.open.return_value = io.BytesIO(b'DISPLAY=:2\0XAUTHORITY=/run/user/1000/xauth_test\0IGNORED=private\0')
        process_root = mock.Mock()
        process_root.glob.return_value = [comm]
        with mock.patch.dict('sys.modules', {'pwd': mock.Mock(getpwnam=mock.Mock(return_value=mock.Mock(pw_uid=1000)))}), mock.patch.object(guest, 'Path', return_value=process_root), mock.patch.object(guest.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='Screen 0: minimum 320 x 200, current 1920 x 1080, maximum 8192 x 8192')) as run:
            self.assertEqual(guest.display_status(), (1920, 1080))
            arguments = run.call_args.args[0]
            self.assertIn('DISPLAY=:2', arguments)
            self.assertIn('XAUTHORITY=/run/user/1000/xauth_test', arguments)
            self.assertNotIn('IGNORED=private', arguments)
            self.assertEqual(arguments[-2:], ['/usr/bin/xrandr', '--current'])
        self.assertEqual(run.call_args.kwargs['timeout'], 4)

    def test_plasma_session_retains_owner_and_display_validation(self):
        comm = mock.MagicMock()
        comm.parent.stat.return_value.st_uid = 1000
        comm.read_text.return_value = 'ksmserver\n'
        comm.parent.__truediv__.return_value.open.return_value = io.BytesIO(b'DISPLAY=:0\0XAUTHORITY=/run/user/1000/xauth\0')
        proc = mock.Mock()
        proc.glob.return_value = [comm]
        with mock.patch.dict('sys.modules', {'pwd': mock.Mock(getpwnam=mock.Mock(return_value=mock.Mock(pw_uid=1000)))}), mock.patch.object(guest, 'Path', return_value=proc), mock.patch.object(guest.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='Screen 0: current 1280 x 800,')) as run:
            self.assertEqual(guest.display_status(), (1280, 800))
            run.reset_mock()
            comm.parent.stat.return_value.st_uid = 0
            self.assertEqual(guest.display_status(), (None, None))
            run.assert_not_called()

    def test_sddm_xauth_requires_owned_regular_file(self):
        for mode, uid, expected in ((stat.S_IFREG | 0o600, 1000, (1280, 800)),
                                    (stat.S_IFLNK | 0o777, 1000, (None, None)),
                                    (stat.S_IFREG | 0o600, 0, (None, None))):
            comm = mock.MagicMock()
            comm.parent.stat.return_value.st_uid = 1000
            comm.read_text.return_value = 'lxqt-session\n'
            comm.parent.__truediv__.return_value.open.return_value = io.BytesIO(b'DISPLAY=:0\0XAUTHORITY=/tmp/xauth_MzuLNv\0')
            process_root = mock.Mock()
            process_root.glob.return_value = [comm]
            authority = mock.Mock()
            authority.lstat.return_value = mock.Mock(st_uid=uid, st_mode=mode)
            with mock.patch.dict('sys.modules', {'pwd': mock.Mock(getpwnam=mock.Mock(return_value=mock.Mock(pw_uid=1000)))}), mock.patch.object(guest, 'Path', side_effect=lambda value: process_root if value == '/proc' else authority), mock.patch.object(guest.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='Screen 0: current 1280 x 800, maximum 8192 x 8192')) as run:
                self.assertEqual(guest.display_status(), expected)
                self.assertEqual(run.called, expected != (None, None))


if __name__ == '__main__':
    unittest.main()
