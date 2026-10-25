import base64
import json
from pathlib import Path
import queue
import socket
import sys
import threading
import time
import types
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import clipboard_bridge as bridge

NONCE = 'a' * 32


class FakeClipboard:
    def __init__(self):
        self.written, self.callback = [], None

    def start(self, callback):
        self.callback = callback

    def stop(self):
        pass

    def set_text(self, text):
        self.written.append(text)
        self.callback(text)


class Endpoint:
    def __init__(self):
        self.inbox, self.sent = queue.Queue(), []
        self.pending, self.timeout, self.closed = b'', 0.3, False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if not self.pending:
            try:
                data = self.inbox.get(timeout=self.timeout)
            except queue.Empty:
                raise socket.timeout() from None
            if data is None:
                return b''
            self.pending = data
        result, self.pending = self.pending[:size], self.pending[size:]
        return result

    def sendall(self, data):
        if self.closed or self.peer.closed:
            raise OSError('Closed mock transport')
        self.sent.append(data)
        self.peer.inbox.put(data)

    def close(self):
        if not self.closed:
            self.closed = True
            self.inbox.put(None)
            self.peer.inbox.put(None)


def endpoints():
    a, b = Endpoint(), Endpoint()
    a.peer, b.peer = b, a
    return a, b


def wait_for(condition):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


class ProtocolTests(unittest.TestCase):
    def test_text_roundtrip_and_strict_limits(self):
        for text in ('hello', 'Привет\r\nмир\t😀', 'x' * 100000):
            self.assertEqual(bridge.decode(bridge.encode(NONCE, text), NONCE), text)
        for text in ('', None, '\ud800', 'nul\0text', 'x' * (bridge.MAX_CHARS + 1)):
            self.assertIsNone(bridge.encode(NONCE, text))
        line = bridge.encode(NONCE, 'text')
        self.assertIsNone(bridge.decode(line, 'b' * 32))
        for value in (b'[]', b'{}', b'\xff', b'x' * (bridge.MAX_LINE + 1)):
            self.assertIsNone(bridge.decode(value, NONCE))

    def test_invalid_deflate_and_bombs_are_rejected(self):
        message = json.loads(bridge.encode(NONCE, 'correct text'))
        packed = base64.b64decode(message['d'])
        for invalid in (packed[:-1], packed + b'extra'):
            message['d'] = base64.b64encode(invalid).decode()
            self.assertIsNone(bridge.decode(json.dumps(message).encode(), NONCE))
        packer = zlib.compressobj(9, zlib.DEFLATED, -15)
        message['d'] = base64.b64encode(packer.compress(b'x' * (8 * 1024 * 1024)) + packer.flush()).decode()
        self.assertIsNone(bridge.decode(json.dumps(message).encode(), NONCE))
        message['v'] = True
        self.assertIsNone(bridge.decode(json.dumps(message).encode(), NONCE))

    def test_oversized_line_is_discarded_until_its_boundary(self):
        framer = bridge.LineFramer()
        valid = bridge.encode(NONCE, 'valid')
        self.assertEqual(list(framer.feed(b'x' * (bridge.MAX_LINE + 5) + valid[:-1])), [])
        self.assertEqual(list(framer.feed(b'\n' + valid)), [valid.rstrip(b'\n')])

    def test_qemu_channel_does_not_use_diagnostic_serial_or_external_network(self):
        args = bridge.arguments(4242)
        self.assertIn('socket,id=pocketclip,host=127.0.0.1,port=4242,server=on,wait=off', args)
        self.assertIn('virtio-serial-pci,id=pocketclipbus', args)
        self.assertIn('virtserialport,bus=pocketclipbus.0,chardev=pocketclip,name=org.pocket.clipboard', args)
        self.assertNotIn('-serial', args)
        self.assertEqual(json.loads(bridge.configuration(NONCE)), {'schema': 1, 'enabled': True, 'session_nonce': NONCE})
        for port in (0, True, 65536):
            with self.assertRaises(ValueError):
                bridge.arguments(port)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.host_end, self.guest_end = endpoints()
        self.host_clipboard, self.guest_clipboard = FakeClipboard(), FakeClipboard()
        self.host = bridge.Bridge(None, NONCE, self.host_clipboard, connector=lambda: self.host_end)
        self.guest = bridge.Bridge(None, NONCE, self.guest_clipboard, connector=lambda: self.guest_end, role='guest')
        self.host.start()
        self.guest.start()
        self.assertTrue(self.host.authenticated.wait(2))
        self.assertTrue(self.guest.authenticated.wait(2))

    def tearDown(self):
        self.host.stop()
        self.guest.stop()

    def test_startup_keeps_both_existing_clipboards(self):
        self.assertEqual(self.host_clipboard.written, [])
        self.assertEqual(self.guest_clipboard.written, [])

    def test_both_directions_and_no_echo(self):
        self.host_clipboard.callback('из Windows')
        self.assertTrue(wait_for(lambda: self.guest_clipboard.written == ['из Windows']))
        self.assertEqual(self.host_clipboard.written, [])
        self.guest_clipboard.callback('из Linux')
        self.assertTrue(wait_for(lambda: self.host_clipboard.written == ['из Linux']))
        self.assertEqual(self.guest_clipboard.written, ['из Windows'])

    def test_repeated_text_is_allowed_after_the_other_side_changes(self):
        self.host_clipboard.callback('A')
        self.assertTrue(wait_for(lambda: self.guest_clipboard.written == ['A']))
        self.guest_clipboard.callback('B')
        self.assertTrue(wait_for(lambda: self.host_clipboard.written == ['B']))
        self.host_clipboard.callback('A')
        self.assertTrue(wait_for(lambda: self.guest_clipboard.written == ['A', 'A']))


class BoundaryTests(unittest.TestCase):
    def failed_send_reconnect(self, sensitive_change):
        old_host, old_guest = endpoints()
        new_host, new_guest = endpoints()
        host_connections, guest_connections = iter((old_host, new_host)), iter((old_guest, new_guest))
        host_clipboard, guest_clipboard = FakeClipboard(), FakeClipboard()
        host = bridge.Bridge(None, NONCE, host_clipboard,
                             connector=lambda: next(host_connections, new_host))
        guest = bridge.Bridge(None, NONCE, guest_clipboard,
                              connector=lambda: next(guest_connections, new_guest), role='guest')
        failed = threading.Event()
        sendall = old_host.sendall

        def fail_text(data):
            if bridge.decode(data, NONCE) is not None:
                if sensitive_change:
                    host.local_change('newer pending copy')
                    host.local_change(None)
                failed.set()
                raise OSError('Synthetic text send failure')
            sendall(data)

        old_host.sendall = fail_text
        host.start()
        guest.start()
        try:
            self.assertTrue(host.authenticated.wait(2))
            self.assertTrue(guest.authenticated.wait(2))
            host_clipboard.callback('copy after reconnect')
            self.assertTrue(failed.wait(2))
            self.assertTrue(wait_for(lambda: host.connection is new_host and guest.connection is new_guest
                                     and host.authenticated.is_set() and guest.authenticated.is_set()))
            self.assertTrue(host.outgoing.empty())
            self.assertEqual(guest_clipboard.written, [])
            self.assertFalse(any(bridge.decode(frame, NONCE) is not None for frame in new_host.sent))
            host_clipboard.callback('copy after reconnect')
            self.assertTrue(wait_for(lambda: guest_clipboard.written == ['copy after reconnect']))
            self.assertEqual(host_clipboard.written, [])
        finally:
            host.stop()
            guest.stop()

    def test_failed_send_reconnect_allows_same_copy(self):
        self.failed_send_reconnect(False)

    def test_sensitive_change_during_failed_send_is_not_replayed(self):
        self.failed_send_reconnect(True)

    def test_no_text_is_sent_to_an_unauthenticated_listener(self):
        local, peer = endpoints()
        clipboard = FakeClipboard()
        worker = bridge.Bridge(None, NONCE, clipboard, connector=lambda: local)
        worker.local_change('PRIVATE-CONTENT')
        worker.start()
        try:
            challenge = json.loads(peer.recv(512))
            self.assertEqual(challenge['t'], 'challenge')
            self.assertNotIn(NONCE.encode(), local.sent[0])
            peer.sendall((json.dumps({'v': 1, 't': 'hello', 'c': challenge['c'], 'h': '0' * 64}) + '\n').encode())
            self.assertTrue(wait_for(lambda: local.closed))
            self.assertNotIn(b'PRIVATE-CONTENT', b''.join(local.sent))
            self.assertEqual(len(local.sent), 1)
        finally:
            worker.stop()

    def test_pending_copies_are_bounded_and_sensitive_change_clears_them(self):
        worker = bridge.Bridge(4242, NONCE, FakeClipboard())
        for index in range(100):
            worker.local_change('copy ' + str(index))
        self.assertEqual(worker.outgoing.qsize(), 1)
        self.assertEqual(bridge.decode(worker.outgoing.get_nowait(), NONCE), 'copy 99')
        worker.local_change('normal')
        worker.local_change(None)
        self.assertTrue(worker.outgoing.empty())

    def test_stop_discards_pending_text_and_ignores_late_notifications(self):
        worker = bridge.Bridge(4242, NONCE, FakeClipboard())
        worker.local_change('pending')
        worker.stop()
        worker.local_change('late notification')
        self.assertTrue(worker.outgoing.empty())

    @unittest.skipUnless(hasattr(bridge, 'WindowsClipboard'), 'Windows API adapter only')
    def test_password_manager_exclusion_never_reads_text(self):
        adapter = bridge.WindowsClipboard.__new__(bridge.WindowsClipboard)
        adapter.exclude = 123
        adapter.open = lambda: True
        api = types.SimpleNamespace(IsClipboardFormatAvailable=lambda value: value == 123,
                                    CloseClipboard=mock.Mock(), GetClipboardData=mock.Mock(side_effect=AssertionError('must not read')))
        with mock.patch.object(bridge, 'user32', api):
            self.assertIsNone(adapter.read())
        api.GetClipboardData.assert_not_called()

    @unittest.skipUnless(hasattr(bridge, 'WindowsClipboard'), 'Windows API adapter only')
    def test_initial_windows_notification_does_not_read_existing_text(self):
        adapter = bridge.WindowsClipboard.__new__(bridge.WindowsClipboard)
        adapter.sequence = 42
        adapter.on_change = mock.Mock()
        adapter.read = mock.Mock(side_effect=AssertionError('must not read'))
        with mock.patch.object(bridge, 'user32', types.SimpleNamespace(GetClipboardSequenceNumber=lambda: 42)):
            adapter.window_proc(None, bridge.WM_CLIPBOARDUPDATE, 0, 0)
        adapter.read.assert_not_called()
        adapter.on_change.assert_not_called()


if __name__ == '__main__':
    unittest.main()
