import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guest_clipboard as guest

NONCE = 'a' * 32
SelectionSnapshot = guest.SelectionSnapshot


class GuestClipboardTests(unittest.TestCase):
    def setUp(self):
        self.monitor = mock.Mock()
        self.monitor.snapshot.return_value = (101, 1)
        self.monitor_factory = mock.patch.object(guest, 'SelectionSnapshot', return_value=self.monitor).start()
        self.addCleanup(mock.patch.stopall)

    def test_configuration_requires_explicit_opt_in_and_session_nonce(self):
        raw = guest.protocol.configuration(NONCE)
        self.assertEqual(guest.parse_config(raw)['session_nonce'], NONCE)
        for value in (b'{}', b'[]', raw + b'{}', raw.replace(b'true', b'1'), raw.replace(b'"schema":1', b'"schema":true'),
                      raw.replace(NONCE.encode(), b'wrong'), raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                      b'x' * (guest.MAX_CONFIG + 1)):
            with self.assertRaises(ValueError):
                guest.parse_config(value)

    def test_sensitive_x11_targets_are_not_exported(self):
        clipboard = guest.XclipClipboard()
        with mock.patch.object(guest, 'read_selection', return_value=b'UTF8_STRING\nx-kde-passwordManagerHint\n') as read:
            self.assertIsNone(clipboard.read_text())
        self.assertEqual(read.call_count, 1)

    def test_utf8_and_size_limits_are_enforced_without_starting_xclip(self):
        clipboard = guest.XclipClipboard()
        for raw, expected in (('Привет'.encode(), 'Привет'), (b'\xff', None), (b'nul\0text', None), (b'a' * (guest.protocol.MAX_CHARS + 1), None)):
            with mock.patch.object(guest, 'read_selection', side_effect=[b'UTF8_STRING\n', raw]):
                self.assertEqual(clipboard.read_text(), expected)

    def test_owner_or_generation_change_during_targets_never_reads_text(self):
        for changed in ((202, 2), (101, 2), None):
            clipboard = guest.XclipClipboard()
            self.monitor.snapshot.side_effect = [(101, 1), changed]
            with mock.patch.object(guest, 'read_selection', return_value=b'UTF8_STRING\n') as read:
                self.assertIsNone(clipboard.read_text())
                self.assertEqual(read.call_args_list, [mock.call('TARGETS', 16384)])

    def test_owner_or_same_owner_generation_change_during_text_is_not_exported(self):
        for changed in ((202, 2), (101, 2), None):
            clipboard = guest.XclipClipboard()
            clipboard.callback = mock.Mock()
            clipboard.previous = guest.protocol.digest('old')
            self.monitor.snapshot.side_effect = [(101, 1), (101, 1), changed]
            with mock.patch.object(guest, 'read_selection', side_effect=[b'UTF8_STRING\n', b'sensitive new copy']):
                clipboard.poll_once()
            self.assertNotIn(mock.call('sensitive new copy'), clipboard.callback.call_args_list)

    def test_monitor_failure_is_closed_and_initial_clipboard_is_not_read(self):
        self.monitor_factory.side_effect = OSError('No XFixes')
        with mock.patch.object(guest, 'read_selection') as read:
            self.assertIsNone(guest.XclipClipboard().read_text())
            read.assert_not_called()

    def test_same_owner_selection_event_advances_generation(self):
        monitor = SelectionSnapshot.__new__(SelectionSnapshot)
        monitor.display, monitor.selection, monitor.event_type, monitor.generation = 1, 2, 77, 0
        monitor.x = mock.Mock()
        monitor.x.XGetSelectionOwner.return_value = 101
        monitor.x.XPending.side_effect = [0, 1, 0]

        def notify(display, pointer):
            guest.ctypes.cast(pointer, guest.ctypes.POINTER(guest.ctypes.c_int)).contents.value = 77
        monitor.x.XNextEvent.side_effect = notify
        self.assertEqual(monitor.snapshot(), (101, 0))
        self.assertEqual(monitor.snapshot(), (101, 1))
        self.assertEqual(monitor.x.XSync.call_count, 2)

    def test_private_monitor_negotiates_extension_subscribes_then_closes_own_window(self):
        x, fixes = mock.Mock(), mock.Mock()
        x.XOpenDisplay.return_value = 10
        x.XCreateSimpleWindow.return_value = 20
        x.XInternAtom.return_value = 30

        def version(display, major, minor):
            guest.ctypes.cast(major, guest.ctypes.POINTER(guest.ctypes.c_int)).contents.value = 5
            return 1
        fixes.XFixesQueryVersion.side_effect = version
        with mock.patch.object(guest.sys, 'platform', 'linux'), mock.patch.object(guest.ctypes, 'CDLL', side_effect=[x, fixes]):
            monitor = SelectionSnapshot()
            fixes.XFixesSelectSelectionInput.assert_called_once_with(10, 20, 30, 7)
            monitor.close()
            monitor.close()
        x.XDestroyWindow.assert_called_once_with(10, 20)
        x.XCloseDisplay.assert_called_once_with(10)

    def test_session_start_primes_existing_selection_and_only_new_changes_leave(self):
        clipboard = guest.XclipClipboard()
        changes = []
        with mock.patch.object(clipboard, 'read_text', side_effect=['already there', 'already there', 'new copy', 'new copy', None]):
            clipboard.start(changes.append)
            try:
                self.assertEqual(changes, [])
                clipboard.poll_once()
                self.assertEqual(changes, [])
                clipboard.poll_once()
                clipboard.poll_once()
                clipboard.poll_once()
                self.assertEqual(changes, ['new copy', None])
            finally:
                clipboard.stop()

    def test_root_preparation_refuses_windows_without_touching_files(self):
        with mock.patch.object(guest.sys, 'platform', 'win32'):
            with mock.patch.object(guest.os, 'open', side_effect=AssertionError('must not open a device')):
                with self.assertRaises(RuntimeError):
                    guest.prepare()

    def test_stopped_guest_neither_publishes_nor_starts_an_owner_process(self):
        clipboard = guest.XclipClipboard()
        clipboard.callback = mock.Mock()
        clipboard.stop()
        with mock.patch.object(clipboard, 'read_text', return_value='late value'):
            clipboard.poll_once()
        with mock.patch.object(guest.subprocess, 'Popen', side_effect=AssertionError('must not start')):
            clipboard.set_text('late remote copy')
        clipboard.callback.assert_not_called()

    def test_virtio_retry_does_not_use_windows_serial_or_network(self):
        self.assertEqual(str(guest.DEVICE).replace('\\', '/'), '/dev/virtio-ports/org.pocket.clipboard')
        self.assertEqual(str(guest.FW_CONFIG).replace('\\', '/'), '/sys/firmware/qemu_fw_cfg/by_name/opt/pocket/clipboard/raw')
        self.assertEqual(json.loads(guest.protocol.configuration(NONCE))['enabled'], True)


if __name__ == '__main__':
    unittest.main()
