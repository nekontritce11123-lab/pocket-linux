import importlib.util
import ctypes
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import linux_window as branding


class WindowBrandingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('C:/Pocket Linux').resolve()
        self.identity = {'pid': 321, 'created': '12345',
                         'image': str(self.root / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe')}
        self.api = mock.Mock()
        self.api.enumerate_windows.return_value = [11, 22]
        self.api.window_pid.side_effect = lambda window: 321 if window == 11 else 999
        self.api.load_icons.return_value = {'small': 100, 'big': 200}
        self.api.set_taskbar.side_effect = lambda window, properties, guard: guard()
        self.api.set_icon.return_value = True
        self.titles = {11: 'QEMU', 22: 'Foreign window'}
        self.api.title.side_effect = lambda window: self.titles[window]
        self.api.set_title.side_effect = lambda window, title: self.titles.__setitem__(window, title) is None
        self.process = mock.patch.object(branding, 'process_identity', return_value=self.identity).start()
        self.native = mock.patch.object(branding, '_Win32', return_value=self.api).start()
        self.addCleanup(mock.patch.stopall)

    def test_only_owned_windows_are_branded_and_repeated_apply_is_idempotent(self):
        window = branding.WindowBranding(self.root, 321, expected_identity=self.identity)
        self.assertTrue(window.apply())
        self.assertTrue(window.apply())
        self.api.load_icons.assert_called_once_with(self.root / 'Launcher.exe')
        self.api.set_taskbar.assert_called_once()
        self.assertEqual(self.api.set_icon.call_args_list, [mock.call(11, 0, 100), mock.call(11, 1, 200)])
        self.api.set_title.assert_called_once_with(11, 'Pocket Linux')
        self.assertEqual(self.titles[22], 'Foreign window')
        self.assertEqual(self.api.release_pointer.call_args_list, [mock.call(11), mock.call(11)])
        self.api.SetWindowPos.assert_not_called()

    def test_pid_reuse_never_changes_new_windows(self):
        window = branding.WindowBranding(self.root, 321)
        self.process.return_value = self.identity | {'created': '12346'}
        self.assertFalse(window.apply())
        self.api.enumerate_windows.assert_not_called()
        self.api.set_taskbar.assert_not_called()
        self.api.set_icon.assert_not_called()
        self.api.release_pointer.assert_not_called()

    def test_foreign_executable_is_refused_before_loading_winapi(self):
        self.process.return_value = self.identity | {'image': 'C:/Other/qemu-system-x86_64.exe'}
        with self.assertRaises(ValueError):
            branding.WindowBranding(self.root, 321)
        self.native.assert_not_called()

    def test_close_keeps_live_window_icons_then_frees_only_owned_handles_after_exit(self):
        window = branding.WindowBranding(self.root, 321)
        window.apply()
        self.assertFalse(window.close())
        self.api.destroy_icon.assert_not_called()
        self.process.return_value = None
        self.assertTrue(window.close())
        self.assertTrue(window.close())
        self.assertEqual(self.api.destroy_icon.call_args_list, [mock.call(100), mock.call(200)])
        self.assertFalse(window.apply())

    def test_taskbar_identity_has_linux_id_and_launcher_resources(self):
        values = branding.taskbar_properties(self.root)
        self.assertEqual(values[2], '"' + str(self.root / 'Launcher.exe') + '"')
        self.assertEqual(values[3], str(self.root / 'Launcher.exe') + ',0')
        self.assertEqual(values[4], 'Pocket Linux')
        self.assertTrue(values[5].startswith('PocketLinux.Desktop.'))
        self.assertEqual(values, branding.taskbar_properties(self.root))
        self.assertNotEqual(values[5], branding.taskbar_properties(Path('C:/Other Linux'))[5])


class PointerReleaseTests(unittest.TestCase):
    def setUp(self):
        self.api = branding._Win32.__new__(branding._Win32)
        self.user = self.api.user = mock.Mock()
        self.user.GetForegroundWindow.return_value = 11
        self.user.GetWindowLongPtrW.return_value = 0
        self.user.SetThreadDpiAwarenessContext.return_value = 123
        self.user.GetSystemMetrics.side_effect = lambda index: {76: -1920, 77: 0, 78: 3840, 79: 1080}[index]
        self.user.ClipCursor.return_value = True

        def clip(pointer):
            rectangle = ctypes.cast(pointer, ctypes.POINTER(branding.wintypes.RECT)).contents
            rectangle.left, rectangle.top, rectangle.right, rectangle.bottom = 0, 0, 1920, 1080
            return True
        self.user.GetClipCursor.side_effect = clip

    def test_foreign_foreground_and_framed_window_do_not_change_cursor(self):
        self.user.GetForegroundWindow.return_value = 22
        self.assertFalse(self.api.release_pointer(11))
        self.user.GetForegroundWindow.return_value = 11
        self.user.GetWindowLongPtrW.return_value = 0x00C00000
        self.assertFalse(self.api.release_pointer(11))
        self.user.ClipCursor.assert_not_called()
        self.user.SetThreadDpiAwarenessContext.assert_not_called()

    def test_borderless_foreground_releases_clip_and_restores_dpi(self):
        self.assertTrue(self.api.release_pointer(11))
        self.user.ClipCursor.assert_called_once_with(None)
        self.assertEqual(self.user.SetThreadDpiAwarenessContext.call_args_list[-1], mock.call(123))

    def test_focus_change_does_not_release_other_application_clip(self):
        self.user.GetForegroundWindow.side_effect = [11, 22]
        self.assertFalse(self.api.release_pointer(11))
        self.user.ClipCursor.assert_not_called()
        self.assertEqual(self.user.SetThreadDpiAwarenessContext.call_args_list[-1], mock.call(123))


class IconExtractionTests(unittest.TestCase):
    def test_one_group_with_two_extracted_sizes_is_successful(self):
        api = branding._Win32.__new__(branding._Win32)
        api.shell, api.user = mock.Mock(), mock.Mock()

        def extract(path, index, big, small, count):
            ctypes.cast(big, ctypes.POINTER(branding.wintypes.HANDLE)).contents.value = 100
            ctypes.cast(small, ctypes.POINTER(branding.wintypes.HANDLE)).contents.value = 200
            return 2
        api.shell.ExtractIconExW.side_effect = extract
        self.assertEqual(api.load_icons(Path('C:/Pocket Linux/Launcher.exe')), {'small': 200, 'big': 100})
        api.user.DestroyIcon.assert_not_called()

if __name__ == '__main__':
    unittest.main()
