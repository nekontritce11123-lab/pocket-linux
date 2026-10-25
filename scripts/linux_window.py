"""Brand only this session's SDL windows; SDL retains all geometry and monitor control."""
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import uuid

from runtime_supervisor import process_identity, same_identity

TITLE = 'Pocket Linux'


def taskbar_properties(root):
    root = Path(root).resolve()
    launcher = root / 'Launcher.exe'
    identifier = 'PocketLinux.Desktop.' + hashlib.sha256(os.path.normcase(str(root)).encode('utf-8')).hexdigest()[:16]
    # AppUserModel ID is set last so Explorer sees complete relaunch properties.
    return {2: '"' + str(launcher) + '"', 3: str(launcher) + ',0', 4: TITLE, 5: identifier}


class _Win32:
    def __init__(self):
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.shell = ctypes.WinDLL('shell32', use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user.EnumWindows.argtypes = [self.callback, wintypes.LPARAM]
        self.user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        self.user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        self.user.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
            wintypes.LPVOID, wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
        self.user.SendMessageTimeoutW.restype = ctypes.c_ssize_t
        self.user.DestroyIcon.argtypes = [wintypes.HANDLE]
        self.user.DestroyIcon.restype = wintypes.BOOL
        self.user.GetForegroundWindow.argtypes = []
        self.user.GetForegroundWindow.restype = wintypes.HWND
        self.user.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        self.user.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        self.user.GetClipCursor.argtypes = [ctypes.POINTER(wintypes.RECT)]
        self.user.GetClipCursor.restype = wintypes.BOOL
        self.user.ClipCursor.argtypes = [ctypes.POINTER(wintypes.RECT)]
        self.user.ClipCursor.restype = wintypes.BOOL
        self.user.GetSystemMetrics.argtypes = [ctypes.c_int]
        self.user.GetSystemMetrics.restype = ctypes.c_int
        self.user.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        self.user.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
        self.shell.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
            ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), wintypes.UINT]
        self.shell.ExtractIconExW.restype = wintypes.UINT

    def window_pid(self, window):
        pid = wintypes.DWORD()
        self.user.GetWindowThreadProcessId(window, ctypes.byref(pid))
        return pid.value

    def release_pointer(self, window):
        """Release SDL's global clip only while this borderless window has focus."""
        if (self.user.GetForegroundWindow() != window
                or self.user.GetWindowLongPtrW(window, -16) & 0x00C00000 == 0x00C00000):
            return False
        previous = self.user.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        try:
            clip = wintypes.RECT()
            left, top = self.user.GetSystemMetrics(76), self.user.GetSystemMetrics(77)
            width, height = self.user.GetSystemMetrics(78), self.user.GetSystemMetrics(79)
            if (width <= 0 or height <= 0 or not self.user.GetClipCursor(ctypes.byref(clip))
                    or not (clip.left > left or clip.top > top
                            or clip.right < left + width or clip.bottom < top + height)):
                return False
            # Focus may change while reading metrics; never release another application's clip.
            if self.user.GetForegroundWindow() != window:
                return False
            return bool(self.user.ClipCursor(None))
        finally:
            if previous:
                self.user.SetThreadDpiAwarenessContext(previous)

    def enumerate_windows(self, pid):
        found = []

        def visit(window, unused):
            if self.window_pid(window) == pid:
                kind = ctypes.create_unicode_buffer(64)
                self.user.GetClassNameW(window, kind, len(kind))
                if kind.value == 'SDL_app':
                    found.append(int(window))
            return True

        if not self.user.EnumWindows(self.callback(visit), 0):
            raise OSError('Cannot enumerate owned SDL windows')
        return found

    def load_icons(self, launcher):
        big, small = wintypes.HANDLE(), wintypes.HANDLE()
        count = self.shell.ExtractIconExW(str(launcher), 0, ctypes.byref(big), ctypes.byref(small), 1)
        # ExtractIconEx counts extracted handles: requesting both sizes can return 2 for one group.
        if count in (0, 0xffffffff) or not big.value or not small.value:
            for icon in {big.value, small.value} - {None, 0}:
                self.user.DestroyIcon(icon)
            raise OSError('Linux launcher icon is unavailable')
        return {'small': small.value, 'big': big.value}

    def destroy_icon(self, icon):
        self.user.DestroyIcon(icon)

    def set_icon(self, window, kind, icon):
        result = ctypes.c_size_t()
        return bool(self.user.SendMessageTimeoutW(window, 0x0080, kind, ctypes.c_void_p(icon),
                                                 0x0002, 200, ctypes.byref(result)))

    def title(self, window):
        title = ctypes.create_unicode_buffer(256)
        self.user.GetWindowTextW(window, title, len(title))
        return title.value

    def set_title(self, window, title):
        result = ctypes.c_size_t()
        text = ctypes.create_unicode_buffer(title)
        return bool(self.user.SendMessageTimeoutW(window, 0x000C, 0, ctypes.cast(text, wintypes.LPVOID),
                                                 0x0002, 200, ctypes.byref(result)))

    def set_taskbar(self, window, properties, still_owned):
        # Same per-window IPropertyStore contract as the accepted Windows controller; no registry writes.
        class Key(ctypes.Structure):
            _fields_ = [('format', ctypes.c_ubyte * 16), ('pid', wintypes.DWORD)]

        class Variant(ctypes.Structure):
            _fields_ = [('vt', wintypes.USHORT), ('reserved', wintypes.USHORT * 3),
                        ('pointer', ctypes.c_void_p), ('tail', ctypes.c_void_p)]

        def guid(value):
            return (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(value).bytes_le)

        def checked(result):
            if result < 0:
                raise OSError('Cannot set owned window taskbar properties')

        ole = ctypes.WinDLL('ole32', use_last_error=True)
        ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        ole.CoInitializeEx.restype = ctypes.c_long
        self.shell.SHGetPropertyStoreForWindow.argtypes = [wintypes.HWND, ctypes.c_void_p,
                                                          ctypes.POINTER(ctypes.c_void_p)]
        self.shell.SHGetPropertyStoreForWindow.restype = ctypes.c_long
        initialized = ole.CoInitializeEx(None, 2)
        if initialized != -2147417850:  # RPC_E_CHANGED_MODE: respect an already initialized COM apartment.
            checked(initialized)
        store = ctypes.c_void_p()
        try:
            if not still_owned():
                return False
            checked(self.shell.SHGetPropertyStoreForWindow(window,
                ctypes.byref(guid('886d8eeb-8cf2-4446-8d02-cdba1dbdcf99')), ctypes.byref(store)))
            if not store.value:
                raise OSError('Missing owned window property store')
            table = ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            release = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(table[2])
            try:
                set_value = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
                    ctypes.POINTER(Key), ctypes.POINTER(Variant))(table[6])
                fmt = guid('9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3')
                for number, text in properties.items():
                    if not still_owned():
                        return False
                    buffer = ctypes.create_unicode_buffer(text)
                    value = Variant()
                    value.vt = 31  # VT_LPWSTR; SetValue copies the borrowed string.
                    value.pointer = ctypes.cast(buffer, ctypes.c_void_p).value
                    checked(set_value(store, ctypes.byref(Key(fmt, number)), ctypes.byref(value)))
                return True
            finally:
                release(store)
        finally:
            if initialized >= 0:
                ole.CoUninitialize()


class WindowBranding:
    def __init__(self, root, pid, expected_identity=None):
        self.root = Path(root).resolve()
        if type(pid) is not int or not 1 <= pid <= 0xffffffff:
            raise ValueError('A session-owned QEMU PID is required')
        actual = process_identity(pid)
        expected_image = self.root / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe'
        if (not actual or os.path.normcase(actual.get('image', '')) != os.path.normcase(str(expected_image))
                or expected_identity is not None and not same_identity(expected_identity, actual)):
            raise ValueError('The process is not this portable Linux session')
        self.identity = dict(actual)
        self.pid = pid
        self.api = _Win32()
        self.icons = {}
        self._branded = set()
        self._closed = False

    def _owned(self, window=None):
        try:
            return (same_identity(self.identity, process_identity(self.pid))
                    and (window is None or self.api.window_pid(window) == self.pid))
        except (OSError, ValueError, RuntimeError):
            return False

    def apply(self):
        if self._closed or not self._owned():
            return False
        applied = False
        try:
            for window in self.api.enumerate_windows(self.pid):
                if not self._owned(window):
                    continue
                if not self.icons:
                    self.icons = self.api.load_icons(self.root / 'Launcher.exe')
                if window not in self._branded:
                    if not self.api.set_taskbar(window, taskbar_properties(self.root), lambda: self._owned(window)):
                        continue
                    success = True
                    for kind, name in ((0, 'small'), (1, 'big')):
                        if not self._owned(window) or not self.api.set_icon(window, kind, self.icons[name]):
                            success = False
                            break
                    if not success:
                        continue
                    self._branded.add(window)
                if not self._owned(window):
                    continue
                self.api.release_pointer(window)
                if self.api.title(window) != TITLE:
                    if not self._owned(window) or not self.api.set_title(window, TITLE):
                        continue
                applied = True
        except (OSError, ValueError, RuntimeError):
            return False
        return applied

    def close(self):
        """Release extracted HICONs after VM exit; never invalidate a live window's icons."""
        if self._closed:
            return True
        try:
            if self.icons and same_identity(self.identity, process_identity(self.pid)):
                return False
        except (OSError, ValueError, RuntimeError):
            return False
        for icon in dict.fromkeys(self.icons.values()):
            self.api.destroy_icon(icon)
        self.icons.clear()
        self._branded.clear()
        self._closed = True
        return True
