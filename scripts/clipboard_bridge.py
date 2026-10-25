"""Opt-in shared text clipboard for Pocket Linux; no content is logged or stored on disk.

Text frames remain compatible with Pocket Windows v1. A nonce-based HMAC handshake
precedes them, so a wrong loopback listener never receives clipboard contents.
"""
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import socket
import threading
import time
import zlib

MAX_CHARS = 256 * 1024
MAX_BYTES = MAX_CHARS * 4
MAX_LINE = 1024 * 1024
MAX_AUTH = 512
EXCLUDE_FORMAT = 'ExcludeClipboardContentFromMonitorProcessing'


def valid_nonce(nonce):
    return type(nonce) is str and re.fullmatch('[a-f0-9]{32}', nonce) is not None


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).digest()


def configuration(nonce):
    if not valid_nonce(nonce):
        raise ValueError('Invalid clipboard session nonce')
    return json.dumps({'schema': 1, 'enabled': True, 'session_nonce': nonce}, separators=(',', ':')).encode('ascii')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate protocol field')
        result[key] = value
    return result


def encode(nonce, text):
    if not valid_nonce(nonce) or type(text) is not str or not text or len(text) > MAX_CHARS or '\0' in text:
        return None
    try:
        raw = text.encode('utf-8')
        if len(raw) > MAX_BYTES:
            return None
        packer = zlib.compressobj(6, zlib.DEFLATED, -15)
        packed = packer.compress(raw) + packer.flush()
        line = (json.dumps({'v': 1, 'n': nonce, 't': 'text', 'z': 1, 'd': base64.b64encode(packed).decode('ascii')}, separators=(',', ':')) + '\n').encode('ascii')
        return line if len(line) <= MAX_LINE else None
    except (UnicodeError, ValueError):
        return None


def decode(line, nonce):
    try:
        if not valid_nonce(nonce) or not isinstance(line, bytes) or len(line) > MAX_LINE:
            return None
        message = json.loads(line.decode('utf-8'), object_pairs_hook=unique)
        if (type(message) is not dict or set(message) != {'v', 'n', 't', 'z', 'd'}
                or type(message['v']) is not int or message['v'] != 1 or message['t'] != 'text'
                or type(message['n']) is not str or not hmac.compare_digest(message['n'].encode('utf-8'), nonce.encode('ascii'))
                or type(message['z']) is not int or message['z'] not in (0, 1) or type(message['d']) is not str):
            return None
        raw = base64.b64decode(message['d'].encode('ascii'), validate=True)
        if message['z']:
            unpacker = zlib.decompressobj(-15)
            raw = unpacker.decompress(raw, MAX_BYTES + 1)
            if len(raw) > MAX_BYTES or not unpacker.eof or unpacker.unconsumed_tail or unpacker.unused_data:
                return None
        if len(raw) > MAX_BYTES:
            return None
        text = raw.decode('utf-8')
        return text if 0 < len(text) <= MAX_CHARS and '\0' not in text else None
    except (ValueError, zlib.error, UnicodeError, TypeError, RecursionError):
        return None


class LineFramer:
    def __init__(self):
        self.buffer = bytearray()
        self.discarding = False

    def feed(self, data):
        while data:
            position = data.find(b'\n')
            part = data if position < 0 else data[:position]
            if not self.discarding:
                if len(self.buffer) + len(part) > MAX_LINE:
                    self.buffer.clear()
                    self.discarding = True
                else:
                    self.buffer.extend(part)
            if position < 0:
                break
            if not self.discarding:
                yield bytes(self.buffer)
            self.buffer.clear()
            self.discarding = False
            data = data[position + 1:]


def proof(nonce, role, challenge):
    return hmac.new(nonce.encode('ascii'), (role + ':' + challenge).encode('ascii'), hashlib.sha256).hexdigest()


def auth_read(connection, buffer, stopping, deadline):
    while b'\n' not in buffer:
        if stopping.is_set() or time.monotonic() >= deadline or len(buffer) > MAX_AUTH:
            raise OSError('Clipboard authentication failed')
        try:
            chunk = connection.recv(MAX_AUTH + 1 - len(buffer))
        except socket.timeout:
            continue
        if not chunk:
            raise OSError('Clipboard authentication closed')
        buffer += chunk
    line, buffer = buffer.split(b'\n', 1)
    if len(line) > MAX_AUTH:
        raise OSError('Clipboard authentication too large')
    try:
        value = json.loads(line.decode('ascii'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise OSError('Clipboard authentication invalid') from None
    if type(value) is not dict or type(value.get('v')) is not int or value['v'] != 1:
        raise OSError('Clipboard authentication invalid')
    return value, buffer


def authenticate(connection, nonce, role, stopping):
    deadline = time.monotonic() + 5
    buffer = b''
    def send(message):
        connection.sendall((json.dumps(message, separators=(',', ':')) + '\n').encode('ascii'))
    if role == 'host':
        challenge = os.urandom(16).hex()
        send({'v': 1, 't': 'challenge', 'c': challenge})
        message, buffer = auth_read(connection, buffer, stopping, deadline)
        if (set(message) != {'v', 't', 'c', 'h'} or message['t'] != 'hello' or message['c'] != challenge
                or type(message['h']) is not str or re.fullmatch('[a-f0-9]{64}', message['h']) is None
                or not hmac.compare_digest(message['h'], proof(nonce, 'guest', challenge))):
            raise OSError('Clipboard authentication refused')
        send({'v': 1, 't': 'ready', 'c': challenge, 'h': proof(nonce, 'host', challenge)})
    else:
        message, buffer = auth_read(connection, buffer, stopping, deadline)
        challenge = message.get('c')
        if (set(message) != {'v', 't', 'c'} or message['t'] != 'challenge' or type(challenge) is not str
                or re.fullmatch('[a-f0-9]{32}', challenge) is None):
            raise OSError('Clipboard challenge invalid')
        send({'v': 1, 't': 'hello', 'c': challenge, 'h': proof(nonce, 'guest', challenge)})
        message, buffer = auth_read(connection, buffer, stopping, deadline)
        if (set(message) != {'v', 't', 'c', 'h'} or message['t'] != 'ready' or message['c'] != challenge
                or type(message['h']) is not str or re.fullmatch('[a-f0-9]{64}', message['h']) is None
                or not hmac.compare_digest(message['h'], proof(nonce, 'host', challenge))):
            raise OSError('Clipboard host authentication refused')
    return buffer


class Bridge:
    def __init__(self, port, nonce, clipboard, log=None, *, connector=None, role='host'):
        if not valid_nonce(nonce) or role not in ('host', 'guest'):
            raise ValueError('Invalid clipboard session')
        if connector is None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('Invalid clipboard port')
        self.port, self.nonce, self.clipboard = port, nonce, clipboard
        self.log = log or (lambda message: None)
        self.connector = connector or (lambda: socket.create_connection(('127.0.0.1', port), timeout=1))
        self.role = role
        self.stopping, self.authenticated = threading.Event(), threading.Event()
        self.outgoing = queue.Queue(maxsize=1)
        self.applied = self.sent = None
        self.thread = self.connection = None
        self.gate = threading.RLock()

    def start(self):
        if self.thread is not None:
            raise RuntimeError('Clipboard bridge already started')
        try:
            self.clipboard.start(self.local_change)
            self.thread = threading.Thread(target=self.run, name='clipboard-bridge', daemon=True)
            self.thread.start()
        except Exception:
            self.clipboard.stop()
            raise
        return self

    def stop(self):
        self.stopping.set()
        with self.gate:
            self.clear_outgoing()
            self.applied = self.sent = None
        if self.connection is not None:
            try:
                self.connection.close()
            except OSError:
                pass
        self.clipboard.stop()
        if self.thread is not None:
            self.thread.join(timeout=3)

    def clear_outgoing(self):
        try:
            self.outgoing.get_nowait()
        except queue.Empty:
            pass

    def local_change(self, text):
        if self.stopping.is_set():
            return
        line = encode(self.nonce, text)
        with self.gate:
            if line is None:
                self.clear_outgoing()
                self.applied = self.sent = None
                return
            value = digest(text)
            if value == self.applied or value == self.sent:
                return
            self.applied, self.sent = None, value
            self.clear_outgoing()
            self.outgoing.put_nowait(line)

    def run(self):
        while not self.stopping.is_set():
            try:
                connection = self.connector()
                self.connection = connection
                self.serve(connection)
            except (OSError, ValueError) as error:
                self.log('clipboard connection unavailable: ' + type(error).__name__)
            finally:
                self.authenticated.clear()
                with self.gate:
                    # A failed send consumes its frame; allow the user to copy that text again.
                    self.sent = None
                if self.connection is not None:
                    self.connection.close()
                    self.connection = None
            self.stopping.wait(1)

    def serve(self, connection):
        connection.settimeout(0.3)
        initial = authenticate(connection, self.nonce, self.role, self.stopping)
        self.authenticated.set()
        self.log('clipboard authenticated')
        framer = LineFramer()
        while not self.stopping.is_set():
            if initial:
                chunk, initial = initial, b''
            else:
                try:
                    line = self.outgoing.get_nowait()
                except queue.Empty:
                    line = None
                if line is not None:
                    connection.settimeout(2)
                    connection.sendall(line)
                    connection.settimeout(0.3)
                try:
                    chunk = connection.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    return
            latest = None
            for line in framer.feed(chunk):
                text = decode(line, self.nonce)
                if text is not None:
                    latest = text
            if latest is not None:
                value = digest(latest)
                with self.gate:
                    if value == self.applied:
                        continue
                    self.applied, self.sent = value, None
                    self.clear_outgoing()
                self.clipboard.set_text(latest)


if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    WM_CLIPBOARDUPDATE, WM_APP, WM_CLOSE = 0x031D, 0x8000, 0x0010
    CF_UNICODETEXT, GMEM_MOVEABLE = 13, 2

    class WNDCLASS(ctypes.Structure):
        _fields_ = [('style', wintypes.UINT), ('lpfnWndProc', WNDPROC), ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
                    ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HANDLE), ('hCursor', wintypes.HANDLE),
                    ('hbrBackground', wintypes.HANDLE), ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR)]

    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.AddClipboardFormatListener.argtypes = [wintypes.HWND]
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.RemoveClipboardFormatListener.argtypes = [wintypes.HWND]
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.GetClipboardSequenceNumber.argtypes = []
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.restype = ctypes.c_size_t
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]

    class WindowsClipboard:
        """Text clipboard of this PC. Owns a hidden message window on its own thread, which must keep pumping
        messages: another program's EmptyClipboard waits for the owner window to answer."""

        def __init__(self):
            self.hwnd, self.on_change, self.pending = None, None, None
            self.ready, self.thread = threading.Event(), None
            self.sequence = None
            self.exclude = user32.RegisterClipboardFormatW(EXCLUDE_FORMAT)
            self.proc = WNDPROC(self.window_proc)

        def start(self, on_change):
            self.on_change = on_change
            self.thread = threading.Thread(target=self.pump, name='clipboard-window', daemon=True)
            self.thread.start()
            if not self.ready.wait(5) or not self.hwnd:
                raise OSError('Clipboard window was not created')

        def stop(self):
            self.on_change = None
            self.pending = None
            if self.hwnd:
                user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
            if self.thread is not None:
                self.thread.join(timeout=3)

        def set_text(self, text):
            self.pending = text
            user32.PostMessageW(self.hwnd, WM_APP, 0, 0)

        def pump(self):
            window_class = WNDCLASS()
            window_class.lpfnWndProc = self.proc
            window_class.hInstance = kernel32.GetModuleHandleW(None)
            window_class.lpszClassName = 'PocketLinuxClipboard'
            user32.RegisterClassW(ctypes.byref(window_class))
            self.hwnd = user32.CreateWindowExW(0, window_class.lpszClassName, None, 0, 0, 0, 0, 0, wintypes.HWND(-3), None,
                                               window_class.hInstance, None)
            if self.hwnd:
                self.sequence = user32.GetClipboardSequenceNumber()
                user32.AddClipboardFormatListener(self.hwnd)
            self.ready.set()
            message = wintypes.MSG()
            while self.hwnd and user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.DispatchMessageW(ctypes.byref(message))

        def window_proc(self, hwnd, message, wparam, lparam):
            try:
                if message == WM_CLIPBOARDUPDATE:
                    sequence = user32.GetClipboardSequenceNumber()
                    if sequence != self.sequence:
                        self.sequence = sequence
                        if self.on_change:
                            self.on_change(self.read())
                    return 0
                if message == WM_APP:
                    text, self.pending = self.pending, None
                    if text:
                        self.write(text)
                    return 0
                if message == WM_CLOSE:
                    user32.RemoveClipboardFormatListener(hwnd)
                    self.hwnd = None
                    user32.DestroyWindow(hwnd)
                    user32.PostQuitMessage(0)
                    return 0
            except Exception:  # a failed copy must never take the window thread down
                return 0
            return user32.DefWindowProcW(hwnd, message, wparam, lparam)

        def open(self):
            for _ in range(20):
                if user32.OpenClipboard(self.hwnd):
                    return True
                time.sleep(0.025)
            return False

        def read(self):
            if not self.open():
                return None
            try:
                if user32.IsClipboardFormatAvailable(self.exclude) or not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                    return None
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle or kernel32.GlobalSize(handle) > (MAX_CHARS + 1) * 2:
                    return None
                pointer = kernel32.GlobalLock(handle)
                if not pointer:
                    return None
                try:
                    data = ctypes.wstring_at(pointer, kernel32.GlobalSize(handle) // 2)
                    return data.split('\0', 1)[0] if '\0' in data else None
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()

        def write(self, text):
            data = (text + '\0').encode('utf-16-le')
            handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
            if not handle:
                return
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                kernel32.GlobalFree(handle)
                return
            ctypes.memmove(pointer, data, len(data))
            kernel32.GlobalUnlock(handle)
            if not self.open():
                kernel32.GlobalFree(handle)
                return
            try:
                user32.EmptyClipboard()
                if not user32.SetClipboardData(CF_UNICODETEXT, handle):
                    kernel32.GlobalFree(handle)
            finally:
                user32.CloseClipboard()


def reserve_port():
    """Reserve a free loopback number; HMAC authentication protects the QEMU bind race."""
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def arguments(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid clipboard port')
    return ['-chardev', 'socket,id=pocketclip,host=127.0.0.1,port=' + str(port) + ',server=on,wait=off',
            '-device', 'virtio-serial-pci,id=pocketclipbus',
            '-device', 'virtserialport,bus=pocketclipbus.0,chardev=pocketclip,name=org.pocket.clipboard']
