"""Opt-in text clipboard for the ordinary Pocket LXQt/X11 user; no clipboard data on disk."""
import ctypes
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if (HERE.parent / 'scripts/clipboard_bridge.py').is_file():
    sys.path.insert(0, str(HERE.parent / 'scripts'))
import clipboard_bridge as protocol

FW_CONFIG = Path('/sys/firmware/qemu_fw_cfg/by_name/opt/pocket/clipboard/raw')
RUN_ROOT = Path('/run/pocket-clipboard')
RUN_CONFIG = RUN_ROOT / 'session.json'
DEVICE = Path('/dev/virtio-ports/org.pocket.clipboard')
MAX_CONFIG = 4096
POLL_SECONDS = 0.4
SENSITIVE_TARGETS = {'x-kde-passwordManagerHint', protocol.EXCLUDE_FORMAT}


def parse_config(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIG:
        raise ValueError('Invalid clipboard configuration size')
    try:
        value = json.loads(raw, object_pairs_hook=protocol.unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid clipboard configuration') from None
    if (type(value) is not dict or set(value) != {'schema', 'enabled', 'session_nonce'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['enabled']) is not bool or not protocol.valid_nonce(value['session_nonce'])):
        raise ValueError('Invalid clipboard configuration fields')
    return value


def read_config(path):
    with path.open('rb') as stream:
        return parse_config(stream.read(MAX_CONFIG + 1))


def prepare():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Preparation runs only as root inside Pocket Linux')
    import pwd
    user = pwd.getpwnam('pocket')
    if any(path.is_symlink() for path in (RUN_ROOT, *RUN_ROOT.parents)):
        raise ValueError('Runtime directory cannot be a symlink')
    RUN_ROOT.mkdir(mode=0o755, exist_ok=True)
    if RUN_ROOT.stat().st_uid != 0:
        raise ValueError('Runtime directory must be root owned')
    RUN_ROOT.chmod(0o755)
    if RUN_CONFIG.exists() or RUN_CONFIG.is_symlink():
        previous = RUN_CONFIG.lstat()
        if not stat.S_ISREG(previous.st_mode) or previous.st_uid != 0:
            raise ValueError('Runtime file must be root owned')
        RUN_CONFIG.unlink()
    subprocess.run(['/usr/sbin/modprobe', 'qemu_fw_cfg'], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=True)
    if not FW_CONFIG.is_file():
        return False
    config = read_config(FW_CONFIG)
    if not config['enabled']:
        return False
    subprocess.run(['/usr/sbin/modprobe', 'virtio_console'], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=True)
    deadline = time.monotonic() + 8
    while not DEVICE.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    target = DEVICE.resolve(strict=True)
    if target.parent != Path('/dev') or re.fullmatch(r'vport[0-9]+p[0-9]+', target.name) is None:
        raise ValueError('Unexpected virtio clipboard device')
    descriptor = os.open(target, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            raise ValueError('Clipboard device must be a character device')
        os.fchown(descriptor, user.pw_uid, user.pw_gid)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    temporary = RUN_ROOT / ('session-' + os.urandom(8).hex() + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        os.fchown(descriptor, 0, user.pw_gid)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = None
            stream.write(protocol.configuration(config['session_nonce']))
        os.replace(temporary, RUN_CONFIG)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return True


class DeviceStream:
    """Socket-shaped nonblocking virtio port; never opens a network socket."""
    def __init__(self):
        self.fd = os.open(DEVICE, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        if not stat.S_ISCHR(os.fstat(self.fd).st_mode):
            os.close(self.fd)
            raise OSError('Invalid clipboard device')
        self.timeout = 0.3
        self.gate = threading.RLock()

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        with self.gate:
            if self.fd is None:
                raise OSError('Clipboard device closed')
            if not select.select([self.fd], [], [], self.timeout)[0]:
                raise socket.timeout()
            try:
                return os.read(self.fd, size)
            except BlockingIOError:
                raise socket.timeout() from None

    def sendall(self, data):
        with self.gate:
            deadline = time.monotonic() + self.timeout
            view = memoryview(data)
            while view:
                if self.fd is None:
                    raise OSError('Clipboard device closed')
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [self.fd], [], remaining)[1]:
                    raise socket.timeout()
                try:
                    written = os.write(self.fd, view)
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise OSError('Clipboard device closed')
                view = view[written:]

    def close(self):
        with self.gate:
            if self.fd is not None:
                descriptor, self.fd = self.fd, None
                os.close(descriptor)


def stop_child(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def read_selection(target, limit):
    process = subprocess.Popen(['/usr/bin/xclip', '-selection', 'clipboard', '-out', '-target', target],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        deadline, chunks, length = time.monotonic() + 0.8, [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                return None
            chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            if length > limit:
                return None
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            return None
        return b''.join(chunks)
    except (OSError, subprocess.TimeoutExpired):
        return None
    finally:
        process.stdout.close()
        stop_child(process)


class SelectionSnapshot:
    """A private X connection tracks every ownership event, including same-owner copies."""
    def __init__(self):
        if sys.platform != 'linux':
            raise OSError('X11 clipboard monitoring requires Linux')
        self.x = ctypes.CDLL('libX11.so.6')
        self.fixes = ctypes.CDLL('libXfixes.so.3')
        self.display = None
        self.window = 0
        self.generation = 0
        for name, args, result in (
                ('XOpenDisplay', [ctypes.c_char_p], ctypes.c_void_p),
                ('XDefaultRootWindow', [ctypes.c_void_p], ctypes.c_ulong),
                ('XCreateSimpleWindow', [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                    ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_ulong], ctypes.c_ulong),
                ('XInternAtom', [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int], ctypes.c_ulong),
                ('XGetSelectionOwner', [ctypes.c_void_p, ctypes.c_ulong], ctypes.c_ulong),
                ('XSync', [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
                ('XPending', [ctypes.c_void_p], ctypes.c_int),
                ('XNextEvent', [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
                ('XDestroyWindow', [ctypes.c_void_p, ctypes.c_ulong], ctypes.c_int),
                ('XCloseDisplay', [ctypes.c_void_p], ctypes.c_int)):
            function = getattr(self.x, name)
            function.argtypes, function.restype = args, result
        self.fixes.XFixesQueryExtension.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        self.fixes.XFixesQueryExtension.restype = ctypes.c_int
        self.fixes.XFixesQueryVersion.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        self.fixes.XFixesQueryVersion.restype = ctypes.c_int
        self.fixes.XFixesSelectSelectionInput.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        self.fixes.XFixesSelectSelectionInput.restype = None
        try:
            self.display = self.x.XOpenDisplay(None)
            event, error = ctypes.c_int(), ctypes.c_int()
            if not self.display or not self.fixes.XFixesQueryExtension(self.display, ctypes.byref(event), ctypes.byref(error)):
                raise OSError('XFixes clipboard monitoring unavailable')
            major, minor = ctypes.c_int(), ctypes.c_int()
            if not self.fixes.XFixesQueryVersion(self.display, ctypes.byref(major), ctypes.byref(minor)) or major.value < 1:
                raise OSError('XFixes selection monitoring unavailable')
            self.event_type = event.value  # XFixesSelectionNotify is extension event zero.
            self.window = self.x.XCreateSimpleWindow(self.display, self.x.XDefaultRootWindow(self.display), 0, 0, 1, 1, 0, 0, 0)
            self.selection = self.x.XInternAtom(self.display, b'CLIPBOARD', 0)
            if not self.window or not self.selection:
                raise OSError('X11 clipboard monitor unavailable')
            self.fixes.XFixesSelectSelectionInput(self.display, self.window, self.selection, 7)
            self.x.XSync(self.display, 0)
        except BaseException:
            self.close()
            raise

    def snapshot(self):
        if not self.display:
            raise OSError('X11 clipboard monitor closed')
        owner = self.x.XGetSelectionOwner(self.display, self.selection)
        self.x.XSync(self.display, 0)
        # XEvent is a union padded to 24 native longs; only its leading type is needed.
        event = (ctypes.c_long * 24)()
        for unused in range(1024):
            if not self.x.XPending(self.display):
                return (int(owner), self.generation) if owner else None
            self.x.XNextEvent(self.display, ctypes.byref(event))
            if ctypes.cast(event, ctypes.POINTER(ctypes.c_int)).contents.value == self.event_type:
                self.generation += 1
        raise OSError('Too many clipboard ownership changes')

    def close(self):
        if self.display:
            if self.window:
                self.x.XDestroyWindow(self.display, self.window)
            self.x.XCloseDisplay(self.display)
            self.display, self.window = None, 0


class XclipClipboard:
    def __init__(self):
        self.callback = self.thread = self.owner = None
        self.stopping = threading.Event()
        self.gate = threading.RLock()
        self.previous = None
        self.selection = None

    def read_text(self):
        try:
            if self.selection is None:
                self.selection = SelectionSnapshot()
            before = self.selection.snapshot()
            if before is None:
                return None
        except (OSError, AttributeError):
            return None
        targets = read_selection('TARGETS', 16384)
        if targets is None or SENSITIVE_TARGETS.intersection(targets.decode('ascii', errors='ignore').split()):
            return None
        try:
            if self.selection.snapshot() != before:
                return None
        except OSError:
            return None
        raw = read_selection('UTF8_STRING', protocol.MAX_BYTES)
        if raw is None:
            return None
        try:
            if self.selection.snapshot() != before:
                return None
        except OSError:
            return None
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            return None
        return text if 0 < len(text) <= protocol.MAX_CHARS and '\0' not in text else None

    def start(self, callback):
        self.callback = callback
        # Prime the baseline without exporting an old selection at session startup.
        with self.gate:
            text = self.read_text()
            self.previous = protocol.digest(text) if text else None
        self.thread = threading.Thread(target=self.poll, name='x11-clipboard', daemon=True)
        self.thread.start()

    def poll_once(self):
        with self.gate:
            text = self.read_text()
            if self.stopping.is_set():
                return
            value = protocol.digest(text) if text else None
            if value == self.previous:
                return
            self.previous = value
            self.callback(text)

    def poll(self):
        while not self.stopping.wait(POLL_SECONDS):
            try:
                self.poll_once()
            except OSError:
                pass

    def set_text(self, text):
        if protocol.encode('0' * 32, text) is None:
            return
        with self.gate:
            if self.stopping.is_set():
                return
            process = subprocess.Popen(['/usr/bin/xclip', '-selection', 'clipboard', '-in', '-target', 'UTF8_STRING', '-quiet'],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            accepted = False
            try:
                os.set_blocking(process.stdin.fileno(), False)
                deadline, data = time.monotonic() + 1, memoryview(text.encode('utf-8'))
                while data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([], [process.stdin], [], remaining)[1]:
                        raise OSError('Clipboard owner unavailable')
                    try:
                        written = os.write(process.stdin.fileno(), data)
                    except BlockingIOError:
                        continue
                    if written <= 0:
                        raise OSError('Clipboard owner closed')
                    data = data[written:]
                process.stdin.close()
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and process.poll() is None:
                    if self.read_text() == text:
                        if self.stopping.is_set():
                            raise OSError('Clipboard bridge stopped')
                        self.previous = protocol.digest(text)
                        old, self.owner = self.owner, process
                        stop_child(old)
                        accepted = True
                        return
                    time.sleep(0.02)
                raise OSError('Clipboard ownership was not confirmed')
            finally:
                if not process.stdin.closed:
                    process.stdin.close()
                if not accepted:
                    stop_child(process)

    def stop(self):
        self.stopping.set()
        with self.gate:
            owner, self.owner = self.owner, None
            stop_child(owner)
            if self.selection is not None:
                self.selection.close()
                self.selection = None
        if self.thread is not None:
            self.thread.join(timeout=2)


def main():
    if sys.argv[1:] == ['--prepare']:
        try:
            prepare()
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError):
            return 1
    if sys.argv[1:] or sys.platform != 'linux' or os.geteuid() == 0:
        return 1
    try:
        if not RUN_CONFIG.is_file() or not os.environ.get('DISPLAY'):
            return 0
        metadata = RUN_CONFIG.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return 1
        config = read_config(RUN_CONFIG)
        if not config['enabled']:
            return 0
        bridge = protocol.Bridge(None, config['session_nonce'], XclipClipboard(), connector=DeviceStream, role='guest')
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: bridge.stopping.set())
        bridge.start()
        bridge.stopping.wait()
        bridge.stop()
        return 0
    except (OSError, ValueError, RuntimeError):
        return 1


if __name__ == '__main__':
    sys.exit(main())
