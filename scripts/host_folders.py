"""Own a confined Windows-folder SMB helper and its restricted QEMU channel, never a VM."""
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import subprocess
import threading
import uuid

from profile_store import _pinned_directory, _plain
from runtime_supervisor import BackendError

MAX_FOLDERS = 64
FW_CFG_NAME = 'opt/pocket/files'
STARTUP_FOLDERS = ('B97D20BB-F46A-4C97-BA10-5E3608430854', '82A5EA35-D9CD-47C5-9629-E15D2F714E6E')
LOCAL_APP_DATA = 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091'


class FoldersError(BackendError):
    """A fixed public error which never includes the SMB credential payload."""


def local_path(value):
    if not isinstance(value, (str, Path)):
        raise FoldersError('Путь выбранной папки должен быть строкой.')
    text = str(value)
    if len(text) > 32767 or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise FoldersError('Некорректный путь выбранной папки.')
    path = Path(text)
    if not path.is_absolute() or not re.fullmatch('[A-Za-z]:', path.drive):
        raise FoldersError('Выбери обычную папку на локальном диске Windows; сетевые и служебные пути запрещены.')
    for part in path.parts[1:]:
        if part in ('.', '..') or part.endswith(('.', ' ')) or any(char in '<>:"|?*' for char in part):
            raise FoldersError('Путь папки содержит неподдерживаемые элементы.')
        if re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', part.split('.')[0], re.IGNORECASE):
            raise FoldersError('Служебные имена Windows нельзя подключать как папки.')
    return path


def canonical_directory(value):
    if os.name != 'nt':
        raise FoldersError('Общий доступ к папкам этого комплекта поддерживается только на Windows.')
    path = local_path(value)
    try:
        for current in (*reversed(path.parents), path):
            info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise FoldersError('Ссылки, junction и точки перенаправления нельзя подключать как папки.')
        resolved = local_path(path.resolve(strict=True))
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        kernel.GetDriveTypeW.restype = wintypes.UINT
        if kernel.GetDriveTypeW(resolved.anchor) not in (2, 3, 6):
            raise FoldersError('Сетевые и неизвестные диски не поддерживаются.')
        return resolved
    except OSError:
        raise FoldersError('Выбранная папка недоступна. Проверь её существование и права доступа.') from None


def overlaps(first, second):
    return first == second or first in second.parents or second in first.parents


def local_drives():
    """Enumerate letters/types only; never inspect user files on the drives."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetLogicalDrives.restype = wintypes.DWORD
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype = wintypes.UINT
    mask = kernel.GetLogicalDrives()
    if not mask:
        raise FoldersError('Не удалось получить список локальных дисков Windows.')
    return [chr(65 + index) + ':\\' for index in range(26)
            if mask & (1 << index) and kernel.GetDriveTypeW(chr(65 + index) + ':\\') in (2, 3)]


def _known_folder(identifier):
    shell, ole = ctypes.WinDLL('shell32', use_last_error=True), ctypes.WinDLL('ole32')
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                                         ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    guid = ctypes.create_string_buffer(uuid.UUID(identifier).bytes_le, 16)
    pointer = ctypes.c_void_p()
    try:
        # DONT_VERIFY also returns a redirected/missing Startup path so its nearest real parent stays protected.
        if shell.SHGetKnownFolderPath(guid, 0x4000, None, ctypes.byref(pointer)) != 0:
            return None
        return Path(ctypes.wstring_at(pointer))
    finally:
        ole.CoTaskMemFree(pointer)


def system_protected_paths():
    """Mirror Windows edition protection of Startup and its private session carrier."""
    local = _known_folder(LOCAL_APP_DATA)
    startups = [_known_folder(identifier) for identifier in STARTUP_FOLDERS]
    if local is None or any(path is None for path in startups):
        raise FoldersError('Не удалось определить защищённые служебные папки Windows. Общий доступ не включён.')
    result = []
    for candidate in [*startups, local / 'WindowsClaudePortable']:
        # Network redirects cannot be reached through local-drive shares or the server's no-reparse traversal.
        if not re.fullmatch('[A-Za-z]:', candidate.drive):
            continue
        try:
            current = candidate
            while not current.exists():
                parent = current.parent
                if parent == current:
                    raise OSError()
                current = parent
            real = local_path(current.resolve(strict=True))
            if real not in result:
                result.append(real)
        except OSError:
            raise FoldersError('Не удалось защитить служебные папки Windows. Общий доступ не включён.') from None
    return result


def normalize_folders(root, files_settings):
    if not isinstance(files_settings, dict) or set(files_settings) - {'schema', 'mode', 'folders'}:
        raise FoldersError('Некорректные настройки папок.')
    if type(files_settings.get('schema', 1)) is not int or files_settings.get('schema', 1) != 1:
        raise FoldersError('Неподдерживаемая версия настроек папок.')
    mode, values = files_settings.get('mode', 'off'), files_settings.get('folders', [])
    if mode not in ('off', 'selected', 'all'):
        raise FoldersError('Допустимы выключенный доступ, выбранные папки или все локальные диски.')
    if not isinstance(values, list) or len(values) > MAX_FOLDERS:
        raise FoldersError('Можно выбрать не более 64 папок.')
    if mode == 'selected' and not values:
        raise FoldersError('Добавь хотя бы одну папку Windows.')
    normalized, seen = [], set()
    protected = canonical_directory(root) if mode == 'selected' else None
    for value in values:
        if not isinstance(value, str):
            raise FoldersError('Путь выбранной папки должен быть строкой.')
        path = canonical_directory(value) if mode == 'selected' else local_path(value)
        if path == Path(path.anchor):
            raise FoldersError('Выбери отдельную папку, а не весь диск.')
        if protected is not None and overlaps(path, protected):
            raise FoldersError('Папку комплекта, её содержимое и родительские папки нельзя передавать Linux.')
        key = str(path).casefold()
        if key in seen:
            raise FoldersError('Одна и та же папка выбрана несколько раз.')
        seen.add(key)
        normalized.append(str(path))
    return {'schema': 1, 'mode': mode, 'folders': normalized}


def parse_ready(raw, nonce, count):
    if not isinstance(raw, (str, bytes)) or len(raw) > 4096:
        raise FoldersError('Сервер папок вернул некорректное подтверждение.')
    try:
        ready = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise FoldersError('Сервер папок не подтвердил запуск.') from None
    if (type(ready) is not dict or set(ready) != {'schema', 'ok', 'session_nonce', 'port', 'share_count'}
            or type(ready['schema']) is not int or ready['schema'] != 1 or ready['ok'] is not True
            or ready['session_nonce'] != nonce or type(ready['share_count']) is not int
            or ready['share_count'] != count or type(ready['port']) is not int
            or not 49152 <= ready['port'] <= 65535):
        raise FoldersError('Подтверждение сервера не относится к выбранным папкам этого сеанса.')
    return ready


def read_ready(process, nonce, count):
    received = queue.Queue(maxsize=1)

    def read():
        try:
            received.put(process.stdout.readline(4097))
        except (OSError, UnicodeError):
            received.put(b'')

    threading.Thread(target=read, daemon=True).start()
    try:
        return parse_ready(received.get(timeout=10), nonce, count)
    except queue.Empty:
        raise FoldersError('Сервер выбранных папок не ответил. Прямой сетевой доступ не включался.') from None


class FolderChannel:
    def __init__(self):
        self.process = None
        self.qemu_args = []
        self.shares = []
        self.session_nonce = None
        self.config_path = None
        self.unavailable = []
        self._directory = None

    def close(self):
        process, self.process = self.process, None
        try:
            if process is not None:
                if process.stdin:
                    try:
                        process.stdin.close()
                    except (OSError, ValueError):
                        pass
                if process.poll() is None:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
        finally:
            if process is not None:
                for name in ('stdout', 'stderr'):
                    stream = getattr(process, name, None)
                    if stream is not None:
                        stream.close()
            if self.config_path is not None:
                self.config_path.unlink(missing_ok=True)
            if self._directory is not None:
                try:
                    self._directory.rmdir()
                except OSError:
                    pass


def start(root, selected_folders, private_dir, path_fn):
    channel = FolderChannel()
    settings = ({'mode': 'selected' if selected_folders else 'off', 'folders': selected_folders}
                if isinstance(selected_folders, list) else selected_folders)
    normalized = normalize_folders(root, settings)
    if normalized['mode'] == 'off':
        return channel
    root, private = canonical_directory(root), canonical_directory(private_dir)
    protected_system = system_protected_paths()
    shares = []
    values = local_drives() if normalized['mode'] == 'all' else normalized['folders']
    for value in values:
        try:
            path = canonical_directory(value)
        except FoldersError:
            if normalized['mode'] != 'all':
                raise
            channel.unavailable.append({'drive': str(value)[:2], 'status': 'unavailable'})
            continue
        if normalized['mode'] == 'selected' and overlaps(path, private):
            raise FoldersError('Служебную папку сеанса и её родителей нельзя передавать Linux.')
        if any(path == folder or folder in path.parents for folder in [root, private, *protected_system]):
            if normalized['mode'] == 'selected':
                raise FoldersError('Выбранная служебная папка Windows защищена от доступа Linux.')
            channel.unavailable.append({'drive': str(value)[:2], 'status': 'protected'})
            continue
        name = ('PC_' + Path(value).drive[0].upper() if normalized['mode'] == 'all'
                else 'PC_' + format(len(shares) + 1, '02d'))
        shares.append({'name': name, 'path': str(path)})
    if not shares:
        raise FoldersError('Нет доступных локальных дисков или папок для подключения.')
    if len(shares) > MAX_FOLDERS:
        raise FoldersError('За один сеанс можно подключить не более 64 папок или дисков.')
    executable = root / 'runtime/host-files/HostFiles.exe'
    if not executable.is_file():
        raise FoldersError('Не найден переносимый сервер папок. Распакуй полный комплект.')
    _plain(executable)
    nonce, password = secrets.token_hex(16), secrets.token_hex(32)
    username = 'WCP_' + secrets.token_hex(12)
    channel.session_nonce = nonce
    channel.shares = shares
    channel._directory = private / ('host-folders-' + nonce)
    try:
        with ExitStack() as pins:
            for directory in [root, private, *(Path(item['path']) for item in shares)]:
                pins.enter_context(_pinned_directory(directory, create=False))
            # The server independently confines every request by pinned file identities,
            # rejecting reparse points/hard links; these checks never replace that server.
            if normalized['mode'] == 'selected':
                normalize_folders(root, normalized)
            from runtime_supervisor import create_private_directory
            try:
                create_private_directory(channel._directory, require_acls=True)
            except BackendError:
                raise FoldersError('Не удалось защитить временный пароль папок. Для общего доступа нужен диск с правами NTFS; FAT/exFAT не подходят.') from None
            protected = list(dict.fromkeys(map(str, (root, root / 'state', private,
                                                     channel._directory, *protected_system))))
            request = {'schema': 1, 'session_nonce': nonce, 'username': username, 'password': password,
                       'shares': channel.shares, 'protected': protected}
            payload = json.dumps(request, ensure_ascii=True).encode('ascii')
            if len(payload) > 65536:
                raise FoldersError('Список путей слишком большой для переносимого сервера папок.')
            channel.process = subprocess.Popen([str(executable)], cwd=executable.parent,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            channel.process.stdin.write(payload + b'\n')
            channel.process.stdin.flush()
            ready = read_ready(channel.process, nonce, len(channel.shares))
            if channel.process.poll() is not None:
                raise FoldersError('Сервер папок завершился до запуска Linux.')
            guest = {'schema': 1, 'session_nonce': nonce, 'server': '192.168.234.4',
                     'username': username, 'password': password, 'shares': [item['name'] for item in channel.shares]}
            channel.config_path = channel._directory / 'files.json'
            with channel.config_path.open('xb') as stream:
                stream.write(json.dumps(guest, ensure_ascii=True).encode('ascii'))
                stream.flush()
                os.fsync(stream.fileno())
            path = path_fn(channel.config_path)
            if not isinstance(path, str) or any(ord(char) < 32 for char in path):
                raise FoldersError('Не удалось подготовить переносимый путь настроек папок.')
            channel.qemu_args = [
                '-netdev', 'user,id=plfiles,restrict=on,ipv6=off,net=192.168.234.0/24,'
                'host=192.168.234.2,dhcpstart=192.168.234.15,'
                'guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:' + str(ready['port']),
                '-device', 'virtio-net-pci,netdev=plfiles,mac=52:54:00:50:4c:03',
                '-fw_cfg', 'name=' + FW_CFG_NAME + ',file=' + path.replace(',', ',,')]
        return channel
    except BaseException:
        channel.close()
        raise
