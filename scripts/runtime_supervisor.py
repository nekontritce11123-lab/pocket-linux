"""Own one portable Linux session; never terminate a guest during normal stop."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from profile_store import ProfileStore, _exclusive_file, _pinned_directory, _plain, _protect, _unprotect
from connection_profile import validate_profile


class BackendError(ValueError):
    """A fixed, non-secret message suitable for the launcher."""


def read_json(path, limit=65536):
    _plain(path)
    with path.open('rb') as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise BackendError('Служебный файл слишком большой; он сохранён без изменений.')
    try:
        return json.loads(payload)
    except (ValueError, UnicodeError, RecursionError):
        raise BackendError('Служебный файл повреждён; он сохранён без изменений.') from None


def write_json(path, value):
    with _pinned_directory(path.parent):
        _plain(path)
        temporary = path.with_name(path.name + '-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('xb') as stream:
                stream.write(json.dumps(value, ensure_ascii=True).encode('ascii'))
                stream.flush()
                os.fsync(stream.fileno())
            _plain(path)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


@contextmanager
def operation_lock(root):
    with _pinned_directory(root / 'state'), _exclusive_file(root / 'state/operation.lock'):
        yield


def helper_module(root):
    path = root / 'start.py'
    _plain(path)
    spec = importlib.util.spec_from_file_location('pocket_linux_start', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def proxy_ipv4(host, port):
    import queue
    import threading
    try:
        server = ipaddress.IPv4Address(host)
    except ValueError:
        replies = queue.Queue(maxsize=1)
        def resolve():
            try:
                replies.put(socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM))
            except OSError:
                replies.put(None)
        threading.Thread(target=resolve, daemon=True).start()
        try:
            addresses = replies.get(timeout=10)
        except queue.Empty:
            raise BackendError('Не удалось определить адрес прокси за 10 секунд. Прямой выход не включался.') from None
        if not addresses:
            raise BackendError('У сервера прокси не найден IPv4. Проверь адрес подключения.')
        server = ipaddress.IPv4Address(addresses[0][4][0])
    if server.is_unspecified or server.is_multicast or server == ipaddress.IPv4Address('255.255.255.255'):
        raise BackendError('Проверь IPv4 и порт прокси-сервера.')
    return str(server)


def profile_to_network(profile, resolve_host=True):
    try:
        clean = validate_profile(profile)
    except ValueError:
        raise BackendError('Проверь адрес, порт и настройки подключения. Для защищённых протоколов проверка сертификата обязательна.') from None
    protocol, host, port = clean['protocol'], clean['host'], clean['port']
    credentials = clean.get('credentials', {})
    if protocol == 'hysteria2' and 'auth' not in credentials:
        raise BackendError('Укажи пароль подключения Hysteria2.')
    if protocol == 'socks5' and any(len(value.encode('utf-8')) > 255 for value in credentials.values()):
        raise BackendError('Логин и пароль SOCKS5 должны содержать не более 255 байт каждый.')
    if protocol != 'socks5' and any(len(value.encode('utf-8')) > 4096 for value in credentials.values()):
        raise BackendError('Пароль или логин подключения слишком длинный. Максимум — 4096 байт.')
    if protocol in ('http', 'https') and ':' in credentials.get('username', ''):
        raise BackendError('Имя пользователя HTTP-прокси не должно содержать двоеточие.')
    if clean.get('obfs') == 'salamander' and len(credentials['obfs_password'].encode('utf-8')) < 4:
        raise BackendError('Пароль маскировки Salamander должен содержать не менее 4 байт.')
    # Resolve only the proxy endpoint on the host, once per launch/probe. Guest DNS stays in the tunnel.
    server = proxy_ipv4(host, port) if resolve_host or host.replace('.', '').isdigit() else host
    proxy = {'type': protocol, 'server': server, 'server_port': port}
    if protocol in ('hysteria2', 'https'):
        proxy['tls_server_name'] = clean.get('tls_server_name', host)
    if protocol == 'hysteria2':
        proxy['password'] = credentials['auth']
        if clean.get('obfs') == 'salamander':
            proxy['obfs_password'] = credentials['obfs_password']
    else:
        proxy.update(credentials)
    return {'listen': '127.0.0.1:0', 'dns_upstream': '1.1.1.1:53', 'proxy': proxy}


def process_identity(pid):
    if type(pid) is not int or not 1 <= pid <= 0xffffffff:
        raise BackendError('Сохранён некорректный идентификатор процесса.')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() in (87, 1168):
            return None
        raise BackendError('Не удалось безопасно проверить процесс. Чужие процессы не изменены.')
    try:
        code = wintypes.DWORD()
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise BackendError('Не удалось проверить состояние процесса.')
        if code.value != 259:
            return None
        times = [wintypes.FILETIME() for unused in range(4)]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in times]):
            raise BackendError('Не удалось проверить время создания процесса.')
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise BackendError('Не удалось проверить путь процесса.')
        return {'pid': pid, 'created': str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime),
                'image': str(Path(buffer.value).resolve())}
    finally:
        kernel.CloseHandle(handle)


def same_identity(expected, actual):
    return bool(isinstance(expected, dict) and isinstance(actual, dict)
                and type(expected.get('pid')) is int and type(actual.get('pid')) is int
                and expected['pid'] == actual['pid']
                and isinstance(expected.get('created'), str) and expected['created'].isdigit()
                and expected.get('created') == actual.get('created')
                and isinstance(expected.get('image'), str) and isinstance(actual.get('image'), str)
                and os.path.normcase(expected['image']) == os.path.normcase(actual['image']))


def read_state(root):
    path = root / 'state/session.json'
    if not path.exists():
        return None
    value = read_json(path)
    try:
        if (not isinstance(value, dict) or type(value['schema']) is not int or value['schema'] != 1
                or uuid.UUID(hex=value['nonce']).hex != value['nonce']
                or value['phase'] not in ('launching', 'starting', 'running', 'stopping', 'stopped',
                                          'failed', 'control-unavailable-guest-running')):
            raise ValueError()
        for key in ('supervisor', 'work', 'network', 'folders'):
            identity = value.get(key)
            if identity is not None and (not isinstance(identity, dict) or set(identity) != {'pid', 'created', 'image'}
                    or type(identity['pid']) is not int or not 1 <= identity['pid'] <= 0xffffffff
                    or not isinstance(identity['created'], str) or not identity['created'].isdigit()
                    or not isinstance(identity['image'], str) or not Path(identity['image']).is_absolute()):
                raise ValueError()
        if value.get('control_port') is not None and (type(value['control_port']) is not int
                                                       or not 1 <= value['control_port'] <= 65535):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise BackendError('Состояние сеанса повреждено. Процессы и диск сохранены; повтори проверку.') from None
    return value


def snapshot(root):
    state = read_state(root)
    result = {'state': state, 'identities': {}, 'work': 'stopped', 'gateway': 'stopped',
              'active': False, 'uncertain': False, 'control_available': False}
    if state is None:
        return result
    expected_images = {'supervisor': root / 'runtime/python-3.12.14/python.exe',
                       'work': root / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe',
                       'network': root / 'PocketNet.exe', 'folders': root / 'runtime/host-files/HostFiles.exe'}
    for key, image in expected_images.items():
        expected = state.get(key)
        kind = 'dead'
        if expected:
            if os.path.normcase(expected['image']) != os.path.normcase(str(image.resolve())):
                kind = 'unknown'
            else:
                try:
                    actual = process_identity(expected['pid'])
                    kind = 'alive' if same_identity(expected, actual) else 'foreign' if actual else 'dead'
                except BackendError:
                    kind = 'unknown'
        result['identities'][key] = kind
    result['uncertain'] = 'unknown' in result['identities'].values()
    live = result['identities']
    launching = (state['phase'] == 'launching' and type(state.get('created_unix')) in (int, float)
                 and 0 <= time.time() - state['created_unix'] < 45)
    result['active'] = result['uncertain'] or 'alive' in live.values() or launching
    if live['work'] == 'alive':
        result['work'] = 'stopping' if state['phase'] == 'stopping' else 'running'
        result['control_available'] = (live['supervisor'] == 'alive' and bool(state.get('control_port'))
                                       and state['phase'] != 'control-unavailable-guest-running')
        if not result['control_available']:
            result['work'] = 'control-unavailable-guest-running'
    elif live['supervisor'] == 'alive' or launching:
        result['work'] = 'stopping' if state['phase'] == 'stopping' else 'starting'
    elif result['uncertain']:
        result['work'] = 'control-unavailable-guest-running'
    if live['network'] == 'alive':
        result['gateway'] = 'running'
    return result


def make_qemu_args(root, settings, address, nonce, qmp_port, helper):
    accel = settings['accel']
    if accel == 'auto':
        from portable_app import host_facts
        accel = 'whpx' if host_facts()['whpx'] else 'tcg'
    argv = helper.build_qemu(root, accel, address, path_fn=helper.qemu_path,
                             memory_mib=settings['work_memory_mib'], vcpus=settings['vcpus'],
                             fullscreen=settings['viewer']['start_fullscreen'],
                             width=settings['windows']['width'], height=settings['windows']['height'])
    argv.extend(['-uuid', str(uuid.UUID(hex=nonce)), '-S', '-qmp', 'tcp:127.0.0.1:' + str(qmp_port)])
    return argv


def volume_persistent_acls(path):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    volume = ctypes.create_unicode_buffer(32768)
    kernel.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    if not kernel.GetVolumePathNameW(str(path), volume, len(volume)):
        raise BackendError('Не удалось проверить защиту файлов на этом диске. Настройки подключения не записаны.')
    flags = wintypes.DWORD()
    kernel.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, wintypes.DWORD]
    if not kernel.GetVolumeInformationW(volume.value, None, 0, None, None, ctypes.byref(flags), None, 0):
        raise BackendError('Не удалось проверить защиту файлов на этом диске. Настройки подключения не записаны.')
    return bool(flags.value & 0x00000008)  # FILE_PERSISTENT_ACLS


def create_private_directory(path, require_acls=True):
    """Create with a protected current-user-only ACL before any secret is written."""
    if require_acls and not volume_persistent_acls(path.parent):
        raise BackendError('Для безопасного прокси нужна папка на NTFS с правами доступа. FAT/exFAT не защищают пароль; конфигурация не записана. Можно запустить Linux без выбранного прокси.')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    token = wintypes.HANDLE()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise BackendError('Не удалось защитить временные настройки подключения.')
    sid_text, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, len(buffer), ctypes.byref(needed)):
            raise BackendError('Не удалось защитить временные настройки подключения.')
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise BackendError('Не удалось защитить временные настройки подключения.')
        sddl = 'D:P(A;OICI;FA;;;' + sid_text.value + ')'
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise BackendError('Не удалось защитить временные настройки подключения.')

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', wintypes.BOOL)]

        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise BackendError('Не удалось создать защищённую папку сеанса.')
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        kernel.CloseHandle(token)


class QMP:
    def __init__(self, connection, nonce):
        self.connection = connection
        connection.settimeout(5)
        self.stream = connection.makefile('rwb')
        self.counter = 0
        try:
            if 'QMP' not in self.read():
                raise BackendError('QEMU не подтвердил управляющий канал.')
            self.execute('qmp_capabilities')
            if self.execute('query-uuid').get('UUID') != str(uuid.UUID(hex=nonce)):
                raise BackendError('Управляющий канал принадлежит другому сеансу; он сохранён.')
        except BaseException:
            self.close()
            raise

    def read(self):
        line = self.stream.readline(65537)
        if not line or len(line) > 65536:
            raise BackendError('Управляющий канал QEMU недоступен.')
        reply = json.loads(line)
        if not isinstance(reply, dict):
            raise BackendError('Некорректный ответ управляющего канала QEMU.')
        return reply

    def execute(self, command):
        self.counter += 1
        request = {'execute': command, 'id': self.counter}
        self.stream.write(json.dumps(request).encode('ascii') + b'\n')
        self.stream.flush()
        for unused in range(100):
            reply = self.read()
            if reply.get('id') == self.counter:
                if 'error' in reply:
                    raise BackendError('QEMU не принял безопасную команду управления.')
                return reply.get('return', {})
        raise BackendError('QEMU не подтвердил команду управления.')

    def close(self):
        self.stream.close()
        self.connection.close()


def decode_control(payload, nonce, token):
    if len(payload) > 4096:
        raise BackendError('Недопустимый запрос управления.')
    try:
        request = json.loads(payload)
        if (not isinstance(request, dict) or set(request) != {'nonce', 'token', 'action'}
                or request['nonce'] != nonce or request['token'] != token
                or request['action'] not in ('stop', 'ping')):
            raise ValueError()
        return request['action']
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise BackendError('Запрос не относится к этому сеансу.') from None


def _listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    return listener


def _receive(connection, limit):
    payload = bytearray()
    while len(payload) <= limit:
        chunk = connection.recv(min(1024, limit + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if b'\n' in chunk:
            break
    if len(payload) > limit:
        raise BackendError('Служебный запрос слишком большой.')
    return bytes(payload)


def send_control(root, action):
    view = snapshot(root)
    state = view['state']
    if not view['control_available'] or not state:
        raise BackendError('Управление Linux не подтверждено. Выключи его через меню рабочего стола.')
    private = root / 'state' / ('session-' + state['nonce'])
    with _pinned_directory(private, create=False):
        protected = read_json(private / 'control.json', 4096).get('protected_token')
        if not isinstance(protected, str):
            raise BackendError('Безопасное управление сеансом не подтверждено.')
        token = _unprotect(protected).get('token')
    if not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
        raise BackendError('Безопасное управление сеансом не подтверждено.')
    with socket.create_connection(('127.0.0.1', state['control_port']), timeout=5) as connection:
        connection.sendall(json.dumps({'nonce': state['nonce'], 'token': token, 'action': action}).encode('ascii') + b'\n')
        reply = json.loads(_receive(connection, 4096))
    if not isinstance(reply, dict) or reply.get('nonce') != state['nonce'] or type(reply.get('ok')) is not bool:
        raise BackendError('Ответ управления не подтверждён. Linux не останавливался принудительно.')
    if not reply['ok']:
        raise BackendError('Не удалось отправить штатное выключение. Выключи Linux через его меню.')
    return reply


def start_session(root, settings):
    view = snapshot(root)
    if view['active']:
        raise BackendError('Linux уже работает или его состояние требует проверки.')
    if view['state'] and view['state']['phase'] != 'stopped':
        raise BackendError('Сначала восстанови завершившийся сеанс; диск и процессы сохранены.')
    from host_folders import normalize_folders
    normalize_folders(root, settings['files'])
    selected = ProfileStore(root / 'profiles').selected_summary()
    if selected:
        profile_to_network(ProfileStore(root / 'profiles').secret_config(selected['profile_id'], selected['revision_id']), resolve_host=False)
    nonce = uuid.uuid4().hex
    state = {'schema': 1, 'nonce': nonce, 'phase': 'launching', 'supervisor': None,
             'work': None, 'network': None, 'folders': None, 'control_port': None,
             'created_unix': time.time(),
             'profile_id': selected['profile_id'] if selected else None,
             'profile_revision_id': selected['revision_id'] if selected else None,
             'message': 'Запускается Linux.'}
    write_json(root / 'state/session.json', state)
    subprocess.Popen([sys.executable, '-X', 'utf8', '-I', '-S', '-B', str(root / 'scripts/runtime_supervisor.py'),
                      '--root', str(root), '--nonce', nonce], cwd=root, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
                     close_fds=True)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        current = read_state(root)
        if current is None or current['nonce'] != nonce:
            raise BackendError('Сеанс изменился; повтори проверку состояния.')
        if current['phase'] == 'running':
            live = snapshot(root)
            if live['identities'].get('work') == 'alive' and live['control_available']:
                return {'ok': True, 'started': True, 'pending': True,
                        'message': 'QEMU запущен; Linux загружается. Интернет отключён.' if not selected else
                                   'Linux загружается с выбранным подключением. Интернет ещё не проверен.'}
        if current['phase'] == 'failed':
            raise BackendError(current.get('message', 'Linux не запущен; повтори проверку.'))
        time.sleep(0.1)
    return {'ok': False, 'code': 'outcome_unknown', 'outcome_unknown': True, 'pending': True,
            'message': 'Запуск ещё не подтверждён. Не повторяй его до проверки состояния; процессы сохранены.'}


def stop_session(root):
    view = snapshot(root)
    if not view['active']:
        return {'ok': True, 'message': 'Linux уже выключен.'}
    send_control(root, 'stop')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        view = snapshot(root)
        if not view['active'] and view['work'] == 'stopped':
            return {'ok': True, 'message': 'Linux штатно выключен.'}
        time.sleep(0.25)
    return {'ok': False, 'pending': True, 'code': 'shutdown_unconfirmed',
            'message': 'Штатное выключение отправлено, но ещё не завершено. Linux не останавливался принудительно.'}


def recover_session(root):
    view = snapshot(root)
    if view['state'] is None:
        return {'ok': True, 'message': 'Незавершённого сеанса нет.'}
    if view['uncertain'] or 'alive' in view['identities'].values():
        raise BackendError('Процессы ещё работают или не опознаны. Выключи Linux штатно; незнакомые PID не изменены.')
    helper = helper_module(root)
    with helper.disk_lock(root / 'state/linux.lock'):
        latest = snapshot(root)
        if latest['uncertain'] or 'alive' in latest['identities'].values():
            raise BackendError('Состояние изменилось. Процессы сохранены; повтори проверку.')
        state = latest['state']
        private = root / 'state' / ('session-' + state['nonce'])
        for name in ('proxy.json', 'control.json', 'clipboard.json', 'status.json'):
            secret = private / name
            if secret.exists():
                _plain(private)
                _plain(secret)
                secret.unlink()
        state.update(phase='stopped', supervisor=None, work=None, network=None, control_port=None,
                     message='Завершившийся сеанс закрыт; диск и профили сохранены.')
        write_json(root / 'state/session.json', state)
    return {'ok': True, 'message': state['message']}


def supervise(root, nonce):
    helper = helper_module(root)
    network = vm = qmp = qmp_listener = control = folders = clipboard = branding = guest = None
    resumed = False
    state = read_state(root)
    if state is None or state['nonce'] != nonce or state['phase'] != 'launching':
        raise BackendError('Запрос запуска устарел; Linux не запущен.')
    secret = root / 'state' / ('session-' + nonce) / 'proxy.json'
    _plain(root / 'state/linux.lock')
    with helper.disk_lock(root / 'state/linux.lock'):
        latest = read_state(root)
        if latest is None or latest['nonce'] != nonce or latest['phase'] != 'launching':
            raise BackendError('Запрос запуска устарел; Linux не запущен.')
        try:
            from portable_app import load_settings
            settings = load_settings(root)
            state.update(phase='starting', supervisor=process_identity(os.getpid()))
            write_json(root / 'state/session.json', state)
            create_private_directory(secret.parent, require_acls=True)
            control_token = os.urandom(32).hex()
            write_json(secret.parent / 'control.json', {'protected_token': _protect({'token': control_token})})
            address = None
            if state.get('profile_id'):
                profile = ProfileStore(root / 'profiles').secret_config(state['profile_id'], state['profile_revision_id'])
                config = profile_to_network(profile)
                write_json(secret, config)
                # start_network never receives credentials; it reads this protected session file.
                import queue
                import threading
                network = subprocess.Popen([str(root / 'PocketNet.exe'), '--config', str(secret)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, text=True, encoding='utf-8',
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                state['network'] = process_identity(network.pid)
                write_json(root / 'state/session.json', state)
                ready = queue.Queue(maxsize=1)
                threading.Thread(target=lambda: ready.put(network.stdout.readline(8193)), daemon=True).start()
                try:
                    address = helper.ready_address(ready.get(timeout=10))
                except (queue.Empty, ValueError):
                    raise BackendError('Прокси-процесс не готов. Linux не запущен, прямой выход запрещён.') from None
                if network.poll() is not None:
                    raise BackendError('Прокси-процесс завершился. Linux не запущен, прямой выход запрещён.')
                secret.unlink()  # PocketNet has parsed READY; plaintext credentials no longer need a file.
            if settings['files']['mode'] != 'off':
                import host_folders
                folders = host_folders.start(root, settings['files'], secret.parent, helper.qemu_path)
                state['folders'] = process_identity(folders.process.pid)
                write_json(root / 'state/session.json', state)
            qmp_listener, control = _listener(), _listener()
            qmp_listener.settimeout(30)
            control.settimeout(0.25)
            argv = make_qemu_args(root, settings, address, nonce, qmp_listener.getsockname()[1], helper)
            if folders is not None:
                argv.extend(folders.qemu_args)
            import guest_status
            status_nonce = os.urandom(16).hex()
            guest = guest_status.Channel(status_nonce, folders.session_nonce if folders else None,
                                        [item['name'] for item in folders.shares] if folders else [])
            serial_index = argv.index('-serial')
            del argv[serial_index:serial_index + 2]
            argv.extend(guest.qemu_args)
            status_path = secret.parent / 'status.json'
            write_json(status_path, {'schema': 1, 'session_nonce': status_nonce, 'network': address is not None})
            argv.extend(['-fw_cfg', 'name=opt/pocket/status,file=' + helper.qemu_path(status_path).replace(',', ',,')])
            clipboard_path = secret.parent / 'clipboard.json'
            if settings['viewer']['share_clipboard']:
                import clipboard_bridge
                port = clipboard_bridge.reserve_port()
                clipboard_nonce = os.urandom(16).hex()
                clipboard_path.write_bytes(clipboard_bridge.configuration(clipboard_nonce))
                argv.extend(clipboard_bridge.arguments(port))
                argv.extend(['-fw_cfg', 'name=opt/pocket/clipboard,file=' + helper.qemu_path(clipboard_path).replace(',', ',,')])
                clipboard = clipboard_bridge.Bridge(port, clipboard_nonce, clipboard_bridge.WindowsClipboard())
            _plain(root / 'state/qemu-stderr.log')
            with (root / 'state/qemu-stderr.log').open('w', encoding='utf-8') as stderr:
                vm = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
                state['work'] = process_identity(vm.pid)
                write_json(root / 'state/session.json', state)
                connection, unused = qmp_listener.accept()
                qmp = QMP(connection, nonce)
                if folders is not None:
                    folders.config_path.unlink()  # QEMU has loaded fw_cfg into memory before its greeting.
                status_path.unlink()
                clipboard_path.unlink(missing_ok=True)
                qmp_listener.close()
                qmp_listener = None
                from linux_window import WindowBranding
                branding = WindowBranding(root, vm.pid, expected_identity=state['work'])
                branding.apply()
                if clipboard is not None:
                    clipboard.start()
                resumed = True  # A lost reply to cont must never trigger forced termination of a running guest.
                qmp.execute('cont')
                if qmp.execute('query-status').get('status') != 'running':
                    raise BackendError('QEMU не подтвердил запуск Linux.')
                state.update(phase='running', control_port=control.getsockname()[1],
                             message='Linux запущен; интернет ещё не проверен.' if address else 'Linux запущен без интернета.')
                write_json(root / 'state/session.json', state)
                while vm.poll() is None:
                    branding.apply()
                    guest.poll()
                    observed = guest.snapshot()
                    for receipt in ('status', 'files'):
                        if isinstance(observed.get(receipt), dict):
                            observed[receipt].pop('session_nonce', None)
                    clip_state = 'ready' if clipboard and clipboard.authenticated.is_set() else 'pending' if clipboard else 'off'
                    if state.get('guest_status') != observed or state.get('clipboard_status') != clip_state:
                        state.update(guest_status=observed, clipboard_status=clip_state)
                        write_json(root / 'state/session.json', state)
                    try:
                        connection, unused = control.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(3)
                        reply = {'ok': False}
                        try:
                            action = decode_control(_receive(connection, 4096), nonce, control_token)
                            reply['nonce'] = nonce
                            if action == 'stop':
                                qmp.execute('system_powerdown')
                                state.update(phase='stopping', message='Ожидается штатное выключение Linux.')
                                write_json(root / 'state/session.json', state)
                            reply['ok'] = True
                        except (OSError, ValueError, KeyError):
                            pass
                        try:
                            connection.sendall(json.dumps(reply).encode('ascii') + b'\n')
                        except OSError:
                            pass
            state.update(phase='stopped' if vm.returncode == 0 else 'failed',
                         message='Linux выключен.' if vm.returncode == 0 else 'QEMU завершился с ошибкой. Проверь state/qemu-stderr.log.')
        except BaseException as error:
            if vm is not None and vm.poll() is None and resumed:
                state.update(phase='control-unavailable-guest-running', control_port=None,
                             message='Linux работает без управления. Выключи его через меню рабочего стола; принудительная остановка запрещена.')
                write_json(root / 'state/session.json', state)
                vm.wait()
                state.update(phase='failed', message='Сеанс завершён после ошибки управления. Диск сохранён.')
            else:
                if vm is not None and vm.poll() is None:
                    helper.stop_owned(vm)  # vCPUs are still held by -S; no running guest is terminated.
                state.update(phase='failed', message=str(error) if isinstance(error, BackendError) else
                             'Linux не запущен. Проверь состав комплекта, настройки и state/qemu-stderr.log.')
        finally:
            for listener in (qmp_listener, control):
                if listener is not None:
                    listener.close()
            if qmp is not None:
                qmp.close()
            if clipboard is not None:
                clipboard.stop()
            if guest is not None:
                guest.close()
            if branding is not None:
                branding.close()
            helper.stop_owned(network)
            if folders is not None:
                folders.close()
            if network is not None and network.stdout:
                network.stdout.close()
            if secret.exists():
                secret.unlink()
            for name in ('control.json', 'clipboard.json', 'status.json'):
                path = secret.parent / name
                if path.exists():
                    path.unlink()
            state.update(control_port=None)
            write_json(root / 'state/session.json', state)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--nonce', required=True)
    args = parser.parse_args()
    if uuid.UUID(hex=args.nonce).hex != args.nonce:
        return 1
    try:
        supervise(args.root.resolve(strict=True), args.nonce)
        return 0
    except (OSError, ValueError, RuntimeError):
        return 1


if __name__ == '__main__':
    sys.modules['runtime_supervisor'] = sys.modules[__name__]
    sys.exit(main())
