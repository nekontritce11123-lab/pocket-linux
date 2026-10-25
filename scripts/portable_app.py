"""Small JSON backend for the shared launcher and the portable Linux edition."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_supervisor as runtime
from runtime_supervisor import BackendError
from connection_profile import import_profile_uri
from profile_store import ProfileStore, StoreBusy, StoreError, SecretsUnavailable, _plain

DEFAULTS = {'schema': 1, 'work_memory_mib': 2048, 'vcpus': 2, 'accel': 'auto',
            'windows': {'schema': 1, 'width': 1280, 'height': 800, 'fit': False},
            'viewer': {'schema': 1, 'start_fullscreen': False, 'remember_window': False, 'share_clipboard': True},
            'files': {'schema': 1, 'mode': 'off', 'folders': []}}
PROFILE_ACTIONS = {'list-profiles': set(), 'get-profile-view': {'profile_id'},
                   'save-profile': {'profile_id', 'profile'}, 'select-profile': {'profile_id'},
                   'import-profile': {'uri', 'profile'},
                   'export-profile': {'profile_id', 'destination', 'include_secrets'}}


def read_request(stream=None, allow_empty=False):
    body = (stream or sys.stdin.buffer).read(65537)
    if len(body) > 65536:
        raise BackendError('Запрос слишком большой. Максимальный размер 64 КиБ.')
    if not body and allow_empty:
        return {}

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError()

    try:
        value = json.loads(body, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise BackendError('Некорректный JSON-запрос.') from None
    if not isinstance(value, dict):
        raise BackendError('Запрос должен быть объектом JSON.')
    return value


def validate_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise BackendError('Неизвестные настройки. Профили и пароли сохраняются отдельно.')
    result = copy.deepcopy(DEFAULTS)
    for key, item in value.items():
        if key in ('windows', 'viewer', 'files'):
            if not isinstance(item, dict) or set(item) - set(DEFAULTS[key]):
                raise BackendError('Некорректные настройки окна или папок.')
            result[key].update(item)
        else:
            result[key] = item
    for group in (result, result['windows'], result['viewer'], result['files']):
        if type(group['schema']) is not int or group['schema'] != 1:
            raise BackendError('Неподдерживаемая версия настроек.')
    for name, low, high in (('work_memory_mib', 1024, 32768), ('vcpus', 1, 32)):
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise BackendError('Память должна быть от 1024 до 32768 МиБ, процессоры — от 1 до 32.')
    if result['accel'] not in ('auto', 'tcg', 'whpx'):
        raise BackendError('Допустимы только TCG или уже включённый WHPX; установка компонентов запрещена.')
    display, viewer, files = (result[key] for key in ('windows', 'viewer', 'files'))
    for name, low, high in (('width', 640, 3840), ('height', 480, 2160)):
        if type(display[name]) is not int or not low <= display[name] <= high:
            raise BackendError('Разрешение должно быть от 640×480 до 3840×2160.')
    if display['fit'] is not False:
        raise BackendError('Автоматический подбор разрешения пока недоступен. Выбери явное разрешение.')
    if any(type(viewer[key]) is not bool for key in ('start_fullscreen', 'remember_window', 'share_clipboard')):
        raise BackendError('Режим окна и буфер обмена должны быть логическими значениями.')
    # Windows stores remember_window but never uses it; preserve that compatibility flag.
    if (files['mode'] not in ('off', 'all', 'selected') or not isinstance(files['folders'], list)
            or len(files['folders']) > 64 or any(not isinstance(path, str) for path in files['folders'])
            or files['mode'] == 'selected' and not files['folders']):
        raise BackendError('Выбери до 64 папок Windows, все диски или выключи доступ к файлам.')
    return result


def load_settings(root):
    path = root / 'config/linux.json'
    return validate_settings(runtime.read_json(path) if path.exists() else {})


def host_facts():
    result = {'windows': os.name == 'nt', 'x64': sys.maxsize > 2**32,
              'logical_processors': os.cpu_count() or 1, 'ram_total_mib': 0,
              'ram_available_mib': 0, 'admin': False, 'whpx': False}
    if os.name != 'nt':
        return result

    class MemoryStatus(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('load', wintypes.DWORD),
                    *[(key, ctypes.c_ulonglong) for key in ('total', 'available', 'page_total',
                        'page_available', 'virtual_total', 'virtual_available', 'extended_available')]]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
    if kernel.GlobalMemoryStatusEx(ctypes.byref(status)):
        result.update(ram_total_mib=status.total // 1048576, ram_available_mib=status.available // 1048576)
    try:
        whp = ctypes.WinDLL('WinHvPlatform.dll')
        present, written = wintypes.BOOL(), wintypes.DWORD()
        whp.WHvGetCapability.argtypes = [ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
        result['whpx'] = whp.WHvGetCapability(0, ctypes.byref(present), ctypes.sizeof(present),
                                             ctypes.byref(written)) == 0 and bool(present.value)
    except OSError:
        pass
    return result


def settings_reply(root, host=None):
    value = load_settings(root)
    return {'ok': True, 'settings': {key: value[key] for key in ('schema', 'work_memory_mib', 'vcpus', 'accel')},
            'windows_settings': value['windows'], 'viewer_settings': value['viewer'],
            'file_settings': value['files'], 'host': host if host is not None else host_facts()}


def save_settings(root, request):
    with runtime.operation_lock(root):
        if runtime.snapshot(root)['active']:
            raise BackendError('Настройки нельзя менять во время работы или запуска Linux. Сначала выключи его.')
        current = load_settings(root)
        merged = dict(current)
        if not isinstance(request, dict):
            raise BackendError('Некорректные настройки.')
        for key, value in request.items():
            merged[key] = current[key] | value if key in ('windows', 'viewer', 'files') and isinstance(value, dict) else value
        value = validate_settings(merged)
        from host_folders import normalize_folders
        value['files'] = normalize_folders(root, value['files'])
        runtime.write_json(root / 'config/linux.json', value)
    return settings_reply(root) | {'message': 'Настройки сохранены для следующего запуска Linux.'}


def profile_action(root, action, request):
    if not isinstance(request, dict) or set(request) - PROFILE_ACTIONS[action]:
        raise ValueError('Unsupported request fields')
    store = ProfileStore(root / 'profiles')

    def public(view):
        return view | {'state': 'pending' if view['selected'] else 'saved',
                       'applied_revision_id': None, 'verified': False,
                       'capabilities': {'tcp': True, 'udp': view['udp_supported']}}

    result = {'ok': True, 'schema': 1, 'code': 'saved'}
    if action == 'list-profiles':
        return result | {'profiles': [public(item) for item in store.list_profiles()],
                         'message': 'Подключения загружены.'}
    if action == 'get-profile-view':
        view = store.get_view(request['profile_id'])
        message = 'Настройки подключения загружены. Пароль не отображается.'
    elif action == 'save-profile':
        view = store.save(request['profile'], profile_id=request.get('profile_id'))
        message = 'Подключение сохранено. Работающий сеанс не изменён.'
    elif action == 'select-profile':
        view = store.select(request['profile_id'])
        message = 'Подключение выбрано для следующего запуска.'
    elif action == 'import-profile':
        if ('uri' in request) == ('profile' in request):
            raise ValueError('Supply one connection link or exported profile')
        profile = import_profile_uri(request['uri']) if 'uri' in request else request['profile']
        view = store.save(profile)
        message = 'Подключение импортировано. Выбери его для следующего запуска.'
    elif action == 'export-profile':
        exported = store.export_to(request['profile_id'], request['destination'],
                                   include_secrets=request.get('include_secrets', False))
        return result | {'exported': exported, 'message': 'Подключение экспортировано.'}
    return result | {'profile': public(view), 'message': message}


def profile_error(error):
    if isinstance(error, BackendError):
        return str(error)
    if isinstance(error, StoreBusy):
        return 'Сейчас выполняется другое действие с подключениями. Повтори после его завершения.'
    if isinstance(error, SecretsUnavailable):
        return 'Пароль недоступен для этого пользователя Windows. Введи его заново в настройках подключения.'
    if isinstance(error, StoreError):
        return 'Не удалось открыть или сохранить подключения. Существующие данные сохранены.'
    messages = {'Port must be an integer between 1 and 65535': 'Порт должен быть числом от 1 до 65535.',
                'IPv6 endpoints are not supported in this version': 'В этой версии укажи адрес IPv4 или имя сервера.',
                'Invalid server name': 'Проверь имя сервера. Вводи адрес без протокола и пути.',
                'Invalid IPv4 address': 'Проверь адрес IPv4.',
                'Unsupported connection protocol': 'Выбери Hysteria2, SOCKS5, HTTP или HTTPS CONNECT.',
                'Enter credentials again when changing protocol or obfuscation': 'При смене протокола или маскировки введи пароль заново.'}
    return messages.get(str(error), 'Проверь поля подключения или формат импорта. Некорректные данные не сохранены.')


def image_ready(root):
    try:
        path = root / 'linux.qcow2'
        _plain(path)
        with path.open('rb') as stream:
            header = stream.read(20)
        magic, version, backing, backing_size = struct.unpack('>IIQI', header)
        return magic == 0x514649fb and version in (2, 3) and backing == 0 and backing_size == 0
    except (OSError, ValueError, struct.error):
        return False


def report(root, full=False):
    host = host_facts()
    checks = {}

    def check(name, passed, title, detail, action='retry', label='Проверить снова'):
        checks[name] = {'passed': bool(passed), 'title': title, 'detail': detail,
                        'action': action, 'action_label': label}

    try:
        settings = settings_reply(root, host)
        value = load_settings(root)
        check('settings', True, 'Настройки Linux', 'Настройки прочитаны.')
    except (OSError, ValueError):
        value = copy.deepcopy(DEFAULTS)
        settings = {'settings': {key: value[key] for key in ('schema', 'work_memory_mib', 'vcpus', 'accel')},
                    'windows_settings': value['windows'], 'viewer_settings': value['viewer'], 'file_settings': value['files']}
        check('settings', False, 'Нужно проверить настройки Linux', 'Исходный файл настроек сохранён.', 'settings', 'Открыть настройки')
    try:
        view = runtime.snapshot(root)
        valid_state = not view['uncertain'] and view['work'] != 'control-unavailable-guest-running'
        if view['state'] and (view['state']['phase'] == 'failed'
                              or view['work'] == 'stopped' and view['state']['phase'] != 'stopped'):
            valid_state = False
        orphaned = (view.get('identities', {}).get('work') == 'dead'
                    and view.get('identities', {}).get('supervisor') == 'dead'
                    and 'alive' in view.get('identities', {}).values())
        check('runtime_state', valid_state and not orphaned, 'Состояние Linux',
              'Linux завершён, но владелец помощников потерян. Они сохранены; перезапусти Windows и восстанови сеанс.' if orphaned else
              'Сеанс опознан.' if valid_state else 'Выключи Linux через меню или восстанови завершившийся сеанс.',
              'recover_session', 'Восстановить сеанс')
    except (OSError, ValueError):
        view = {'state': None, 'active': True, 'uncertain': True, 'work': 'control-unavailable-guest-running',
                'gateway': 'stopped', 'control_available': False, 'identities': {}}
        check('runtime_state', False, 'Состояние Linux не подтверждено', 'Процессы не изменялись.', 'recover_session', 'Восстановить сеанс')
    required = ('runtime/python-3.12.14/python.exe', 'runtime/qemu-11.1.0/qemu-system-x86_64.exe',
                'scripts/runtime_supervisor.py', 'scripts/profile_store.py', 'scripts/connection_profile.py', 'start.py')
    check('runtime_files', all((root / name).is_file() for name in required), 'Переносимые компоненты',
          'Для этой редакции нужен полный распакованный комплект; установка в Windows не используется.')
    check('guest_files', image_ready(root), 'Диск Debian', 'Нужен самостоятельный linux.qcow2 без внешнего базового диска.')
    check('gateway_package', (root / 'PocketNet.exe').is_file(), 'Сетевой процесс Windows',
          'PocketNet используется только для выбранного прокси; прямого запасного пути нет.')
    folders_ok = True
    if value['files']['mode'] != 'off':
        try:
            from host_folders import normalize_folders
            normalize_folders(root, value['files'])
            if not (root / 'runtime/host-files/HostFiles.exe').is_file():
                raise BackendError('Не найден переносимый сервер папок. Распакуй полный комплект.')
            detail = 'Выбранные папки будут доступны в Linux; изменения сохраняются в исходных файлах.'
        except (OSError, ValueError) as error:
            folders_ok = False
            detail = str(error) if isinstance(error, BackendError) else 'Проверь выбранные папки Windows.'
        check('host_files', folders_ok, 'Папки Windows', detail, 'settings', 'Выбрать папки')
    check('windows_x64', host['windows'] and host['x64'], 'Windows x64', 'Виртуализация выполняется переносимым QEMU.')
    check('memory', view['active'] or host['ram_available_mib'] >= value['work_memory_mib'] + 512,
          'Оперативная память', 'Linux выделяется ' + str(value['work_memory_mib']) + ' МиБ.', 'settings', 'Настроить память')
    check('acceleration', value['accel'] in ('auto', 'tcg') or host['whpx'], 'Режим виртуализации',
          'TCG не требует установки компонентов; WHPX используется только если уже доступен.', 'settings', 'Открыть настройки')
    selected, supported = None, False
    try:
        store = ProfileStore(root / 'profiles')
        selected = store.selected_summary()
        if selected:
            runtime.profile_to_network(store.secret_config(selected['profile_id'], selected['revision_id']), resolve_host=False)
            supported = True
        check('connection', True, 'Подключение Linux', 'Прокси выбран; интернет сеанса ещё не проверен.' if selected else
              'Профиль не выбран: Linux запустится без интернета.', 'connection', 'Настроить подключение')
    except (OSError, ValueError) as error:
        check('connection', False, 'Нужно проверить подключение', profile_error(error), 'connection', 'Настроить подключение')
    blockers = [dict(item, code=name) for name, item in checks.items() if not item['passed']]
    running = view['work'] == 'running'
    applied_id = view['state'].get('profile_id') if view['state'] else None
    applied_revision = view['state'].get('profile_revision_id') if view['state'] else None
    selected_applied = bool(view['active'] and selected and selected['profile_id'] == applied_id
                            and selected.get('revision_id') == applied_revision)
    guest = (view.get('state') or {}).get('guest_status') or {}
    received = guest.get('received_at')
    fresh = type(received) in (int, float) and 0 <= time.time() - received <= 60
    status = guest.get('status') if fresh and running else None
    status = status if isinstance(status, dict) else {}
    verified = bool(applied_id and view['gateway'] == 'running' and status.get('network') == 'ready'
                    and status.get('dns') is True and status.get('https') is True)
    files_receipt = guest.get('files') if running else None
    files_state = ('off' if value['files']['mode'] == 'off' else 'unavailable' if not folders_ok else
                   files_receipt['status'] if isinstance(files_receipt, dict)
                   and view.get('identities', {}).get('folders') == 'alive' else 'pending' if running else 'configured')
    display_state = {'status': 'unconfirmed' if running else 'not_running'}
    if status.get('width') and status.get('height'):
        requested = value['windows']
        display_state.update(status='ready' if (status['width'], status['height']) == (requested['width'], requested['height']) else 'failed',
                             width=status['width'], height=status['height'],
                             requested_width=requested['width'], requested_height=requested['height'])
    warning = ('Linux запущен без интернета. Выбранное подключение применится после перезапуска.'
               if not applied_id else 'Текущий сеанс использует подключение, выбранное при запуске. Доступность сайтов ещё не проверена.')
    if verified:
        warning = ''
    elif applied_id and running and (status.get('network') == 'failed' or view['gateway'] != 'running'):
        warning = 'Подключение недоступно. Прямой выход в интернет заблокирован.'
    force_offer = runtime.force_stop_offer(root, view)
    identities = view.get('identities', {})
    recoverable = bool(view['state'] and (view['state']['phase'] != 'stopped' or view['active'])
                       and not checks['runtime_state']['passed']
                       and not view['uncertain'] and not {'foreign', 'unknown'}.intersection(identities.values())
                       and (not view['active'] or identities.get('work') == 'dead' and identities.get('supervisor') == 'alive'))
    return {**settings, 'ok': not blockers, 'schema': 1, 'root': str(root), 'host': host,
            'message': blockers[0]['title'] if blockers else 'Linux работает.' if running else 'Всё готово к запуску Linux.',
            'report_kind': 'preflight' if full else 'runtime_status', 'checks': checks, 'blockers': blockers,
            'checked_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'already_running': bool(view['active']),
            'runtime': {'work': view['work'], 'gateway': view['gateway'], 'control_available': view['control_available']},
            'network_verified': verified, 'network_acceptance_scope': 'guest_dns_https' if verified else 'unverified', 'network_warning': warning,
            'connection': {'selected_profile': selected, 'verified': verified,
                           'selected_applied': selected_applied,
                           'applied_profile_id': applied_id, 'applied_revision_id': applied_revision},
            'force_stop_session': force_offer,
            'capabilities': {'stop': bool(view['control_available']), 'force_stop': force_offer is not None,
                             'test_profile': supported and not view['active'],
                             'recover_session': recoverable,
                             'prepare_host': False},
            'gateway_version': 'PocketNet', 'host_files': {'status': files_state},
            'windows_display': display_state,
            'clipboard': {'status': (view.get('state') or {}).get('clipboard_status', 'off') if running else 'off'},
            'startup': {'phase': view['work']}, 'secret_values_exposed': False, 'network_requests_made': False}


def test_profile(root, request):
    if set(request) - {'profile_id'}:
        raise BackendError('Некорректный запрос проверки подключения.')
    store = ProfileStore(root / 'profiles')
    selected = store.selected_summary()
    identifier = request.get('profile_id') or (selected['profile_id'] if selected else None)
    if not identifier:
        raise BackendError('Сначала выбери подключение для проверки.')
    profile = store.secret_config(identifier)
    config = runtime.profile_to_network(profile)
    folder = root / 'state' / ('probe-' + uuid.uuid4().hex)
    secret = folder / 'proxy.json'
    with runtime._pinned_directory(root / 'state'):
        runtime.create_private_directory(folder)
    try:
        runtime.write_json(secret, config)
        result = subprocess.run([str(root / 'PocketNet.exe'), '--config', str(secret), '--probe'],
                                capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or len(result.stdout) > 4096:
            raise BackendError('Прокси не подтвердил защищённое соединение.')
        receipt = json.loads(result.stdout)
        if not isinstance(receipt, dict) or receipt.get('ok') is not True or receipt.get('protocol') != profile['protocol']:
            raise BackendError('Прокси не подтвердил защищённое соединение.')
        return {'ok': True, 'verified': True, 'scope': 'proxy_tcp_tls',
                'message': 'Прокси передал проверочное защищённое соединение. Сеть самого Linux ещё не проверена.'}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'ok': False, 'verified': False, 'code': 'proxy_check_failed',
                'message': 'Проверка через прокси не прошла. Прямое соединение не использовалось.'}
    finally:
        secret.unlink(missing_ok=True)
        folder.rmdir()


def show_desktop(root):
    view = runtime.snapshot(root)
    if view['identities'].get('work') != 'alive':
        raise BackendError('Работающий Linux не найден. Обнови состояние панели.')
    identity = view['state']['work']
    user = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.ShowWindowAsync.argtypes = [wintypes.HWND, ctypes.c_int]
    user.SetForegroundWindow.argtypes = [wintypes.HWND]
    windows = []

    @callback_type
    def inspect(window, unused):
        pid = wintypes.DWORD()
        user.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value == identity['pid'] and user.IsWindowVisible(window):
            windows.append(window)
        return True

    user.EnumWindows(inspect, 0)
    if not windows or not runtime.same_identity(identity, runtime.process_identity(identity['pid'])):
        raise BackendError('Окно Linux ещё не появилось. Повтори через несколько секунд.')
    user.ShowWindowAsync(windows[0], 9)
    foreground = bool(user.SetForegroundWindow(windows[0]))
    return {'ok': True, 'message': 'Рабочий стол Linux открыт.' if foreground else
            'Окно Linux восстановлено. Выбери его на панели задач.'}


def dispatch(root, action, request):
    if action in PROFILE_ACTIONS:
        return profile_action(root, action, request)
    if action == 'save-settings':
        return save_settings(root, request)
    if action == 'test-profile':
        return test_profile(root, request)
    if action == 'force-stop':
        with runtime.operation_lock(root):
            result = runtime.force_stop_session(root, request)
        return report(root) | result
    if request:
        raise BackendError('Это действие не принимает дополнительных полей.')
    if action in ('diagnose', 'status'):
        return report(root, full=action == 'diagnose')
    if action == 'get-settings':
        return settings_reply(root)
    if action == 'show-desktop':
        return show_desktop(root)
    if action in ('prepare-host', 'prepare-components', 'repair-gateway'):
        raise BackendError('Эта редакция полностью переносимая. Установка и изменение компонентов Windows не выполняются; распакуй полный комплект.')
    if action in ('start', 'stop', 'recover-session'):
        with runtime.operation_lock(root):
            if action == 'start':
                checked = report(root, full=True)
                if not checked['ok']:
                    return checked
                result = runtime.start_session(root, load_settings(root))
            elif action == 'stop':
                result = runtime.stop_session(root)
            else:
                result = runtime.recover_session(root)
        return report(root) | result
    raise BackendError('Неизвестное действие Linux-бэкенда.')


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise BackendError('Некорректные параметры служебного запроса.')


def main():
    action = None
    try:
        parser = JsonArgumentParser(add_help=False)
        parser.add_argument('--root', type=Path, required=True)
        parser.add_argument('--action', required=True)
        args = parser.parse_args()
        action = args.action
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise BackendError('Папка программы не найдена.')
        _plain(root)
        result = dispatch(root, action, read_request(allow_empty=True))
    except BackendError as error:
        result = {'ok': False, 'message': str(error)}
    except (StoreError, ValueError, TypeError, KeyError) as error:
        result = {'ok': False, 'message': profile_error(error) if action in PROFILE_ACTIONS or action == 'test-profile'
                  else 'Некорректные служебные данные. Диск и настройки сохранены.'}
    except (OSError, RuntimeError):
        result = {'ok': False, 'message': 'Служебный компонент недоступен. Проверь папку комплекта; установки в Windows не выполнялись.'}
    result.setdefault('schema', 1)
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
