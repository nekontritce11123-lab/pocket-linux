"""Atomic profile metadata with Windows CurrentUser DPAPI credentials."""
import base64
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import stat
import uuid

from connection_profile import validate_profile

MAX_STORE_BYTES = 8 * 1024 * 1024


class StoreError(ValueError):
    pass


class StoreBusy(StoreError):
    pass


class SecretsUnavailable(StoreError):
    pass


def _winapi():
    if os.name != 'nt':
        raise StoreError('Profile storage requires Windows')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.WriteFile.restype = wintypes.BOOL
    kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 wintypes.LPVOID, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    return kernel


def _plain(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise StoreError('Profile path cannot contain links or reparse points')
    if not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
        raise StoreError('Profile files cannot be hard links')


@contextmanager
def _exclusive_file(path, create=True):
    kernel = _winapi()
    _plain(path)
    handle = kernel.CreateFileW(str(path), 0xC0000000 if create else 0x80000000,
                                0, None, 4 if create else 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        if ctypes.get_last_error() in (32, 33):
            raise StoreBusy('Another profile operation is running')
        raise StoreError('Cannot access profile operation lock')
    try:
        _plain(path)
        yield handle
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def _pinned_directory(directory, create=True):
    """Deny directory deletion/rename while traversing and writing the store."""
    kernel = _winapi()
    with ExitStack() as stack:
        for current in [*reversed(directory.parents), directory]:
            _plain(current)
            if not current.exists():
                if current != directory or not create:
                    raise StoreError('Profile parent directory must already exist')
                current.mkdir()
            handle = kernel.CreateFileW(str(current), 0x80, 3, None, 3, 0x02200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise StoreError('Cannot access profile directory')
            stack.callback(kernel.CloseHandle, handle)
            _plain(current)
            if not current.is_dir():
                raise StoreError('Profile path is not a directory')
        yield


class _Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(data, decrypt=False):
    kernel = _winapi()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = _Blob(len(data), source_buffer)
    output = _Blob()
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise SecretsUnavailable('Credentials are unavailable for this Windows user; enter them again')
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        if output.data:
            ctypes.memset(output.data, 0, output.size)
            kernel.LocalFree(output.data)


def _protect(credentials):
    return base64.b64encode(_dpapi(json.dumps(credentials, ensure_ascii=False).encode('utf-8'))).decode('ascii')


def _unprotect(blob):
    try:
        value = json.loads(_dpapi(base64.b64decode(blob, validate=True), decrypt=True).decode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise SecretsUnavailable('Credentials are unavailable for this Windows user; enter them again') from None


def _identifier(value):
    if not isinstance(value, str) or len(value) != 32:
        raise ValueError('Invalid profile or revision identifier')
    try:
        if uuid.UUID(hex=value).hex != value:
            raise ValueError()
    except ValueError:
        raise ValueError('Invalid profile or revision identifier') from None
    return value


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate profile storage field')
        result[key] = value
    return result


class ProfileStore:
    def __init__(self, directory):
        directory = Path(directory).absolute()
        if '..' in directory.parts:
            raise StoreError('Profile directory cannot contain parent traversal')
        self.directory = directory

    @contextmanager
    def _transaction(self):
        try:
            with _pinned_directory(self.directory), _exclusive_file(self.directory / 'profiles.lock'):
                yield
        except OSError:
            raise StoreError('Profile storage is unavailable; check the directory and permissions') from None

    def _read(self):
        path = self.directory / 'profiles.json'
        _plain(path)
        if not path.exists():
            return {'schema': 1, 'selected_profile_id': None, 'profiles': {}}
        try:
            with _exclusive_file(path, create=False) as handle:
                kernel = _winapi()
                kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
                kernel.ReadFile.restype = wintypes.BOOL
                buffer = ctypes.create_string_buffer(MAX_STORE_BYTES + 1)
                count = wintypes.DWORD()
                if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                    raise StoreError('Cannot read profile storage')
                payload = buffer.raw[:count.value]
            if len(payload) > MAX_STORE_BYTES:
                raise ValueError()
            data = json.loads(payload, object_pairs_hook=_unique_keys)
            if (not isinstance(data, dict) or set(data) != {'schema', 'selected_profile_id', 'profiles'}
                    or type(data['schema']) is not int or data['schema'] != 1 or not isinstance(data['profiles'], dict)):
                raise ValueError()
            if data['selected_profile_id'] is not None:
                _identifier(data['selected_profile_id'])
                if data['selected_profile_id'] not in data['profiles']:
                    raise ValueError()
            for profile_id, item in data['profiles'].items():
                _identifier(profile_id)
                if not isinstance(item, dict) or set(item) != {'current_revision_id', 'revisions'} or not isinstance(item['revisions'], dict):
                    raise ValueError()
                if _identifier(item['current_revision_id']) not in item['revisions']:
                    raise ValueError()
                for revision_id, revision in item['revisions'].items():
                    _identifier(revision_id)
                    if not isinstance(revision, dict) or set(revision) != {'config', 'credentials_blob'}:
                        raise ValueError()
                    if 'credentials' in revision['config'] or validate_profile(revision['config']) != revision['config']:
                        raise ValueError()
                    blob = revision['credentials_blob']
                    if blob is not None:
                        if not isinstance(blob, str) or len(blob) > 131072 or not base64.b64decode(blob, validate=True):
                            raise ValueError()
            return data
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise StoreError('Profile storage is damaged; the existing file has been preserved') from None

    def _write(self, data):
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
        if len(payload) > MAX_STORE_BYTES:
            raise StoreError('Profile history exceeds 8 MiB; export profiles before continuing')
        temporary = self.directory / ('profiles-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('xb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _plain(self.directory / 'profiles.json')
            os.replace(temporary, self.directory / 'profiles.json')
        finally:
            if temporary.exists():
                temporary.unlink()

    def _revision(self, data, profile_id, revision_id=None):
        _identifier(profile_id)
        if profile_id not in data['profiles']:
            raise ValueError('Profile does not exist')
        item = data['profiles'][profile_id]
        revision_id = item['current_revision_id'] if revision_id is None else _identifier(revision_id)
        if revision_id not in item['revisions']:
            raise ValueError('Profile revision does not exist')
        return revision_id, item['revisions'][revision_id]

    def _view(self, data, profile_id):
        revision_id, revision = self._revision(data, profile_id)
        available = True
        if revision['credentials_blob'] is not None:
            try:
                validate_profile(revision['config'] | {'credentials': _unprotect(revision['credentials_blob'])})
            except (SecretsUnavailable, ValueError):
                available = False
        required = revision['config']['protocol'] == 'hysteria2'
        present = revision['credentials_blob'] is not None
        return revision['config'] | {'profile_id': profile_id, 'revision_id': revision_id,
                'auth_present': present, 'secrets_available': available,
                'needs_credentials': not available or (required and not present),
                'selected': data['selected_profile_id'] == profile_id}

    def list_profiles(self):
        with self._transaction():
            data = self._read()
            return [self._view(data, profile_id) for profile_id in data['profiles']]

    def selected_summary(self):
        """Check selected credentials locally, returning only safe metadata and availability."""
        if not self.directory.exists():
            return None
        with self._transaction():
            data = self._read()
            profile_id = data['selected_profile_id']
            if profile_id is None:
                return None
            view = self._view(data, profile_id)
            return {key: view[key] for key in ('name', 'protocol', 'profile_id', 'revision_id',
                                              'auth_present', 'secrets_available', 'needs_credentials')} | {'state': 'pending'}

    def get_view(self, profile_id):
        with self._transaction():
            return self._view(self._read(), profile_id)

    def save(self, config, credentials=None, profile_id=None):
        config = validate_profile(config)
        embedded = config.pop('credentials', None)
        if embedded is not None:
            if credentials is not None:
                raise ValueError('Supply credentials in only one place')
            credentials = embedded
        if credentials is not None:
            credentials = validate_profile(config | {'credentials': credentials})['credentials']
        with self._transaction():
            data = self._read()
            old = None
            if profile_id is not None:
                _, old = self._revision(data, profile_id)
            else:
                profile_id = uuid.uuid4().hex
            if credentials is None and old is not None:
                if old['credentials_blob'] is not None and (old['config']['protocol'], old['config'].get('obfs')) != (config['protocol'], config.get('obfs')):
                    raise ValueError('Enter credentials again when changing protocol or obfuscation')
                blob = old['credentials_blob']
            elif credentials:
                blob = _protect(credentials)
            else:
                blob = None
            if config['protocol'] == 'hysteria2' and blob is None:
                raise ValueError('Hysteria2 authentication is required')
            revision_id = uuid.uuid4().hex
            item = data['profiles'].setdefault(profile_id, {'current_revision_id': revision_id, 'revisions': {}})
            item['revisions'][revision_id] = {'config': config, 'credentials_blob': blob}
            item['current_revision_id'] = revision_id
            self._write(data)
            return self._view(data, profile_id)

    def select(self, profile_id):
        with self._transaction():
            data = self._read()
            self._revision(data, profile_id)
            data['selected_profile_id'] = profile_id
            self._write(data)
            return self._view(data, profile_id)

    def export(self, profile_id, include_secrets=False):
        if type(include_secrets) is not bool:
            raise ValueError('Explicit boolean permission is required to export credentials')
        if include_secrets:
            return self.secret_config(profile_id)
        with self._transaction():
            _, revision = self._revision(self._read(), profile_id)
            return dict(revision['config'])

    def export_to(self, profile_id, destination, include_secrets=False):
        """Write an explicitly selected new JSON file; return metadata, never credentials."""
        if type(include_secrets) is not bool:
            raise ValueError('Explicit boolean permission is required to export credentials')
        try:
            path = Path(destination)
        except (TypeError, ValueError):
            raise StoreError('Choose a new absolute JSON file for profile export') from None
        if (not path.is_absolute() or '..' in path.parts or path.suffix.lower() != '.json'
                or ':' in path.name or str(path).startswith(('\\\\?\\', '\\\\.\\'))):
            raise StoreError('Choose a new absolute JSON file for profile export')
        payload = json.dumps(self.export(profile_id, include_secrets=include_secrets),
                             ensure_ascii=False, indent=2).encode('utf-8')
        try:
            with _pinned_directory(path.parent, create=False):
                _plain(path)
                kernel = _winapi()
                handle = kernel.CreateFileW(str(path), 0x40010000, 0, None, 1, 0x00200000, None)
                if handle == ctypes.c_void_p(-1).value:
                    raise StoreError('Cannot create export file; choose a new file in a writable directory')
                try:
                    written = wintypes.DWORD()
                    if (not kernel.WriteFile(handle, payload, len(payload), ctypes.byref(written), None)
                            or written.value != len(payload) or not kernel.FlushFileBuffers(handle)):
                        raise StoreError('Profile export could not be completed')
                except BaseException:
                    # Delete the exact CREATE_NEW handle, even if its path was targeted by another process.
                    delete = wintypes.BOOL(True)
                    if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
                        raise StoreError('Profile export failed and its partial file could not be removed') from None
                    raise
                finally:
                    kernel.CloseHandle(handle)
        except OSError:
            raise StoreError('Cannot create export file; choose a new file in a writable directory') from None
        return {'path': str(path), 'bytes': len(payload), 'include_secrets': include_secrets}

    def secret_config(self, profile_id, revision_id=None):
        """Sensitive result: pass only to the gateway; never include in logs or GUI responses."""
        with self._transaction():
            _, revision = self._revision(self._read(), profile_id, revision_id)
            config = dict(revision['config'])
            if revision['credentials_blob'] is not None:
                config['credentials'] = _unprotect(revision['credentials_blob'])
            elif config['protocol'] == 'hysteria2':
                raise SecretsUnavailable('Enter Hysteria2 credentials before connecting')
            try:
                return validate_profile(config)
            except ValueError:
                raise SecretsUnavailable('Saved credentials are invalid; enter them again') from None
