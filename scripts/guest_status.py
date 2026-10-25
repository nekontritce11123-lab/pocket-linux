"""Bounded, session-bound guest receipts over QEMU's local serial socket."""
import json
import re
import socket
import time

MAX_LINE = 4096


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def _nonce(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value) is not None


class Channel:
    def __init__(self, nonce, file_nonce=None, expected_shares=()):
        shares = tuple(expected_shares)
        if (not _nonce(nonce) or (file_nonce is not None and not _nonce(file_nonce))
                or len(shares) > 64
                or any(not isinstance(s, str) or not re.fullmatch('PC_[A-Za-z0-9_]{1,48}', s) for s in shares)
                or len(set(shares)) != len(shares) or bool(shares) != (file_nonce is not None)):
            raise ValueError('Invalid status channel configuration')
        self.nonce, self.file_nonce, self.expected_shares = nonce, file_nonce, set(shares)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(('127.0.0.1', 0))
            self._listener.listen(1)
            self._listener.setblocking(False)
        except BaseException:
            self._listener.close()
            raise
        self.port = self._listener.getsockname()[1]
        self._connection = None
        self._buffer, self._discard = b'', False
        self._status = self._files = None
        self._received_at = self._files_received_at = None

    @property
    def qemu_args(self):
        return ['-chardev', 'socket,id=pocketstatus,host=127.0.0.1,port=' + str(self.port) + ',server=off',
                '-serial', 'chardev:pocketstatus']

    def _line(self, line):
        kind, separator, raw = line.partition(b' ')
        if not separator or kind not in (b'POCKET_STATUS', b'POCKET_FILES'):
            return
        try:
            value = json.loads(raw, object_pairs_hook=_object)
            if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1:
                return
            if kind == b'POCKET_STATUS':
                if (set(value) != {'schema', 'session_nonce', 'network', 'dns', 'https', 'width', 'height'}
                        or value['session_nonce'] != self.nonce or value['network'] not in ('ready', 'failed', 'off')
                        or type(value['dns']) is not bool or type(value['https']) is not bool
                        or any(v is not None and (type(v) is not int or not 320 <= v <= 16384)
                               for v in (value['width'], value['height']))
                        or (value['width'] is None) != (value['height'] is None)
                        or (value['network'] == 'ready') != (value['dns'] and value['https'])
                        or (value['network'] == 'off' and (value['dns'] or value['https']))):
                    return
                self._status, self._received_at = value, time.time()
            else:
                if (self.file_nonce is None or value.get('session_nonce') != self.file_nonce
                        or set(value) != {'schema', 'session_nonce', 'status', 'mounted', 'failed', 'code'}
                        or value['status'] not in ('ready', 'failed')
                        or not isinstance(value['code'], str) or not re.fullmatch('[a-z_]{1,64}', value['code'])
                        or type(value['mounted']) is not list or type(value['failed']) is not list):
                    return
                names = value['mounted'] + value['failed']
                if (any(type(name) is not str for name in names) or len(names) != len(set(names))
                        or set(names) != self.expected_shares
                        or (value['status'] == 'ready') != (not value['failed'])):
                    return
                self._files, self._files_received_at = value, time.time()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return

    def _feed(self, data):
        for part in data.splitlines(keepends=True):
            complete = part.endswith(b'\n')
            if not self._discard:
                self._buffer += part
                if len(self._buffer) > MAX_LINE:
                    self._buffer, self._discard = b'', True
                elif complete:
                    self._line(self._buffer.rstrip(b'\r\n'))
                    self._buffer = b''
            if complete:
                self._discard = False

    def poll(self):
        if self._connection is None and self._listener is not None:
            try:
                self._connection, _ = self._listener.accept()
                self._connection.setblocking(False)
                self._listener.close()
                self._listener = None
            except (BlockingIOError, OSError):
                return
        if self._connection is None:
            return
        for _ in range(16):
            try:
                data = self._connection.recv(4096)
            except BlockingIOError:
                break
            except OSError:
                data = b''
            if not data:
                self._connection.close()
                self._connection = None
                break
            self._feed(data)

    def snapshot(self):
        fresh = self._received_at is not None and 0 <= time.time() - self._received_at <= 60
        return {'status': dict(self._status) if fresh else None, 'received_at': self._received_at,
                'fresh': fresh, 'files': json.loads(json.dumps(self._files)),
                'files_received_at': self._files_received_at}

    def close(self):
        for connection in (self._connection, self._listener):
            if connection is not None:
                connection.close()
        self._connection = self._listener = None
