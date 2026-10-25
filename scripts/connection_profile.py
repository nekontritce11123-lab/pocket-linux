"""Strict, network-free connection profile validation and URI import."""
import ipaddress
import json
import re
from urllib.parse import parse_qsl, unquote, urlsplit

PROTOCOLS = ('hysteria2', 'socks5', 'http', 'https')
FIELDS = {'schema', 'name', 'protocol', 'host', 'port', 'tls_server_name', 'obfs',
          'credentials', 'tls_verify', 'udp_supported'}


def _text(value, field, limit, empty=False):
    if (not isinstance(value, str) or len(value) > limit or
            (not value and not empty) or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('Invalid profile field: ' + field)
    return value


def _host(value):
    value = _text(value, 'host', 253).removesuffix('.')
    if ':' in value or '[' in value or ']' in value:
        raise ValueError('IPv6 endpoints are not supported in this version')
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('Invalid IPv4 address') from None
    try:
        value = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Invalid server name') from None
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                               for label in value.split('.')):
        raise ValueError('Invalid server name')
    return value


def validate_profile(value):
    """Normalize metadata and optional credentials; missing secrets may be re-entered later."""
    if not isinstance(value, dict) or set(value) - FIELDS:
        raise ValueError('Profile object has unsupported fields')
    try:
        if len(json.dumps(value, ensure_ascii=False).encode('utf-8')) > 65536:
            raise ValueError('Profile exceeds 64 KiB')
    except (TypeError, UnicodeError, RecursionError):
        raise ValueError('Invalid profile data') from None
    if type(value.get('schema', 1)) is not int or value.get('schema', 1) != 1:
        raise ValueError('Unsupported profile schema')
    protocol = value.get('protocol')
    if protocol not in PROTOCOLS:
        raise ValueError('Unsupported connection protocol')
    port = value.get('port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Port must be an integer between 1 and 65535')
    tls = protocol in ('hysteria2', 'https')
    udp = protocol == 'hysteria2'
    if 'tls_verify' in value and (type(value['tls_verify']) is not bool or value['tls_verify'] != tls):
        raise ValueError('TLS verification cannot be disabled or added to this protocol')
    if 'udp_supported' in value and (type(value['udp_supported']) is not bool or value['udp_supported'] != udp):
        raise ValueError('UDP capability is determined by the protocol')
    host = _host(value.get('host'))
    result = {'schema': 1, 'name': _text(value.get('name', host), 'name', 128),
              'protocol': protocol, 'host': host, 'port': port,
              'tls_verify': tls, 'udp_supported': udp}
    sni = value.get('tls_server_name', '')
    if sni:
        if not tls:
            raise ValueError('TLS server name requires a TLS connection')
        result['tls_server_name'] = _host(sni)
    elif sni != '':
        raise ValueError('Invalid TLS server name')
    obfs = value.get('obfs', '')
    if obfs:
        if not udp or obfs != 'salamander':
            raise ValueError('Only Hysteria2 salamander obfuscation is supported')
        result['obfs'] = obfs
    elif obfs != '':
        raise ValueError('Invalid obfuscation setting')
    if 'credentials' in value:
        credentials = value['credentials']
        allowed = {'auth', 'obfs_password'} if udp else {'username', 'password'}
        if not isinstance(credentials, dict) or set(credentials) - allowed:
            raise ValueError('Unsupported credential fields')
        if udp:
            _text(credentials.get('auth'), 'auth', 8192)
            if obfs:
                _text(credentials.get('obfs_password'), 'obfs_password', 8192)
            elif 'obfs_password' in credentials:
                raise ValueError('Obfuscation password requires salamander')
        elif credentials:
            _text(credentials.get('username'), 'username', 8192)
            _text(credentials.get('password'), 'password', 8192)
        result['credentials'] = dict(credentials)
    return result


def import_profile_uri(uri):
    """Import a supported URI without ever returning its text in errors."""
    if (not isinstance(uri, str) or len(uri.encode('utf-8', errors='replace')) > 8192
            or re.search(r'%(?![0-9a-fA-F]{2})', uri)
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in uri)):
        raise ValueError('Invalid connection link (maximum 8 KiB)')
    try:
        parsed = urlsplit(uri)
        protocol = 'hysteria2' if parsed.scheme == 'hy2' else parsed.scheme
        if (protocol not in PROTOCOLS or parsed.path not in ('', '/') or not parsed.hostname
                or parsed.netloc.endswith(':') or parsed.netloc.count('@') > 1):
            raise ValueError()
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                          encoding='utf-8', errors='strict', max_num_fields=8)
        query = dict(pairs)
        allowed = {'sni', 'obfs', 'obfs-password', 'insecure'} if protocol == 'hysteria2' else set()
        if len(query) != len(pairs) or set(query) - allowed or query.get('insecure', '0') != '0':
            raise ValueError()
        result = {'protocol': protocol, 'host': parsed.hostname,
                  'port': parsed.port or (443 if protocol in ('hysteria2', 'https') else 1080 if protocol == 'socks5' else 80)}
        if parsed.fragment:
            result['name'] = unquote(parsed.fragment, encoding='utf-8', errors='strict')
        if protocol == 'hysteria2':
            if '@' in parsed.netloc:
                auth = parsed.netloc.rsplit('@', 1)[0]
                result['credentials'] = {'auth': unquote(auth, encoding='utf-8', errors='strict')}
            if 'sni' in query:
                result['tls_server_name'] = query['sni']
            if 'obfs' in query:
                result['obfs'] = query['obfs']
            if 'obfs-password' in query:
                result.setdefault('credentials', {})['obfs_password'] = query['obfs-password']
        elif '@' in parsed.netloc:
            result['credentials'] = {'username': unquote(parsed.username or '', errors='strict'),
                                     'password': unquote(parsed.password or '', errors='strict')}
        if parsed.port == 0:
            raise ValueError()
        return validate_profile(result)
    except (ValueError, UnicodeError, TypeError):
        raise ValueError('Invalid or unsupported connection link; check protocol, address, port and TLS options') from None
