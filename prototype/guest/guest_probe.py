"""Runs inside the disposable Debian guest; destinations belong to the offline fixture."""
import json
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import time


def emit(kind, **data):
    line = kind + ' ' + json.dumps(data, separators=(',', ':'), ensure_ascii=True) + '\n'
    if len(line) > 8192:
        line = 'PL_ERROR {"error":"ReceiptTooLarge","kind":' + json.dumps(kind) + '}\n'
    with open('/dev/ttyS0', 'w', encoding='ascii') as serial:
        serial.write(line)
        serial.flush()


def command(*args):
    result = subprocess.run(args, capture_output=True, timeout=3, check=False)
    return {'code': result.returncode, 'text': result.stdout[:1024].decode(errors='replace')}


def inventory():
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    total_kib = int(memory['MemTotal'].split()[0])
    available_kib = int(memory['MemAvailable'].split()[0])
    result = subprocess.run(['df', '-B1', '--output=size,used', '/'],
                            capture_output=True, text=True, timeout=3, check=True)
    root_size, root_used = map(int, result.stdout.splitlines()[1].split())
    if not (0 <= available_kib <= total_kib < 2**64 and 0 <= root_used <= root_size < 2**64):
        raise ValueError('Invalid inventory values')
    return {'mem_total_kib': total_kib, 'mem_available_kib': available_kib,
            'root_size_bytes': root_size, 'root_used_bytes': root_used}


def dns_query(address):
    packet = struct.pack('!6H', 0x504c, 0x0100, 1, 0, 0, 0) + b'\x07example\x04test\x00' + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.7)
        sock.connect((address, 53))
        sock.send(packet)
        reply = sock.recv(512)
    if len(reply) < 12:
        raise ValueError('Short DNS reply')
    ident, flags, _, answers, _, _ = struct.unpack('!6H', reply[:12])
    if ident != 0x504c or not flags & 0x8000 or flags & 15 or not answers:
        raise ValueError('Invalid or unsuccessful DNS reply')
    return {'bytes': len(reply), 'answers': answers}


def dns_burst():
    pending = {0x504c, 0x504d}
    received_bytes = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.7)
        sock.connect(('192.168.127.1', 53))
        for ident in sorted(pending):
            sock.send(struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) +
                      b'\x07example\x04test\x00' + struct.pack('!HH', 1, 1))
        for _ in range(2):
            reply = sock.recv(512)
            if len(reply) < 12:
                raise ValueError('Short DNS burst reply')
            ident, flags, _, answers, _, _ = struct.unpack('!6H', reply[:12])
            if ident not in pending or not flags & 0x8000 or flags & 15 or not answers:
                raise ValueError('Invalid, duplicate or unsuccessful DNS burst reply')
            pending.remove(ident)
            received_bytes += len(reply)
    return {'bytes': received_bytes, 'replies': 2}


def tcp_probe(address='198.18.0.10', family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.7)
        sock.connect((address, 18080))
        sock.sendall(b'GET /pl-probe HTTP/1.0\r\nHost: example.test\r\n\r\n')
        reply = sock.recv(1024)
    if not reply.startswith(b'HTTP/1.') or b' 200 ' not in reply.split(b'\r\n', 1)[0]:
        raise ValueError('Expected fixture HTTP 200')
    return {'bytes': len(reply)}


def udp_probe():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.7)
        sock.connect(('198.18.0.10', 18081))
        sock.send(b'PL_UDP_ECHO')
        reply = sock.recv(1024)
    if reply != b'PL_UDP_ECHO':
        raise ValueError('Unexpected UDP echo')
    return {'bytes': len(reply)}


def forbidden_public_probe():
    # The host verifies this endpoint is reachable; the fixture deliberately refuses it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.7)
        sock.connect(('1.1.1.1', 443))
    return {'connected': True}


def main():
    emit('PL_BOOT', python=platform.python_version(), kernel=platform.release(),
         debian=Path('/etc/debian_version').read_text().strip())
    emit('PL_INVENTORY', **inventory())
    emit('PL_NETWORK', addresses=command('ip', '-j', 'address'), routes=command('ip', '-j', 'route'),
         ipv6_routes=command('ip', '-6', '-j', 'route'))
    emit('PL_READY', duration_seconds=90, interval_seconds=3)
    if sys.argv[1:] != ['inventory']:
        probes = [('tcp', tcp_probe), ('udp', udp_probe), ('dns', lambda: dns_query('192.168.127.1')),
                  ('dns_burst', dns_burst),
                  ('direct_dns', lambda: dns_query('198.18.0.10')),
                  ('ipv6', lambda: tcp_probe('2001:db8::10', socket.AF_INET6)),
                  ('forbidden_public', forbidden_public_probe)]
        started = time.monotonic()
        phase = 0
        while time.monotonic() - started < 90:
            for name, probe in probes:
                try:
                    emit('PL_PROBE', phase=phase, name=name, ok=True, result=probe(),
                         elapsed=round(time.monotonic() - started, 3))
                except Exception as error:
                    emit('PL_PROBE', phase=phase, name=name, ok=False, error=type(error).__name__,
                         detail=str(error)[:160], elapsed=round(time.monotonic() - started, 3))
            phase += 1
            time.sleep(3)
    emit('PL_DONE', mode=sys.argv[1:])


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        emit('PL_ERROR', error=type(error).__name__, detail=str(error)[:160])
    finally:
        subprocess.run(['systemctl', 'poweroff'], timeout=10, check=False)
