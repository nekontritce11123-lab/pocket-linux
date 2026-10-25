"""Loopback-only SOCKS5 test fixture: fixed synthetic services, no Internet forwarding."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import select
import socket
import socketserver
import struct
import threading
import time

LIMIT = 4096
TIMEOUT = 3


def exact(sock, length):
    if not 0 <= length <= LIMIT:
        raise ValueError('Frame exceeds bound')
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError('Closed frame')
        result.extend(chunk)
    return bytes(result)


def address(sock, atyp):
    if atyp == 1:
        host = socket.inet_ntoa(exact(sock, 4))
    elif atyp == 3:
        host = exact(sock, exact(sock, 1)[0]).decode('ascii')
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    else:
        raise ValueError('Unknown address type')
    return host, struct.unpack('!H', exact(sock, 2))[0]


def dns_reply(packet):
    if not 12 <= len(packet) <= 512:
        raise ValueError('DNS size')
    ident, flags, questions, answers, authority, extra = struct.unpack('!6H', packet[:12])
    if questions != 1 or flags & 0xF800 or answers or authority or extra:
        raise ValueError('Unsupported DNS request')
    offset, labels = 12, []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if not size:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError('Invalid DNS label')
        labels.append(packet[offset:offset + size].lower())
        offset += size
    if offset + 4 != len(packet):
        raise ValueError('DNS question size')
    success = labels == [b'example', b'test'] and packet[offset:] == b'\x00\x01\x00\x01'
    header = struct.pack('!6H', ident, 0x8080 | (flags & 0x0100) | (0 if success else 3),
                         1, int(success), 0, 0)
    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04' + socket.inet_aton('198.18.0.10')
    return header + packet[12:] + (answer if success else b'')


def disconnect(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class QuietTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture, sock = self.server.fixture, self.request
        sock.settimeout(TIMEOUT)
        session = {'sock': sock, 'peer': self.client_address[0], 'udp_source': None, 'udp': False}
        with fixture.lock:
            if len(fixture.sessions) >= 64:
                return
            fixture.sessions.append(session)
        try:
            version, count = exact(sock, 2)
            methods = exact(sock, count)
            if version != 5 or 0 not in methods or not fixture.available:
                sock.sendall(b'\x05\xff')
                return
            sock.sendall(b'\x05\x00')
            version, command, reserved, atyp = exact(sock, 4)
            host, port = address(sock, atyp)
            if version != 5 or reserved or not fixture.available:
                return
            if command == 3:
                if atyp != 1 or host not in ('0.0.0.0', self.client_address[0]):
                    sock.sendall(b'\x05\x02\x00\x01' + bytes(6))
                    return
                with fixture.lock:
                    session['udp'] = True
                    if port:
                        session['udp_source'] = (self.client_address[0], port)
                sock.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') +
                             struct.pack('!H', fixture.ports['udp_port']))
                while fixture.available:
                    try:
                        if sock.recv(1) == b'':
                            break
                    except socket.timeout:
                        continue
                return
            accepted = command == 1 and (host, port) in {('198.18.0.10', 18080), ('198.18.0.53', 53)} and atyp == 1
            fixture.audit('tcp', host, port, accepted)
            if not accepted:
                sock.sendall(b'\x05\x02\x00\x01' + bytes(6))
                return
            sock.sendall(b'\x05\x00\x00\x01' + bytes(6))
            if port == 53:
                while fixture.available:
                    length = struct.unpack('!H', exact(sock, 2))[0]
                    reply = dns_reply(exact(sock, length))
                    fixture.increment('dns_hits')
                    sock.sendall(struct.pack('!H', len(reply)) + reply)
            else:
                # The only outbound dial in this fixture is its own loopback origin.
                with socket.create_connection(('127.0.0.1', fixture.ports['origin_port']), TIMEOUT) as origin:
                    while fixture.available:
                        readable, _, _ = select.select([sock, origin], [], [], 0.2)
                        for source in readable:
                            data = source.recv(LIMIT)
                            if not data:
                                return
                            (origin if source is sock else sock).sendall(data)
        except (OSError, EOFError, ValueError, UnicodeError):
            pass
        finally:
            with fixture.lock:
                fixture.sessions.remove(session)


class UDPServer(socketserver.UDPServer):
    def handle_error(self, request, client_address):
        pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        fixture = self.server.fixture
        if not fixture.available or not 10 <= len(packet) <= LIMIT or packet[:4] != b'\x00\x00\x00\x01':
            return
        with fixture.lock:
            session = next((item for item in fixture.sessions if item['udp'] and
                            item['udp_source'] == self.client_address), None)
            if session is None:
                session = next((item for item in fixture.sessions if item['udp'] and
                                item['udp_source'] is None and item['peer'] == self.client_address[0]), None)
                if session is not None:
                    session['udp_source'] = self.client_address
            if session is None:
                return
        host, port = socket.inet_ntoa(packet[4:8]), struct.unpack('!H', packet[8:10])[0]
        accepted = (host, port) in {('198.18.0.10', 18081), ('198.18.0.53', 53)}
        fixture.audit('udp', host, port, accepted)
        if not accepted:
            return
        try:
            if port == 53:
                payload = dns_reply(packet[10:])
                fixture.increment('dns_hits')
            else:
                payload = packet[10:]
                fixture.increment('udp_hits')
            sock.sendto(packet[:10] + payload, self.client_address)
        except (OSError, ValueError):
            pass


class HTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        self.request.settimeout(TIMEOUT)
        super().setup()

    def do_GET(self):
        fixture = self.server.fixture
        if self.server.service == 'origin':
            fixture.increment('origin_hits')
            self.reply(200, b'PL_OK\n', 'text/plain')
        elif self.path == '/state':
            self.reply(200, json.dumps(fixture.state()).encode())
        else:
            self.reply(404, b'{}')

    def do_POST(self):
        if self.server.service != 'control' or self.path not in ('/down', '/up'):
            self.reply(404, b'{}')
            return
        self.server.fixture.set_available(self.path == '/up')
        self.reply(200, json.dumps(self.server.fixture.state()).encode())

    def reply(self, status, payload, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class Fixture:
    def __init__(self, output, port=0):
        self.log = Path(output).open('x', encoding='utf-8')
        self.lock = threading.RLock()
        self.available = True
        self.sessions, self.servers, self.threads = [], [], []
        self.counts = {'origin_hits': 0, 'udp_hits': 0, 'dns_hits': 0, 'audit_entries': 0, 'audit_dropped': 0}
        self.ports = {}
        try:
            for key, server_type, handler in [('tcp_port', QuietTCPServer, SocksHandler),
                                               ('udp_port', UDPServer, UDPHandler),
                                               ('origin_port', ThreadingHTTPServer, HTTPHandler),
                                               ('control_port', ThreadingHTTPServer, HTTPHandler)]:
                server = server_type(('127.0.0.1', port if key == 'tcp_port' else 0), handler)
                server.fixture = self
                server.service = 'origin' if key == 'origin_port' else 'control'
                self.servers.append(server)
                self.ports[key] = server.server_address[1]
        except Exception:
            for server in self.servers:
                server.server_close()
            self.log.close()
            raise

    def start(self):
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    def increment(self, key):
        with self.lock:
            self.counts[key] += 1

    def audit(self, event, destination, port, accepted):
        with self.lock:
            if self.counts['audit_entries'] >= 10000:
                self.counts['audit_dropped'] += 1
                return
            entry = {'event': event, 'destination': destination[:255], 'port': port,
                     'accepted': accepted, 'time': round(time.time(), 3)}
            self.log.write(json.dumps(entry, separators=(',', ':')) + '\n')
            self.log.flush()
            self.counts['audit_entries'] += 1

    def state(self):
        with self.lock:
            return {**self.counts, 'available': self.available, 'active_sessions': len(self.sessions),
                    'udp_associations': sum(item['udp'] for item in self.sessions)}

    def set_available(self, available):
        with self.lock:
            self.available = available
            if not available:
                for session in self.sessions:
                    disconnect(session['sock'])

    def close(self):
        self.set_available(False)
        for server, thread in zip(self.servers, self.threads):
            server.shutdown()
            thread.join(timeout=TIMEOUT)
        for server in self.servers:
            server.server_close()
        with self.lock:
            self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New audit JSONL path; parent must exist')
    parser.add_argument('--port', type=int, default=0)
    options = parser.parse_args()
    if not 0 <= options.port <= 65535:
        parser.error('Port must be 0..65535')
    fixture = Fixture(options.output, options.port).start()
    print(json.dumps({'event': 'READY', **fixture.ports}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        fixture.close()


if __name__ == '__main__':
    main()
