import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import socks_fixture


def request(address, port, command=1):
    return b'\x05' + bytes([command, 0, 1]) + socket.inet_aton(address) + struct.pack('!H', port)


class CodecTests(unittest.TestCase):
    def test_fragmented_and_closed_frames(self):
        class Fragmented:
            def __init__(self):
                self.chunks = iter([b'a', b'bc', b''])

            def recv(self, size):
                return next(self.chunks)

        sock = Fragmented()
        self.assertEqual(socks_fixture.exact(sock, 3), b'abc')
        with self.assertRaises(EOFError):
            socks_fixture.exact(sock, 1)
        with self.assertRaises(ValueError):
            socks_fixture.exact(sock, 4097)

    def test_dns_deterministic_and_invalid_frames(self):
        question = b'\x07example\x04test\x00\x00\x01\x00\x01'
        header = struct.pack('!6H', 5, 0x0100, 1, 0, 0, 0)
        reply = socks_fixture.dns_reply(header + question)
        self.assertEqual(struct.unpack('!6H', reply[:12]), (5, 0x8180, 1, 1, 0, 0))
        self.assertEqual(reply[-4:], socket.inet_aton('198.18.0.10'))
        other = socks_fixture.dns_reply(header + question.replace(b'example', b'blocked'))
        self.assertEqual(struct.unpack('!6H', other[:12])[1] & 15, 3)
        for packet in [b'bad', header + b'\xff', header + question + b'extra',
                       header + b'x' * 513]:
            with self.assertRaises(ValueError):
                socks_fixture.dns_reply(packet)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.log = Path(self.temporary.name) / 'audit.jsonl'
        self.fixture = socks_fixture.Fixture(self.log).start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(self.fixture.close)

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.fixture.ports['tcp_port']), timeout=2)
        self.addCleanup(sock.close)
        sock.sendall(b'\x05\x01\x00')
        self.assertEqual(socks_fixture.exact(sock, 2), b'\x05\x00')
        return sock

    def test_http_and_rejection_never_dial_external(self):
        real_connect = socket.create_connection
        destinations = []

        def guarded(address, *args, **kwargs):
            destinations.append(address)
            self.assertEqual(address[0], '127.0.0.1')
            return real_connect(address, *args, **kwargs)

        with patch.object(socks_fixture.socket, 'create_connection', side_effect=guarded):
            sock = self.connect()
            sock.sendall(request('198.18.0.10', 18080))
            self.assertEqual(socks_fixture.exact(sock, 10)[1], 0)
            sock.sendall(b'GET / HTTP/1.0\r\nHost: example.test\r\n\r\n')
            chunks = []
            while data := sock.recv(4096):
                chunks.append(data)
            self.assertIn(b'200 OK', b''.join(chunks))
            self.assertIn(b'PL_OK', b''.join(chunks))
            blocked = self.connect()
            blocked.sendall(request('1.1.1.1', 443))
            self.assertNotEqual(socks_fixture.exact(blocked, 10)[1], 0)
        self.assertEqual(self.fixture.state()['origin_hits'], 1)
        self.assertTrue(destinations)

    def test_udp_association_echo_dns_and_rejection(self):
        association = self.connect()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(udp.close)
        udp.bind(('127.0.0.1', 0))
        udp.settimeout(0.2)
        association.sendall(request('127.0.0.1', udp.getsockname()[1], 3))
        self.assertEqual(socks_fixture.exact(association, 10)[1], 0)
        server = ('127.0.0.1', self.fixture.ports['udp_port'])
        header = b'\x00\x00\x00\x01' + socket.inet_aton('198.18.0.10') + struct.pack('!H', 18081)
        udp.sendto(header + b'echo', server)
        self.assertEqual(udp.recv(4096), header + b'echo')
        dns = struct.pack('!6H', 42, 0x0100, 1, 0, 0, 0) + b'\x07example\x04test\x00\x00\x01\x00\x01'
        dns_header = b'\x00\x00\x00\x01' + socket.inet_aton('198.18.0.53') + b'\x00\x35'
        udp.sendto(dns_header + dns, server)
        reply = udp.recv(4096)[10:]
        self.assertEqual(struct.unpack('!6H', reply[:12])[3], 1)
        self.assertEqual(reply[-4:], socket.inet_aton('198.18.0.10'))
        for packet in [header[:2] + b'\x01' + header[3:] + b'fragment',
                       b'\x00\x00\x00\x01' + socket.inet_aton('8.8.8.8') + b'\x00\x35' + dns]:
            udp.sendto(packet, server)
            with self.assertRaises(socket.timeout):
                udp.recv(4096)
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(stranger.close)
        stranger.settimeout(0.2)
        stranger.sendto(header + b'unbound', server)
        with self.assertRaises(socket.timeout):
            stranger.recv(4096)
        association.shutdown(socket.SHUT_RDWR)
        association.close()
        deadline = time.monotonic() + 2
        while self.fixture.state()['udp_associations'] and time.monotonic() < deadline:
            time.sleep(0.01)
        udp.sendto(header + b'after-close', server)
        with self.assertRaises(socket.timeout):
            udp.recv(4096)

    def test_dns_tcp_and_proxy_down_up(self):
        sock = self.connect()
        sock.sendall(request('198.18.0.53', 53))
        self.assertEqual(socks_fixture.exact(sock, 10)[1], 0)
        dns = struct.pack('!6H', 7, 0x100, 1, 0, 0, 0) + b'\x07example\x04test\x00\x00\x01\x00\x01'
        sock.sendall(struct.pack('!H', len(dns)) + dns)
        length = struct.unpack('!H', socks_fixture.exact(sock, 2))[0]
        self.assertEqual(socks_fixture.exact(sock, length)[-4:], socket.inet_aton('198.18.0.10'))
        endpoint = 'http://127.0.0.1:' + str(self.fixture.ports['control_port'])
        with urlopen(Request(endpoint + '/down', method='POST'), timeout=2) as response:
            self.assertFalse(json.load(response)['available'])
        self.assertEqual(sock.recv(1), b'')
        rejected = socket.create_connection(('127.0.0.1', self.fixture.ports['tcp_port']), timeout=2)
        self.addCleanup(rejected.close)
        rejected.sendall(b'\x05\x01\x00')
        self.assertEqual(socks_fixture.exact(rejected, 2), b'\x05\xff')
        with urlopen(Request(endpoint + '/up', method='POST'), timeout=2) as response:
            self.assertTrue(json.load(response)['available'])
        self.connect()

    def test_audit_is_exclusive_and_has_no_payload(self):
        with self.assertRaises(FileExistsError):
            socks_fixture.Fixture(self.log)
        sock = self.connect()
        sock.sendall(request('203.0.113.1', 80))
        socks_fixture.exact(sock, 10)
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertTrue(entries)
        self.assertTrue(all(set(entry) <= {'event', 'destination', 'port', 'accepted', 'time'} for entry in entries))


if __name__ == '__main__':
    unittest.main()
