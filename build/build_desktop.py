"""Build a fresh Linux image through an allowlisted loopback package mirror."""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('probe_helpers', ROOT / 'prototype/run_probe.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
REPOS = {'debian': 'https://deb.debian.org/debian',
         'security': 'https://security.debian.org/debian-security'}


def upstream(path):
    path = urllib.parse.unquote(path, errors='strict')
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or '%' in path or '\\' in path:
        raise ValueError('Only canonical repository paths are allowed')
    parts = parsed.path.split('/')
    if len(parts) < 4 or parts[0] or parts[1] not in REPOS or parts[2] not in ('pool', 'dists'):
        raise ValueError('Unknown repository path')
    if any(p in ('.', '..', '') for p in parts[1:]) or not re.fullmatch(r'[A-Za-z0-9_./+~:-]+', path):
        raise ValueError('Invalid repository path')
    return REPOS[parts[1]] + '/' + '/'.join(parts[2:])


def select_package(text, name):
    records = []
    for paragraph in text.strip().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in paragraph.splitlines()
                      if ': ' in line and not line.startswith(' '))
        if fields.get('Package') == name and fields.get('Architecture') == 'amd64':
            records.append(fields)
    if not records:
        raise ValueError('Official amd64 package missing: ' + name)
    chosen = max(records, key=lambda r: tuple(int(x) for x in re.findall(r'\d+', r['Version'])))
    if (not re.fullmatch(r'[0-9a-f]{64}', chosen.get('SHA256', ''))
            or not re.fullmatch(r'pool/[A-Za-z0-9_./+~:-]+\.deb', chosen.get('Filename', ''))
            or '..' in chosen['Filename'] or int(chosen['Size']) <= 0):
        raise ValueError('Invalid official package metadata')
    return chosen


def download(url, target, expected=None):
    if not target.exists():
        part = target.with_suffix(target.suffix + '.part')
        try:
            with urllib.request.urlopen(url, timeout=90) as response, part.open('wb') as out:
                shutil.copyfileobj(response, out, 1024 * 1024)
            part.replace(target)
        except Exception:
            part.unlink(missing_ok=True)
            raise
    with target.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected and digest != expected:
        raise ValueError('Artifact SHA256 mismatch: ' + target.name)
    return digest


def fetch_artifacts(output):
    folder = output.parent / 'downloads'
    folder.mkdir(exist_ok=True)
    result = {}
    for name in ('claude-desktop', 'claude-code'):
        base = 'https://downloads.claude.ai/' + name + '/apt/stable/'
        index = folder / (name + '-Packages')
        download(base + 'dists/stable/main/binary-amd64/Packages', index)
        data = select_package(index.read_text(encoding='utf-8'), name)
        filename = name + '.deb'
        data['url'] = base + data['Filename']
        download(data['url'], folder / filename, data['SHA256'])
        if (folder / filename).stat().st_size != int(data['Size']):
            raise ValueError('Artifact size mismatch')
        result[name] = data
        print(json.dumps({'event': 'ARTIFACT', 'name': name, 'version': data['Version'],
                          'bytes': int(data['Size'])}), flush=True)
    (output / 'artifacts.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


class Mirror(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, output):
        self.output = output
        self.cache = output.parent / 'cache'
        self.cache.mkdir(exist_ok=True)
        self.guard = threading.Lock()
        self.locks = {}
        super().__init__(('127.0.0.1', 0), MirrorHandler)


class MirrorHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            if self.path in ('/artifacts/claude-desktop.deb', '/artifacts/claude-code.deb'):
                file = self.server.output.parent / 'downloads' / self.path.rsplit('/', 1)[1]
            else:
                url = upstream(self.path)
                key = hashlib.sha256(url.encode('ascii')).hexdigest()
                file = self.server.cache / key
                with self.server.guard:
                    lock = self.server.locks.setdefault(key, threading.Lock())
                with lock:
                    download(url, file)
            self.send_response(200)
            self.send_header('Content-Length', str(file.stat().st_size))
            self.end_headers()
            with file.open('rb') as source:
                shutil.copyfileobj(source, self.wfile, 1024 * 1024)
        except urllib.error.HTTPError as error:
            self.send_error(error.code)
        except ValueError:
            self.send_error(403)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as error:
            print(json.dumps({'event': 'MIRROR_ERROR', 'path': self.path, 'error': str(error)}), flush=True)
            self.send_error(502)


def seed_network():
    return {'version': 2, 'ethernets': {'build0': {
        'match': {'macaddress': '52:54:00:50:4c:01'}, 'set-name': 'build0',
        'dhcp4': False, 'dhcp6': False, 'accept-ra': False, 'addresses': ['192.168.127.2/24'],
        'gateway4': '192.168.127.1'}}}


def build_network_args(port):
    return ['-netdev', json.dumps({'type': 'stream', 'id': 'buildnet', 'server': False,
                                  'addr': {'type': 'inet', 'host': '127.0.0.1', 'port': str(port)}}),
            '-device', 'virtio-net-pci,netdev=buildnet,mac=52:54:00:50:4c:01']


def qmp_command(sock, command, arguments=None):
    stream = sock.makefile('rwb', buffering=0)
    # Only used with a fresh control connection, so consume its greeting first.
    json.loads(stream.readline())
    for cmd in ({'execute': 'qmp_capabilities'}, {'execute': command, 'arguments': arguments or {}}):
        stream.write(json.dumps(cmd).encode('utf-8') + b'\n')
        while True:
            result = json.loads(stream.readline())
            if 'return' in result or 'error' in result:
                if 'error' in result:
                    raise RuntimeError(result['error'])
                break
    return result


class TestClipboard:
    """Only synthetic acceptance markers; never opens the actual Windows clipboard."""
    def start(self, callback):
        self.callback, self.received = callback, None

    def set_text(self, value):
        self.received = value

    def stop(self):
        pass


def run(output, mode='build', base=None, accel='whpx', proxy_config=None, network_exe=None, with_files=False, with_clipboard=False, desktop='lxqt'):
    if desktop not in ('lxqt', 'plasma'):
        raise ValueError('Unknown desktop')
    output.mkdir(parents=True, exist_ok=False)
    mirror = None
    fixture = None
    network = None
    network_log = None
    proc = None
    net_port = None
    file_channel = None
    clipboard = None
    clipboard_path = status_path = None
    qemu = ROOT / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe'
    img = qemu.with_name('qemu-img.exe')
    base = base or ROOT / 'images/debian-13-genericcloud-amd64.qcow2'
    disk = output / 'working.qcow2'
    serial = output / 'serial.log'
    try:
        subprocess.run([str(img), 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                        helpers.qemu_path(base), helpers.qemu_path(disk)], check=True, capture_output=True)
        if mode == 'build':
            subprocess.run([str(img), 'resize', helpers.qemu_path(disk), '16G'], check=True, capture_output=True)
            artifacts = fetch_artifacts(output)
            mirror = Mirror(output)
            threading.Thread(target=mirror.serve_forever, daemon=True).start()
            # Reuse the tested proxy fixture: it can dial only our loopback mirror, never arbitrary hosts.
            fixture = helpers.Fixture(output / 'build-proxy-audit.jsonl')
            fixture.ports['origin_port'] = mirror.server_port
            fixture.start()
            config = {'listen': '127.0.0.1:0', 'dns_upstream': '198.18.0.53:53',
                      'proxy': {'type': 'socks5', 'server': '127.0.0.1', 'server_port': fixture.ports['tcp_port']}}
            config_path = output / 'build-proxy.json'
            config_path.write_text(json.dumps(config), encoding='utf-8')
            network_log = (output / 'network-stderr.log').open('w', encoding='utf-8')
            network = helpers.launch([str(ROOT / 'Debian-LXQt/PocketNet.exe'), '--config', str(config_path)],
                                     stdout=subprocess.PIPE, stderr=network_log, text=True)
            ready = json.loads(network.stdout.readline())
            assert ready.get('direct_fallback') is False
            net_port = int(ready['listen'].rsplit(':', 1)[1])
            seed = output / 'seed'
            seed.mkdir()
            files = []
            for name in ('guest_setup.sh', 'guest_verify.py', 'guest_style.py', 'guest_plasma.py', 'guest_access.py', 'guest_folders.py',
                         'guest_clipboard.py', 'guest_status.py', 'pocket-clipboard.service',
                         'pocket-status.service', 'pocket-clipboard.desktop'):
                files.append({'path': '/opt/pocket-build/' + name, 'permissions': '0700',
                              'content': Path(__file__).with_name(name).read_text(encoding='utf-8')})
            files.append({'path': '/opt/pocket-build/clipboard_bridge.py', 'permissions': '0644',
                          'content': (ROOT / 'scripts/clipboard_bridge.py').read_text(encoding='utf-8')})
            theme_root = ROOT / 'third-party/arc-openbox'
            for asset in sorted(theme_root.rglob('*')):
                if not asset.is_file():
                    continue
                relative = asset.relative_to(theme_root).as_posix()
                destination = ('/usr/share/themes/' + relative if relative.startswith('Arc/openbox-3/')
                               else '/usr/share/doc/pocket-arc-openbox/' + relative)
                files.append({'path': destination, 'permissions': '0644', 'encoding': 'b64',
                              'content': base64.b64encode(asset.read_bytes()).decode('ascii')})
            files.append({'path': '/opt/pocket-build/artifacts.json', 'permissions': '0600',
                          'content': json.dumps(artifacts)})
            user = {'users': [{'name': 'pocket', 'groups': ['sudo', 'audio', 'video'],
                              'shell': '/bin/bash', 'lock_passwd': True,
                              'sudo': ['ALL=(ALL) ALL']}],
                    'disable_root': True, 'ssh_pwauth': False, 'write_files': files,
                    'runcmd': [['bash', '/opt/pocket-build/guest_setup.sh', desktop]]}
            (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(user), encoding='utf-8')
            (seed / 'meta-data').write_text(json.dumps({'instance-id': 'desktop-' + output.name,
                                                      'local-hostname': 'pocket-linux'}), encoding='utf-8')
            (seed / 'network-config').write_text(json.dumps(seed_network()), encoding='utf-8')
        if mode == 'verify' and proxy_config:
            network_log = (output / 'network-stderr.log').open('w', encoding='utf-8')
            network = helpers.launch([str(network_exe), '--config', str(proxy_config)],
                                     stdout=subprocess.PIPE, stderr=network_log, text=True)
            ready = json.loads(network.stdout.readline(8193))
            if (ready.get('direct_fallback') is not False or ready.get('event') != 'READY'
                    or not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}', ready.get('listen', ''))):
                raise RuntimeError('Proxy did not confirm a fail-closed loopback interface')
            net_port = int(ready['listen'].rsplit(':', 1)[1])
            if net_port > 65535:
                raise RuntimeError('Invalid proxy port')
            proxy_config.unlink()
        if with_files:
            sys.path.insert(0, str(ROOT / 'scripts'))
            import host_folders
            from runtime_supervisor import create_private_directory
            share = output / 'windows-share'
            share.mkdir()
            (share / 'windows-sentinel.txt').write_text('Pocket Windows shared test\n', encoding='utf-8')
            private = output / 'files-private'
            create_private_directory(private)
            file_channel = host_folders.start(ROOT / 'Debian-LXQt', [str(share)], private, helpers.qemu_path)
        # The QMP socket is host loopback only, with no guest network forwarding.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            qmp_port = sock.getsockname()[1]
        args = [str(qemu), '-L', helpers.qemu_path(qemu.parent / 'share'), '-machine', 'q35,smm=off',
                '-accel', 'tcg,thread=multi' if accel == 'tcg' else 'whpx',
                '-m', '4096' if mode == 'build' else '2048', '-smp', '2',
                '-nodefaults', '-display', 'none', '-device', 'VGA,vgamem_mb=64,xres=1280,yres=800',
                '-monitor', 'none', '-no-reboot',
                '-serial', 'file:' + helpers.qemu_path(serial),
                '-qmp', f'tcp:127.0.0.1:{qmp_port},server=on,wait=off',
                '-blockdev', json.dumps({'driver': 'qcow2', 'file': {'driver': 'file', 'filename': helpers.qemu_path(disk)},
                                         'discard': 'unmap', 'node-name': 'rootdisk'}),
                '-device', 'virtio-blk-pci,drive=rootdisk,bootindex=1',
                '-device', 'qemu-xhci,id=usb', '-device', 'usb-tablet,bus=usb.0']
        args.extend(['-cpu', 'max' if accel == 'tcg' else
                     'qemu64,ssse3=on,sse4.1=on,sse4.2=on,popcnt=on'])
        if mode == 'build':
            args.extend(['-blockdev', json.dumps({'driver': 'vvfat', 'dir': helpers.qemu_path(seed),
                          'label': 'CIDATA', 'fat-type': 16, 'rw': False, 'read-only': True, 'node-name': 'seed'}),
                         '-device', 'virtio-blk-pci,drive=seed'])
        if net_port is not None:
            args.extend(build_network_args(net_port))
        else:
            args.extend(['-nic', 'none'])
        if file_channel is not None:
            args.extend(file_channel.qemu_args)
        if with_clipboard:
            sys.path.insert(0, str(ROOT / 'scripts'))
            import clipboard_bridge
            from runtime_supervisor import create_private_directory
            import secrets
            nonce = secrets.token_hex(16)
            private = output / 'clipboard-private'
            create_private_directory(private)
            clipboard_path = private / 'clipboard.json'
            clipboard_path.write_bytes(clipboard_bridge.configuration(nonce))
            status_path = private / 'status.json'
            status_path.write_text(json.dumps({'schema': 1, 'session_nonce': nonce, 'network': net_port is not None}), encoding='ascii')
            args.extend(['-fw_cfg', 'name=opt/pocket/clipboard,file=' + helpers.qemu_path(clipboard_path),
                         '-fw_cfg', 'name=opt/pocket/status,file=' + helpers.qemu_path(status_path)])
            port = clipboard_bridge.reserve_port()
            args.extend(clipboard_bridge.arguments(port))
            fake_clipboard = TestClipboard()
            clipboard = clipboard_bridge.Bridge(port, nonce, fake_clipboard).start()
        (output / 'command.json').write_text(json.dumps(args, indent=2), encoding='utf-8')
        with (output / 'qemu-stderr.log').open('w', encoding='utf-8') as stderr:
            proc = helpers.launch(args, stdout=subprocess.DEVNULL, stderr=stderr)
            (output / 'pid.json').write_text(json.dumps({'pid': proc.pid, 'qmp_port': qmp_port}), encoding='utf-8')
            print(json.dumps({'event': 'VM_STARTED', 'mode': mode, 'pid': proc.pid, 'output': str(output)}), flush=True)
            started = time.monotonic()
            seen = 0
            receipts = []
            screenshot = False
            timeout = 3600 if mode == 'build' else 1200
            while time.monotonic() - started < timeout:
                if serial.exists():
                    lines = helpers.complete_serial_lines(serial)
                    for line in lines[seen:]:
                        at = line.find('POCKET_')
                        if at >= 0:
                            message = line[at:].strip()
                            receipts.append(message)
                            print(message, flush=True)
                            if message.startswith('POCKET_CLIPBOARD_TEST_READY ') and clipboard is not None:
                                if not clipboard.authenticated.wait(timeout=10):
                                    raise RuntimeError('Clipboard did not authenticate the guest')
                                fake_clipboard.callback('Windows: общий текст ✓')
                            if message.startswith('POCKET_STOP_PROXY ') and network is not None:
                                network.terminate()
                                network.wait(timeout=10)
                            if message.startswith(('POCKET_DESKTOP ', 'POCKET_UI ', 'POCKET_BROWSER ')):
                                try:
                                    with socket.create_connection(('127.0.0.1', qmp_port), timeout=5) as control:
                                        name = ('desktop.ppm' if message.startswith('POCKET_UI ') else
                                                'browser.ppm' if message.startswith('POCKET_BROWSER ') else 'desktop-home.ppm')
                                        qmp_command(control, 'screendump', {'filename': helpers.qemu_path(output / name)})
                                    if message.startswith('POCKET_UI '):
                                        screenshot = True
                                except Exception as error:
                                    print(json.dumps({'event': 'SCREENSHOT_ERROR', 'error': str(error)}), flush=True)
                    seen = len(lines)
                if proc.poll() is not None:
                    break
                time.sleep(2)
            if proc.poll() is None:
                raise TimeoutError('Guest did not complete within its build/test limit')
            expected = 'POCKET_BUILD_DONE ' if mode == 'build' else 'POCKET_VERIFY_DONE '
            files_ok = (file_channel is None or
                        (share / 'windows-sentinel.txt').read_text() == 'Pocket Windows shared test\n'
                        and (share / 'Общие файлы работают.txt').is_file()
                        and (share / 'Общие файлы работают.txt').read_text(encoding='utf-8') == 'Общий файл: Linux и Windows\n'
                        and not (share / 'удалить.tmp').exists())
            clipboard_ok = clipboard is None or fake_clipboard.received == 'Linux: ответ в Windows ✓'
            result = {'mode': mode, 'accel': accel, 'exit_code': proc.returncode,
                      'network_exit_before_cleanup': network.poll() if network else None,
                      'proxy_state': fixture.state() if fixture else None,
                      'seconds': round(time.monotonic()-started, 3), 'receipts': receipts,
                      'screenshot': screenshot, 'disk': str(disk), 'shared_files_host_verified': files_ok if with_files else None,
                      'clipboard_bidirectional': clipboard_ok if with_clipboard else None,
                      'passed': proc.returncode == 0 and any(x.startswith(expected) for x in receipts)
                                and not any(x.startswith('POCKET_ERROR ') for x in receipts) and files_ok and clipboard_ok}
            (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps(result, ensure_ascii=False), flush=True)
            if not result['passed']:
                raise RuntimeError('Guest build/verification failed; inspect serial.log')
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        if mirror is not None:
            mirror.shutdown()
            mirror.server_close()
        if network is not None and network.poll() is None:
            network.terminate()
            network.wait(timeout=10)
        if fixture is not None:
            fixture.close()
        if network_log is not None:
            network_log.close()
        if file_channel is not None:
            file_channel.close()
        if clipboard is not None:
            clipboard.stop()
        for path in (clipboard_path, status_path):
            if path is not None:
                path.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--mode', choices=['build', 'verify'], default='build')
    parser.add_argument('--base', type=Path)
    parser.add_argument('--accel', choices=['whpx', 'tcg'], default='whpx')
    parser.add_argument('--proxy-config', type=Path)
    parser.add_argument('--network-exe', type=Path)
    parser.add_argument('--with-files', action='store_true')
    parser.add_argument('--with-clipboard', action='store_true')
    parser.add_argument('--desktop', choices=['lxqt', 'plasma'], default='lxqt')
    opts = parser.parse_args()
    if bool(opts.proxy_config) != bool(opts.network_exe) or opts.proxy_config and opts.mode != 'verify':
        parser.error('Proxy config and network executable are paired verification-only options')
    if (opts.with_files or opts.with_clipboard) and opts.mode != 'verify':
        parser.error('Selected-folder acceptance is verification-only')
    run(opts.output.resolve(), opts.mode, opts.base.resolve() if opts.base else None, opts.accel,
        opts.proxy_config.resolve() if opts.proxy_config else None,
        opts.network_exe.resolve() if opts.network_exe else None, opts.with_files, opts.with_clipboard, opts.desktop)
