"""Attach an independent, restricted SMB channel to the existing proxy test VM."""
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent

COMBINED_SCRIPT = '''import importlib.util
import subprocess
import threading
import time

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

netprobe = load('pl_netprobe', '/opt/pl-probe.py')
fileprobe = load('pl_fileprobe', '/opt/pl-files-probe.py')

def files_after_delay():
    time.sleep(30)
    try:
        fileprobe.main(poweroff=False)
    except Exception as error:
        netprobe.emit('PL_ERROR', error=type(error).__name__)

thread = threading.Thread(target=files_after_delay, daemon=True)
thread.start()
try:
    netprobe.main()
except Exception as error:
    netprobe.emit('PL_ERROR', error=type(error).__name__)
finally:
    thread.join(timeout=60)
    if thread.is_alive():
        netprobe.emit('PL_ERROR', error='FilesThreadTimeout')
    try:
        subprocess.run(['systemctl', 'poweroff'], timeout=10, check=False)
    except Exception:
        pass
'''


class FileChannel:
    def __init__(self, output_dir):
        # Delay this import: run_files_probe reuses helpers defined by run_probe.
        sys.path.insert(0, str(HERE))
        import run_files_probe
        self.helpers = run_files_probe
        self.output = Path(output_dir) / 'files'
        self.output.mkdir(exist_ok=False)
        self.share = self.output / 'share'
        self.share.mkdir()
        (self.share / 'windows-sentinel.txt').write_text(run_files_probe.WINDOWS_TEXT, encoding='utf-8', newline='')
        self.request = run_files_probe.host_request(self.share)
        self.helper = None
        self.receipts, self.ready = [], None
        self.attached, self.duplicate = False, False
        try:
            executable = HERE.parents[1] / 'runtime/host-files/HostFiles.exe'
            self.helper = run_files_probe.launch([str(executable)], stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.helper.stdin.write(json.dumps(self.request, ensure_ascii=True).encode('ascii') + b'\n')
            self.helper.stdin.flush()
            self.ready = run_files_probe.read_host_ready(self.helper, self.request)
        except Exception:
            self.close()
            raise

    def attach(self, commands):
        if self.attached:
            raise ValueError('File channel already attached')
        seed = Path(commands['serial_log']).parent / 'seed'
        user_path, network_path = seed / 'user-data', seed / 'network-config'
        user = json.loads(user_path.read_text(encoding='utf-8').split('\n', 1)[1])
        network = json.loads(network_path.read_text(encoding='utf-8'))
        if 'files0' in network['ethernets'] or any('id=plfiles' in arg for arg in commands['qemu_argv']):
            raise ValueError('File network already present')
        config = {key: self.request[key] for key in ('session_nonce', 'username', 'password')}
        user['write_files'].extend([
            {'path': '/opt/pl-files-probe.py', 'permissions': '0600',
             'content': (HERE / 'guest_files_probe.py').read_text(encoding='utf-8')},
            {'path': '/opt/pl-files-config.json', 'permissions': '0600', 'content': json.dumps(config)},
            {'path': '/opt/pl-combined.py', 'permissions': '0600', 'content': COMBINED_SCRIPT}])
        user['runcmd'] = [['python3', '-I', '-B', '/opt/pl-combined.py']]
        network['ethernets']['files0'] = {
            'match': {'macaddress': '52:54:00:50:4c:03'}, 'set-name': 'files0',
            'dhcp4': False, 'dhcp6': False, 'accept-ra': False, 'addresses': ['192.168.234.15/24']}
        user_path.write_text('#cloud-config\n' + json.dumps(user), encoding='utf-8')
        network_path.write_text(json.dumps(network), encoding='utf-8')
        commands['qemu_argv'].extend([
            '-netdev', 'user,id=plfiles,restrict=on,ipv6=off,net=192.168.234.0/24,'
            'host=192.168.234.2,dhcpstart=192.168.234.15,'
            'guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:' + str(self.ready['port']),
            '-device', 'virtio-net-pci,netdev=plfiles,mac=52:54:00:50:4c:03'])
        self.attached = True

    def accept(self, line, phase):
        position = line.find('PL_FILES ')
        if position < 0:
            return False
        try:
            receipt = self.helpers.parse_files_receipt(line[position:], self.request['session_nonce'])
        except ValueError:
            return False
        if self.receipts:
            self.duplicate = True
        else:
            receipt = json.loads(self.safe_text(json.dumps(receipt)))
            self.receipts.append({'phase': phase, 'data': receipt})
        return True

    def checks(self):
        def content(name, expected):
            try:
                path = self.share / name
                return (path.stat().st_size == len(expected.encode('utf-8'))
                        and path.read_text(encoding='utf-8') == expected)
            except (OSError, UnicodeError):
                return False
        return {
            'files_single_receipt': len(self.receipts) == 1 and not self.duplicate,
            'files_guest_operations': bool(self.receipts) and self.receipts[0]['data']['ok'],
            'files_during_proxy_down': bool(self.receipts) and self.receipts[0]['phase'] == 'proxy_down',
            'files_windows_sentinel': content('windows-sentinel.txt', self.helpers.WINDOWS_TEXT),
            'files_windows_result': content(self.helpers.FINAL_NAME, self.helpers.LINUX_TEXT),
            'files_temps_deleted': not (self.share / 'linux-write.tmp').exists()
                                  and not (self.share / self.helpers.DELETE_NAME).exists()}

    def safe_text(self, text):
        return self.helpers.scrub(text, self.request)

    def close(self):
        if self.helper is not None:
            self.helpers.stop_owned(self.helper, graceful=True)
            self.helper = None
