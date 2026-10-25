"""Run a new, isolated SMB/guest filesystem check; never load host sharing profiles."""
import argparse
import json
from pathlib import Path
import queue
import re
import secrets
import subprocess
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / 'guest'))
from prepare_guest import prepare
from run_probe import qemu_path, launch
from guest_files_probe import WINDOWS_TEXT, LINUX_TEXT, FINAL_NAME, DELETE_NAME

FLAGS = ('read_ok', 'write_ok', 'rename_ok', 'delete_ok', 'unmount_ok')


def host_request(share):
    return {'schema': 1, 'session_nonce': secrets.token_hex(16),
            'username': 'WCP_' + secrets.token_hex(12), 'password': secrets.token_hex(32),
            'shares': [{'name': 'PC_SPIKE', 'path': str(share)}], 'protected': []}


def read_host_ready(process, request):
    ready_queue = queue.Queue(maxsize=1)
    def read():
        try:
            ready_queue.put(process.stdout.readline(4097))
        except OSError:
            ready_queue.put(b'')
    threading.Thread(target=read, daemon=True).start()
    raw = ready_queue.get(timeout=10)
    if len(raw) > 4096:
        raise ValueError('HostFiles receipt too large')
    try:
        ready = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError('Invalid HostFiles receipt') from error
    if (type(ready) is not dict or set(ready) != {'schema', 'ok', 'session_nonce', 'port', 'share_count'}
            or type(ready['schema']) is not int or ready['schema'] != 1 or ready['ok'] is not True
            or ready['session_nonce'] != request['session_nonce'] or type(ready['share_count']) is not int
            or ready['share_count'] != 1 or type(ready['port']) is not int or not 49152 <= ready['port'] <= 65535):
        raise ValueError('HostFiles did not confirm this single-share session')
    return ready


def prepare_files_guest(output, base, qemu, port, request):
    commands = prepare(output, base, qemu, port, mode='inventory')
    seed = output / 'seed'
    config = {key: request[key] for key in ('session_nonce', 'username', 'password')}
    user = {'users': [], 'disable_root': True, 'ssh_pwauth': False,
            'write_files': [
                {'path': '/opt/pl-files-probe.py', 'permissions': '0600',
                 'content': (HERE / 'guest_files_probe.py').read_text(encoding='utf-8')},
                {'path': '/opt/pl-files-config.json', 'permissions': '0600', 'content': json.dumps(config)}],
            'runcmd': [['python3', '-I', '-B', '/opt/pl-files-probe.py']]}
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(user), encoding='utf-8')
    network_path = seed / 'network-config'
    network = json.loads(network_path.read_text())
    nic = network['ethernets']['lan0']
    nic['addresses'] = ['192.168.234.15/24']
    nic.pop('gateway4')
    nic.pop('nameservers')
    network_path.write_text(json.dumps(network), encoding='utf-8')
    argv = commands['qemu_argv']
    argv[argv.index('-netdev') + 1] = (
        'user,id=plnet,restrict=on,ipv6=off,net=192.168.234.0/24,'
        'host=192.168.234.2,dhcpstart=192.168.234.15,'
        'guestfwd=tcp:192.168.234.4:445-tcp:127.0.0.1:' + str(port))
    usb = argv.index('qemu-xhci,id=plseedusb') - 1
    argv[usb:usb + 4] = ['-device', 'virtio-blk-pci,drive=plseed,bootindex=2']
    argv[argv.index('virtio-blk-pci,drive=pldisk')] = 'virtio-blk-pci,drive=pldisk,bootindex=1'
    for index, arg in enumerate(argv):
        if arg == '-blockdev':
            block = json.loads(argv[index + 1])
            if 'file' in block:
                block['file']['filename'] = qemu_path(block['file']['filename'])
            if 'dir' in block:
                block['dir'] = qemu_path(block['dir'])
            argv[index + 1] = json.dumps(block, separators=(',', ':'))
        elif arg == '-serial':
            argv[index + 1] = 'file:' + qemu_path(output / 'serial.log')
    argv.extend(['-L', qemu_path(qemu.parent / 'share')])
    commands['overlay_argv'][-2:] = [qemu_path(base), qemu_path(output / 'overlay.qcow2')]
    (output / 'commands.json').write_text(json.dumps(commands, indent=2), encoding='utf-8')
    return commands


def parse_files_receipt(line, nonce):
    if not line.startswith('PL_FILES '):
        return None
    if len(line) > 2048:
        raise ValueError('Files receipt too large')
    try:
        data = json.loads(line[len('PL_FILES '):])
    except ValueError as error:
        raise ValueError('Invalid files receipt JSON') from error
    if (type(data) is not dict or set(data) != {'schema', 'session_nonce', 'ok', 'stage', 'detail', *FLAGS}
            or type(data['schema']) is not int or data['schema'] != 1 or data['session_nonce'] != nonce
            or type(data['ok']) is not bool or any(type(data[key]) is not bool for key in FLAGS)
            or type(data['stage']) is not str or re.fullmatch('[a-z]{1,16}', data['stage']) is None
            or type(data['detail']) is not str or len(data['detail']) > 240
            or data['ok'] != all(data[key] for key in FLAGS)):
        raise ValueError('Files receipt does not match current session')
    return data


def scrub(text, request):
    for key in ('username', 'password'):
        text = text.replace(request[key], '[redacted]')
    return text


def stop_owned(process, graceful=False):
    if process.poll() is None:
        if graceful and process.stdin:
            try:
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        else:
            process.kill()
        process.wait(timeout=10)
    for name in ('stdin', 'stdout', 'stderr'):
        stream = getattr(process, name, None)
        if stream is not None:
            stream.close()


def run(output, base, qemu, host_files):
    if not all(path.is_file() for path in (base, qemu, host_files)):
        raise ValueError('Base image, QEMU and HostFiles executable must exist')
    output.mkdir(parents=True, exist_ok=False)
    share = output / 'share'
    share.mkdir()
    (share / 'windows-sentinel.txt').write_text(WINDOWS_TEXT, encoding='utf-8', newline='')
    request = host_request(share)
    report = {'schema': 1, 'verdict': 'failed', 'checks': {}, 'receipt': None}
    helper = overlay_process = vm = None
    stage = 'host_start'
    try:
        helper = launch([str(host_files)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        helper.stdin.write(json.dumps(request, ensure_ascii=True).encode('ascii') + b'\n')
        helper.stdin.flush()
        ready = read_host_ready(helper, request)
        report['host_ready'] = ready
        stage = 'prepare'
        commands = prepare_files_guest(output / 'guest', base, qemu, ready['port'], request)
        stage = 'overlay'
        overlay_process = launch(commands['overlay_argv'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        overlay_process.communicate(timeout=20)
        if overlay_process.returncode:
            raise RuntimeError('Overlay creation failed')
        stage = 'guest'
        with (output / 'qemu-stderr.log').open('w', encoding='utf-8') as qerr:
            vm = launch(commands['qemu_argv'], stdout=subprocess.DEVNULL, stderr=qerr)
            print(json.dumps({'event': 'VM_STARTED', 'pid': vm.pid, 'output': str(output)}), flush=True)
            try:
                report['vm_exit'] = vm.wait(timeout=120)
            except subprocess.TimeoutExpired:
                report['timeout'] = True
                stop_owned(vm)
                report['vm_exit'] = vm.returncode
        stage = 'receipt'
        serial_path = Path(commands['serial_log'])
        if serial_path.exists():
            with serial_path.open(encoding='utf-8', errors='replace') as stream:
                serial = stream.read(4 * 1024 * 1024)
            for line in serial.splitlines():
                position = line.find('PL_FILES ')
                if position >= 0:
                    try:
                        data = parse_files_receipt(line[position:], request['session_nonce'])
                    except ValueError:
                        continue
                    if report['receipt'] is not None:
                        raise ValueError('Duplicate files receipt')
                    report['receipt'] = data
        result = share / FINAL_NAME
        report['checks'] = {
            'guest_operations': report['receipt'] is not None and report['receipt']['ok'],
            'windows_sentinel_intact': (share / 'windows-sentinel.txt').read_text(encoding='utf-8') == WINDOWS_TEXT,
            'windows_sees_linux_content': result.is_file() and result.read_text(encoding='utf-8') == LINUX_TEXT,
            'temporary_files_deleted': not (share / 'linux-write.tmp').exists() and not (share / DELETE_NAME).exists(),
            'normal_shutdown': report.get('vm_exit') == 0 and not report.get('timeout', False)}
        report['verdict'] = 'passed' if all(report['checks'].values()) else 'failed'
    except Exception as error:
        report['error'] = {'stage': stage, 'type': type(error).__name__}
    finally:
        for process in (vm, overlay_process, helper):
            if process is not None:
                try:
                    stop_owned(process, graceful=process is helper)
                except Exception as error:
                    report['cleanup_error'] = type(error).__name__
                    report['verdict'] = 'failed'
        for path in (output / 'qemu-stderr.log', output / 'guest/serial.log'):
            if path.exists():
                with path.open(encoding='utf-8', errors='replace') as stream:
                    text = stream.read(4 * 1024 * 1024)
                path.write_text(scrub(text, request), encoding='utf-8')
        safe_report = scrub(json.dumps(report, ensure_ascii=True, indent=2), request)
        (output / 'result.json').write_text(safe_report, encoding='utf-8')
    print(json.dumps({'event': 'RESULT', 'verdict': report['verdict'], 'checks': report['checks']}), flush=True)
    return report['verdict'] == 'passed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'base', 'qemu', 'host-files'):
        parser.add_argument('--' + name, type=Path, required=True)
    options = parser.parse_args()
    sys.exit(0 if run(options.output.resolve(), options.base.resolve(), options.qemu.resolve(),
                     options.host_files.resolve()) else 1)
