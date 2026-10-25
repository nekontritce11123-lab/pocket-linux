"""Run the isolated QEMU/SOCKS failure test. Only child processes and new files are changed."""
import argparse
import ctypes
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'fixture'))
sys.path.insert(0, str(HERE / 'guest'))
sys.path.insert(0, str(HERE / 'files'))
from socks_fixture import Fixture
from prepare_guest import prepare, parse_receipt


def process_memory(process):
    class Counters(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [
            (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
    result = Counters()
    result.cb = ctypes.sizeof(result)
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(process._handle)),
                                                ctypes.byref(result), result.cb)
    return {'working_set_bytes': result.WorkingSetSize, 'private_commit_bytes': result.PagefileUsage} if ok else {}


def launch(argv, **options):
    return subprocess.Popen(argv, creationflags=subprocess.CREATE_NO_WINDOW, **options)


def complete_serial_lines(path):
    # Do not count a half-written UART receipt as consumed; keep CRLF unmodified until LF arrives.
    with path.open(encoding='utf-8', errors='replace', newline='') as stream:
        return stream.read().split('\n')[:-1]


def qemu_path(path):
    # Reuse Pocket Windows' workaround for this QEMU build's ANSI file API.
    path = Path(path)
    existing = path if path.exists() else path.parent
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(existing), buf, len(buf)):
        raise OSError('Cannot obtain QEMU-compatible path')
    value = buf.value if path.exists() else str(Path(buf.value) / path.name)
    if not value.isascii():
        raise ValueError('This QEMU build needs an ASCII short path')
    return value.replace('\\', '/')


def run(output, base, qemu, accel='whpx', mode='probe', with_files=False, network_exe=None):
    if with_files and mode != 'probe':
        raise ValueError('Combined files check requires probe mode')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'accel': accel, 'mode': mode, 'phases': [], 'receipts': [], 'memory': [], 'verdict': 'incomplete'}
    children = []
    files = []
    file_channel = None
    fixture = Fixture(output / 'proxy-audit.jsonl').start()
    try:
        config = {'listen': '127.0.0.1:0', 'dns_upstream': '198.18.0.53:53',
                  'proxy': {'type': 'socks5', 'server': '127.0.0.1', 'server_port': fixture.ports['tcp_port']}}
        config_path = output / 'proxy.json'
        config_path.write_text(json.dumps(config), encoding='utf-8')
        neterr = open(output / 'network-stderr.log', 'w', encoding='utf-8'); files.append(neterr)
        network = launch([str(network_exe or HERE / 'PocketNet.exe'), '--config', str(config_path)],
                         stdout=subprocess.PIPE, stderr=neterr, text=True)
        children.append(network)
        ready_queue = queue.Queue()
        threading.Thread(target=lambda: ready_queue.put(network.stdout.readline()), daemon=True).start()
        ready = json.loads(ready_queue.get(timeout=10))
        report['network_ready'] = ready
        port = int(ready['listen'].rsplit(':', 1)[1])
        commands = prepare(output / 'guest', base, qemu, port, mode=mode)
        if with_files:
            from integration import FileChannel
            file_channel = FileChannel(output)
            file_channel.attach(commands)
        # The cloud kernel always supports virtio; a USB seed would add an unnecessary driver dependency.
        argv = commands['qemu_argv']
        argv[argv.index('-accel')+1] = 'tcg,thread=multi' if accel == 'tcg' else 'whpx'
        if accel == 'tcg':
            argv.extend(['-cpu', 'max'])
            # This bundled BIOS loops in guest SMM under TCG; WHPX already does not emulate SMM.
            argv[argv.index('-machine')+1] = 'q35,smm=off'
        usb = argv.index('qemu-xhci,id=plseedusb') - 1
        argv[usb:usb+4] = ['-device', 'virtio-blk-pci,drive=plseed,bootindex=2']
        argv[argv.index('virtio-blk-pci,drive=pldisk')] = 'virtio-blk-pci,drive=pldisk,bootindex=1'
        for index, arg in enumerate(argv):
            if arg == '-blockdev':
                block = json.loads(argv[index+1])
                if 'file' in block:
                    block['file']['filename'] = qemu_path(block['file']['filename'])
                if 'dir' in block:
                    block['dir'] = qemu_path(block['dir'])
                argv[index+1] = json.dumps(block, separators=(',', ':'))
            elif arg == '-serial':
                argv[index+1] = 'file:' + qemu_path(output / 'guest' / 'serial.log')
        argv.extend(['-L', qemu_path(qemu.parent / 'share')])
        report['qemu_argv'] = argv
        overlay_argv = commands['overlay_argv']
        overlay_argv[-2:] = [qemu_path(base), qemu_path(output / 'guest' / 'overlay.qcow2')]
        subprocess.run(overlay_argv, capture_output=True, timeout=20, check=True)
        qerr = open(output / 'qemu-stderr.log', 'w', encoding='utf-8'); files.append(qerr)
        vm = launch(argv, stdout=subprocess.DEVNULL, stderr=qerr)
        children.append(vm)
        print(json.dumps({'event': 'VM_STARTED', 'pid': vm.pid, 'output': str(output)}), flush=True)
        started, guest_ready, last_sample = time.monotonic(), None, 0
        phase = 'boot'
        seen = 0
        serial_path = Path(commands['serial_log'])
        while time.monotonic() - started < 300:
            now = time.monotonic()
            if serial_path.exists():
                lines = complete_serial_lines(serial_path)
                for line in lines[seen:]:
                    if file_channel is not None and file_channel.accept(line, phase):
                        continue
                    pos = line.find('PL_')
                    if pos < 0:
                        continue
                    try:
                        receipt = parse_receipt(line[pos:])
                    except ValueError:
                        continue
                    if receipt:
                        kind, data = receipt
                        report['receipts'].append({'kind': kind, 'data': data, 'phase': phase,
                                                   'host_elapsed': round(now-started, 3)})
                        if kind == 'PL_READY' and guest_ready is None:
                            guest_ready, phase = now, 'healthy'
                            report['phases'].append({'name': phase, 'at': round(now-started, 3), 'state': fixture.state()})
                            print(json.dumps({'event': 'GUEST_READY'}), flush=True)
                seen = len(lines)
            if guest_ready is not None and mode == 'probe':
                elapsed = now-guest_ready
                next_phase = ('network_killed' if elapsed >= 60 else 'restored' if elapsed >= 40
                              else 'proxy_down' if elapsed >= 20 else 'healthy')
                if next_phase != phase:
                    if next_phase == 'proxy_down': fixture.set_available(False)
                    elif next_phase == 'restored': fixture.set_available(True)
                    elif next_phase == 'network_killed': network.kill(); network.wait(timeout=5)
                    phase = next_phase
                    report['phases'].append({'name': phase, 'at': round(now-started, 3), 'state': fixture.state()})
                    print(json.dumps({'event': 'PHASE', 'name': phase, 'state': fixture.state()}), flush=True)
            if now-last_sample >= 5:
                report['memory'].append({'at': round(now-started, 3), 'phase': phase,
                                         'network': process_memory(network), 'qemu': process_memory(vm)})
                last_sample = now
            if vm.poll() is not None:
                break
            time.sleep(0.2)
        report['vm_exit'] = vm.poll()
        report['fixture_final'] = fixture.state()
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        probes = [r for r in report['receipts'] if r['kind'] == 'PL_PROBE']
        checks = {}
        for stage in (() if mode == 'inventory' else ('healthy', 'proxy_down', 'restored', 'network_killed')):
            boundary = next((p['at'] for p in report['phases'] if p['name'] == stage), float('inf'))
            for name in ('tcp', 'udp', 'dns', 'dns_burst', 'direct_dns', 'ipv6', 'forbidden_public'):
                samples = [r for r in probes if r['phase'] == stage and r['data']['name'] == name
                           and r['host_elapsed'] > boundary+3]
                expected = stage in ('healthy', 'restored') and name not in ('ipv6','forbidden_public')
                checks[stage+':'+name] = bool(samples) and all(r['data']['ok'] == expected for r in samples)
        checks['guest_completed'] = any(r['kind'] == 'PL_DONE' for r in report['receipts'])
        checks['normal_shutdown'] = report['vm_exit'] == 0
        if file_channel is not None:
            checks.update(file_channel.checks())
            report['files_receipts'] = file_channel.receipts
        if mode == 'inventory':
            checks['inventory_received'] = any(r['kind'] == 'PL_INVENTORY' for r in report['receipts'])
        report['checks'] = checks
        report['verdict'] = 'passed' if all(checks.values()) else 'failed'
        print(json.dumps({'event': 'RESULT', 'verdict': report['verdict'], 'checks': checks}), flush=True)
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'detail': str(error)[:300]}
        raise
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        fixture.close()
        if file_channel is not None:
            try:
                file_channel.close()
            except Exception as error:
                report['verdict'] = 'failed'
                report['files_cleanup_error'] = type(error).__name__
            serial = output / 'guest' / 'serial.log'
            if serial.exists():
                serial.write_text(file_channel.safe_text(serial.read_text(encoding='utf-8', errors='replace')), encoding='utf-8')
        for stream in files:
            stream.close()
        result_text = json.dumps(report, indent=2)
        if file_channel is not None:
            result_text = file_channel.safe_text(result_text)
        (output / 'result.json').write_text(result_text, encoding='utf-8')
    return report['verdict'] == 'passed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--accel', choices=('whpx','tcg'), default='whpx')
    parser.add_argument('--mode', choices=('probe','inventory'), default='probe')
    parser.add_argument('--with-files', action='store_true')
    parser.add_argument('--network-exe', type=Path)
    options = parser.parse_args()
    sys.exit(0 if run(options.output.resolve(), options.base.resolve(), options.qemu.resolve(), options.accel, options.mode, options.with_files, options.network_exe) else 1)
