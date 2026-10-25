"""Write an offline NoCloud seed and argv arrays; never execute QEMU or qemu-img."""
import argparse
import json
from pathlib import Path

MAC = '52:54:00:50:4c:01'
RECEIPTS = {'PL_BOOT', 'PL_INVENTORY', 'PL_NETWORK', 'PL_READY', 'PL_PROBE', 'PL_DONE', 'PL_ERROR'}


def parse_receipt(line):
    if not line.startswith('PL_'):
        return None
    if len(line) > 8192:
        raise ValueError('Receipt exceeds 8192 characters')
    kind, separator, payload = line.strip().partition(' ')
    if kind not in RECEIPTS or not separator:
        raise ValueError('Unknown receipt')
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError('Invalid receipt JSON') from error
    if not isinstance(data, dict):
        raise ValueError('Receipt must contain an object')
    return kind, data


def prepare(output, base, qemu, net_port, memory=1024, mode='probe'):
    output, base, qemu = map(Path, (output, base, qemu))
    if (not all(path.is_absolute() for path in (output, base, qemu))
            or not 1 <= net_port <= 65535 or memory not in (1024, 2048)
            or mode not in ('probe', 'inventory')):
        raise ValueError('Absolute paths, valid port, memory and mode required')
    if not base.is_file() or not qemu.is_file():
        raise ValueError('Base image and QEMU executable must exist')
    output.mkdir(parents=True, exist_ok=False)
    seed = output / 'seed'
    seed.mkdir()
    probe = Path(__file__).with_name('guest_probe.py').read_text(encoding='utf-8')
    user = {'users': [], 'disable_root': True, 'ssh_pwauth': False,
            'write_files': [{'path': '/opt/pl-probe.py', 'permissions': '0600', 'content': probe}],
            'runcmd': [['python3', '-I', '-B', '/opt/pl-probe.py', mode]]}
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(user), encoding='utf-8')
    (seed / 'meta-data').write_text(json.dumps({'instance-id': output.name,
                                              'local-hostname': 'pocket-linux-probe'}), encoding='utf-8')
    network = {'version': 2, 'ethernets': {'lan0': {
        'match': {'macaddress': MAC}, 'set-name': 'lan0', 'dhcp4': False, 'dhcp6': False,
        'accept-ra': False, 'addresses': ['192.168.127.2/24'],
        'gateway4': '192.168.127.1', 'nameservers': {'addresses': ['192.168.127.1']}}}}
    (seed / 'network-config').write_text(json.dumps(network), encoding='utf-8')
    overlay = output / 'overlay.qcow2'
    block = {'driver': 'qcow2', 'file': {'driver': 'file', 'filename': str(overlay)},
             'node-name': 'pldisk'}
    media = {'driver': 'vvfat', 'dir': str(seed), 'label': 'CIDATA', 'fat-type': 16,
             'rw': False, 'read-only': True, 'node-name': 'plseed'}
    net = {'type': 'stream', 'id': 'plnet', 'server': False,
           'addr': {'type': 'inet', 'host': '127.0.0.1', 'port': str(net_port)}}
    compact = lambda value: json.dumps(value, separators=(',', ':'))
    args = [str(qemu), '-machine', 'q35', '-accel', 'whpx', '-m', str(memory), '-smp', '2',
            '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial',
            'file:' + str(output / 'serial.log'), '-no-reboot',
            '-blockdev', compact(block), '-device', 'virtio-blk-pci,drive=pldisk',
            '-blockdev', compact(media), '-device', 'qemu-xhci,id=plseedusb',
            '-device', 'usb-storage,drive=plseed,bus=plseedusb.0,removable=on',
            '-netdev', compact(net), '-device', 'virtio-net-pci,netdev=plnet,mac=' + MAC]
    manifest = {'schema': 1, 'mode': mode, 'serial_log': str(output / 'serial.log'),
                'overlay_argv': [str(qemu.with_name('qemu-img.exe')), 'create', '-f', 'qcow2',
                                 '-F', 'qcow2', '-b', str(base), str(overlay)], 'qemu_argv': args}
    (output / 'commands.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--net-port', type=int, required=True)
    parser.add_argument('--memory', type=int, choices=(1024, 2048), default=1024)
    parser.add_argument('--mode', choices=('probe', 'inventory'), default='probe')
    options = parser.parse_args()
    prepare(options.output, options.base, options.qemu, options.net_port, options.memory, options.mode)
    print(options.output / 'commands.json')


if __name__ == '__main__':
    main()
