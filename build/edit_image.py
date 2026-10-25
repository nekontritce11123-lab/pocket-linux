"""Patch only a new overlay of our Linux build, using a disposable offline Debian helper."""
import argparse
import base64
import importlib.util
import json
import hashlib
from pathlib import Path
import subprocess
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('probe_helpers', ROOT / 'prototype/run_probe.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_desktop import qmp_command

PATCH_SCRIPT = '''import base64, hashlib, json, os, pathlib, subprocess, time
mount = pathlib.Path('/mnt/target')
mounted = False
try:
    mount.mkdir(exist_ok=True)
    print('POCKET_EDIT_READY', flush=True)
    device = pathlib.Path('/dev/disk/by-id/virtio-PLPATCH-part1')
    for _ in range(60):
        if device.exists(): break
        time.sleep(1)
    assert device.exists(), 'Target disk did not arrive'
    subprocess.run(['mount', str(device), str(mount)], check=True)
    mounted = True
    assert (mount/'var/lib/pocket-build/artifacts.json').is_file(), 'Not a Pocket Linux build'
    grub = mount/'boot/grub/grub.cfg'
    if grub.is_file():
        print('POCKET_GRUB ' + json.dumps([line for line in grub.read_text().splitlines()
              if line.startswith(('menuentry ', 'submenu ', '\\tmenuentry '))]), flush=True)
    data = json.loads(pathlib.Path('/opt/patch.json').read_text())
    for item in data:
        relative = pathlib.PurePosixPath(item['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        target = mount.joinpath(*relative.parts)
        for parent in [target, *target.parents]:
            if parent == mount:
                break
            assert not parent.is_symlink(), 'Patch refuses symlink traversal'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(item['content']))
        target.chmod(int(item.get('mode', '0644'), 8))
        if relative.parts[:2] == ('home', 'pocket'):
            os.chown(target, 1000, 1000)
    icons = mount/'opt/pocket-build/kf6-breeze-icon-theme.deb'
    if icons.exists():
        assert hashlib.sha256(icons.read_bytes()).hexdigest() == 'e76846b881c36c74f889fc85b5957dfafd35c3c8c9547da4a94684037d32f88f'
        subprocess.run(['chroot', str(mount), 'dpkg', '-i', '/opt/pocket-build/kf6-breeze-icon-theme.deb'], check=True)
        icons.unlink()
    if any(item['path'] == 'etc/default/grub.d/99-pocket.cfg' for item in data):
        for name in ('dev', 'proc', 'sys'):
            subprocess.run(['mount', '--bind', '/'+name, str(mount/name)], check=True)
        try:
            subprocess.run(['chroot', str(mount), '/usr/sbin/update-grub'], check=True)
        finally:
            for name in ('sys', 'proc', 'dev'):
                subprocess.run(['umount', str(mount/name)], check=True)
    for unit in ('pocket-clipboard.service', 'pocket-status.service', 'pocket-verify.service'):
        if any(item['path'] == 'etc/systemd/system/' + unit for item in data):
            subprocess.run(['systemctl', '--root', str(mount), 'enable', unit], check=True)
    os.sync()
    subprocess.run(['umount', str(mount)], check=True)
    mounted = False
    print('POCKET_EDIT_DONE ' + json.dumps({'files':len(data)}), flush=True)
except Exception as e:
    print('POCKET_ERROR ' + json.dumps({'stage':'offline-edit','error':repr(e)}), flush=True)
finally:
    if mounted:
        subprocess.run(['umount', str(mount)])
    subprocess.run(['systemctl','poweroff'])
'''


def edit(base, output, manifest):
    output.mkdir(parents=True, exist_ok=False)
    base = base.resolve(strict=True)
    scratch = ROOT.parent / 'Разработка/Служебное/_temp/2026-10-25-pocket-linux/desktop-build'
    if not base.is_relative_to(scratch.resolve()):
        raise ValueError('Only a fresh image in this task build directory can be edited')
    qemu = ROOT / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe'
    seed = output / 'seed'
    seed.mkdir()
    patch = []
    for item in json.loads(manifest.read_text(encoding='utf-8')):
        relative = Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Relative guest path required')
        patch.append({'path': relative.as_posix(), 'mode': item.get('mode', '0644'),
                      'content': base64.b64encode(Path(item['source']).read_bytes()).decode('ascii')})
    user = {'users': [], 'disable_root': True, 'write_files': [
        {'path': '/opt/patch.json', 'permissions': '0600', 'content': json.dumps(patch)},
        {'path': '/opt/patch.py', 'permissions': '0600', 'content': PATCH_SCRIPT}],
        'runcmd': [['python3', '-I', '-B', '/opt/patch.py']]}
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(user), encoding='utf-8')
    (seed / 'meta-data').write_text(json.dumps({'instance-id': output.name}), encoding='utf-8')
    (seed / 'network-config').write_text(json.dumps({'version': 2, 'ethernets': {'stub': {
        'match': {'macaddress': '52:54:00:50:4c:09'}, 'dhcp4': False, 'dhcp6': False,
        'accept-ra': False, 'addresses': ['192.168.234.15/24']}}}), encoding='utf-8')
    disks = [('helper', ROOT / 'images/debian-13-genericcloud-amd64.qcow2'), ('edited', base)]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        qmp_port = sock.getsockname()[1]
    args = [str(qemu), '-L', helpers.qemu_path(qemu.parent / 'share'), '-machine', 'q35,smm=off',
            '-accel', 'whpx', '-m', '1024', '-smp', '2', '-nodefaults', '-display', 'none',
            '-netdev', 'user,id=stub,restrict=on,ipv6=off,net=192.168.234.0/24',
            '-device', 'virtio-net-pci,netdev=stub,mac=52:54:00:50:4c:09',
            '-device', 'pcie-root-port,id=patchport,chassis=3,slot=3',
            '-monitor', 'none', '-no-reboot', '-serial', 'file:' + helpers.qemu_path(output / 'serial.log')]
    args += ['-qmp', f'tcp:127.0.0.1:{qmp_port},server=on,wait=off']
    for index, (name, source) in enumerate(disks):
        target = output / (name + '.qcow2')
        subprocess.run([str(qemu.with_name('qemu-img.exe')), 'create', '-f', 'qcow2', '-F', 'qcow2',
                        '-b', helpers.qemu_path(source), helpers.qemu_path(target)], check=True, capture_output=True)
        if index == 0:
            args += ['-blockdev', json.dumps({'driver': 'qcow2', 'file': {'driver': 'file', 'filename': helpers.qemu_path(target)},
                                          'node-name': name}), '-device', f'virtio-blk-pci,drive={name},bootindex={index+1}']
    args += ['-blockdev', json.dumps({'driver': 'vvfat', 'dir': helpers.qemu_path(seed), 'label': 'CIDATA',
                                     'fat-type': 16, 'rw': False, 'read-only': True, 'node-name': 'seed'}),
             '-device', 'virtio-blk-pci,drive=seed']
    with (output / 'qemu-stderr.log').open('w') as error:
        proc = helpers.launch(args, stdout=subprocess.DEVNULL, stderr=error)
        (output / 'pid.json').write_text(json.dumps({'pid': proc.pid, 'qmp_port': qmp_port}))
        try:
            deadline, attached = time.monotonic() + 180, False
            while proc.poll() is None and time.monotonic() < deadline:
                log = output / 'serial.log'
                if not attached and log.exists() and 'POCKET_EDIT_READY' in log.read_text(errors='replace'):
                    commands = [('blockdev-add', {'driver': 'qcow2', 'file': {'driver': 'file',
                                 'filename': helpers.qemu_path(output / 'edited.qcow2')}, 'node-name': 'edited'}),
                                ('device_add', {'driver': 'virtio-blk-pci', 'drive': 'edited', 'serial': 'PLPATCH', 'id': 'patchdisk', 'bus': 'patchport'})]
                    for command, arguments in commands:
                        with socket.create_connection(('127.0.0.1', qmp_port), timeout=5) as control:
                            qmp_command(control, command, arguments)
                    attached = True
                time.sleep(1)
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
    serial = (output / 'serial.log').read_text(encoding='utf-8', errors='replace')
    passed = proc.returncode == 0 and 'POCKET_EDIT_DONE ' in serial and 'POCKET_ERROR ' not in serial
    result = {'passed': passed, 'source': str(base), 'output': str(output / 'edited.qcow2'),
              'patch': [{'path': item['path'], 'mode': item['mode'],
                         'sha256': hashlib.sha256(base64.b64decode(item['content'])).hexdigest()} for item in patch]}
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k != 'patch'}), flush=True)
    if not passed:
        raise RuntimeError('Offline image edit failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    options = parser.parse_args()
    edit(options.base, options.output, options.manifest)
