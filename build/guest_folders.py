"""Mount only the ephemeral SMB shares declared by Pocket's QEMU fw_cfg channel."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time

MAX_CONFIG_BYTES = 8192
FW_CONFIG = Path('/sys/firmware/qemu_fw_cfg/by_name/opt/pocket/files/raw')
MOUNT_ROOT = Path('/mnt/windows')
RUN_ROOT = Path('/run/pocket-files')


def guard_guest():
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('Run only as root inside Pocket Linux, never on Windows.')


def parse_config(raw):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('Invalid files configuration size')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate files configuration field')
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid files configuration JSON') from None
    if (type(value) is not dict or set(value) != {'schema', 'session_nonce', 'server', 'username', 'password', 'shares'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['session_nonce'], str) or not re.fullmatch('[a-f0-9]{32}', value['session_nonce'])
            or value['server'] != '192.168.234.4'
            or not isinstance(value['username'], str) or not re.fullmatch('WCP_[A-Za-z0-9_]{1,32}', value['username'])
            or not isinstance(value['password'], str) or not re.fullmatch('[a-f0-9]{64}', value['password'])
            or not isinstance(value['shares'], list) or not 1 <= len(value['shares']) <= 64
            or any(not isinstance(name, str) or not re.fullmatch('PC_[A-Za-z0-9_]{1,48}', name) for name in value['shares'])
            or len({name.casefold() for name in value['shares']}) != len(value['shares'])):
        raise ValueError('Invalid files configuration fields')
    return value


def mount_arguments(config, share, credentials, uid, gid):
    config = parse_config(json.dumps(config).encode('utf-8'))
    path = PurePosixPath(Path(credentials).as_posix())
    if (share not in config['shares'] or path.parent != PurePosixPath('/run/pocket-files')
            or not re.fullmatch('credentials-[A-Za-z0-9_-]+', path.name)
            or type(uid) is not int or type(gid) is not int or not 1 <= uid <= 0x7fffffff or not 1 <= gid <= 0x7fffffff):
        raise ValueError('Invalid mount parameters')
    options = ['credentials=' + str(path), 'vers=2.1', 'sec=ntlmssp', 'sign', 'port=445',
               'uid=' + str(uid), 'gid=' + str(gid), 'forceuid', 'forcegid',
               'file_mode=0644', 'dir_mode=0755', 'iocharset=utf8', 'mapchars', 'nosuid', 'nodev', 'soft']
    return ['/usr/sbin/mount.cifs', '//' + config['server'] + '/' + share,
            str(PurePosixPath('/mnt/windows') / share), '-o', ','.join(options)]


def mount_with_retry(arguments, deadline):
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=min(15, remaining), check=False)
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        if attempt != 2:
            time.sleep(min(2, max(0, deadline - time.monotonic())))
    return False


def checked_directory(path, mode):
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('Mount directories cannot be symlinks')
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise ValueError('Mount directories must be root-owned')
    path.chmod(mode)


def mount_table():
    result = {}
    for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines():
        before, separator, after = line.partition(' - ')
        fields, filesystem = before.split(), after.split()
        if separator and len(fields) >= 5 and len(filesystem) >= 2:
            result[fields[4]] = (filesystem[0], filesystem[1])
    return result


def remove_empty_mountpoints():
    checked_directory(MOUNT_ROOT, 0o755)
    mounted = mount_table()
    for target in MOUNT_ROOT.iterdir():
        if not re.fullmatch(r'PC_(?:[A-Z]|[0-9]{2})', target.name) or str(target) in mounted:
            continue
        try:
            info = target.lstat()
            if stat.S_ISDIR(info.st_mode) and info.st_uid == 0:
                # rmdir preserves nonempty folders, links and any user data beneath a former mount.
                target.rmdir()
        except OSError:
            pass


def mount_selected(config):
    import pwd
    pocket = pwd.getpwnam('pocket')
    checked_directory(RUN_ROOT, 0o700)
    checked_directory(MOUNT_ROOT, 0o755)
    mounted, failed = [], []
    descriptor, name = tempfile.mkstemp(prefix='credentials-', dir=RUN_ROOT)
    credentials = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='ascii', newline='\n') as stream:
            stream.write('username=' + config['username'] + '\npassword=' + config['password'] + '\n')
        deadline = time.monotonic() + 40
        for share in config['shares']:
            target = MOUNT_ROOT / share
            table = mount_table()
            source = '//' + config['server'] + '/' + share
            if str(target) in table:
                (mounted if table[str(target)] == ('cifs', source) else failed).append(share)
                continue
            try:
                checked_directory(target, 0o755)
                if any(target.iterdir()):
                    failed.append(share)
                    continue
                arguments = mount_arguments(config, share, credentials, pocket.pw_uid, pocket.pw_gid)
                success = mount_with_retry(arguments, deadline)
                # A successful process exit alone does not prove the intended share was mounted.
                success = success and mount_table().get(str(target)) == ('cifs', source)
                (mounted if success else failed).append(share)
            except (OSError, ValueError):
                failed.append(share)
    finally:
        credentials.unlink(missing_ok=True)
    return mounted, failed


def prepare_shortcuts():
    import pwd
    pocket = pwd.getpwnam('pocket')
    home = Path(pocket.pw_dir)
    if home != Path('/home/pocket') or home.is_symlink():
        raise ValueError('Unexpected Pocket home')
    checked_directory(MOUNT_ROOT, 0o755)
    shortcut = home / 'Windows'
    if not shortcut.exists() and not shortcut.is_symlink():
        shortcut.symlink_to(MOUNT_ROOT, target_is_directory=True)
        os.lchown(shortcut, pocket.pw_uid, pocket.pw_gid)
    # Existing user-created files/directories are preserved; the desktop entry always targets the mount root.
    desktop = home / 'Desktop'
    if desktop.is_symlink():
        raise ValueError('Desktop cannot be a symlink')
    desktop.mkdir(mode=0o755, exist_ok=True)
    os.chown(desktop, pocket.pw_uid, pocket.pw_gid)
    entry = desktop / 'pocket-windows-files.desktop'
    if entry.is_symlink():
        raise ValueError('Desktop entry cannot be a symlink')
    content = ('[Desktop Entry]\nType=Application\nName=Windows Files\nName[ru]=Файлы Windows\n'
               'Exec=xdg-open /mnt/windows\nIcon=folder-shared\nTerminal=false\nCategories=Utility;\n')
    if not entry.is_file() or entry.read_text(encoding='utf-8') != content:
        entry.write_text(content, encoding='utf-8')
    os.chown(entry, pocket.pw_uid, pocket.pw_gid)
    entry.chmod(0o755)


def emit(result):
    line = 'POCKET_FILES ' + json.dumps(result, ensure_ascii=True, separators=(',', ':')) + '\n'
    sys.stdout.write(line)
    sys.stdout.flush()
    try:
        with Path('/dev/ttyS0').open('w', encoding='ascii') as serial:
            serial.write(line)
            serial.flush()
    except OSError:
        pass


def main():
    result = {'schema': 1, 'session_nonce': '', 'status': 'failed', 'mounted': [], 'failed': [], 'code': 'initializing'}
    try:
        guard_guest()
        if sys.argv[1:] == ['--prepare-shortcuts']:
            # Image preparation only: the root runtime service never rewrites user-owned desktop files.
            prepare_shortcuts()
            result.update(status='off', code='shortcuts_prepared')
            emit(result)
            return 0
        if sys.argv[1:]:
            raise ValueError('Unsupported files helper arguments')
        remove_empty_mountpoints()
        module = subprocess.run(['/usr/sbin/modprobe', 'qemu_fw_cfg'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=False)
        if module.returncode:
            result['code'] = 'fw_cfg_unavailable'
            emit(result)
            return 1
        if not FW_CONFIG.is_file():
            result.update(status='off', code='not_selected')
            emit(result)
            return 0
        with FW_CONFIG.open('rb') as stream:
            config = parse_config(stream.read(MAX_CONFIG_BYTES + 1))
        result['session_nonce'] = config['session_nonce']
        module = subprocess.run(['/usr/sbin/modprobe', 'cifs'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=False)
        if module.returncode:
            result['code'] = 'cifs_unavailable'
        else:
            result['mounted'], result['failed'] = mount_selected(config)
            result.update(status='ready' if not result['failed'] else 'failed',
                          code='mounted' if not result['failed'] else 'mount_failed')
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired):
        # Never serialize command exceptions, credentials or captured mount.cifs output.
        result.update(status='failed', code='configuration_or_mount_failed')
    emit(result)
    return 0 if result['status'] == 'ready' else 1


if __name__ == '__main__':
    sys.exit(main())
