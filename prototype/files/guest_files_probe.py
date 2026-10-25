"""Disposable guest check; no package installation or network beyond the SMB mount."""
import json
from pathlib import Path
import subprocess

WINDOWS_TEXT = 'Pocket Linux: привет из Windows\n'
LINUX_TEXT = 'Pocket Linux: привет из Linux\n'
FINAL_NAME = 'Проверка-файлов.txt'
DELETE_NAME = 'удалить-временный.txt'


def safe_error(text, config):
    for key in ('username', 'password'):
        text = text.replace(config.get(key, ''), '[redacted]') if config.get(key) else text
    return text[:240]


def mount_arguments(config):
    return ['mount', '-i', '-t', 'cifs', '//192.168.234.4/PC_SPIKE', '/mnt/hosttest', '-o',
            'username=' + config['username'] + ',password=' + config['password'] + ',vers=2.1,sec=ntlmssp,sign']


def main(poweroff=True):
    config = {}
    mounted = False
    receipt = {'schema': 1, 'session_nonce': '', 'ok': False, 'stage': 'config', 'detail': '',
               'read_ok': False, 'write_ok': False, 'rename_ok': False, 'delete_ok': False, 'unmount_ok': False}
    try:
        config = json.loads(Path('/opt/pl-files-config.json').read_text())
        receipt['session_nonce'] = config['session_nonce']
        receipt['stage'] = 'modprobe'
        result = subprocess.run(['modprobe', 'cifs'], capture_output=True, timeout=10, check=False)
        if result.returncode:
            receipt['detail'] = safe_error(result.stderr.decode(errors='replace'), config)
            return
        root = Path('/mnt/hosttest')
        root.mkdir(parents=True, exist_ok=True)
        receipt['stage'] = 'mount'
        result = subprocess.run(mount_arguments(config), capture_output=True, timeout=20, check=False)
        if result.returncode:
            receipt['detail'] = safe_error(result.stderr.decode(errors='replace'), config)
            return
        mounted = True
        receipt['stage'] = 'read'
        receipt['read_ok'] = (root / 'windows-sentinel.txt').read_text(encoding='utf-8') == WINDOWS_TEXT
        if not receipt['read_ok']:
            raise ValueError('Windows sentinel content mismatch')
        receipt['stage'] = 'write'
        temporary = root / 'linux-write.tmp'
        with temporary.open('x', encoding='utf-8', newline='') as stream:
            stream.write(LINUX_TEXT)
        receipt['write_ok'] = temporary.read_text(encoding='utf-8') == LINUX_TEXT
        receipt['stage'] = 'rename'
        final = root / FINAL_NAME
        if final.exists():
            raise FileExistsError('Result already exists')
        temporary.rename(final)
        receipt['rename_ok'] = not temporary.exists() and final.read_text(encoding='utf-8') == LINUX_TEXT
        receipt['stage'] = 'delete'
        disposable = root / DELETE_NAME
        with disposable.open('x', encoding='utf-8') as stream:
            stream.write('own temporary file')
        disposable.unlink()
        receipt['delete_ok'] = not disposable.exists()
    except Exception as error:
        # Exception text from subprocess may contain the credential-bearing argv.
        receipt['detail'] = type(error).__name__
    finally:
        if mounted:
            try:
                result = subprocess.run(['umount', '/mnt/hosttest'], capture_output=True, timeout=10, check=False)
                receipt['unmount_ok'] = result.returncode == 0
                if result.returncode:
                    receipt['stage'] = 'unmount'
                    receipt['detail'] = safe_error(result.stderr.decode(errors='replace'), config)
            except Exception as error:
                receipt['stage'], receipt['detail'] = 'unmount', type(error).__name__
        receipt['ok'] = all(receipt[key] for key in ('read_ok', 'write_ok', 'rename_ok', 'delete_ok', 'unmount_ok'))
        if receipt['ok']:
            receipt['stage'] = 'done'
        try:
            with open('/dev/ttyS0', 'w', encoding='ascii') as serial:
                serial.write('PL_FILES ' + json.dumps(receipt, separators=(',', ':'), ensure_ascii=True) + '\n')
                serial.flush()
        finally:
            if poweroff:
                try:
                    subprocess.run(['systemctl', 'poweroff'], timeout=10, check=False)
                except Exception:
                    pass


if __name__ == '__main__':
    main()
