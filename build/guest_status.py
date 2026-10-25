#!/usr/bin/python3
"""Report guest connectivity and actual X11 geometry over the serial channel.

Guest DNS and HTTPS use the sole external NIC: desktop/start.py connects it only
to PocketNet's loopback stream, never QEMU NAT. The optional SMB NIC is restricted
to its one port without a gateway/DNS. verify-09/result.json confirms that stopping
PocketNet blocks IP, hostname and DNS. No proxy credentials enter this guest.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

FW_CONFIG = Path('/sys/firmware/qemu_fw_cfg/by_name/opt/pocket/status/raw')


def parse_config(raw):
    if not isinstance(raw, bytes) or len(raw) > 1024:
        raise ValueError('Invalid status configuration size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'schema', 'session_nonce', 'network'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['session_nonce'], str) or not re.fullmatch('[a-f0-9]{32}', value['session_nonce'])
            or type(value['network']) is not bool):
        raise ValueError('Invalid status configuration')
    return value


def network_status(enabled):
    if not enabled:
        return 'off', False, False
    results = []
    for command in (
            ['/usr/bin/getent', 'ahostsv4', 'www.debian.org'],
            ['/usr/bin/curl', '--disable', '--head', '--silent', '--fail', '--max-time', '5',
             '--output', '/dev/null', 'https://www.debian.org/']):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=5, check=False,
                                    env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'})
            results.append(result.returncode == 0)
        except (OSError, subprocess.TimeoutExpired):
            results.append(False)
    return ('ready' if all(results) else 'failed'), *results


def display_status():
    import pwd
    try:
        user = pwd.getpwnam('pocket')
        for comm in Path('/proc').glob('[0-9]*/comm'):
            try:
                if comm.parent.stat().st_uid != user.pw_uid or comm.read_text().strip() not in ('lxqt-session', 'ksmserver'):
                    continue
                with (comm.parent / 'environ').open('rb') as stream:
                    raw = stream.read(65537)
                if len(raw) > 65536:
                    continue
                env = dict(item.decode().split('=', 1) for item in raw.split(b'\0') if b'=' in item)
                display, authority = env.get('DISPLAY', ''), env.get('XAUTHORITY', '')
                if not re.fullmatch(r':[0-9]{1,3}(?:\.[0-9]{1,2})?', display):
                    continue
                if not authority:
                    authority = '/home/pocket/.Xauthority'
                if len(authority) > 1024:
                    continue
                if re.fullmatch('/tmp/xauth_[A-Za-z0-9]+', authority):
                    info = Path(authority).lstat()
                    if info.st_uid != user.pw_uid or not stat.S_ISREG(info.st_mode):
                        continue
                elif not authority.startswith(('/home/pocket/', '/run/')):
                    continue
                result = subprocess.run(['/usr/sbin/runuser', '-u', 'pocket', '--', '/usr/bin/env',
                                         'DISPLAY=' + display, 'XAUTHORITY=' + authority, 'LC_ALL=C',
                                         '/usr/bin/xrandr', '--current'], capture_output=True, text=True,
                                        timeout=4, check=False)
                match = re.search(r'\bcurrent ([0-9]+) x ([0-9]+),', result.stdout[:16384])
                if result.returncode == 0 and match:
                    width, height = map(int, match.groups())
                    if 320 <= width <= 16384 and 320 <= height <= 16384:
                        return width, height
            except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
                continue
    except (OSError, KeyError):
        pass
    return None, None


def collect(config):
    network, dns, https = network_status(config['network'])
    width, height = display_status()
    return {'schema': 1, 'session_nonce': config['session_nonce'], 'network': network,
            'dns': dns, 'https': https, 'width': width, 'height': height}


def main():
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('Run only as root inside Pocket Linux')
    subprocess.run(['/usr/sbin/modprobe', 'qemu_fw_cfg'], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    with FW_CONFIG.open('rb') as stream:
        config = parse_config(stream.read(1025))
    while True:
        started = time.monotonic()
        line = 'POCKET_STATUS ' + json.dumps(collect(config), separators=(',', ':')) + '\n'
        with Path('/dev/ttyS0').open('w', encoding='ascii') as serial:
            serial.write(line)
        time.sleep(max(1, 20 - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
