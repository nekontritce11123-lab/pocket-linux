#!/usr/bin/python3
"""Prepare a fresh Pocket Linux user and keyring without password prompts.

GNOME Keyring 48 ignores EOF-only stdin; a NUL byte is an explicit empty string.
SDDM sources Xsession.d before the DE. KWallet 6.13 supports the two keys below.
The owner explicitly chose passwordless full administration inside this VM.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

MARKER = Path('/var/lib/pocket-build/passwordless.json')
SUDOERS = 'pocket ALL=(ALL:ALL) NOPASSWD: ALL\n'
POLKIT = '''polkit.addRule(function(action, subject) {
    if (subject.user === "pocket" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
'''
XSESSION = '''# Initialize the login keyring before desktop applications can request it.
if [ "$(id -un)" = pocket ]; then
    /usr/bin/python3 -I -B /opt/pocket/guest_access.py --session || \\
        echo 'Pocket Linux: passwordless keyring initialization failed; existing keys were preserved.' >&2
fi
'''


def guard_guest():
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('Run setup only as root inside the prepared Pocket Debian guest.')
    build = Path('/var/lib/pocket-build/artifacts.json')
    if build.is_symlink() or not build.is_file():
        raise RuntimeError('Pocket build marker missing; refusing to configure this system.')
    with build.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise RuntimeError('Invalid Pocket build marker.')
    artifacts = json.loads(raw)
    if not isinstance(artifacts, dict) or not {'claude-desktop', 'claude-code'} <= set(artifacts):
        raise RuntimeError('Invalid Pocket build marker.')


def check_keyrings(home):
    """Read only format headers; never reset an existing protected keyring."""
    for directory in (home / '.local/share/keyrings', home / '.local/share/kwalletd'):
        if directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents):
            raise RuntimeError('Refusing a keyring directory symlink.')
        if not directory.exists():
            continue
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('Refusing an existing keyring directory entry.')
            if path.name == 'default':
                with path.open('rb') as stream:
                    if stream.read(64).strip() != b'login':
                        raise RuntimeError('Refusing to replace an existing keyring alias.')
            elif path.suffix == '.keyring':
                with path.open('rb') as stream:
                    if path.name != 'login.keyring' or stream.read(10) != b'[keyring]\n':
                        raise RuntimeError('Refusing to replace an existing keyring.')
            elif path.suffix == '.kwl':
                raise RuntimeError('Refusing to disable an existing KWallet.')


def unlock_keyring():
    subprocess.run(['/usr/bin/gnome-keyring-daemon', '--unlock', '--components=secrets'],
                   input=b'\0', capture_output=True, timeout=20, check=True)
    base = ['/usr/bin/gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets']
    result = subprocess.run(base + ['--object-path', '/org/freedesktop/secrets', '--method',
                                   'org.freedesktop.Secret.Service.ReadAlias', 'default'],
                            capture_output=True, timeout=10, check=True)
    match = re.fullmatch(rb"\(objectpath '(/org/freedesktop/secrets/collection/[A-Za-z0-9_]+)',\)\s*", result.stdout)
    if not match:
        raise RuntimeError('Passwordless default keyring is unavailable.')
    result = subprocess.run(base + ['--object-path', match[1].decode('ascii'), '--method',
                                   'org.freedesktop.DBus.Properties.Get',
                                   'org.freedesktop.Secret.Collection', 'Locked'],
                            capture_output=True, timeout=10, check=True)
    if result.stdout.strip() != b'(<false>,)':
        raise RuntimeError('Existing keyring is locked; it has not been reset.')


def session():
    if sys.platform != 'linux' or not hasattr(os, 'getuid'):
        raise RuntimeError('The keyring hook runs only in the Pocket Linux session.')
    import pwd
    user = pwd.getpwnam('pocket')
    home = Path(user.pw_dir)
    runtime = Path('/run/user/' + str(user.pw_uid))
    if (os.getuid() != user.pw_uid or user.pw_uid == 0 or home != Path('/home/pocket')
            or home.is_symlink() or not MARKER.is_file() or MARKER.is_symlink()
            or not os.environ.get('DBUS_SESSION_BUS_ADDRESS')
            or runtime.is_symlink() or runtime.stat().st_uid != user.pw_uid):
        raise RuntimeError('Invalid Pocket user session for passwordless keyring.')
    ready = runtime / 'pocket-keyring-ready.json'
    if ready.is_symlink() or ready.exists() and ready.stat().st_uid != user.pw_uid:
        raise RuntimeError('Unexpected keyring readiness file.')
    ready.unlink(missing_ok=True)
    check_keyrings(home)
    unlock_keyring()
    check_keyrings(home)
    descriptor, temporary = tempfile.mkstemp(prefix='.pocket-keyring-', dir=runtime)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump({'schema': 1, 'ready': True, 'uid': user.pw_uid,
                       'passwordless': True, 'checked_at': int(time.time())}, stream)
            stream.write('\n')
        os.replace(temporary, ready)
    finally:
        Path(temporary).unlink(missing_ok=True)


def empty_fresh_account(name='pocket'):
    if name not in ('pocket', 'root'):
        raise RuntimeError('Only the two explicit Pocket image accounts may be configured.')
    result = subprocess.run(['/usr/bin/passwd', '--status', name], capture_output=True,
                            text=True, timeout=10, check=True)
    fields = result.stdout.split()
    if len(fields) < 2 or fields[0] != name or fields[1] not in ('L', 'NP'):
        raise RuntimeError('Refusing to remove an existing user password.')
    if fields[1] == 'L':
        # A locked account may retain a real password hash; only fresh lock markers are safe.
        record = subprocess.run(['/usr/bin/getent', 'shadow', name], capture_output=True,
                                text=True, timeout=10, check=True).stdout.strip().split(':')
        if len(record) != 9 or record[0] != name or record[1] not in ('!', '!!', '*', '!*'):
            raise RuntimeError('Refusing to remove an existing locked password.')
        subprocess.run(['/usr/bin/passwd', '--delete', name], capture_output=True,
                       timeout=10, check=True)


def apply_access():
    guard_guest()
    import pwd
    user = pwd.getpwnam('pocket')
    home = Path(user.pw_dir)
    if user.pw_uid == 0 or home != Path('/home/pocket') or home.is_symlink():
        raise RuntimeError('Unexpected Pocket user home.')
    check_keyrings(home)
    spec = importlib.util.spec_from_file_location('pocket_guest_style', Path(__file__).with_name('guest_style.py'))
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    subprocess.run(['/usr/sbin/visudo', '-cf', '-'], input=SUDOERS, text=True,
                   capture_output=True, timeout=10, check=True)
    for name in ('pocket', 'root'):
        empty_fresh_account(name)
    helpers.write_file(Path('/etc/sudoers.d/90-pocket-local'), SUDOERS, mode=0o440)
    helpers.write_file(Path('/etc/polkit-1/rules.d/00-pocket-local.rules'), POLKIT)
    wallet = home / '.config/kwalletrc'
    original = wallet.read_text(encoding='utf-8') if wallet.is_file() and not wallet.is_symlink() else ''
    content = helpers.ini_update(original, {'Wallet': {'Enabled': 'false'},
                                          'org.freedesktop.secrets': {'apiEnabled': 'false'}})
    helpers.write_file(wallet, content, user.pw_uid, user.pw_gid, 0o600)
    os.chown(wallet.parent, user.pw_uid, user.pw_gid)
    helpers.write_file(Path('/opt/pocket/guest_access.py'), Path(__file__).read_bytes(), mode=0o755)
    helpers.write_file(Path('/etc/X11/Xsession.d/95pocket-keyring'), XSESSION)
    # Electron otherwise selects disabled KWallet on KDE instead of our unlocked Secret Service.
    helpers.write_file(Path('/usr/local/bin/claude-desktop'),
                       '#!/bin/sh\nexec /usr/bin/claude-desktop --password-store=gnome-libsecret "$@"\n', mode=0o755)
    helpers.write_file(MARKER, json.dumps({'schema': 1, 'user': 'pocket',
                       'account_passwords': {'pocket': 'empty', 'root': 'empty'},
                       'keyring_password': 'empty', 'local_admin_without_password': True,
                       'polkit_scope': ['pocket', 'local', 'active']}, indent=2) + '\n')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--session']:
            session()
        elif not sys.argv[1:]:
            apply_access()
            print('POCKET_ACCESS_DONE {"passwordless":true,"user":"pocket"}')
        else:
            raise RuntimeError('Unknown argument.')
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('POCKET_ACCESS_ERROR ' + str(error), file=sys.stderr)
        sys.exit(1)
