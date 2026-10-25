#!/usr/bin/python3
"""One-time acceptance in our fresh Linux image, never on the Windows host."""
import json
import os
from pathlib import Path
import pwd
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


def emit(kind, **data):
    with open('/dev/ttyS0', 'w') as serial:
        serial.write(kind + ' ' + json.dumps(data, ensure_ascii=True) + '\n')


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args!r} exited {result.returncode}: {result.stderr[-2000:]}')
    return result.stdout.strip()


def wait_window(prefix, name, process):
    for _ in range(120):
        titles = command(prefix + ['xwininfo', '-root', '-tree'])
        windows = re.findall(r'^\s+(0x[0-9a-f]+) "([^"]*)"[^\n]*?\s(\d+)x(\d+)[+-]\d+[+-]\d+', titles, re.M)
        window = next((wid for wid, title, width, height in windows
                       if name in title.lower() and int(width) >= 400 and int(height) >= 300), None)
        if window and 'Map State: IsViewable' in command(prefix + ['xwininfo', '-id', window]):
            return titles
        if process.poll() is not None:
            raise RuntimeError(name + ' exited before opening a window')
        time.sleep(1)
    raise RuntimeError(name + ' window did not appear')


def close_app(app):
    app.terminate()
    try:
        app.wait(timeout=10)
    except subprocess.TimeoutExpired:
        app.kill()
        app.wait(timeout=10)


def main():
    env = None
    for _ in range(90):
        pids = subprocess.run(['pgrep', '-u', 'pocket', '-x', 'lxqt-session|ksmserver'], capture_output=True, text=True).stdout.split()
        if pids:
            raw = Path('/proc/' + pids[0] + '/environ').read_bytes()
            env = dict(x.decode().split('=', 1) for x in raw.split(b'\0') if b'=' in x)
            break
        time.sleep(2)
    if env is None:
        raise RuntimeError('X11 desktop session did not start')
    plasma = env.get('XDG_CURRENT_DESKTOP', '').lower().find('kde') >= 0
    passwordless = Path('/var/lib/pocket-build/passwordless.json').is_file()
    access_receipt = Path('/var/lib/pocket-build/passwordless-verified-once')
    repeated = access_receipt.is_file()
    user = pwd.getpwnam('pocket')
    prefix = ['runuser', '-u', 'pocket', '--', 'env', 'HOME=' + user.pw_dir,
              'DISPLAY=' + env.get('DISPLAY', ':0'), 'XAUTHORITY=' + env.get('XAUTHORITY', user.pw_dir + '/.Xauthority'),
              'XDG_RUNTIME_DIR=/run/user/' + str(user.pw_uid),
              'DBUS_SESSION_BUS_ADDRESS=' + env.get('DBUS_SESSION_BUS_ADDRESS', 'unix:path=/run/user/' + str(user.pw_uid) + '/bus')]
    prefix += [name + '=' + env[name] for name in ('LANG', 'LANGUAGE', 'XDG_CURRENT_DESKTOP',
               'DESKTOP_SESSION', 'KDE_FULL_SESSION', 'QT_QUICK_BACKEND', 'KWIN_COMPOSE') if name in env]
    if not plasma:
        for name in ('com.anthropic.Claude.desktop', 'pocket-claude-code.desktop',
                     'firefox-esr.desktop', 'pocket-windows-files.desktop'):
            command(prefix + ['gio', 'set', '-t', 'string', user.pw_dir + '/Desktop/' + name,
                              'metadata::trust', 'true'])
    time.sleep(5)
    emit('POCKET_DESKTOP', desktop='plasma' if plasma else 'lxqt', locale=env.get('LANG', ''),
         memory=command(['free', '-b']), style=env.get('QT_STYLE_OVERRIDE', ''))
    time.sleep(3)
    version = command(prefix + ['claude', '--version'])
    help_text = command(prefix + ['claude', '--help'])
    assert 'Claude' in version and len(help_text) > 100
    clipboard_checked = False
    if Path('/run/pocket-clipboard/session.json').is_file():
        emit('POCKET_CLIPBOARD_TEST_READY', requested=True)
        for attempt in range(30):
            value = subprocess.run(prefix + ['xclip', '-selection', 'clipboard', '-out'],
                                   capture_output=True, text=True, timeout=3)
            if value.returncode == 0 and value.stdout == 'Windows: общий текст ✓':
                break
            time.sleep(1)
        else:
            raise RuntimeError('Host clipboard marker did not reach the guest')
        # Foreground owner is kept alive while the guest bridge observes this copy.
        owner = subprocess.Popen(prefix + ['xclip', '-selection', 'clipboard', '-in', '-quiet'],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        owner.stdin.write('Linux: ответ в Windows ✓'.encode('utf-8'))
        owner.stdin.close()
        time.sleep(5)
        close_app(owner)
        clipboard_checked = True
        emit('POCKET_CLIPBOARD', host_to_guest=True, guest_to_host=True)
    if sys.argv[1:] == ['--clipboard-only']:
        assert clipboard_checked, 'Clipboard channel missing'
        Path('/var/lib/pocket-build/verify-once').unlink()
        command(['systemctl', 'disable', 'pocket-verify.service'])
        emit('POCKET_VERIFY_DONE', clipboard=True, scope='clipboard-after-security-fix')
        return
    network = None
    if command(['ip', 'route', 'show', 'default']):
        resolver = Path('/etc/resolv.conf')
        emit('POCKET_NETWORK_CONFIG', routes=command(['ip', 'route']),
             resolver_link=os.readlink(resolver) if resolver.is_symlink() else None,
             resolver=resolver.read_text()[:2000])
        with urllib.request.urlopen('https://1.1.1.1/cdn-cgi/trace', timeout=30) as response:
            trace = dict(line.split('=', 1) for line in response.read(4096).decode().splitlines() if '=' in line)
        emit('POCKET_IP_NETWORK', egress_ip=trace.get('ip'))
        with urllib.request.urlopen('https://www.debian.org/', timeout=30) as response:
            assert response.status == 200
        try:
            with urllib.request.urlopen('https://claude.ai/', timeout=30) as response:
                claude_status = response.status
        except urllib.error.HTTPError as error:
            claude_status = error.code
        network = {'debian_https': True, 'egress_ip': trace.get('ip'), 'claude_http_status': claude_status}
        emit('POCKET_NETWORK', **network)
    browser_profile = user.pw_dir + '/.cache/pocket-browser-check'
    command(prefix + ['mkdir', '-p', browser_profile])
    with open('/var/log/pocket-browser-check.log', 'w') as browser_log:
        browser = subprocess.Popen(prefix + ['firefox-esr', '--no-remote', '--profile', browser_profile,
            'https://claude.ai/login' if network else 'about:blank'], stdout=browser_log, stderr=subprocess.STDOUT)
        wait_window(prefix, 'firefox', browser)
        time.sleep(15)
        emit('POCKET_BROWSER', visible=True, version=command(prefix + ['firefox-esr', '--version']))
        time.sleep(3)
        close_app(browser)
    if passwordless:
        access = json.loads(Path('/var/lib/pocket-build/passwordless.json').read_text())
        assert access.get('local_admin_without_password') is True, 'Incomplete passwordless image'
        assert command(prefix + ['sh', '-c', 'command -v claude-desktop']) == '/usr/local/bin/claude-desktop', 'Claude keyring wrapper is not on the desktop PATH'
        for name in ('pocket', 'root'):
            assert command(['passwd', '--status', name]).split()[1] == 'NP', 'A Linux account still has a password'
        readiness = json.loads(Path('/run/user/' + str(user.pw_uid) + '/pocket-keyring-ready.json').read_text())
        assert readiness.get('ready') is True and readiness.get('uid') == user.pw_uid
        assert command(prefix + ['sudo', '-n', 'id', '-u']) == '0', 'Local administration asks for a password'
        assert command(prefix + ['su', 'root', '-c', 'id -u'], input='') == '0', 'Switching to root asks for a password'
        command(prefix + ['pkcheck', '--action-id', 'org.freedesktop.policykit.exec', '--process', pids[0]])
        if repeated:
            assert command(prefix + ['secret-tool', 'lookup', 'pocket-qa', 'cold-boot']) == 'Pocket QA synthetic secret'
        else:
            command(prefix + ['secret-tool', 'store', '--label=Pocket QA only', 'pocket-qa', 'cold-boot'],
                    input='Pocket QA synthetic secret')
        emit('POCKET_ACCESS', passwordless=True, cold_boot=2 if repeated else 1, persisted_secret=repeated)
    else:
        # Legacy LXQt acceptance: its random test keyring is removed below; no user account is used.
        import secrets
        command(prefix + ['gnome-keyring-daemon', '--unlock'], input=secrets.token_urlsafe(32))
    desktop_log = open('/var/log/pocket-desktop-check.log', 'w')
    app = subprocess.Popen(prefix + ['claude-desktop', '--disable-gpu'], stdout=desktop_log, stderr=subprocess.STDOUT)
    titles = wait_window(prefix, 'claude', app)
    time.sleep(20)
    if passwordless:
        prompts = subprocess.run(['pgrep', '-u', 'pocket', '-x', 'gcr-prompter|kwalletmanager|kwalletmanager5'], capture_output=True)
        assert prompts.returncode == 1, 'An unexpected password prompt is running'
    emit('POCKET_UI', desktop_window=True, environment='plasma' if plasma else 'lxqt', claude_code=version, user='pocket',
         kernel=command(['uname', '-r']), memory=command(['free', '-b']), window_tree=titles[:6000])
    time.sleep(12)
    close_app(app)
    if network:
        emit('POCKET_STOP_PROXY', requested=True)
        time.sleep(4)
        command(['resolvectl', 'flush-caches'])
        blocked = {}
        for name, url in (('direct_ip', 'https://1.1.1.1/cdn-cgi/trace'),
                          ('hostname', 'https://www.debian.org/')):
            try:
                urllib.request.urlopen(url, timeout=6).close()
            except urllib.error.HTTPError:
                blocked[name] = False
            except (OSError, urllib.error.URLError):
                blocked[name] = True
            else:
                blocked[name] = False
        try:
            socket.getaddrinfo('www.debian.org', 443)
        except OSError:
            blocked['dns'] = True
        else:
            blocked['dns'] = False
        assert all(blocked.values()), 'Direct traffic survived proxy shutdown'
        network['proxy_stopped_blocks'] = blocked
        emit('POCKET_PROXY_BLOCKED', **blocked)
    shared = Path('/mnt/windows/PC_01')
    files_checked = False
    if Path('/sys/firmware/qemu_fw_cfg/by_name/opt/pocket/files/raw').is_file():
        assert shared.is_mount(), 'Selected Windows folder was not mounted'
        command(prefix + ['python3', '-I', '-B', '-c', r'''
from pathlib import Path
import os
assert os.getuid() == 1000
shared = Path('/mnt/windows/PC_01')
assert (shared / 'windows-sentinel.txt').read_text() == 'Pocket Windows shared test\n'
target = shared / 'Проверка из Linux.txt'
with target.open('x', encoding='utf-8') as stream:
    stream.write('Общий файл: Linux и Windows\n')
renamed = target.with_name('Общие файлы работают.txt')
target.rename(renamed)
assert renamed.read_text() == 'Общий файл: Linux и Windows\n'
disposable = shared / 'удалить.tmp'
disposable.write_text('temporary QA file')
disposable.unlink()
'''])
        files_checked = True
        emit('POCKET_SHARED_FILES', read=True, write=True, rename=True, delete=True,
             proxy_stopped=network is not None)
    # Keep the kernel that actually passed the desktop check; never purge the running kernel.
    packages = command(['dpkg-query', '-W', '-f=${binary:Package}\n']).splitlines()
    kernel = command(['uname', '-r'])
    keep = {'linux-image-' + kernel, 'linux-image-cloud-amd64' if '-cloud-' in kernel else 'linux-image-amd64'}
    remove = [p for p in packages if p.startswith('linux-image-') and p not in keep]
    remove += [p for p in ('cloud-init', 'cloud-guest-utils', 'openssh-server', 'openssh-sftp-server') if p in packages]
    subprocess.run(['apt-get', '-y', 'purge', *remove], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.STDOUT, timeout=600, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    Path('/etc/default/grub.d/99-pocket.cfg').write_text('GRUB_DEFAULT=0\n')
    command(['update-grub'])
    installed = command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Installed-Size}\n'])
    Path('/var/lib/pocket-build/packages.tsv').write_text(installed + '\n')
    result = {'desktop': command(['dpkg-query', '-W', '-f=${Version}', 'claude-desktop']),
              'code': version, 'environment': 'plasma' if plasma else 'lxqt',
              'environment_version': command(['dpkg-query', '-W', '-f=${Version}', 'plasma-desktop' if plasma else 'lxqt-core']),
              'kernel': command(['uname', '-r']), 'user': 'pocket', 'uid': user.pw_uid,
              'installed_kib': sum(int(row.rsplit('\t', 1)[1]) for row in installed.splitlines()),
              'package_count': len(installed.splitlines()),
              'memory': command(['free', '-b']), 'filesystem': command(['df', '-B1', '/']),
              'routes': command(['ip', 'route']), 'network': network, 'shared_files': files_checked,
              'browser_window': True, 'native_code_help': True, 'desktop_window': True,
              'clipboard': clipboard_checked, 'passwordless': passwordless,
              'passwordless_cold_boot': (2 if repeated else 1) if passwordless else None}
    Path('/var/lib/pocket-build/verification.json').write_text(json.dumps(result, indent=2))
    if passwordless and not repeated:
        access_receipt.touch()
    else:
        if passwordless:
            command(prefix + ['secret-tool', 'clear', 'pocket-qa', 'cold-boot'])
        Path('/var/lib/pocket-build/verify-once').unlink()
        subprocess.run(['systemctl', 'disable', 'pocket-verify.service'], check=True, capture_output=True)
    subprocess.run(['apt-get', 'clean'], check=True)
    # Close the disposable session before removing its temporary test keyring and application caches.
    command(['systemctl', 'stop', 'sddm.service'])
    subprocess.run(['loginctl', 'terminate-user', 'pocket'], check=False, capture_output=True)
    # No account was used: discard only this fresh user's generated application caches and test state.
    import shutil
    for relative in ('.cache', '.config/Claude', '.claude', '.config/claude', '.local/share/keyrings'):
        if relative == '.local/share/keyrings' and passwordless and not repeated:
            continue  # The second cold boot must unlock the same real store without test assistance.
        target = Path(user.pw_dir) / relative
        if target.exists():
            shutil.rmtree(target)
    for file in Path('/var/log').glob('pocket-*'):
        file.unlink(missing_ok=True)
    subprocess.run(['journalctl', '--rotate'], capture_output=True)
    subprocess.run(['journalctl', '--vacuum-size=1M'], capture_output=True)
    os.sync()
    subprocess.run(['fstrim', '-av'], capture_output=True)
    emit('POCKET_VERIFY_DONE', **result)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        emit('POCKET_ERROR', stage='verify', error=repr(error))
    finally:
        os.sync()
        subprocess.run(['systemctl', 'poweroff'], check=False)
