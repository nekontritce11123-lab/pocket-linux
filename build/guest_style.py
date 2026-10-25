"""Apply the compact light LXQt image style inside the prepared Debian guest only.

Schema sources: lxqt-panel 2.1.0 panel/resources/panel.conf and panel/lxqtpanel.cpp;
lxqt-session 2.1.0 config/lxqt.conf, config/session.conf; pcmanfm-qt 2.1.0
pcmanfm/settings.cpp; lxqt-config 2.1.0 keyboardlayoutconfig.cpp.
"""
import configparser
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def ini_update(text, changes):
    parser = configparser.ConfigParser(interpolation=None, delimiters=('=',), strict=False)
    parser.optionxform = str
    if text.strip():
        parser.read_string(text)
    for section, values in changes.items():
        if not parser.has_section(section):
            parser.add_section(section)
        for name, value in values.items():
            parser[section][name] = str(value)
    output = io.StringIO()
    parser.write(output, space_around_delimiters=False)
    return output.getvalue()


def panel_config(applications):
    # QSettings root key and array syntax match the upstream 2.1 panel defaults/API.
    text = '''panels=panel1

[panel1]
plugins=fancymenu,desktopswitch,quicklaunch,taskbar,statusnotifier,tray,worldclock
position=Bottom
desktop=0
panelSize=38
iconSize=24
lineCount=1
width=100
width-percent=true
reserve-space=true
hidable=false
opacity=100
background-color=#f7f8fa
font-color=#273142
iconTheme=Papirus

[fancymenu]
type=fancymenu
alignment=Left
filterClear=true
autoSel=true
autoSelDelay=150
showText=true
text=Меню
ownIcon=true
icon=/usr/share/lxqt/graphics/helix.svg

[desktopswitch]
type=desktopswitch

[quicklaunch]
type=quicklaunch
alignment=Left
'''
    text += ''.join('apps\\' + str(index) + '\\desktop=' + application + '\n'
                    for index, application in enumerate(applications, 1))
    text += 'apps\\size=' + str(len(applications)) + '\n'
    return text + '''
[taskbar]
type=taskbar
buttonWidth=180
groupingEnabled=true
showOnlyOneDesktopTasks=true

[statusnotifier]
type=statusnotifier
alignment=Right

[tray]
type=tray
alignment=Right

[worldclock]
type=worldclock
alignment=Right
formatType=custom-timeonly
timePadHour=true
timeShowSeconds=false
timeAMPM=false
showDate=false
showTimezone=false
showTooltip=true
'''


def openbox_config(text):
    root = ET.fromstring(text)
    namespace = root.tag.partition('}')[0][1:] if root.tag.startswith('{') else ''
    if root.tag.rsplit('}', 1)[-1] != 'openbox_config':
        raise ValueError('Unexpected Openbox template')
    if namespace:
        ET.register_namespace('', namespace)
    prefix = '{' + namespace + '}' if namespace else ''

    def node(path):
        current = root
        for name in path.split('/'):
            child = current.find(prefix + name)
            if child is None:
                child = ET.SubElement(current, prefix + name)
            current = child
        return current

    node('theme/name').text = 'Arc'
    node('desktops/number').text = '2'
    names = node('desktops/names')
    for child in list(names):
        names.remove(child)
    for number in (1, 2):
        ET.SubElement(names, prefix + 'name').text = 'Рабочий стол ' + str(number)
    for font in node('theme').findall(prefix + 'font'):
        for name, value in (('name', 'DejaVu Sans'), ('size', '10')):
            item = font.find(prefix + name)
            if item is None:
                item = ET.SubElement(font, prefix + name)
            item.text = value
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='unicode') + '\n'


def guard_guest():
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('Run only as root inside the prepared Debian guest; never on Windows.')
    marker = Path('/var/lib/pocket-build/artifacts.json')
    if marker.is_symlink() or not marker.is_file():
        raise RuntimeError('Pocket Debian build marker is missing; refusing to change this system.')
    with marker.open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise RuntimeError('Invalid Pocket Debian build marker')
    artifacts = json.loads(data)
    if not isinstance(artifacts, dict) or not {'claude-desktop', 'claude-code'} <= set(artifacts):
        raise RuntimeError('Invalid Pocket Debian build marker')


def write_file(path, data, uid=0, gid=0, mode=0o644):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError('Refusing to follow a configuration symlink: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode('utf-8') if isinstance(data, str) else data
    if path.is_file() and path.read_bytes() == payload:
        os.chown(path, uid, gid)
        path.chmod(mode)
        return
    descriptor, temporary = tempfile.mkstemp(prefix='.pocket-style-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, uid, gid)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def desktop_launcher(applications):
    return next((path for path in sorted(applications.glob('*.desktop'))
                 if 'claude' in path.name.lower() and 'code' not in path.name.lower()), None)


def apply_style():
    import pwd
    pocket = pwd.getpwnam('pocket')
    home = Path(pocket.pw_dir)
    if home != Path('/home/pocket') or home.is_symlink():
        raise RuntimeError('Unexpected Pocket user home')
    for comm in Path('/proc').glob('[0-9]*/comm'):
        try:
            if comm.parent.stat().st_uid == pocket.pw_uid and comm.read_text().strip() == 'lxqt-session':
                raise RuntimeError('Stop SDDM/LXQt before applying the image style.')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    required = ('/usr/share/Kvantum/KvArc/KvArc.kvconfig', '/usr/share/Kvantum/KvArc/KvArc.svg',
                '/usr/share/themes/Arc/openbox-3/themerc', '/usr/share/icons/Papirus/index.theme',
                '/etc/xdg/openbox/rc.xml')
    for name in required:
        if not Path(name).is_file():
            raise RuntimeError('Required style asset missing: ' + name)
    if not any(Path('/usr/lib').glob('*/qt6/plugins/imageformats/libqsvg.so')):
        raise RuntimeError('qt6-svg-plugins is required for visible SVG icons.')
    applications = Path('/usr/share/applications')
    desktop = desktop_launcher(applications)
    code = applications / 'pocket-claude-code.desktop'
    browser = applications / 'firefox-esr.desktop'
    if desktop is None or not code.is_file() or not browser.is_file():
        raise RuntimeError('Claude Desktop/Code and Firefox launchers must be prepared before applying the style.')

    def user_write(relative, content, mode=0o644):
        path = home / relative
        write_file(path, content, pocket.pw_uid, pocket.pw_gid, mode)
        current = path.parent
        while current != home.parent:
            os.chown(current, pocket.pw_uid, pocket.pw_gid)
            if current == home:
                break
            current = current.parent

    def user_ini(relative, changes, fallback=''):
        path = home / relative
        user_write(relative, ini_update(path.read_text(encoding='utf-8') if path.is_file() else fallback, changes))

    user_ini('.config/lxqt/lxqt.conf', {'General': {'theme': 'System', 'icon_theme': 'Papirus',
             'single_click_activate': 'false', 'palette_override': 'false',
             'tool_button_style': 'ToolButtonTextBesideIcon'},
             'Qt': {'style': 'kvantum', 'font': '"DejaVu Sans,10,-1,5,50,0,0,0,0,0"'}})
    user_ini('.config/lxqt/session.conf', {'General': {'window_manager': 'openbox'},
             'Environment': {'LANG': 'ru_RU.UTF-8', 'LANGUAGE': 'ru_RU:ru:en_US:en', 'QT_QPA_PLATFORMTHEME': 'lxqt'},
             'Keyboard': {'layout': '"us,ru"', 'variant': '","', 'model': 'pc105', 'options': 'grp:alt_shift_toggle'}})
    user_write('.config/lxqt/panel.conf', panel_config([str(desktop), str(code), str(browser)]))
    user_write('.config/Kvantum/kvantum.kvconfig', '[General]\ntheme=KvArc\n')
    user_write('.config/Kvantum/KvArc/KvArc.kvconfig', ini_update(
        Path('/usr/share/Kvantum/KvArc/KvArc.kvconfig').read_text(encoding='utf-8'),
        {'%General': {'composite': 'false', 'translucent_windows': 'false', 'blurring': 'false',
                      'popup_blurring': 'false', 'animate_states': 'false'}, 'Hacks': {'blur_translucent': 'false'}}))
    user_write('.config/Kvantum/KvArc/KvArc.svg', Path('/usr/share/Kvantum/KvArc/KvArc.svg').read_bytes())
    user_ini('.config/gtk-3.0/settings.ini', {'Settings': {'gtk-theme-name': 'Arc', 'gtk-icon-theme-name': 'Papirus',
             'gtk-font-name': 'DejaVu Sans 10', 'gtk-application-prefer-dark-theme': 'false', 'gtk-enable-animations': 'false'}})
    user_write('.gtkrc-2.0', 'gtk-theme-name="Arc"\ngtk-icon-theme-name="Papirus"\ngtk-font-name="DejaVu Sans 10"\n')
    user_ini('.config/pcmanfm-qt/lxqt/settings.conf', {'System': {'IconThemeName': 'Papirus'},
             'Desktop': {'WallpaperMode': 'none', 'Wallpaper': '', 'BgColor': '#e9edf2', 'FgColor': '#273142',
                         'ShadowColor': '#e9edf2', 'DesktopIconSize': '48', 'DesktopShortcuts': 'Home, Trash',
                         'Font': '"DejaVu Sans,10,-1,5,50,0,0,0,0,0"'}})
    template = Path('/etc/xdg/openbox/rc.xml').read_text(encoding='utf-8')
    # Both standard Openbox and distro-specific LXQt entry points receive the same preserved bindings.
    for name in ('rc.xml', 'lxqt-rc.xml'):
        path = home / '.config/openbox' / name
        user_write('.config/openbox/' + name, openbox_config(path.read_text(encoding='utf-8') if path.is_file() else template))
    directories = home / '.config/user-dirs.dirs'
    lines = directories.read_text(encoding='utf-8').splitlines() if directories.is_file() else []
    lines = [line for line in lines if not line.startswith('XDG_DESKTOP_DIR=')]
    user_write('.config/user-dirs.dirs', '\n'.join(lines + ['XDG_DESKTOP_DIR="$HOME/Desktop"']) + '\n')
    user_write('.config/user-dirs.locale', 'ru_RU\n')
    for source in (desktop, code, browser):
        changes = {'Icon': 'utilities-terminal'} if source == code else {}
        if source == browser:
            changes.update(Name='Browser', **{'Name[ru]': 'Браузер'})
        content = ini_update(source.read_text(encoding='utf-8'), {'Desktop Entry': changes})
        user_write('Desktop/' + source.name, content, 0o755)
        if source == code:
            write_file(source, content)
    # Debian 13 links this file to locale.conf; let its own utility update the canonical location.
    subprocess.run(['update-locale', 'LANG=ru_RU.UTF-8', 'LANGUAGE=ru_RU:ru:en_US:en'], check=True)
    write_file(Path('/etc/default/keyboard'), 'XKBMODEL="pc105"\nXKBLAYOUT="us,ru"\nXKBVARIANT=""\nXKBOPTIONS="grp:alt_shift_toggle"\nBACKSPACE="guess"\n')


def main():
    try:
        guard_guest()
        apply_style()
        print('POCKET_STYLE_DONE ' + json.dumps({'ok': True, 'style': 'KvArc', 'icons': 'Papirus',
              'panel_px': 38, 'desktops': 2, 'compositor': False, 'locale': 'ru_RU.UTF-8'}))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print('POCKET_STYLE_ERROR ' + json.dumps({'ok': False, 'message': str(error)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
