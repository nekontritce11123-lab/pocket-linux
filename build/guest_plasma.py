"""Configure the fresh Plasma/X11 image, without a GPU or optional KDE suites.

Uses Plasma 6 desktop scripting and KConfig, not third-party shell extensions.
https://develop.kde.org/docs/plasma/scripting/api/
"""
import importlib.util
import json
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('pocket_style', Path(__file__).with_name('guest_style.py'))
style = importlib.util.module_from_spec(spec)
spec.loader.exec_module(style)


def layout_script(wallpaper):
    image = json.dumps('file://' + wallpaper.as_posix(), ensure_ascii=True)
    return '''// First-run layout of the disposable Pocket image only.
var panel = new Panel;
panel.location = "bottom";
panel.height = 48;
panel.lengthMode = "fill";
panel.hiding = "none";
panel.alignment = "center";
var left = panel.addWidget("org.kde.plasma.panelspacer");
left.currentConfigGroup = ["General"];
left.writeConfig("expanding", true);
var menu = panel.addWidget("org.kde.plasma.kickoff");
menu.currentConfigGroup = ["General"];
menu.writeConfig("icon", "start-here-kde");
menu.writeConfig("favoritesPortedToKAstats", false);
menu.writeConfig("favorites", "com.anthropic.Claude.desktop,firefox-esr.desktop,org.kde.dolphin.desktop,pocket-claude-code.desktop,systemsettings.desktop");
var tasks = panel.addWidget("org.kde.plasma.icontasks");
tasks.currentConfigGroup = ["General"];
tasks.writeConfig("launchers", "applications:org.kde.dolphin.desktop,applications:firefox-esr.desktop,applications:com.anthropic.Claude.desktop,applications:pocket-claude-code.desktop");
tasks.writeConfig("fill", false);
var right = panel.addWidget("org.kde.plasma.panelspacer");
right.currentConfigGroup = ["General"];
right.writeConfig("expanding", true);
panel.addWidget("org.kde.plasma.systemtray");
var clock = panel.addWidget("org.kde.plasma.digitalclock");
clock.currentConfigGroup = ["Appearance"];
clock.writeConfig("showDate", true);
clock.writeConfig("use24hFormat", 2);
clock.writeConfig("showSeconds", 2);
panel.addWidget("org.kde.plasma.showdesktop");
for (var desktop of desktopsForActivity(currentActivity())) {
    desktop.wallpaperPlugin = "org.kde.image";
    desktop.currentConfigGroup = ["Wallpaper", "org.kde.image", "General"];
    desktop.writeConfig("Image", ''' + image + ''');
    desktop.currentConfigGroup = ["General"];
    desktop.writeConfig("url", "desktop:/");
    desktop.writeConfig("iconSize", 3);
}
'''


def apply_style():
    import pwd
    user = pwd.getpwnam('pocket')
    home = Path(user.pw_dir)
    if home != Path('/home/pocket') or home.is_symlink():
        raise RuntimeError('Unexpected Pocket user home')
    for comm in Path('/proc').glob('[0-9]*/comm'):
        try:
            if comm.parent.stat().st_uid == user.pw_uid and comm.read_text().strip() in ('plasmashell', 'ksmserver'):
                raise RuntimeError('Stop Plasma before preparing its image defaults')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    layout = Path('/usr/share/plasma/look-and-feel/org.kde.breeze.desktop/contents/layouts/org.kde.plasma.desktop-layout.js')
    if not layout.is_file() or not Path('/usr/share/xsessions/plasmax11.desktop').is_file():
        raise RuntimeError('Plasma X11 packages are incomplete')
    wallpapers = sorted(Path('/usr/share/wallpapers').glob('*/contents/images/1920x1080.*'))
    if not wallpapers:
        raise RuntimeError('A packaged Plasma wallpaper is required')
    wallpaper = next((p for p in wallpapers if p.parts[-4] == 'Next'), wallpapers[0])

    def write(relative, data, mode=0o644):
        path = home / relative
        style.write_file(path, data, user.pw_uid, user.pw_gid, mode)
        for parent in path.parents:
            if parent == home.parent:
                break
            os.chown(parent, user.pw_uid, user.pw_gid)

    def ini(relative, values):
        path = home / relative
        write(relative, style.ini_update(path.read_text(encoding='utf-8') if path.is_file() else '', values))

    ini('.config/kdeglobals', {
        'General': {'ColorScheme': 'BreezeLight', 'Name': 'Breeze Light', 'font': 'Inter,10,-1,5,50,0,0,0,0,0',
                    'menuFont': 'Inter,10,-1,5,50,0,0,0,0,0', 'smallestReadableFont': 'Inter,9,-1,5,50,0,0,0,0,0'},
        'KDE': {'SingleClick': 'false', 'LookAndFeelPackage': 'org.kde.breeze.desktop', 'AnimationDurationFactor': '0'},
        'Icons': {'Theme': 'breeze'}, 'KDE Action Restrictions': {'lock_screen': 'false'},
        'KDE Full Session': {'DesktopNames': 'KDE'}})
    ini('.config/kwinrc', {'Compositing': {'Enabled': 'false'}, 'Desktops': {'Number': '1'},
                         'Windows': {'Placement': 'Centered'},
                         'org.kde.kdecoration2': {'library': 'org.kde.breeze', 'BorderSize': 'None', 'BorderSizeAuto': 'false'}})
    # QEMU has no accelerated guest 3D: rasterise Qt Quick rather than running llvmpipe effects.
    write('.config/plasma-workspace/env/pocket-rendering.sh',
          '#!/bin/sh\nexport QT_QUICK_BACKEND=software\nexport KWIN_COMPOSE=N\n', 0o755)
    ini('.config/kscreenlockerrc', {'Daemon': {'Autolock': 'false', 'LockOnResume': 'false'}})
    ini('.config/ksmserverrc', {'General': {'loginMode': 'emptySession', 'confirmLogout': 'false'}})
    ini('.config/baloofilerc', {'Basic Settings': {'Indexing-Enabled': 'false'}})
    ini('.config/kxkbrc', {'Layout': {'Use': 'true', 'LayoutList': 'us,ru', 'Options': 'grp:alt_shift_toggle',
                                   'ResetOldOptions': 'true', 'ShowFlag': 'false', 'DisplayNames': 'EN,RU'}})
    ini('.config/dolphinrc', {'General': {'GlobalViewProps': 'true', 'ShowFullPath': 'false',
                                       'HomeUrl': 'file:///home/pocket'},
                            'DetailsMode': {'IconSize': '32'}, 'IconsMode': {'IconSize': '64'}})
    ini('.config/gtk-3.0/settings.ini', {'Settings': {'gtk-theme-name': 'Breeze', 'gtk-icon-theme-name': 'breeze',
                                                  'gtk-font-name': 'Inter 10', 'gtk-enable-animations': 'false'}})
    ini('.config/mimeapps.list', {'Default Applications': {'inode/directory': 'org.kde.dolphin.desktop;',
                                                        'x-scheme-handler/http': 'firefox-esr.desktop;',
                                                        'x-scheme-handler/https': 'firefox-esr.desktop;'}})
    # The host bridge owns cross-OS text. Do not keep another persistent clipboard history.
    write('.config/autostart/org.kde.klipper.desktop', '[Desktop Entry]\nType=Application\nHidden=true\n')
    ini('.config/klipperrc', {'General': {'KeepClipboardContents': 'false', 'MaxClipItems': '1', 'IgnoreSelection': 'true'}})
    write('.config/user-dirs.dirs', 'XDG_DESKTOP_DIR="$HOME/Desktop"\nXDG_DOWNLOAD_DIR="$HOME/Downloads"\nXDG_DOCUMENTS_DIR="$HOME/Documents"\n')
    write('.config/user-dirs.locale', 'ru_RU\n')
    for folder in ('Desktop', 'Downloads', 'Documents'):
        path = home / folder
        path.mkdir(exist_ok=True)
        os.chown(path, user.pw_uid, user.pw_gid)
    applications = Path('/usr/share/applications')
    for name in ('com.anthropic.Claude.desktop', 'pocket-claude-code.desktop', 'firefox-esr.desktop'):
        source = applications / name
        write('Desktop/' + name, source.read_bytes(), 0o755)
    write('.local/share/user-places.xbel', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xbel><xbel version="1.0">
<bookmark href="file:///home/pocket"><title>Личные файлы Linux</title><info><metadata owner="http://freedesktop.org"><icon name="user-home"/></metadata></info></bookmark>
<bookmark href="file:///mnt/windows"><title>Файлы Windows</title><info><metadata owner="http://freedesktop.org"><icon name="folder-shared"/></metadata></info></bookmark>
<bookmark href="file:///home/pocket/Downloads"><title>Загрузки</title><info><metadata owner="http://freedesktop.org"><icon name="folder-downloads"/></metadata></info></bookmark>
</xbel>\n''')
    style.write_file(layout, layout_script(wallpaper))
    print('POCKET_STYLE_DONE ' + json.dumps({'desktop': 'Plasma X11', 'wallpaper': str(wallpaper),
                                           'compositor': False, 'qtquick': 'software', 'panel_px': 48}))


if __name__ == '__main__':
    style.guard_guest()
    apply_style()
