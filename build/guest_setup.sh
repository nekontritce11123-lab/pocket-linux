#!/bin/bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
desktop=${1:-lxqt}
case "$desktop" in
    lxqt) session=lxqt.desktop; terminal=qterminal ;;
    plasma) session=plasmax11.desktop; terminal=konsole ;;
    *) echo 'Unknown desktop'; exit 2 ;;
esac
exec > >(tee -a /var/log/pocket-build.log /dev/ttyS0) 2>&1
trap 'code=$?; echo "POCKET_ERROR {\"stage\":\"build\",\"line\":$LINENO,\"exit\":$code}"; sync; systemctl poweroff; exit "$code"' ERR
echo 'POCKET_STAGE {"stage":"apt-index"}'
cat >/etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: http://198.18.0.10:18080/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://198.18.0.10:18080/security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
test ! -s /etc/apt/sources.list || mv /etc/apt/sources.list /opt/pocket-build/original-sources.list
cat >/etc/apt/apt.conf.d/90pocket-compact <<'EOF'
APT::Install-Recommends "false";
APT::Install-Suggests "false";
Acquire::Languages "none";
Acquire::Retries "3";
EOF
apt-get update
echo 'POCKET_STAGE {"stage":"download-claude"}'
python3 - <<'PY'
import hashlib, json, pathlib, shutil, urllib.request
data = json.loads(pathlib.Path('/opt/pocket-build/artifacts.json').read_text())
for name, meta in data.items():
    file = pathlib.Path('/opt/pocket-build') / (name + '.deb')
    with urllib.request.urlopen('http://198.18.0.10:18080/artifacts/' + file.name, timeout=180) as response, file.open('wb') as target:
        shutil.copyfileobj(response, target, 1024 * 1024)
    with file.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert digest == meta['SHA256'], name + ' checksum mismatch'
    assert file.stat().st_size == int(meta['Size']), name + ' size mismatch'
PY
echo 'POCKET_STAGE {"stage":"install-desktop"}'
# The cloud kernel omits graphics drivers; the normal Debian kernel is required for X11.
if [ "$desktop" = plasma ]; then
    packages=(plasma-desktop plasma-workspace kwin-x11 plasma-integration breeze breeze-gtk-theme
              dolphin konsole systemsettings kscreen fonts-inter fonts-noto-color-emoji)
else
    packages=(lxqt-core openbox qt-style-kvantum qt-style-kvantum-themes papirus-icon-theme arc-theme
              lxqt-panel-l10n lxqt-session-l10n pcmanfm-qt-l10n qterminal-l10n lxqt-config-l10n
              lxqt-runner-l10n lxqt-notificationd-l10n lxqt-globalkeys-l10n lxqt-policykit-l10n libfm-qt-l10n)
fi
apt-get install -y --no-install-recommends linux-image-amd64 sddm qt6-svg-plugins "${packages[@]}" \
    xserver-xorg-core xserver-xorg-input-libinput xserver-xorg-video-fbdev xserver-xorg-video-vesa \
    xinit x11-utils x11-xserver-utils xclip dbus-x11 dbus-user-session gvfs xdg-utils fonts-dejavu-core fonts-liberation locales \
    firefox-esr firefox-esr-l10n-ru git ca-certificates curl cifs-utils gnome-keyring libpam-gnome-keyring \
    libasound2t64 libayatana-appindicator3-1 xdg-desktop-portal-gtk python3 libsecret-tools libglib2.0-bin \
    /opt/pocket-build/claude-desktop.deb /opt/pocket-build/claude-code.deb
echo 'POCKET_STAGE {"stage":"configure"}'
command -v gdbus secret-tool >/dev/null
install -d /etc/sddm.conf.d /etc/systemd/network /etc/systemd/resolved.conf.d /etc/xdg/lxqt /home/pocket/Desktop
cat >/etc/sddm.conf.d/10-pocket.conf <<EOF
[Autologin]
User=pocket
Session=$session
Relogin=true
EOF
printf 'en_US.UTF-8 UTF-8\nru_RU.UTF-8 UTF-8\n' >/etc/locale.gen
locale-gen
update-locale LANG=ru_RU.UTF-8
cat >/etc/default/keyboard <<'EOF'
XKBMODEL="pc105"
XKBLAYOUT="us,ru"
XKBVARIANT=""
XKBOPTIONS="grp:alt_shift_toggle"
BACKSPACE="guess"
EOF
cat >/etc/systemd/network/05-pocket.network <<'EOF'
[Match]
MACAddress=52:54:00:50:4c:01
[Network]
Address=192.168.127.2/24
Gateway=192.168.127.1
DNS=192.168.127.1
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF
cat >/etc/systemd/network/20-pocket-files.network <<'EOF'
[Match]
MACAddress=52:54:00:50:4c:03
[Network]
Address=192.168.234.15/24
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF
cat >/etc/systemd/resolved.conf.d/10-pocket.conf <<'EOF'
[Resolve]
DNS=192.168.127.1
FallbackDNS=
Domains=~.
LLMNR=no
MulticastDNS=no
EOF
printf 'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n' >/etc/sysctl.d/90-pocket-ipv6.conf
systemctl enable systemd-networkd sddm
systemctl disable networking.service ssh.service ssh.socket 2>/dev/null || true
systemctl set-default graphical.target
install -d /etc/default/grub.d /etc/systemd/system/systemd-networkd-wait-online.service.d
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*-amd64' ! -name '*-cloud-*' -printf '%f\n' | sort -V | tail -n 1)
test -n "$kernel"
printf 'GRUB_DEFAULT="Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux %s"\n' "${kernel#vmlinuz-}" >/etc/default/grub.d/99-pocket.cfg
printf '[Service]\nExecStart=\nExecStart=/bin/true\n' >/etc/systemd/system/systemd-networkd-wait-online.service.d/pocket.conf
touch /etc/cloud/cloud-init.disabled
cat >/usr/share/applications/pocket-claude-code.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Claude Code
Comment=Claude Code in a terminal
Exec=$terminal -e claude
Icon=utilities-terminal
Terminal=false
Categories=Development;
EOF
cp /usr/share/applications/pocket-claude-code.desktop /home/pocket/Desktop/
find /usr/share/applications -maxdepth 1 -iname '*claude*.desktop' ! -name 'pocket-claude-code.desktop' -exec cp '{}' /home/pocket/Desktop/ \;
chmod 0755 /home/pocket/Desktop/*.desktop
chown -R pocket:pocket /home/pocket/Desktop
usermod -a -G render pocket
install -d -m 0755 /var/lib/pocket-build
cp /opt/pocket-build/artifacts.json /var/lib/pocket-build/artifacts.json
systemctl stop sddm.service 2>/dev/null || true
if [ "$desktop" = plasma ]; then
    python3 -I -B /opt/pocket-build/guest_plasma.py
else
    python3 -I -B /opt/pocket-build/guest_style.py
fi
python3 -I -B /opt/pocket-build/guest_access.py
install -m 0755 /opt/pocket-build/guest_folders.py /usr/local/sbin/pocket-folders
python3 -I -B /usr/local/sbin/pocket-folders --prepare-shortcuts
cat >/etc/systemd/system/pocket-folders.service <<'EOF'
[Unit]
Description=Selected Windows folders for Pocket Linux
After=systemd-networkd.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/local/sbin/pocket-folders
TimeoutStartSec=65
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl enable pocket-folders.service
install -d /opt/pocket /etc/xdg/autostart
install -m 0644 /opt/pocket-build/clipboard_bridge.py /opt/pocket/clipboard_bridge.py
install -m 0755 /opt/pocket-build/guest_clipboard.py /opt/pocket/guest_clipboard.py
install -m 0755 /opt/pocket-build/guest_status.py /opt/pocket/guest_status.py
install -m 0644 /opt/pocket-build/pocket-clipboard.service /etc/systemd/system/pocket-clipboard.service
install -m 0644 /opt/pocket-build/pocket-status.service /etc/systemd/system/pocket-status.service
install -m 0644 /opt/pocket-build/pocket-clipboard.desktop /etc/xdg/autostart/pocket-clipboard.desktop
systemctl enable pocket-clipboard.service pocket-status.service
install -m 0755 /opt/pocket-build/guest_verify.py /usr/local/sbin/pocket-verify
touch /var/lib/pocket-build/verify-once
cat >/etc/systemd/system/pocket-verify.service <<'EOF'
[Unit]
Description=One-time Pocket Linux image acceptance
After=display-manager.service pocket-folders.service
ConditionPathExists=/var/lib/pocket-build/verify-once
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/local/sbin/pocket-verify
TimeoutStartSec=900
[Install]
WantedBy=graphical.target
EOF
systemctl enable pocket-verify.service
# Restore ordinary signed Debian repositories for later updates through the chosen proxy.
sed -i 's|http://198.18.0.10:18080/debian|https://deb.debian.org/debian|; s|http://198.18.0.10:18080/security|https://security.debian.org/debian-security|' /etc/apt/sources.list.d/debian.sources
apt-get clean
rm -f /opt/pocket-build/*.deb
rm -rf /var/lib/apt/lists/*
update-initramfs -u
update-grub
sync
fstrim -av || true
echo 'POCKET_BUILD_DONE {"ok":true,"next":"cold-boot-verification"}'
systemctl poweroff
