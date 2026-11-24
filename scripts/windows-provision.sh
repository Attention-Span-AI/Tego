#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Only executed as root inside the dedicated distribution, after asset verification.
set -euo pipefail
# WSL distributions share numeric identities. Use 26743 instead of the usual
# first-user 1000; root in another distribution can still assume any identity.
uid=26743
gid=26743
config=$(cat <<'CONF'
[boot]
systemd=true
[automount]
enabled=false
mountFsTab=false
ldconfig=false
[interop]
enabled=false
appendWindowsPath=false
[general]
guiApplications=false
[gpu]
enabled=false
appendLibPath=false
[user]
default=tego
CONF
)
if [ "${2:-}" = check ]; then
    if [ -f /etc/wsl.conf ] && [ "$(cat /etc/wsl.conf)" = "$config" ] &&
        [ "$(id -u tego 2>/dev/null)" = "$uid" ] && [ "$(id -g tego 2>/dev/null)" = "$gid" ]; then
        exit 0
    fi
    exit 10
fi
if ! id tego >/dev/null 2>&1; then
    groupadd --gid "$gid" tego
    useradd --uid "$uid" --gid "$gid" --create-home --shell /bin/bash tego
elif [ "$(id -u tego)" != "$uid" ] || [ "$(id -g tego)" != "$gid" ]; then
    # usermod refuses a busy account; the installer asks before this repair.
    groupmod --gid "$gid" tego
    usermod --uid "$uid" --gid "$gid" tego
fi
[ "$(id -u tego)" = "$uid" ]
[ "$(id -g tego)" = "$gid" ]
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null ||
    ! dpkg-query -W -f='${Status}' dbus-user-session 2>/dev/null | grep -q 'install ok installed'; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl python3 systemd systemd-sysv dbus-user-session
fi
install -d -m 0755 /usr/local/lib/tego
printf '%s' "$1" | base64 -d >/usr/local/lib/tego/windows-entry
chmod 0755 /usr/local/lib/tego/windows-entry
printf '%s\n' "$config" >/etc/wsl.conf
# No sudo group or passwordless escalation: Windows can explicitly select root
# for administration. Enable the user manager for scope entry after a cold start.
install -d -m 0755 /var/lib/systemd/linger
touch /var/lib/systemd/linger/tego
# Keep repair writes in root-owned directories; a user-owned .profile could
# have become a symlink since the previous installation.
cat >/etc/profile.d/tego-path.sh <<'PROFILE'
export PATH="$HOME/.local/bin:$PATH"
PROFILE
chmod 0644 /etc/profile.d/tego-path.sh
# Windows PowerShell's text pipeline can append a final CRLF to this LF asset.
# Exit after the checked script body, before that extra carriage-return line.
exit 0
