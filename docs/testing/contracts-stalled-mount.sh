#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Owed in a guest. Never execute this entry point on the host.
set -eu
[ "${TEGO_DISPOSABLE_HOST:-}" = kvm ]
[ "$(id -u)" = 0 ]
[ -n "${SUDO_UID:-}" ]
[ -n "${SUDO_GID:-}" ]
[ "$SUDO_UID" != 0 ]
command -v python3 >/dev/null
command -v setpriv >/dev/null
command -v fusermount >/dev/null
test -c /dev/fuse
mkdir -p /sys/fs/fuse/connections
if ! awk '$5 == "/sys/fs/fuse/connections" { found = 1 } END { exit !found }' /proc/self/mountinfo; then
    mount -t fusectl fusectl /sys/fs/fuse/connections
fi
exec python3 -I /vm/recipes/contracts-stalled-mount.py
