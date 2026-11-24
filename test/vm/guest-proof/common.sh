#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Shared helpers of the guest proofs: the payload is mounted at /mnt/p2, Tego is installed per user from a pair.
P=/mnt/p2
B=$HOME/.local/bin
FAILS=0
export PATH="$B:$PATH"
ok() { echo "CHECK PASS: $1"; }
bad() { echo "CHECK FAIL: $1"; FAILS=$((FAILS + 1)); }
chk() { if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }
# inst PAIR: put the pair's tego and tego-control side by side in ~/.local/bin
inst() {
	mkdir -p "$B"
	install -m 0755 "$P/bin/$1/tego" "$B/tego"
	install -m 0755 "$P/bin/$1/tego-control" "$B/tego-control"
	chmod go-w "$B/tego-control"
	echo "INSTALLED pair $1: tego $(sha256sum "$B/tego" | cut -c1-16)..., tego-control $(sha256sum "$B/tego-control" | cut -d' ' -f1)"
}
facts() {
	echo "== facts"
	uname -r
	grep -E '^(PRETTY_NAME|ID)=' /etc/os-release
	id
	loginctl show-user "$USER" -p Linger -p State
	cat /sys/kernel/security/lsm
	echo
	echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"
	systemctl --user is-system-running
}
