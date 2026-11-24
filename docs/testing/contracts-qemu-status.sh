#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Host wrapper. Keep raw QEMU exit status outside the harness's removed tmp tree.
set -u
: "${CONTRACTS_QEMU_REAL:?}" "${CONTRACTS_QEMU_STATUS:?}"
if [ "${1:-}" = --version ]; then
    exec "$CONTRACTS_QEMU_REAL" "$@"
fi
"$CONTRACTS_QEMU_REAL" "$@" &
qemu_child=$!
trap 'kill -TERM "$qemu_child" 2>/dev/null || true' TERM
trap 'kill -INT "$qemu_child" 2>/dev/null || true' INT
trap 'kill -HUP "$qemu_child" 2>/dev/null || true' HUP
while :; do
    wait "$qemu_child"
    qemu_rc=$?
    kill -0 "$qemu_child" 2>/dev/null || break
done
printf '%s\n' "$qemu_rc" > "$CONTRACTS_QEMU_STATUS"
exit "$qemu_rc"
