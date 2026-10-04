#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests bpf-toolchain.sh's guard on the directory it empties: a non-empty directory it did not make is refused
# (exit 2) with its contents left alone. Nothing is fetched.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-bpf-toolchain-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir "$tmp/work"
echo precious >"$tmp/work/file"
rc=0
"$here/bpf-toolchain.sh" "$tmp/work" >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -ne 2 ] || [ "$(cat "$tmp/work/file" 2>/dev/null)" != precious ]; then
	echo "FAIL: a directory the script did not make: exit ${rc}, want 2 with its file kept"
	sed 's/^/    /' "$tmp/out"
	exit 1
fi
echo "ok   a directory the script did not make is refused"
