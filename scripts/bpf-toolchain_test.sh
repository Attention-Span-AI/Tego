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

# A default upgrade must choose a fresh marked cache, not adopt even an exact
# old stamp. Populate the new cache as a previous marked install would have.
legacy="$tmp/cache/tego/bpf-toolchain"
owned="$tmp/cache/tego/bpf-toolcache"
mkdir -p "$legacy/bin" "$owned/bin"
echo precious >"$legacy/file"
pin() { sed -n "s/^$1=//p" "$here/bpf-toolchain.sh"; }
printf '%s %s %s wrappers-%s\n' "$(pin LLVM_SHA256)" "$(pin LIBC_SHA256)" \
	"$(pin ZLIB_SHA256)" "$(pin WRAPPERS)" >"$owned/stamp"
cp "$owned/stamp" "$legacy/stamp"
printf '#!/bin/sh\nexit 0\n' >"$owned/bin/clang"
chmod +x "$owned/bin/clang"
cp "$owned/bin/clang" "$legacy/bin/clang"
: >"$owned/.tego-bpf-toolchain"
rc=0
XDG_CACHE_HOME="$tmp/cache" "$here/bpf-toolchain.sh" >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -ne 0 ] || [ "$(cat "$tmp/out")" != "$owned/bin" ] ||
	[ "$(cat "$legacy/file")" != precious ] || [ -e "$legacy/.tego-bpf-toolchain" ]; then
	echo "FAIL: default cache upgrade did not leave the unmarked cache alone"
	cat "$tmp/out"
	exit 1
fi
rc=0
"$here/bpf-toolchain.sh" "$legacy" >"$tmp/out" 2>&1 || rc=$?
if [ "$rc" -ne 2 ] || [ "$(cat "$legacy/file")" != precious ] || [ -e "$legacy/.tego-bpf-toolchain" ]; then
	echo "FAIL: a matching legacy stamp authorized an explicit unmarked cache"
	exit 1
fi
echo "ok   default cache upgrade leaves legacy state untouched; explicit legacy paths refuse"
