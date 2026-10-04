#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bpf-toolchain.sh — fetches the pinned toolchain `make gen` compiles bpf/ with, and prints the directory of its
# clang and llvm-strip, for PATH. The committed objects in internal/bpf must be exactly its output (CI job bpf-gen).
#
# The pin is LLVM 20.1.8's release build together with the C library it runs on. The release clang is linked
# dynamically against the host's glibc, and its output depends on that glibc: the same clang, on the same input
# and flags, made trace_bpfel.o and trace_bpfeb.o with other bytes of the same size on Ubuntu 24.04's glibc 2.39
# than on Ubuntu 25.10's 2.42 (measured 2026-09-24; the GitHub runner is 24.04, so bpf-gen failed on objects made
# on 25.10). So clang and llvm-strip run here through the loader and libraries of Ubuntu 24.04's libc6 and zlib1g,
# fetched and checked like the LLVM tarball, with no library of the host's, and with the environment variables that
# change how that glibc allocates (GLIBC_TUNABLES, MALLOC_*) or what it loads (LD_PRELOAD, LD_AUDIT) removed, since
# either changes the output too (GLIBC_TUNABLES=glibc.malloc.mmap_threshold=4096 did). The output is then the same
# on every x86_64 Linux machine whose /etc/ld.so.preload is empty, which the loader still reads.
#
# Usage: scripts/bpf-toolchain.sh [DIR]   (default ${XDG_CACHE_HOME:-$HOME/.cache}/tego/bpf-toolchain)
# Needs curl, sha256sum, tar with xz, ar and zstd. Prints DIR/bin on stdout; progress goes to stderr.
set -euo pipefail

LLVM='LLVM-20.1.8-Linux-X64'
LLVM_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.8/$LLVM.tar.xz"
LLVM_SHA256=1ead36b3dfcb774b57be530df42bec70ab2d239fbce9889447c7a29a4ddc1ae6
# Each package is fetched from the archive's pool first, a mirror network, and from Launchpad's +files URL when that
# fails: the pool drops an update once a newer one supersedes it, and Launchpad keeps a published package for good
# but answered 503 to a CI runner (2026-09-24). A package the pool has dropped takes a dated snapshot.ubuntu.com URL
# in its place, which does not change. Whichever answers, the sha256 decides.
LIBC_URLS="http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.39-0ubuntu8.9_amd64.deb https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.39-0ubuntu8.9_amd64.deb"
LIBC_SHA256=ff5557d99b51f761c4b7c92368b9cc45565eda17df9bf9eb4b134d09825008be
ZLIB_URLS="https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb https://launchpad.net/ubuntu/+archive/primary/+files/zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb"
ZLIB_SHA256=84b9cf5752b29c9f92c27cd4c4ba9bbcc70b5ccf9b1b515421a28ae23212e273

dir="${1:-${XDG_CACHE_HOME:-$HOME/.cache}/tego/bpf-toolchain}"
# The wrappers' own version is part of the stamp, so a change to them is written into an existing toolchain.
WRAPPERS=2
marker=.tego-bpf-toolchain
# Two runs on one directory (two `make gen`s on the default cache) would remove each other's half-built toolchain,
# so the second waits for the first and then finds its stamp.
mkdir -p "$(dirname "$dir")"
if command -v flock >/dev/null; then
	exec 9>"$dir.lock"
	flock 9
fi
stamp="$LLVM_SHA256 $LIBC_SHA256 $ZLIB_SHA256 wrappers-$WRAPPERS"
if [ "$(cat "$dir/stamp" 2>/dev/null)" = "$stamp" ] && [ -x "$dir/bin/clang" ]; then
	echo "$dir/bin"
	exit 0
fi
# DIR is emptied below, so a directory that is not this script's own (no marker, and no stamp from before there
# was one) is refused, as scripts/coverage.sh refuses one it did not make.
if [ -e "$dir" ] && [ ! -f "$dir/$marker" ] && [ ! -f "$dir/stamp" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
	echo "bpf-toolchain: $dir exists and was not made by bpf-toolchain.sh (no $marker in it); not emptying it. Name another directory." >&2
	exit 2
fi
[ "$(uname -m)" = x86_64 ] || { echo "bpf-toolchain: the pinned toolchain is x86_64 only, not $(uname -m)" >&2; exit 1; }
for tool in curl sha256sum tar xz ar zstd; do
	command -v "$tool" >/dev/null || { echo "bpf-toolchain: $tool is not on PATH" >&2; exit 1; }
done

rm -rf "$dir"
mkdir -p "$dir/dl" "$dir/lib"
echo "made by scripts/bpf-toolchain.sh, which empties this directory when its toolchain changes" >"$dir/$marker"
fetch() { # "url..." sha256 file: the first URL whose download has the sha256, each tried with curl's retries
	local url
	for url in $1; do
		echo "bpf-toolchain: fetching $url" >&2
		if curl -fsSL --retry 4 --retry-all-errors --retry-delay 3 --connect-timeout 20 -o "$3" "$url" &&
			echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then
			return 0
		fi
		echo "bpf-toolchain: $url failed or did not match its sha256" >&2
	done
	echo "bpf-toolchain: no source gave $(basename "$3") with sha256 $2" >&2
	return 1
}
fetch "$LLVM_URL" "$LLVM_SHA256" "$dir/dl/llvm.tar.xz"
tar -C "$dir" -xJf "$dir/dl/llvm.tar.xz" "$LLVM/bin/clang-20" "$LLVM/bin/llvm-objcopy" "$LLVM/lib/clang"
unpack() { # name "url..." sha256 library...
	local name="$1" url="$2" sha="$3" lib
	shift 3
	fetch "$url" "$sha" "$dir/dl/$name.deb"
	mkdir -p "$dir/dl/$name"
	ar p "$dir/dl/$name.deb" data.tar.zst | zstd -dcq | tar -C "$dir/dl/$name" -x
	for lib in "$@"; do
		cp -L "$dir/dl/$name/usr/lib/x86_64-linux-gnu/$lib" "$dir/lib/$lib"
	done
}
unpack libc "$LIBC_URLS" "$LIBC_SHA256" ld-linux-x86-64.so.2 libc.so.6 libm.so.6
unpack zlib "$ZLIB_URLS" "$ZLIB_SHA256" libz.so.1
rm -rf "$dir/dl"

# clang finds its resource directory from its own executable, which under an explicit loader is the loader, so
# the wrapper names it. llvm-strip is llvm-objcopy run under that name, which is what the release's symlink does.
# Each wrapper finds the toolchain from its own path, so the directory can be moved (a CI cache restores it).
mkdir -p "$dir/bin"
keep_env='unset GLIBC_TUNABLES LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH MALLOC_ARENA_MAX MALLOC_ARENA_TEST MALLOC_CHECK_ MALLOC_MMAP_MAX_ MALLOC_MMAP_THRESHOLD_ MALLOC_PERTURB_ MALLOC_TOP_PAD_ MALLOC_TRIM_THRESHOLD_'
cat >"$dir/bin/clang" <<EOF
#!/bin/sh
$keep_env
d="\$(cd "\$(dirname "\$0")/.." && pwd)"
exec "\$d/lib/ld-linux-x86-64.so.2" --library-path "\$d/lib" "\$d/$LLVM/bin/clang-20" -resource-dir "\$d/$LLVM/lib/clang/20" "\$@"
EOF
cat >"$dir/bin/llvm-strip" <<EOF
#!/bin/sh
$keep_env
d="\$(cd "\$(dirname "\$0")/.." && pwd)"
exec "\$d/lib/ld-linux-x86-64.so.2" --library-path "\$d/lib" --argv0 llvm-strip "\$d/$LLVM/bin/llvm-objcopy" "\$@"
EOF
chmod 0755 "$dir/bin/clang" "$dir/bin/llvm-strip"
"$dir/bin/clang" --version | head -1 >&2
echo "$stamp" >"$dir/stamp"
echo "$dir/bin"
