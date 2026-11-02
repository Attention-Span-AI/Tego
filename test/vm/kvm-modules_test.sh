#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kvm-run.sh's find_ko, which locates a --module's file: the kernel treats - and _ in a module name as
# one and modinfo prints underscores, but the files keep the hyphens they were built with (snd-hda-intel.ko.zst),
# so a hyphenated module, or a dependency that modinfo spells with underscores, was "neither built in nor in
# linux-modules". find_ko is taken from the script as written. Then its fetch_module_tree, which finds the module
# tree a --module is read from: apt's for this host's kernel, a kernel-matrix row's own for a row's (below).
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-kvm-modules-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

sed -n '/^find_ko() {/p' "$here/kvm-run.sh" >"$tmp/find_ko.sh"
[ -s "$tmp/find_ko.sh" ] || { echo "FAIL find_ko is not defined on one line in kvm-run.sh"; exit 1; }
. "$tmp/find_ko.sh"

mkdir -p "$tmp/m/kernel/sound"
: >"$tmp/m/kernel/sound/snd-hda-intel.ko.zst"
: >"$tmp/m/kernel/sound/overlay.ko"
: >"$tmp/m/kernel/sound/snd_plain_us.ko.xz"

check() { # want name
	got=$(find_ko "$tmp/m" "$2")
	case "$got" in
	*"$1") echo "ok   find_ko $2" ;;
	*) echo "FAIL find_ko $2: got '$got', want ...$1"; exit 1 ;;
	esac
}
check snd-hda-intel.ko.zst snd-hda-intel
check snd-hda-intel.ko.zst snd_hda_intel
check overlay.ko overlay
check snd_plain_us.ko.xz snd-plain-us
[ -z "$(find_ko "$tmp/m" absent)" ] || { echo "FAIL find_ko found a module that is not there"; exit 1; }
echo "ok   find_ko of an absent module is empty"

# fetch_module_tree, taken from the script as written, with fetch_debs and env_fail standing in: on this host's kernel
# it asks apt for linux-modules-<kernel>, and for -extra when a module is not in it. A kernel-matrix row's kernel has
# no such package, so a --module there needs the row's own tree (fetch-kernel.py --modules), and without one the guest
# is refused with exit 97 naming that command instead of an apt failure about a package nobody publishes; a row's
# tree, stamped with its package's digest, is all the modules the row has, so no -extra is asked for beside it.
sed -n '/^fetch_module_tree() {/,/^}/p' "$here/kvm-run.sh" >"$tmp/fetch_module_tree.sh"
grep -q '^}' "$tmp/fetch_module_tree.sh" || { echo "FAIL fetch_module_tree is not in kvm-run.sh"; exit 1; }
. "$tmp/fetch_module_tree.sh"
fetch_debs() { echo "fetch_debs $2" >>"$tmp/fetched"; mkdir -p "$KDIR/mods/lib/modules/$KVER"; }
env_fail() { echo "env_fail: $*"; exit 97; }

KVER=6.17.0-41-generic KDIR="$tmp/host"
: >"$tmp/fetched"
fetch_module_tree
fetch_module_tree extra
[ "$(cat "$tmp/fetched")" = "fetch_debs linux-modules-$KVER
fetch_debs linux-modules-extra-$KVER" ] || { echo "FAIL this host's kernel: apt was asked for $(cat "$tmp/fetched")"; exit 1; }
echo "ok   fetch_module_tree asks apt for this host's kernel's modules, and -extra when asked"

KVER=matrix-debian-13 KDIR="$tmp/row"
: >"$tmp/fetched"
set +e
said=$(fetch_module_tree)
rc=$?
set -e
case "$rc:$said" in
97:*"fetch-kernel.py --modules debian-13"*) echo "ok   a row's kernel with no tree is refused, naming fetch-kernel.py --modules" ;;
*) echo "FAIL a row's kernel with no tree: exit $rc, said '$said'"; exit 1 ;;
esac
[ ! -s "$tmp/fetched" ] || { echo "FAIL a row's kernel: apt was asked for $(cat "$tmp/fetched")"; exit 1; }
mkdir -p "$KDIR/mods/lib/modules/$KVER"
echo 7794643cf4560de2a7e3b069e8ca8511ad2a568d652ea285f0fe051f79bc9e99 >"$KDIR/mods/.package-sha256"
fetch_module_tree
fetch_module_tree extra
[ ! -s "$tmp/fetched" ] || { echo "FAIL a row's tree: apt was asked for $(cat "$tmp/fetched")"; exit 1; }
echo "ok   a row's own tree is used as it is, with no -extra asked for beside it"
