#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kvm-run.sh's find_ko, which locates a --module's file: the kernel treats - and _ in a module name as
# one and modinfo prints underscores, but the files keep the hyphens they were built with (snd-hda-intel.ko.zst),
# so a hyphenated module, or a dependency that modinfo spells with underscores, was "neither built in nor in
# linux-modules". find_ko is taken from the script as written.
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
