#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-control-pin.sh [--static] TEGO CONTROL: checks that TEGO pins CONTROL (ADR 0100 (1b)). `make build` runs it on
# bin/tego and bin/tego-control, and .goreleaser.yaml's tego-control build on each target's pair.
#
# Always: CONTROL's SHA-256 is the pin TEGO was linked with (the -X value is in the binary's bytes). Without
# --static, and when both run here (the host's architecture, and not as root, which tego-control refuses), it also
# runs them: `tego version`'s control_sha256 is that hash, `tego-control version`'s sha256 is too, and the two print
# the same version, commit and date. --static is for a cross-built pair this machine cannot run.
set -euo pipefail

static=0
if [ "${1:-}" = "--static" ]; then
	static=1
	shift
fi
if [ "$#" -ne 2 ]; then
	echo "usage: $0 [--static] TEGO CONTROL" >&2
	exit 2
fi
tego=$1
control=$2
fail() {
	echo "check-control-pin: $*" >&2
	exit 1
}
[ -f "$tego" ] || fail "$tego: no such file"
[ -f "$control" ] || fail "$control: no such file"
sum=$(sha256sum "$control" | cut -d' ' -f1)
[ "${#sum}" -eq 64 ] || fail "cannot hash $control"
grep -q -a -F "$sum" "$tego" || fail "$tego does not pin $control's SHA-256 $sum: build the pair together (make build)"
if [ "$static" -eq 1 ]; then
	echo "check-control-pin: $tego pins $control ($sum)"
	exit 0
fi
if [ "$(id -u)" -eq 0 ]; then
	echo "check-control-pin: $tego pins $control ($sum); not run as root, which tego-control refuses"
	exit 0
fi
field() { sed -n "s/^$1=//p"; }
tv=$("$tego" version) || fail "$tego version failed"
cv=$("$control" version) || fail "$control version failed"
[ "$(field control_sha256 <<<"$tv")" = "$sum" ] || fail "$tego version says control_sha256=$(field control_sha256 <<<"$tv"), want $sum"
[ "$(field sha256 <<<"$cv")" = "$sum" ] || fail "$control version says sha256=$(field sha256 <<<"$cv"), want $sum"
[ "$(field tego <<<"$tv")" = "$(field tego-control <<<"$cv")" ] || fail "versions differ: tego=$(field tego <<<"$tv") tego-control=$(field tego-control <<<"$cv")"
for k in commit date; do
	[ "$(field "$k" <<<"$tv")" = "$(field "$k" <<<"$cv")" ] || fail "$k differs: tego $(field "$k" <<<"$tv"), tego-control $(field "$k" <<<"$cv")"
done
echo "check-control-pin: $tego pins $control ($sum), and both print version $(field tego <<<"$tv")"
