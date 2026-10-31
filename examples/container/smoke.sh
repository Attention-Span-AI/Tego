#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh: the image's own check, run inside the container as the tego user (the CI container job runs it through
# compose.yaml's agent service, so with that file's settings):
#   1. tego and tego-control print one version and tego-control is the binary tego pins;
#   2. tego doctor finds tier landlock usable here (--require landlock: exit 211 otherwise);
#   3. tego test: four harmless actions on decoys, each refused and recorded;
#   4. a short tego run of the example agent (hello.yaml): exit 0, its one allowed write made, its one disallowed
#      write refused and recorded, and its chain verified against the anchor in ~/.tego.
# Exit 0 when all hold; the first that does not ends the script with its own message.
set -euo pipefail

# It runs tego as whoever starts it, with that user's own ~/.tego and runtime directory: in the image that is the tego
# user and its state volume. Anyone else would get these runs in their own ledger and chain anchor, so it refuses
# unless TEGO_SMOKE_HERE=1 says the caller has isolated tego itself (TEGO_CONFIG, a test build's anchor variables).
if [ "$(id -un)" != tego ] && [ "${TEGO_SMOKE_HERE:-0}" != 1 ]; then
	echo "smoke: runs as the image's tego user only (this is $(id -un)); TEGO_SMOKE_HERE=1 if you isolated tego" >&2
	exit 2
fi

share=${TEGO_SHARE:-/usr/local/share/tego}
contract=${TEGO_SMOKE_CONTRACT:-$share/hello.yaml}
work=${TEGO_WORK:-/work}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
	echo "smoke: FAIL: $*" >&2
	exit 1
}
field() { sed -n "s/^$1=//p"; }

echo "smoke: 1. versions and the control pin"
tv=$(tego version)
cv=$(tego-control version)
printf '%s\n%s\n' "$tv" "$cv"
sum=$(sha256sum "$(command -v tego-control)" | cut -d' ' -f1)
[ "$(field control_sha256 <<<"$tv")" = "$sum" ] || fail "tego pins control_sha256=$(field control_sha256 <<<"$tv"), the image's tego-control is $sum"
[ "$(field tego <<<"$tv")" = "$(field tego-control <<<"$cv")" ] || fail "tego and tego-control print different versions"

echo "smoke: 2. tego doctor --require landlock"
tego doctor --require landlock || fail "tego doctor: tier landlock is not usable in this container (exit $?)"

echo "smoke: 3. tego test"
TMPDIR="$tmp" tego test || fail "tego test (exit $?)"

echo "smoke: 4. tego run $contract"
rm -f "$work/out/hello.txt" "$work/outside.txt"
rc=0
tego run --tier landlock "$contract" 2>"$tmp/run.err" || rc=$?
cat "$tmp/run.err" >&2
[ "$rc" -eq 0 ] || fail "tego run exited $rc"
run=$(sed -n 's/^tego run: \(r-[^ ]*\) ended.*/\1/p' "$tmp/run.err" | head -n 1)
[ -n "$run" ] || fail "tego run printed no run id"
grep -q '^hello from an agent under tego' "$work/out/hello.txt" || fail "the allowed write is not in $work/out/hello.txt"
[ ! -e "$work/outside.txt" ] || fail "the disallowed write went through: $work/outside.txt exists"
tego events "$run" --verdict refused >"$tmp/refused.txt"
cat "$tmp/refused.txt"
grep -q 'outside.txt' "$tmp/refused.txt" || fail "the ledger of $run records no refusal of $work/outside.txt"
tego events "$run" --verify || fail "tego events $run --verify (exit $?)"
echo "smoke: ok ($run)"
