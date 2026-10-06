#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# doctor-refusal.sh — the whole body of a doctor-only kernel-matrix row (fetch-kernel.py's DOCTOR_ONLY; ADR 0017's
# 2026-10-05 note): that this machine is refused, with the remedy, and that tego will not run on it. Ubuntu 22.04's
# 5.15 is the row: its Landlock is ABI 1, below doctor.MinLandlockABI = 2 (rename and link confined to one directory),
# so no tier is offered, tier 2 never runs there, and no kill test has a tier to run at. What the row can check is the
# product's answer, as the person on that machine sees it:
#
#   tego doctor                      exits 1 (a finding: no tier can run), says `tier: none`, and ends on the one
#                                     `fix:` line that makes tier landlock available;
#   tego doctor --require landlock   exits 211;
#   tego doctor --json               holds an empty tier and a Landlock ABI below 2;
#   tego run <contract>              exits 125 with [tier-unavailable] and that same fix, with the tier auto-selected
#                                     and with --tier landlock pinned.
#
# The fix is the one doctor's D4 says for a kernel with Landlock ABI 1 ("boot a kernel >= 5.19 (Landlock ABI 2 ...)"),
# or for one with none ("boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y", "add landlock to the kernel's lsm=
# line ..."): a distro may build 5.15 either way, and either is a machine with no tier and a remedy.
#
# It fails when a part of that is wrong, and when the machine offers a tier at all: a doctor-only row whose kernel
# gained one is stale, and should run in full. It never starts a run on such a machine: `tego run` is only called
# once doctor has said there is no tier to run at, so the check on a developer's box fails before it runs anything.
# test/vm/doctor-refusal_test.sh holds each of these to a stand-in that gets one part wrong.
#
# The identity is the caller's: run-matrix-row.sh calls it as the user and as root. The machine config, and with it
# the ledger root, is a scratch directory's, and so is HOME, but tego keeps its own log under the home the passwd
# database names for the invoking uid, not $HOME. The check is for a guest, which is thrown away; on any other box
# it stops after `tego doctor` when doctor offers a tier, and never reaches a run.
#
# Usage: doctor-refusal.sh <tego-binary>
# Exit 0 when the refusal is whole, 1 when a part is wrong (the last line is FAIL: and the parts), 2 on a usage error.
set -uo pipefail

usage() {
	echo "usage: doctor-refusal.sh <tego-binary>" >&2
	exit 2
}
[ $# -eq 1 ] || usage
tego="$1"
[ -x "$tego" ] || { echo "doctor-refusal: $tego is not an executable file" >&2; exit 2; }

problems=()
problem() {
	problems+=("$1")
	echo "doctor-refusal: $1" >&2
}
finish() {
	if [ "${#problems[@]}" -eq 0 ]; then
		echo "PASS: no tier is offered (Landlock ABI $abi): doctor exits 1 with tier: none and \"fix: $fix\", --require landlock exits 211, tego run exits 125 [tier-unavailable] with that fix"
		exit 0
	fi
	local msg="" p
	for p in "${problems[@]}"; do msg+="${msg:+; }$p"; done
	echo "FAIL: $msg"
	exit 1
}
abi="?"
fix=""

if ! command -v jq >/dev/null 2>&1; then
	# The guest carries jq (matrix.sh); a guest without one is a broken harness, never a pass.
	problem "jq is not on PATH, and doctor --json cannot be read without it"
	finish
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/tego-doctor-refusal.XXXXXX")" || { echo "doctor-refusal: no scratch directory" >&2; exit 2; }
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the directory is made absolute.
work="$(cd "$work" && pwd)" || { echo "doctor-refusal: cannot enter $work" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
export HOME="$work"
# Every tego call here, doctor included, runs with an isolation of its own: a binary built with -tags tegotesthooks (the
# matrix builds the guests' with it under VM_TESTHOOKS=1) refuses a machine config whose ledger_root is the built-in
# ~/.tego/runs, which is what no TEGO_CONFIG gives it, and a product build would anchor in the guest user's ~/.tego.
# The machine config names a ledger_root of its own, the chain anchor and the own-log home are in the work directory, and
# no shell history is kept (identity-config.md R27).
cat >"$work/config.yaml" <<EOF
version: 0
ledger_root: $work/runs
stop_grace: 3s
EOF
chmod 600 "$work/config.yaml"
mkdir -p "$work/log-home"
export TEGO_CONFIG="$work/config.yaml" TEGO_TEST_CHAIN_ANCHOR="$work/chain.log" TEGO_TEST_OWN_LOG_HOME="$work/log-home" HISTFILE=/dev/null

# doctor's own answer, as text.
out="$("$tego" doctor 2>&1)"
rc=$?
tier_line="$(grep -E '^tier: ' <<<"$out" | tail -1)"
case "$tier_line" in
"tier: none"*) ;;
*)
	problem "this machine offers a tier (doctor says \"${tier_line:-no tier line}\"): the row should run in full, so take it out of fetch-kernel.py's DOCTOR_ONLY"
	# No run is started on a machine that offers a tier: tego run would run the contract.
	finish
	;;
esac
[ "$rc" = 1 ] || problem "doctor exited $rc, want 1 (no tier at all can run)"
fix="$(sed -n 's/^fix: //p' <<<"$out" | tail -1)"
if [ -z "$fix" ]; then
	problem "doctor's output has no final fix: line"
else
	case "$fix" in
	"boot a kernel >= 5.19 "* | "boot a kernel >= 5.13 "* | "add landlock to the kernel's lsm= line"*) ;;
	*) problem "doctor's fix is \"$fix\", want the remedy for Landlock: boot a kernel >= 5.19 (ABI 1), boot one >= 5.13 with CONFIG_SECURITY_LANDLOCK=y, or add landlock to lsm=" ;;
	esac
fi
grep -qE '^FAIL landlock: .*; fix: ' <<<"$out" || problem "doctor's landlock line (D4) does not fail with a fix"
grep -qE '^missing for landlock: ' <<<"$out" || problem "doctor does not say what is missing for landlock"

# --require landlock: 211 and the sentence.
req="$("$tego" doctor --require landlock 2>&1)"
rrc=$?
[ "$rrc" = 211 ] || problem "doctor --require landlock exited $rrc, want 211"
grep -q 'required tier landlock is not available on this machine' <<<"$req" ||
	problem "doctor --require landlock does not say the tier is not available on this machine"

# --json: no tier and an ABI below the floor (0 where there is no Landlock at all).
js="$("$tego" doctor --json 2>/dev/null)"
jtier="$(jq -r '.tier // ""' <<<"$js" 2>/dev/null)"
abi="$(jq -r '.landlock_abi // 0' <<<"$js" 2>/dev/null)"
[ -z "$jtier" ] || problem "doctor --json names tier $jtier on a machine whose text says tier: none"
case "$abi" in
0 | 1) ;;
*) problem "doctor --json reports Landlock ABI ${abi:-none}, which is not below the floor of 2" ;;
esac

# tego run: refused before anything starts, and the same refusal when a tier is pinned.
mkdir -p "$work/out"
cat >"$work/agent.yaml" <<EOF
version: 0
name: refusal
command: ["true"]
fs:
  write: ["$work/out/"]
exec:
  allow: ["true"]
EOF
for pin in auto landlock; do
	args=(run "$work/agent.yaml")
	[ "$pin" = auto ] || args+=(--tier "$pin")
	rout="$("$tego" "${args[@]}" 2>&1)"
	rrc=$?
	[ "$rrc" = 125 ] || problem "tego run (tier $pin) exited $rrc, want 125"
	grep -qF '[tier-unavailable]' <<<"$rout" || problem "tego run (tier $pin) does not refuse with [tier-unavailable]: $rout"
	if [ -n "$fix" ]; then
		grep -qF -- "$fix" <<<"$rout" || problem "tego run (tier $pin) does not carry doctor's fix \"$fix\": $rout"
	fi
done
finish
