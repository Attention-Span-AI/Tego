#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests doctor-refusal.sh, the whole body of a doctor-only kernel-matrix row (fetch-kernel.py's DOCTOR_ONLY:
# Ubuntu 22.04's 5.15, below Landlock ABI 2, where no tier is offered), against a stand-in tego that plays a
# machine. The check exists to fail: a row that passed whatever doctor said would assert nothing, and a doctor-only
# row whose kernel gained a tier must fail, because then it should run in full. So each case below makes one
# part of the refusal wrong, or the machine one that runs, and the check must say so.
#
# The stand-in answers what the real binary printed on that kernel (5.15.0-198-generic in a KVM guest,
# 2026-10-05): doctor exits 1 with `tier: none` and the fix, `doctor --require landlock` exits 211, `doctor
# --json` carries an empty tier and the ABI, and `tego run` exits 125 [tier-unavailable] with the same fix.
# STUB_MACHINE picks the machine, and STUB_RAN names a file the stand-in appends to when `run` starts a run, so a
# case can show the check never ran a contract on a machine that offers a tier.
#
# Usage: test/vm/doctor-refusal_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-doctor-refusal-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || fail "jq is not on PATH; doctor-refusal.sh reads doctor --json with it"

FIX_ABI1='boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)'
FIX_NONE='boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y'

cat >"$tmp/tego" <<'EOF'
#!/usr/bin/env bash
# The stand-in machine: STUB_MACHINE is abi1 (the 5.15 guest), none (no Landlock at all), offers (a machine with a
# tier), or abi1 with one part wrong: nofix, exit0, require0, runs0, noanchor, jsontier.
m="${STUB_MACHINE:-abi1}"
fix="boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)"
abi=1
land="FAIL landlock: ABI 1 is below the supported minimum 2 (rename and link confined to one directory); fix: $fix"
if [ "$m" = none ]; then
	fix="boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y"
	abi=0
	land="FAIL landlock: landlock_create_ruleset: function not implemented (tier landlock unavailable); fix: $fix"
fi
if [ "$m" = delegation-first ] || [ "$m" = delegation-only ]; then
	fix="enable systemd user delegation (Delegate=cpu memory pids); and $fix"
	[ "$m" != delegation-only ] || fix="enable systemd user delegation (Delegate=cpu memory pids)"
fi
doctor() {
	echo "tego=v0 commit=x date=x go=go1.27.1 contract_schema=0 record_v=1"
	echo "ok   kernel: 5.15.0-198-generic (>= 5.14.0)"
	echo "$land"
	echo "ok   seccomp: NEW_LISTENER + ADDFD(SEND) round trip"
	echo
	if [ "$m" = offers ]; then
		echo "tier: landlock"
		return
	fi
	echo "tier: none (this machine can only record)"
	echo "missing for landlock: ${land#FAIL }"
	[ "$m" = nofix ] || echo "fix: $fix"
}
# A test build refuses every command, doctor included, that has no machine config of its own (identity-config.md R27).
[ -n "${TEGO_CONFIG:-}" ] && [ -n "${TEGO_TEST_CHAIN_ANCHOR:-}" ] && [ -n "${TEGO_TEST_OWN_LOG_HOME:-}" ] || {
	echo "tego: this binary is built with tegotesthooks and must not reach the invoking user's own ~/.tego" >&2
	exit 125
}
case "$1" in
doctor)
	shift
	case "${1:-}" in
	--json)
		tier=""
		[ "$m" != jsontier ] || tier="landlock"
		[ "$m" != offers ] || tier="landlock"
		printf '{"tier":"%s","landlock_abi":%s}\n' "$tier" "$abi"
		[ -z "$tier" ] && exit 1 || exit 0
		;;
	--require)
		doctor
		if [ "$m" = offers ]; then exit 0; fi
		[ "$m" = require0 ] && exit 0
		echo "required tier ${2:-landlock} is not available on this machine"
		exit 211
		;;
	esac
	doctor
	if [ "$m" = offers ] || [ "$m" = exit0 ]; then exit 0; fi
	exit 1
	;;
run)
	[ -z "${STUB_RAN:-}" ] || echo "run $*" >>"$STUB_RAN"
	[ "$m" != runs0 ] || exit 0
	if [ "$m" = offers ]; then exit 0; fi
	pin="no enforcement tier available on this machine"
	case " $* " in *" --tier landlock "*) pin="tier landlock pinned but not available" ;; esac
	[ "$m" = noanchor ] && { echo "$2: $pin"; exit 125; }
	echo "$2: $pin [tier-unavailable] missing for landlock: ${land#FAIL }; fix: $fix" >&2
	exit 125
	;;
esac
exit 2
EOF
chmod +x "$tmp/tego"

# check_case NAME WANT [VAR=value...]: runs the check against the stand-in with those variables, wants WANT (pass or
# fail), and for fail the text WANT_TEXT in what it printed. The check's home is the case's own directory.
check_case() {
	local name="$1" want="$2" out rc
	shift 2
	rm -f "$tmp/ran"
	out="$(env -i PATH="$PATH" HOME="$tmp" TMPDIR="$tmp" STUB_RAN="$tmp/ran" "$@" "$here/doctor-refusal.sh" "$tmp/tego" 2>&1)"
	rc=$?
	case "$want" in
	pass) [ "$rc" = 0 ] || fail "$name: exited $rc, want 0: $out" ;;
	fail) [ "$rc" = 1 ] || fail "$name: exited $rc, want 1: $out" ;;
	esac
	LAST_OUT="$out"
}
has() { grep -qF -- "$2" <<<"$1" || fail "$3: the output lacks \"$2\": $1"; }

# 1. The machine this row exists for passes, and the check says which fix it saw. The same check passes a kernel
# with no Landlock at all, which says another fix: both are a machine with no tier and a remedy.
check_case "5.15, Landlock ABI 1" pass STUB_MACHINE=abi1
has "$LAST_OUT" "PASS:" "ABI 1"
has "$LAST_OUT" "$FIX_ABI1" "ABI 1"
check_case "no Landlock at all" pass STUB_MACHINE=none
has "$LAST_OUT" "$FIX_NONE" "no Landlock"
check_case "delegation and ABI 1 both need fixing" pass STUB_MACHINE=delegation-first
has "$LAST_OUT" "$FIX_ABI1" "all blockers"
check_case "the final fix omits the kernel blocker" fail STUB_MACHINE=delegation-only
has "$LAST_OUT" "doctor's fix" "omitted Landlock remedy"
# It runs `tego run` twice, the auto selection and a pin, and each is refused.
[ "$(wc -l <"$tmp/ran" 2>/dev/null || echo 0)" -eq 2 ] || fail "the check ran tego run $(wc -l <"$tmp/ran" 2>/dev/null || echo 0) times, want 2 (auto, and --tier landlock)"

# 2. A machine that offers a tier is not a doctor-only row. The check fails, says so, and never starts a run: on a
# developer's box `tego run` of any contract would run it.
check_case "a machine that offers a tier" fail STUB_MACHINE=offers
has "$LAST_OUT" "FAIL:" "offers a tier"
has "$LAST_OUT" "offers a tier" "offers a tier"
[ ! -s "$tmp/ran" ] || fail "the check started a run on a machine whose doctor offers a tier: $(cat "$tmp/ran")"

# 3. Each part of the refusal, made wrong, fails the check, and the failure names the part.
check_case "doctor exits 0 though it names no tier" fail STUB_MACHINE=exit0
has "$LAST_OUT" "doctor exited 0" "doctor exit"
check_case "doctor prints no fix" fail STUB_MACHINE=nofix
has "$LAST_OUT" "no final fix: line" "no fix"
check_case "--require landlock exits 0" fail STUB_MACHINE=require0
has "$LAST_OUT" "--require landlock" "require"
check_case "tego run starts the run" fail STUB_MACHINE=runs0
has "$LAST_OUT" "tego run (tier auto) exited 0" "run exit"
check_case "tego run's refusal lacks the fix and the code" fail STUB_MACHINE=noanchor
has "$LAST_OUT" "[tier-unavailable]" "run text"
check_case "--json names a tier" fail STUB_MACHINE=jsontier
has "$LAST_OUT" "doctor --json" "json"

# 4. It needs a binary, and says so as a usage error, never as a pass.
rc=0
"$here/doctor-refusal.sh" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "no argument exited $rc, want 2"
rc=0
"$here/doctor-refusal.sh" "$tmp/missing" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "a missing binary exited $rc, want 2"

echo "ok doctor-refusal_test.sh"
