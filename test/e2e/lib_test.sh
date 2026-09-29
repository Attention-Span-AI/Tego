#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kt_run (test/e2e/lib.sh), the bound every kill test puts on a `tego run`, against the harness defect
# the second review of a re-acceptance run found: kt_run asked
# timeout(1) for the SIGKILL that follows its SIGTERM (`timeout -k 10`), and uutils' timeout, the one Ubuntu
# 25.10 ships, never sends it, so a launcher that ignores SIGTERM held the kill test until it chose to exit.
#
# Each case runs kt_run from lib.sh as written, with the timeout(1) first on PATH (uutils' or GNU's), on a
# command made here; the kill case needs about 11 s. It passes with either timeout once kt_run escalates by
# itself; with uutils' and kt_run's former `timeout -k 10` the kill case fails on its time.
#
# Usage: test/e2e/lib_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-lib-test.XXXXXX")"
# lib.sh makes its scratch directory under TMPDIR and sets its own exit trap, so the test's trap comes after.
export TMPDIR="$tmp"
# shellcheck source=test/e2e/lib.sh
. "$here/lib.sh"
trap 'kt_cleanup; rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
command -v pgrep >/dev/null 2>&1 || fail "pgrep is not on PATH; the watchdog case looks for the watchdog with it"
ms() { echo $(($(date +%s%N) / 1000000)); }

# 1. The command's own status and its stdin reach the caller: kt_run is in the foreground, as it was.
out="$(echo through | kt_run cat)"
[ "$out" = through ] || fail "stdin did not reach the command under kt_run: got \"$out\""
kt_run sh -c 'exit 3'
rc=$?
[ "$rc" = 3 ] || fail "kt_run returned $rc for a command that exited 3"

# 2. At the bound a command that SIGTERM ends is ended then, and kt_run says so and returns 124.
t0="$(ms)"
KT_RUN_TIMEOUT=1 kt_run sleep 30 2>"$tmp/term.err"
rc=$?
t="$(($(ms) - t0))"
[ "$rc" = 124 ] || fail "a run past its bound returned $rc, want 124"
[ "$t" -lt 5000 ] || fail "sleep 30 under a 1 s bound took ${t}ms; SIGTERM should have ended it at the bound"
grep -q 'did not return within 1s' "$tmp/term.err" || fail "no bound line on stderr: $(cat "$tmp/term.err")"

# 3. A command that ignores SIGTERM, and a child it started, are killed ten seconds past the bound: not left to
# run out their 30 s, which is what uutils' timeout alone does with -k.
t0="$(ms)"
# shellcheck disable=SC2016 # the inner bash expands it
KT_RUN_TIMEOUT=1 kt_run bash -c 'trap "" TERM; sleep 30 & echo $! >"$1"; wait' ignores "$tmp/child" 2>"$tmp/kill.err"
rc=$?
t="$(($(ms) - t0))"
[ "$rc" = 124 ] || fail "a run that ignored SIGTERM returned $rc, want 124"
[ "$t" -lt 16000 ] || fail "a command ignoring SIGTERM under a 1 s bound took ${t}ms; kt_run should kill it about 11 s in"
[ "$t" -ge 10000 ] || fail "a command ignoring SIGTERM was killed after ${t}ms, before the 10 s grace had passed"
child="$(cat "$tmp/child")"
[ -n "$child" ] || fail "the command never started its child"
# A killed child whose parent died with it is a zombie until the reaper collects it, and a zombie is dead.
for _ in $(seq 20); do
	state="$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null)"
	[ -n "$state" ] && [ "$state" != Z ] || break
	sleep 0.1
done
[ -z "$state" ] || [ "$state" = Z ] || fail "the command's child (pid $child, state $state) outlived the kill of its group"

# 4. The watchdog lives while the command runs and is gone, sleep and all, once kt_run returns; the bound is a
# number no other process sleeps for, so the watchdog's sleep is the one pgrep finds.
# shellcheck disable=SC2016 # the inner sh expands it
KT_RUN_TIMEOUT=4321 kt_run sh -c 'pgrep -f "^sleep 4331\$" >"$1"' watch "$tmp/during"
[ -s "$tmp/during" ] || fail "no watchdog (sleep 4331) while the command ran; the case below would prove nothing"
left="$(pgrep -f '^sleep 4331$')"
[ -z "$left" ] || fail "the watchdog's sleep outlived kt_run: pid $left"

# 5. A named skip is exit 77, which the matrix reads as SKIP; a bash syntax error or a usage error, both exit 2,
# is a FAIL, and the matrix must not take it for a skip.
bash -c '. "$1"; kt_skip "for the test"' _ "$here/lib.sh" 2>/dev/null
rc=$?
[ "$rc" = 77 ] || fail "kt_skip exited $rc, want 77"
bash -c 'if then fi' 2>/dev/null
rc=$?
[ "$rc" = 2 ] || fail "a bash syntax error exited $rc; the case below assumes 2"
for want in "0 PASS" "77 SKIP" "1 FAIL" "2 FAIL" "124 FAIL" "125 FAIL"; do
	got="$(kt_verdict "${want% *}")"
	[ "$got" = "${want#* }" ] || fail "kt_verdict ${want% *} is $got, want ${want#* }"
done

# 6. kt_ledger_valid refuses a ledger with a torn line anywhere, which jq alone reports only by its status.
printf '%s\n' '{"run":"a"}' '{"run":"b"}' >"$tmp/ok.jsonl"
kt_ledger_valid "$tmp/ok.jsonl" || fail "kt_ledger_valid refused a well-formed ledger"
printf '%s\n' '{"run":"a"}' 'GARBAGE' '{"run":"b"}' '{"run":"b"}' >"$tmp/bad.jsonl"
! kt_ledger_valid "$tmp/bad.jsonl" || fail "kt_ledger_valid passed a ledger with an unparseable line"
! kt_ledger_valid "$tmp/missing.jsonl" || fail "kt_ledger_valid passed a ledger that is not there"

# 7. A binary a kill test is handed (identity-config.md R27): a product build is refused where it would append the test's
# runs to the invoking user's own ~/.tego/chain.log, a test build (the name TEGO_TEST_CHAIN_ANCHOR in the file) is
# accepted, and so is any binary on a disposable machine. kt_config exports the whole isolation.
printf '#!/bin/sh\nexit 0\n' >"$tmp/product"
printf '#!/bin/sh\n# a test build names TEGO_TEST_CHAIN_ANCHOR\nexit 0\n' >"$tmp/hooked"
chmod +x "$tmp/product" "$tmp/hooked"
(unset TEGO_DISPOSABLE_HOST; TEGO_BIN="$tmp/product" kt_ensure_tego) >/dev/null 2>"$tmp/req.err"
rc=$?
if [ "$rc" != 1 ] || ! grep -q 'not built with -tags tegotesthooks' "$tmp/req.err"; then
	fail "a product build handed to a kill test was not refused (exit $rc): $(cat "$tmp/req.err")"
fi
got="$(unset TEGO_DISPOSABLE_HOST; TEGO_BIN="$tmp/hooked" kt_ensure_tego)"
[ "$got" = "$tmp/hooked" ] || fail "a test build handed to a kill test was not accepted: \"$got\""
got="$(TEGO_DISPOSABLE_HOST=kvm TEGO_BIN="$tmp/product" kt_ensure_tego)"
[ "$got" = "$tmp/product" ] || fail "a product build on a disposable machine was not accepted: \"$got\""
mkdir -p "$tmp/cfg"
iso="$(kt_config "$tmp/cfg" >/dev/null 2>&1; echo "$TEGO_TEST_CHAIN_ANCHOR|$TEGO_TEST_OWN_LOG_HOME|$HISTFILE")"
[ "$iso" = "$tmp/cfg/chain.log|$tmp/cfg/log-home|/dev/null" ] || fail "kt_config does not export the isolation: $iso"
# ... and a runtime directory of its own (R27 clause b4): a launch makes <XDG_RUNTIME_DIR>/tego and sweeps it, so a kill
# test that kept the invoking user's would make their /run/user/<uid>/tego and remove what their crashed runs left there.
# The directory is 0700 whatever the umask (tego refuses one others can write) and replaces the inherited value.
xdg="$(umask 002; XDG_RUNTIME_DIR=/run/user/12345 kt_config "$tmp/cfg" >/dev/null 2>&1; echo "$XDG_RUNTIME_DIR")"
[ "$xdg" = "$tmp/cfg/run" ] || fail "kt_config does not point XDG_RUNTIME_DIR at its own directory: ${xdg:-unset}"
mode="$(stat -c %a "$tmp/cfg/run" 2>/dev/null)"
[ "$mode" = 700 ] || fail "kt_config's XDG_RUNTIME_DIR is mode ${mode:-missing}, not 700"

# 8. Sourcing lib.sh is already an isolation: the doctor a kill test runs before it calls kt_config, through
# kt_tier_available and kt_doctor_tier, is answered by a test build, not refused for reaching the invoking user's own
# ~/.tego. The build is the one kt_ensure_tego makes, with the real guard in it.
case "${TEGO_CONFIG:-}" in "$KT_ROOT"/iso/config.yaml) ;; *) fail "sourcing lib.sh did not isolate: TEGO_CONFIG=${TEGO_CONFIG:-unset}" ;; esac
[ "${TEGO_TEST_CHAIN_ANCHOR:-}" = "$KT_ROOT/iso/chain.log" ] || fail "sourcing lib.sh left the chain anchor at ${TEGO_TEST_CHAIN_ANCHOR:-unset}"
[ "${XDG_RUNTIME_DIR:-}" = "$KT_ROOT/iso/run" ] || fail "sourcing lib.sh left XDG_RUNTIME_DIR at ${XDG_RUNTIME_DIR:-unset}"
unset TEGO_BIN
hooked_bin="$(kt_ensure_tego)" || fail "kt_ensure_tego could not build the tego binary"
reason="$(kt_tier_available "$hooked_bin" landlock)"
case "$reason" in *tegotesthooks*) fail "kt_tier_available on a test build is refused by the isolation guard: $reason" ;; esac
"$hooked_bin" doctor --json >"$tmp/doctor.json" 2>"$tmp/doctor.err"
grep -q tegotesthooks "$tmp/doctor.err" && fail "a doctor before kt_config is refused by the isolation guard: $(cat "$tmp/doctor.err")"
grep -q '"tier"' "$tmp/doctor.json" || fail "doctor --json before kt_config printed no report: $(cat "$tmp/doctor.json") $(cat "$tmp/doctor.err")"

echo "PASS kt_run passes status and stdin, ends a run at its bound, and kills a run that ignores SIGTERM ${t}ms in"
