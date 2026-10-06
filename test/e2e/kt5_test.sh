#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kill test 5 (test/e2e/kt5-ask.sh) against stand-ins, with no root, kernel, network or real tego:
#
#   1. R7's number: "under 1% of wall time or 1 s, whichever is larger" (kt5_budget_ms, taken from the script's own
#      text), and a run slower by less than it passes where one slower by more fails, printed as TARGET-MISS with the
#      figure, never relaxed;
#   2. R7's "the same contract without them": the two contracts a cell runs differ in the two ask entries and in
#      nothing else, which is what makes the difference in time theirs;
#   3. what a cell measures: the median of KT5_RUNS runs of each, base and ask in alternating order so a host that
#      drifts falls on both alike, after one run of each that is not counted, with the wall time taken inside the
#      bound, as kill test 4's is (test/e2e/kt4_test.sh);
#   4. the facts a verdict rests on: run_end's supervisor block present, the supervisor in the loop for the ask run,
#      the entries untouched (no ask or answer line), the tier and the plane the run was asked for;
#   5. a cell that cannot run is a named skip, never a pass.
#
# Kill test 5 runs as written, from a copy of test/e2e, in a tree of stand-ins: a tego that answers doctor, runs
# the command it is given after its own wall-time delay for the contract it was given (longer when the contract
# declares the ask entries) and writes the ledger lines kill test 5 reads; a 20-step agent and a pip workload that
# succeed at once; a model stand-in that only reports a port; an openssl that makes the two files; and a timeout
# that returns 400 ms after its command, as uutils' does late.
#
# Run it as a user, or as root under sudo; as root with no sudo user kill test 5 is a named skip, so it refuses.
#
# Usage: test/e2e/kt5_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-kt5-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "jq is not on PATH; kill test 5 reads the ledger with it"
command -v python3 >/dev/null 2>&1 || fail "python3 is not on PATH; kill test 5's model stand-in is started with it"
if [ "$(id -u)" = 0 ] && { [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" = 0 ]; }; then
	fail "run as a user, or as root under sudo from a user: as root with no sudo user kill test 5 skips"
fi

# 1. The budget, from the script's own function, so the numbers tested are the ones judged with. It is a
# function of the base median in ms: the larger of 1% of it (rounded up) and 1000.
[ -f "$here/kt5-ask.sh" ] || fail "test/e2e/kt5-ask.sh does not exist"
fn="$(sed -n '/^kt5_budget_ms() {$/,/^}$/p' "$here/kt5-ask.sh")"
[ -n "$fn" ] || fail "kt5-ask.sh has no kt5_budget_ms function"
eval "$fn"
for case in "0 1000" "500 1000" "99999 1000" "100000 1000" "100001 1001" "250000 2500" "2210 1000" "3600000 36000"; do
	got="$(kt5_budget_ms "${case% *}")"
	[ "$got" = "${case#* }" ] || fail "kt5_budget_ms ${case% *} is $got, want ${case#* }: the larger of 1% of the base median and 1000 ms"
done

# 1b. Whether a run passes only by R7's 1 s half (it is slower by 1% of the base median, rounded up, or more), which
# the PASS line then says: the same function of the script's text.
fn="$(sed -n '/^kt5_over_one_percent() {$/,/^}$/p' "$here/kt5-ask.sh")"
[ -n "$fn" ] || fail "kt5-ask.sh has no kt5_over_one_percent function"
eval "$fn"
for case in "2000 263 yes" "2000 20 yes" "2000 19 no" "2000 -50 no" "100001 1001 yes" "100001 1000 no" "250000 2500 yes" "250000 2499 no"; do
	read -r b d want <<<"$case"
	if kt5_over_one_percent "$b" "$d"; then got=yes; else got=no; fi
	[ "$got" = "$want" ] || fail "kt5_over_one_percent $b $d is $got, want $want: slower by 1% of the base median (rounded up) or more"
done

# The stand-in tree. kt_repo_root is two directories above lib.sh, so the copy's repository root is $tmp/repo.
repo="$tmp/repo"
mkdir -p "$repo/test/e2e" "$repo/test/workloads/python-steps" "$repo/test/workloads/model-stub" \
	"$repo/test/workloads/build/python" "$repo/examples/profiles/base" "$tmp/bin" "$tmp/log"
# The agent a root run drops to reads all of it as the user.
chmod 755 "$tmp" "$tmp/bin" "$tmp/log"
cp "$here/kt5-ask.sh" "$here/lib.sh" "$here/kt-exit.sh" "$repo/test/e2e/"
printf 'extends: nothing\n' >"$repo/examples/profiles/base/python-dev.yaml"
# The 20-step agent and the build workload: each prints what the real one prints when it succeeds, and one run.sh
# stand-in is told the paths the real one is, so kill test 5 cannot give it the wrong number of them.
cat >"$repo/test/workloads/python-steps/agent.py" <<'EOF'
print("steps=20 ok=20")
EOF
cat >"$repo/test/workloads/build/python/run.sh" <<'EOF'
#!/usr/bin/env bash
[ $# = 4 ] || { echo "run.sh stand-in: want 4 arguments, got $#" >&2; exit 2; }
mkdir -p "$3" "$4"
echo "${STUB_PIP_OUT:-3 passed in 0.01s}"
exit "${STUB_PIP_RC:-0}"
EOF
chmod +x "$repo/test/workloads/build/python/run.sh"
cat >"$repo/test/workloads/model-stub/server.py" <<'EOF'
import argparse, os, time
ap = argparse.ArgumentParser()
for a in ("--cert", "--key", "--ready", "--log"):
    ap.add_argument(a)
a = ap.parse_args()
with open(os.environ["STUB_LOG"] + "/stubs", "a") as f:
    f.write("started\n")
with open(a.ready + ".part", "w") as f:
    f.write("40443")
os.replace(a.ready + ".part", a.ready)
time.sleep(3600)
EOF
cat >"$repo/test/e2e/pydeps.sh" <<'EOF'
#!/usr/bin/env bash
mkdir -p "$STUB_PYDEPS/pip-bootstrap" "$STUB_PYDEPS/wheelhouse"
echo "$STUB_PYDEPS"
EOF
chmod +x "$repo/test/e2e/pydeps.sh"
cat >"$tmp/bin/openssl" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
	case "$1" in
	-keyout | -out) : >"$2"; shift 2 ;;
	*) shift ;;
	esac
done
EOF
cat >"$tmp/bin/timeout" <<'EOF'
#!/usr/bin/env bash
# timeout [-k N] BOUND COMMAND...: runs COMMAND and returns its status STUB_TIMEOUT_LATE seconds after it exits.
while [ $# -gt 0 ]; do
	case "$1" in
	-k) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
shift
"$@"
rc=$?
sleep "${STUB_TIMEOUT_LATE:-0}"
exit "$rc"
EOF
# The tego stand-in. doctor: every tier is available but $STUB_NO_TIER. run: the contract's variant is whether it
# names the ask destination; every run is logged ("<variant> <tier>", and the contract the first time a variant is
# seen), takes STUB_BASE_MS plus STUB_ASK_MS when it is the ask variant, leaves a ledger under the machine config's
# ledger_root with the lines kill test 5 reads, then runs the command after --.
cat >"$tmp/bin/tego" <<'EOF'
#!/usr/bin/env bash
# A stand-in for a tegotesthooks build: the name TEGO_TEST_CHAIN_ANCHOR is what kt_require_testhooks looks for.
case "$1" in
doctor)
	[ "${STUB_NO_TIER:-}" != "${3:-}" ] || { echo "tier ${3:-} is unavailable (stand-in)"; exit 1; }
	exit 0
	;;
run) ;;
*) echo "tego stand-in: unexpected $*" >&2; exit 2 ;;
esac
contract="$2" tier="" plane="${STUB_PLANE:-}"
shift 2
while [ $# -gt 0 ] && [ "$1" != -- ]; do
	[ "$1" != --tier ] || { tier="$2"; shift; }
	shift
done
shift
variant=base
grep -q 'tcp://192.0.2.2:443' "$contract" && variant=ask
echo "$variant $tier ${TEGO_TEST_PLANE:-auto}" >>"$STUB_LOG/runs"
[ -e "$STUB_LOG/contract.$variant" ] || cp "$contract" "$STUB_LOG/contract.$variant"
ms=${STUB_BASE_MS:-100}
[ "$variant" = base ] || ms=$((ms + ${STUB_ASK_MS:-0}))
sleep "$(awk -v m="$ms" 'BEGIN { printf "%.3f", m / 1000 }')"
root="$(sed -n 's/^ledger_root: //p' "$TEGO_CONFIG")"
run="$root/r-kt5-test"
mkdir -p "$run"
# What the tier records: tier landlock has no plane; cgroup and bpflsm name theirs, STUB_PLANE or the boot's own.
case "$tier" in
landlock) plane_json='' ;;
bpflsm) plane_json=',"decision_plane":"lsm"' ;;
*) plane_json=",\"decision_plane\":\"${plane:-${TEGO_TEST_PLANE:-fmod_ret}}\"" ;;
esac
notif=3 held=0 askcap="${STUB_BASE_CAP:-false}"
[ "$variant" = base ] || { notif=${STUB_ASK_NOTIF:-9}; held=${STUB_ASK_HELD:-4}; askcap="${STUB_ASK_CAP:-true}"; }
{
	echo "{\"kind\":\"run_start\",\"tier\":\"${STUB_TIER_AS:-$tier}\"$plane_json,\"capabilities\":{\"ask\":$askcap}}"
	[ -z "${STUB_ASKED:-}" ] || [ "$variant" = base ] || echo '{"kind":"ask","op":"open"}'
	case "${STUB_SUPERVISOR:-ok}" in
	ok) echo "{\"kind\":\"run_end\",\"reason\":\"exit\",\"supervisor\":{\"notifications\":$notif,\"held_ms\":$held}}" ;;
	none) echo '{"kind":"run_end","reason":"exit"}' ;;
	zero) echo '{"kind":"run_end","reason":"exit","supervisor":{"notifications":0,"held_ms":0}}' ;;
	esac
} >"$run/events.jsonl"
"$@"
EOF
chmod +x "$tmp/bin/openssl" "$tmp/bin/timeout" "$tmp/bin/tego"

# run_kt5 runs kill test 5 with the stand-ins first on PATH and the variables given, its output in $tmp/out and its
# exit status in $rc. Every run of the stand-in tego is logged in $tmp/log/runs.
run_kt5() {
	rm -f "$tmp/log/runs" "$tmp/log/contract.base" "$tmp/log/contract.ask" "$tmp/log/stubs"
	env PATH="$tmp/bin:$PATH" TMPDIR="$tmp" HOME="$tmp" STUB_LOG="$tmp/log" STUB_PYDEPS="$tmp/pydeps" \
		TEGO_BIN="$tmp/bin/tego" "$@" bash "$repo/test/e2e/kt5-ask.sh" >"$tmp/out" 2>&1
	rc=$?
}
half() { grep "^KT-HALF kt5 $1 " "$tmp/out"; }

# 2. Within the budget: the ask contract costs 60 ms over the base one's 100. Both kinds pass, at tier landlock; each
# cell ran its warm-up of each variant and then KT5_RUNS of each, and the line carries the medians, the supervisor
# block's, and the number of runs.
run_kt5 KT5_RUNS=4 KT5_TIERS=landlock STUB_BASE_MS=100 STUB_ASK_MS=60 STUB_TIMEOUT_LATE=0.4
[ "$rc" = 0 ] || fail "kill test 5 exited $rc for an ask entry that costs 60 ms: $(grep -E '^(KT-HALF|FAIL|SKIP)' "$tmp/out" | head -4)"
for cell in agent20-landlock pip-landlock; do
	line="$(half "$cell")"
	case "$line" in
	*" PASS "*"4 runs"*) ;;
	*) fail "want a PASS of $cell over 4 runs: ${line:-no KT-HALF line}" ;;
	esac
done
# 2a. The median under tego is the run's own, not the run plus the bound's late notice (kt4_test.sh's case).
base_med="$(half agent20-landlock | sed -n 's/.*base \([0-9]*\) ms.*/\1/p')"
ask_med="$(half agent20-landlock | sed -n 's/.* ask \([0-9]*\) ms.*/\1/p')"
[ -n "$base_med" ] && [ -n "$ask_med" ] || fail "no medians in: $(half agent20-landlock)"
[ "$base_med" -lt 400 ] || fail "the base median is ${base_med} ms, which holds the stand-in timeout's 400 ms: $(half agent20-landlock)"
[ "$ask_med" -gt "$base_med" ] || fail "the ask median ${ask_med} ms is not over the base median ${base_med} ms the stand-in made it 60 ms slower than"
# 2a'. The figure carries its share of the run, and a run 60 ms slower than one of about 120 ms is over 1% of it, passes
# by the 1 s half only, and says so.
case "$(half agent20-landlock)" in
*" PASS +"*" ms (+"*"%), over 1% of the run and inside the allowance by its 1 s: "*) ;;
*) fail "the PASS line does not give the share of the run and the half it passed by: $(half agent20-landlock)" ;;
esac
# 2b. The supervisor block of each variant is reported.
case "$(half agent20-landlock)" in
*"notifications 3 -> 9"*"held_ms 0 -> 4"*) ;;
*) fail "the supervisor block's medians are not in the line: $(half agent20-landlock)" ;;
esac

# 3. Warm-up and order. Per cell the stand-in saw: base, ask (not counted), then the pairs, base first on the odd
# ones and ask first on the even ones, so each variant ran KT5_RUNS + 1 times and the first run of a cell is the
# base's. Both kinds ran, agent20 then pip.
run_kt5 KT5_RUNS=4 KT5_TIERS=landlock STUB_BASE_MS=20 KT5_KINDS=pip
[ "$rc" = 0 ] || fail "kill test 5 on one kind exited $rc: $(tail -3 "$tmp/out")"
order="$(awk '{print $1}' "$tmp/log/runs" | paste -sd' ' -)"
[ "$order" = "base ask base ask ask base base ask ask base" ] ||
	fail "the runs of one cell went in the order \"$order\", want a warm-up pair, then base ask, ask base, base ask, ask base"

# 4. The same contract without them: the contracts differ in the two ask entries and nothing else, and the ask
# entries are the ones R7 names, one fs.ask and one net.ask.
diff "$tmp/log/contract.base" "$tmp/log/contract.ask" >"$tmp/contract.diff"
[ "$(grep -c '^>' "$tmp/contract.diff")" = 2 ] || fail "the ask contract does not add exactly two lines to the base one: $(cat "$tmp/contract.diff")"
[ "$(grep -c '^<' "$tmp/contract.diff")" = 0 ] || fail "the ask contract drops a line of the base one: $(cat "$tmp/contract.diff")"
grep -q '^> *ask: \["[^"]*/never/"\]$' "$tmp/contract.diff" || fail "no fs.ask entry in the ask contract: $(cat "$tmp/contract.diff")"
grep -q '^> *ask: \["tcp://192.0.2.2:443"\]$' "$tmp/contract.diff" || fail "no net.ask entry in the ask contract: $(cat "$tmp/contract.diff")"
# The section the net.ask entry sits in is in both: a net: section is not the cost of an ask entry (kill test 4's).
grep -q '^net:$' "$tmp/log/contract.base" || fail "the base contract has no net: section, so its difference from the ask one is the section's too"

# 5. Over the budget: 1300 ms over the base one's 100 is not under a second. FAIL, printed as TARGET-MISS with the
# figure and the budget, exit 1, the verdict of that cell alone.
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_BASE_MS=100 STUB_ASK_MS=1300
[ "$rc" = 1 ] || fail "kill test 5 exited $rc for an ask entry that costs 1300 ms, want 1"
line="$(half pip-landlock)"
case "$line" in
*" FAIL TARGET-MISS +"*" ms (+"*"%) is not under the budget of 1000 ms"*) ;;
*) fail "want FAIL TARGET-MISS with the figure, its share of the run and the budget of 1000 ms: ${line:-no KT-HALF line}" ;;
esac
over="$(sed -n 's/.* FAIL TARGET-MISS +\([0-9]*\) ms .*/\1/p' <<<"$line")"
{ [ -n "$over" ] && [ "$over" -ge 1200 ] && [ "$over" -le 1500 ]; } ||
	fail "the figure in the TARGET-MISS line is \"$over\" ms, want about the 1300 ms the stand-in added: $line"

# 6. What a cell rests on. Each of these is a FAIL that no median of times can make up for.
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_SUPERVISOR=none
[ "$rc" = 1 ] || fail "a ledger whose run_end has no supervisor block passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"supervisor"*) ;; *) fail "the missing supervisor block is not named: $(half pip-landlock)" ;; esac
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_SUPERVISOR=zero
[ "$rc" = 1 ] || fail "an ask run the supervisor saw nothing of passed ($rc): $(tail -2 "$tmp/out")"
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_ASKED=1
[ "$rc" = 1 ] || fail "a run that touched an ask entry passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"touched"*) ;; *) fail "the touched ask entry is not named: $(half pip-landlock)" ;; esac
# The two contracts are two contracts to tego too: its run_start says its approval machinery was live (capabilities.ask)
# for the one that declared the entries and not for the other, or the pair compares a contract with itself, which at tier
# landlock changes no notification count and would pass.
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_ASK_CAP=false
[ "$rc" = 1 ] || fail "an ask contract whose run says its approval machinery was not live passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"ask contract's run_start says capabilities.ask is false, want true"*) ;; *) fail "the dead approval machinery is not named: $(half pip-landlock)" ;; esac
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_BASE_CAP=true
[ "$rc" = 1 ] || fail "a base contract whose run says its approval machinery was live passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"base contract's run_start says capabilities.ask is true, want false"*) ;; *) fail "the live approval machinery of the base run is not named: $(half pip-landlock)" ;; esac
run_kt5 KT5_RUNS=2 KT5_TIERS=cgroup KT5_KINDS=pip STUB_TIER_AS=landlock
[ "$rc" = 1 ] || fail "a run asked for tier cgroup that ran at landlock passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-cgroup)" in *"asked for tier cgroup and ran at tier landlock"*) ;; *) fail "the wrong tier is not named: $(grep '^KT-HALF' "$tmp/out")" ;; esac
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_PIP_RC=3
[ "$rc" = 1 ] || fail "a workload that exited 3 passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"exited 3"*) ;; *) fail "the exit status is not named: $(half pip-landlock)" ;; esac
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS=pip STUB_PIP_OUT="no tests ran"
[ "$rc" = 1 ] || fail "a workload whose output is not its own passed ($rc): $(tail -2 "$tmp/out")"
case "$(half pip-landlock)" in *"not the workload's"*) ;; *) fail "the foreign output is not named: $(half pip-landlock)" ;; esac
# A KT5_RUNS that is no count, and a workload that does not exist, are usage errors, exit 2 (a FAIL to the matrix),
# not a verdict over no runs and not a skip with no reason.
run_kt5 KT5_RUNS=0 KT5_TIERS=landlock
[ "$rc" = 2 ] || fail "KT5_RUNS=0 exited $rc, want the usage error 2: $(tail -2 "$tmp/out")"
run_kt5 KT5_RUNS=2 KT5_TIERS=landlock KT5_KINDS="pip npm"
[ "$rc" = 2 ] || fail "a KT5_KINDS naming a workload there is none of exited $rc, want the usage error 2: $(tail -2 "$tmp/out")"
grep -q 'KT5_KINDS names "npm"' "$tmp/out" || fail "the unknown workload is not named: $(cat "$tmp/out")"
[ ! -e "$tmp/log/runs" ] || fail "a run was made before the unknown workload was refused"

# 6b. The 20-step agent's model stand-in is started once, outside every run, and every cell of that workload reuses it
# (each run is told the one certificate); the agent is run as kill test 2 runs it, with the forwarder's URL ("-") and
# twenty steps, through a contract that names the stand-in's port as its model.
run_kt5 KT5_RUNS=2 KT5_TIERS="landlock cgroup" KT5_KINDS=agent20 STUB_BASE_MS=20
[ "$rc" = 0 ] || fail "the agent on two tiers exited $rc: $(grep -E '^(KT-HALF|FAIL|SKIP)' "$tmp/out")"
[ "$(grep -c started "$tmp/log/stubs")" = 1 ] || fail "the model stand-in was started $(grep -c started "$tmp/log/stubs") times for two cells, want once"
grep -q 'host: "127.0.0.1", port: 40443 }' "$tmp/log/contract.ask" || fail "the contract does not name the model stand-in's port: $(grep -n models -A2 "$tmp/log/contract.ask")"
grep -q '^capture: forwarder$' "$tmp/log/contract.ask" || fail "the 20-step agent's contract does not capture through the forwarder"

# 7. Tiers. Tier cgroup names the plane the ledger says decided it, and a plane pin the run did not get is a
# named skip, not a pass under a label the run did not have.
run_kt5 KT5_RUNS=2 KT5_TIERS="landlock cgroup bpflsm" KT5_KINDS=pip STUB_BASE_MS=20
[ "$rc" = 0 ] || fail "three tiers exited $rc: $(grep -E '^(KT-HALF|FAIL|SKIP)' "$tmp/out")"
for cell in pip-landlock pip-cgroup@fmod_ret pip-bpflsm; do
	[ -n "$(half "$cell")" ] || fail "no cell $cell: $(grep '^KT-HALF' "$tmp/out")"
done
run_kt5 KT5_RUNS=2 KT5_TIERS=cgroup KT5_KINDS=pip KT5_PLANES="fmod_ret lsm" STUB_BASE_MS=20 STUB_PLANE=fmod_ret
[ "$rc" = 0 ] || fail "a pin the run did not get failed the test ($rc), want a skip of that cell: $(grep -E '^(KT-HALF|FAIL|SKIP)' "$tmp/out")"
case "$(half 'pip-cgroup@fmod_ret')" in *" PASS "*) ;; *) fail "the pinned plane that was honoured did not pass: $(grep '^KT-HALF' "$tmp/out")" ;; esac
grep -q '^KT-HALF kt5 pip-cgroup@lsm SKIP .*fmod_ret' "$tmp/out" ||
	fail "a pin to lsm whose run was decided by fmod_ret is not a named skip: $(grep '^KT-HALF' "$tmp/out")"

# 8. A tier the machine does not offer is a named skip of each of its cells, and with nothing else run the whole test
# is a skip (exit 77), as kill test 4's is.
run_kt5 KT5_RUNS=2 KT5_TIERS=bpflsm KT5_KINDS=pip STUB_NO_TIER=bpflsm
[ "$rc" = 77 ] || fail "a test with no tier to run exited $rc, want the skip 77: $(tail -3 "$tmp/out")"
grep -q '^KT-HALF kt5 pip-bpflsm SKIP .*bpflsm' "$tmp/out" || fail "the unavailable tier is not a named skip: $(grep '^KT-HALF' "$tmp/out")"

echo "PASS kill test 5 judges the larger of 1% and 1 s, runs the same contract with and without the ask entries, and skips by name"
