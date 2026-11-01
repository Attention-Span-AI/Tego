#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# live-e2e.sh: the live-block end-to-end check. It drives a looping
# probe agent, isolated from the person's own tego (its own config, ledger root, chain anchor and HOME), through two
# runs and checks what `tego block` says against what the agent sees:
#   1. tego run with held reads (fs.reads: held): block the probe's data folder, the agent's reads are refused within
#      2 s; unblock, they are allowed again within 2 s; `tego block --list` says "In force" between.
#   2. tego watch: block the same folder; `tego block` prints "recorded, not enforced", the lines under the block are
#      verdict observed, and the agent keeps reading.
#
# Usage: scripts/live-e2e.sh [work-dir]
#   TEGO=<path>  the tego binary, built with -tags tegotesthooks (the isolation uses its test hooks); default: tego on
#                PATH. The work dir (default: a new one under ${TMPDIR:-/tmp}) holds everything the runs write and is
#                kept for reading afterwards. Exit 0 when every check holds, 1 when one fails, 2 on a setup error.
# It needs Landlock (tier landlock, no root); it starts nothing as root and touches no ~/.tego.
set -euo pipefail

TEGO=${TEGO:-$(command -v tego || true)}
if [[ -z "$TEGO" || ! -x "$TEGO" ]]; then
	echo "live-e2e: set TEGO to a tego binary built with -tags tegotesthooks" >&2
	exit 2
fi
W=${1:-$(mktemp -d "${TMPDIR:-/tmp}/live-e2e.XXXXXX")}
mkdir -p "$W"
W=$(cd "$W" && pwd)
chmod 700 "$W"

fails=0
pass() { echo "PASS $*"; }
fail() {
	echo "FAIL $*"
	fails=$((fails + 1))
}

# Isolation: tego's own config, ledger root and chain anchor live in the work dir's state folder (tegotesthooks), and
# so do HOME and XDG_RUNTIME_DIR (a launch makes <runtime dir>/tego and sweeps what crashed runs left there); the
# probe's project is beside it, since tego refuses a contract that writes inside its own folder.
S="$W/state"
mkdir -p "$S/home" "$S/own" "$S/ledger" "$S/run"
chmod 700 "$S" "$S/ledger" "$S/run"
printf 'ledger_root: %s\n' "$S/ledger" >"$S/tego.yaml"
chmod 600 "$S/tego.yaml"
export TEGO_CONFIG="$S/tego.yaml" TEGO_TEST_CHAIN_ANCHOR="$S/chain.log" TEGO_TEST_OWN_LOG_HOME="$S/own" HOME="$S/home" \
	XDG_RUNTIME_DIR="$S/run"

# The probe: every 0.2 s it reads data/secret.txt, writes tmp/f<i> and runs ls, and logs what each did.
P="$W/p"
mkdir -p "$P/data" "$P/tmp"
echo "fake secret" >"$P/data/secret.txt"
cat >"$P/agent.sh" <<'EOF'
#!/bin/bash
i=0
while true; do
  i=$((i+1))
  if cat data/secret.txt >/dev/null 2>&1; then r=read-ok; else r=read-refused; fi
  if touch tmp/f$i 2>/dev/null; then w=write-ok; else w=write-refused; fi
  if ls >/dev/null 2>&1; then x=ls-ok; else x=ls-refused; fi
  echo "$(date +%s%N) i=$i $r $w $x" >> tmp/log.txt
  sleep 0.2
done
EOF
chmod 755 "$P/agent.sh"
cat >"$P/agent.yaml" <<EOF
version: 0
name: live-probe
command: ["./agent.sh"]
capture: off
tier: landlock
record: summary
fs:
  write: ["./tmp/", "/dev/null"]
  reads: held
exec:
  allow: [bash, cat, touch, ls, date, sleep, "$P/agent.sh"]
env:
  pass: ["PATH", "HOME"]
EOF

agent_pid=""
cleanup() {
	if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
		kill "$agent_pid" 2>/dev/null || true
		wait "$agent_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

# newest_run prints the newest run directory's id under the ledger root, waiting up to 10 s for one newer than $1.
newest_run() {
	local before=$1 id=""
	for _ in $(seq 1 100); do
		id=$(find "$S/ledger" -maxdepth 1 -name 'r-*' -type d -printf '%T@ %f\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2)
		if [[ -n "$id" && "$id" != "$before" && -s "$S/ledger/$id/events.jsonl" ]]; then
			echo "$id"
			return 0
		fi
		sleep 0.1
	done
	return 1
}

# wait_log WORD SINCE_NS: waits up to 2 s for a probe log line written after SINCE_NS that holds WORD; prints the
# milliseconds it took.
wait_log() {
	local word=$1 since=$2 t
	for _ in $(seq 1 40); do
		t=$(awk -v s="$since" -v w="$word" '$1 > s && index($0, w) { print $1; exit }' "$P/tmp/log.txt" 2>/dev/null || true)
		if [[ -n "$t" ]]; then
			echo $(((t - since) / 1000000))
			return 0
		fi
		sleep 0.05
	done
	return 1
}

stop_run() {
	"$TEGO" stop "$1" >/dev/null 2>&1 || true
	if [[ -n "$agent_pid" ]]; then
		wait "$agent_pid" 2>/dev/null || true
		agent_pid=""
	fi
}

# --- 1. tego run with held reads
echo "== tego run (tier landlock, reads held)"
: >"$P/tmp/log.txt"
(cd "$P" && exec "$TEGO" run "$P/agent.yaml" </dev/null >"$W/run.out" 2>&1) &
agent_pid=$!
run1=$(newest_run "") || {
	echo "live-e2e: the run did not start; $W/run.out says:" >&2
	cat "$W/run.out" >&2
	exit 2
}
echo "run $run1"
if wait_log read-ok 0 >/dev/null; then pass "the probe reads before any block"; else fail "the probe never read"; fi

t0=$(date +%s%N)
out=$("$TEGO" block "$run1" path "$P/data" 2>&1)
echo "$out"
if ms=$(wait_log read-refused "$t0"); then pass "read refused ${ms} ms after tego block"; else fail "no read refused within 2 s of tego block"; fi
if ms=$(wait_log write-ok "$t0"); then pass "writes outside the block still go through (${ms} ms)"; else fail "writes stopped"; fi
list=$("$TEGO" block --list "$run1" 2>&1)
echo "$list"
if grep -q "In force" <<<"$list"; then pass "tego block --list says In force"; else fail "tego block --list does not say In force"; fi
# Read the events whole first: grep -q stops reading early, and pipefail would then fail on tego's SIGPIPE.
events=$("$TEGO" events "$run1" --json 2>/dev/null || true)
if grep -q '"why":"live-block-added"' <<<"$events"; then
	pass "the launcher wrote its live-block-added line"
else
	fail "no live-block-added line"
fi

t1=$(date +%s%N)
"$TEGO" unblock "$run1" path "$P/data"
if ms=$(wait_log read-ok "$t1"); then pass "read allowed again ${ms} ms after tego unblock"; else fail "reads still refused 2 s after tego unblock"; fi
stop_run "$run1"

# --- 2. tego watch
echo "== tego watch (records only)"
: >"$P/tmp/log.txt"
(cd "$P" && exec "$TEGO" watch -- "$P/agent.sh" </dev/null >"$W/watch.out" 2>&1) &
agent_pid=$!
run2=$(newest_run "$run1") || {
	echo "live-e2e: the watch run did not start; $W/watch.out says:" >&2
	cat "$W/watch.out" >&2
	exit 2
}
echo "run $run2"
wait_log read-ok 0 >/dev/null || fail "the watched probe never read"
t2=$(date +%s%N)
out=$("$TEGO" block "$run2" path "$P/data" 2>&1)
echo "$out"
if grep -q "recorded, not enforced: run $run2 is a tego watch run" <<<"$out"; then
	pass "tego block says recorded, not enforced"
else
	fail "tego block does not say recorded, not enforced"
fi
if grep -q "puts it in force" <<<"$out"; then fail "tego block claims the watched run puts it in force"; fi
sleep 2
after=$(awk -v s="$((t2 + 1000000000))" '$1 > s' "$P/tmp/log.txt")
if [[ -z "$after" ]]; then
	fail "the watched probe logged nothing after the block"
elif grep -q read-refused <<<"$after"; then
	fail "a watched run refused a read"
else
	pass "the watched agent keeps reading (as the block said)"
fi
list=$("$TEGO" block --list "$run2" 2>&1)
echo "$list"
if grep -q "Recorded, not enforced" <<<"$list"; then pass "tego block --list says Recorded, not enforced"; else fail "tego block --list does not say Recorded, not enforced"; fi
lines=$("$TEGO" events "$run2" --json 2>/dev/null | grep '"rule":"live.block\[path:' | grep -v '"kind":"gap"' || true)
if [[ -n "$lines" ]] && ! grep -qv '"verdict":"observed"' <<<"$lines"; then
	pass "$(wc -l <<<"$lines") lines under the block, every one verdict observed"
else
	fail "the lines under the block are not all observed"
fi
stop_run "$run2"

echo "work dir: $W"
if ((fails > 0)); then
	echo "live-e2e: $fails check(s) failed"
	exit 1
fi
echo "live-e2e: all checks passed"
