#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt1-identity.sh — kill test 1 (P0-DESIGN §10 "1 identity (two concurrent runs, 100%
# attribution)"; §12 acceptance item 1; docs/p0/supervisor.md "kill test 1 (two concurrent runs, no
# cross-`Loop` leakage, E15, 100% attribution)"; docs/FEATURES.md E3 "concurrent runs... 100%
# attribution. Kill test 1.").
#
# What it attacks: that every event a run's ledger carries is attributed to that run and to no
# other, even while a second, unrelated run is live at the same moment. Two independent mechanisms
# carry this guarantee in tier 1 (no root needed, README.md's table):
#   1. pkg/spec/identity.Env installs TEGO_RUN_ID into the child's own environment right before
#      execve, unconditionally (spec/identity/RUN-IDENTITY.md) — what the agent believes about
#      itself.
#   2. internal/ledger.Writer.Append stamps run/agent on every line from the Writer's own
#      identity.RunRef, unconditionally, overwriting whatever the caller set (internal/ledger/writer.go
#      "Run, Agent... are overwritten unconditionally").
# Either one regressing is a 100%-attribution failure a real user would see as one run's events
# showing up under another run's id. This script starts two runs at once, each told to write its own
# TEGO_RUN_ID into its own declared directory, and checks both mechanisms independently.
#
# The two runs meet in the middle: each writes a marker into its own directory and then waits for the
# other's before it finishes, so the pass is only reachable when both runs really were live at the same
# moment. An earlier version slept instead, with `sleep` missing from exec.allow; the sleep was refused
# and the runs could finish one after the other without the test noticing.
#
# Tier: $KT_TIER (default landlock) through `tego run --tier`; the kernel matrix runs it once as the
# user at landlock and once under sudo at cgroup (test/vm/run-matrix-row.sh).
# Detects: needs that tier (`tego doctor --require <tier>`); skips by name otherwise.
# Exit 0 pass, 1 fail, 2 skip (never a silent pass) — see test/e2e/lib.sh.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

tego="$(kt_ensure_tego)"

tier="${KT_TIER:-landlock}"
kt_note "checking the $tier tier is available"
if ! reason="$(kt_tier_available "$tego" "$tier")"; then
	kt_skip "$tier tier unavailable on this machine: $reason"
fi
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

# One run's work directory: its own out dir, config, contract and task script, tagged A or B so
# the two runs never share a path — the point is that they run at the same time and are still kept
# apart, not that they were forced apart by not overlapping. The task script (not inline shell on
# the tego command line) is what the contract's own command: field names, so the two never drift
# apart the way a hand-duplicated inline command could.
mk_run() {
	local tag="$1" work="$2" peer="$3" out
	out="$work/out"
	mkdir -p "$out"
	kt_config "$work" >/dev/null
	cat >"$work/task.sh" <<-'EOF'
	#!/usr/bin/env bash
	# $1: this run's identity file; $2: this run's marker; $3: the other run's marker.
	printf '%s' "$TEGO_RUN_ID" > "$1"
	: > "$2"
	for _ in $(seq 400); do
		[ -e "$3" ] && exit 0
		sleep 0.05
	done
	echo "the other run never started while this one was live" >&2
	exit 3
	EOF
	chmod 755 "$work/task.sh"
	cat >"$work/agent.yaml" <<-EOF
	version: 0
	name: kt1-$tag
	command: ["bash", "task.sh", "$out/identity.txt", "$out/started", "$peer"]
	fs:
	  write: ["$out/"]
	exec:
	  allow: ["bash", "sleep", "seq"]
	env:
	  pass: ["PATH", "HOME"]
	limits:
	  pids: 32
	  wall: 60s
	record: summary
	EOF
	kt_agent_owns "$out"
}

# Both work directories exist before either contract is written, so each contract can name the other
# run's marker.
workA="$(kt_workdir)"
workB="$(kt_workdir)"
mk_run a "$workA" "$workB/out/started"
mk_run b "$workB" "$workA/out/started"

run_one() {
	local work="$1"
	(
		TEGO_CONFIG="$work/config.yaml"
		export TEGO_CONFIG
		cd "$work" && kt_run "$tego" run agent.yaml --tier "$tier" --offline -- \
			bash task.sh "$work/out/identity.txt" "$work/out/started" "$2"
	) >"$work/run.out" 2>"$work/run.err"
}

kt_note "starting run A and run B at the same time (tier $tier)"
run_one "$workA" "$workB/out/started" &
pidA=$!
run_one "$workB" "$workA/out/started" &
pidB=$!

wait "$pidA"; exitA=$?
wait "$pidB"; exitB=$?

[ "$exitA" -eq 0 ] || kt_fail "run A exited $exitA, expected 0: $(kt_err_line "$workA/run.err")"
[ "$exitB" -eq 0 ] || kt_fail "run B exited $exitB, expected 0: $(kt_err_line "$workB/run.err")"

dirA="$(find "$workA/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*')"
dirB="$(find "$workB/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*')"
[ -n "$dirA" ] || kt_fail "run A left no run directory under $workA/runs"
[ -n "$dirB" ] || kt_fail "run B left no run directory under $workB/runs"
idA="$(basename "$dirA")"
idB="$(basename "$dirB")"
kt_save_fixture "kt1-identity-$tier" "$dirA"
kt_note "run A = $idA, run B = $idB"

[ "$idA" != "$idB" ] || kt_fail "both runs minted the same run id ($idA): identity is not unique under concurrency"

# Mechanism 1: the environment the agent itself observed.
seenA="$(cat "$workA/out/identity.txt" 2>/dev/null || echo '<missing>')"
seenB="$(cat "$workB/out/identity.txt" 2>/dev/null || echo '<missing>')"
[ "$seenA" = "$idA" ] || kt_fail "run A's own workload saw TEGO_RUN_ID=$seenA, its real run id is $idA (env attribution broken)"
[ "$seenB" = "$idB" ] || kt_fail "run B's own workload saw TEGO_RUN_ID=$seenB, its real run id is $idB (env attribution broken)"

# Mechanism 2: the ledger's own stamp, 100% of lines.
events_ok() {
	local dir="$1" want="$2" total bad
	kt_ledger_valid "$dir/events.jsonl" || kt_fail "$dir/events.jsonl has a line that is not JSON: the attribution check would stop there and pass the lines after it unexamined"
	total="$(wc -l <"$dir/events.jsonl")"
	bad="$(jq -r 'select(.run != "'"$want"'") | .run' "$dir/events.jsonl" | wc -l)"
	[ "$total" -gt 0 ] || kt_fail "$dir/events.jsonl is empty — the test exercised nothing"
	[ "$bad" -eq 0 ] || kt_fail "$dir/events.jsonl: $bad of $total lines carry a run id other than $want (100% attribution broken)"
}
events_ok "$dirA" "$idA"
events_ok "$dirB" "$idB"

# No cross-contamination: run A's ledger never even mentions run B's id, and vice versa.
if grep -q "$idB" "$dirA/events.jsonl"; then
	kt_fail "run A's ledger ($dirA/events.jsonl) mentions run B's id ($idB): cross-run leakage"
fi
if grep -q "$idA" "$dirB/events.jsonl"; then
	kt_fail "run B's ledger ($dirB/events.jsonl) mentions run A's id ($idA): cross-run leakage"
fi

kt_pass "two concurrent runs at tier $tier, live at the same moment, distinct ids, 100% of $( wc -l <"$dirA/events.jsonl" )+$( wc -l <"$dirB/events.jsonl" ) events correctly attributed, no cross-run leakage"
