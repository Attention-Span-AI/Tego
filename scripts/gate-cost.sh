#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# gate-cost.sh — measures what the full private gate (scripts/precommit.sh) costs with nothing cached, and holds it to
# its job budget.
#
# Why it exists: the gate's time was known from remembered runs ("about 22 to 25 minutes one step at a time",
# CONTRIBUTING.md), each with a warm Go build cache and a different load, while the CI job it mirrors (ci.yml's
# build-test) has a fixed allotment. A gate that has grown past the job it mirrors, or that runs on more jobs than it
# was asked to, was found only when somebody waited for it. This runs the gate once with an empty Go build cache and
# says what it cost, as numbers a later run can be compared with.
#
# What it measures (one run of the gate, TEGO_PRECOMMIT_JOBS=JOBS, GOCACHE a new empty directory under the output
# directory, the module cache as it is: nothing is fetched):
#   wall      seconds from start to end of the gate
#   serial    the sum of the steps' own durations, as the gate prints them (what one step at a time would take, give or
#             take the steps' own overlap of sub-processes)
#   cpu       user + system seconds of the gate and everything it started
#   rss       the largest resident set of any one process, in MB (GNU time)
#   jobs      the "precommit: jobs: N" line the gate printed: it must say JOBS, or the job budget was not honoured
#   cache     the size of the Go build cache the run built, in MB
#
# What it holds it to (exit 1 when any fails): the gate passed; the gate said it ran JOBS jobs; wall within the
# budget, which is the job's allotment, ci.yml's build-test timeout-minutes by default (--budget-minutes MIN states
# another). A budget that is only a timeout is a ceiling: say the intended figure with --budget-minutes when it is
# lower. The full report goes to DIR/gate-cost.txt as key=value lines.
#
# It is a heavy run (the whole gate, built from nothing: tens of minutes, several GB of RAM and cache). It refuses to
# start while tego-gate.service is active, and it should not be started beside other load: the figures would not be
# the gate's. Do not run it while a merge gate or a guest job is running.
#
# Usage: scripts/gate-cost.sh [--jobs N] [--budget-minutes MIN] [-o DIR]
#   --jobs N             TEGO_PRECOMMIT_JOBS for the run (default 4)
#   --budget-minutes MIN the wall budget (default: build-test's timeout-minutes in .github/workflows/ci.yml)
#   -o DIR               where the empty build cache, the gate's log and gate-cost.txt go (default: a new directory under
#                        ${TEGO_SCRATCH:-${XDG_CACHE_HOME:-$HOME/.cache}/tego}/gate-cost; an existing DIR must be empty)
# Environment: GATE_COST_CMD replaces the gate command (the self-test's stand-in; it measures nothing of the real
#   gate, so a run with it says STAND-IN on its first line and in its verdict, writes stand_in=yes and result=stand-in
#   into the report, and exits 3 where a real run would exit 0); GATE_COST_SERVICE names the systemd user unit whose
#   activity refuses the run (default tego-gate.service; empty: no check).
# Exit: 0 within budget (the real gate was run); 1 over budget, the gate failed or ran another number of jobs; 2 usage
#   or a refused start; 3 a stand-in command ran (GATE_COST_CMD) and nothing failed: nothing was measured.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
usage() {
	sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
	exit 2
}
jobs=4
budget=""
out=""
while [ $# -gt 0 ]; do
	case "$1" in
	--jobs) [ $# -ge 2 ] || usage; jobs=$2; shift 2 ;;
	--budget-minutes) [ $# -ge 2 ] || usage; budget=$2; shift 2 ;;
	-o) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
	*) usage ;;
	esac
done
case "$jobs" in '' | *[!0-9]* | 0) echo "gate-cost: --jobs must be a positive integer, not '$jobs'" >&2; exit 2 ;; esac
if [ -z "$budget" ]; then
	# build-test's own timeout-minutes: the first one under its key in the workflow.
	budget=$(awk '/^  build-test:/ { on = 1; next } on && /^  [A-Za-z0-9_-]+:/ { exit } on && $1 == "timeout-minutes:" { print $2; exit }' .github/workflows/ci.yml)
fi
case "$budget" in '' | *[!0-9]* | 0) echo "gate-cost: no budget: --budget-minutes is not a positive integer and ci.yml's build-test has no timeout-minutes ('$budget')" >&2; exit 2 ;; esac

service=${GATE_COST_SERVICE-tego-gate.service}
if [ -n "$service" ] && command -v systemctl >/dev/null && systemctl --user is-active -q "$service" 2>/dev/null; then
	echo "gate-cost: $service is active: a gate is running, and this run would be measured beside it" >&2
	exit 2
fi
time_bin=/usr/bin/time
[ -x "$time_bin" ] || { echo "gate-cost: needs GNU time at $time_bin" >&2; exit 2; }

if [ -z "$out" ]; then
	parent="${TEGO_SCRATCH:-${XDG_CACHE_HOME:-$HOME/.cache}/tego}/gate-cost"
	mkdir -p "$parent"
	out=$(mktemp -d "$parent/run-XXXXXX")
elif [ -e "$out" ]; then
	[ -d "$out" ] && [ -z "$(ls -A "$out")" ] || { echo "gate-cost: $out exists and is not an empty directory" >&2; exit 2; }
else
	mkdir -p "$out"
fi
out=$(cd "$out" && pwd)
cache="$out/gocache"
mkdir "$cache"

log="$out/gate.log"
timelog="$out/time.log"
report="$out/gate-cost.txt"
stand_in=no
if [ -n "${GATE_COST_CMD:-}" ]; then
	stand_in=yes
	read -ra cmd <<<"$GATE_COST_CMD"
	echo "gate-cost: STAND-IN: GATE_COST_CMD replaced scripts/precommit.sh with '${cmd[*]}'; the figures below are not the gate's cost" >&2
else
	cmd=(./scripts/precommit.sh)
fi
echo "gate-cost: ${cmd[*]} with TEGO_PRECOMMIT_JOBS=$jobs and an empty GOCACHE ($cache); log $log"
start=$SECONDS
rc=0
env -u TEGO_PRECOMMIT_SINCE TEGO_PRECOMMIT_JOBS="$jobs" GOCACHE="$cache" \
	"$time_bin" -f 'cpu_user=%U\ncpu_sys=%S\nrss_kb=%M' -o "$timelog" "${cmd[@]}" >"$log" 2>&1 || rc=$?
wall=$((SECONDS - start))

# The steps' durations as the gate prints them: "name   ok (123s)" or "FAIL (123s)".
serial=$(sed -n 's/.*\(ok\|FAIL\) (\([0-9][0-9]*\)s)$/\2/p' "$log" | awk '{ s += $1 } END { print s + 0 }')
jobs_line=$(sed -n 's/^precommit: jobs: \([0-9][0-9]*\).*/\1/p' "$log" | head -n 1)
cpu=$(awk -F= '$1 == "cpu_user" || $1 == "cpu_sys" { s += $2 } END { printf "%.0f", s }' "$timelog" 2>/dev/null || echo 0)
rss_kb=$(sed -n 's/^rss_kb=//p' "$timelog" 2>/dev/null | head -n 1)
rss_mb=$(( ${rss_kb:-0} / 1024 ))
cache_mb=$(du -sm "$cache" 2>/dev/null | awk '{ print $1 }')

status=0
verdict=()
if [ "$rc" != 0 ]; then
	status=1
	verdict+=("the gate failed (exit $rc): a failed run's cost is not the gate's")
fi
if [ "${jobs_line:-}" != "$jobs" ]; then
	status=1
	verdict+=("the gate printed jobs: ${jobs_line:-none}, not $jobs: the job budget was not honoured")
fi
if [ "$wall" -gt $((budget * 60)) ]; then
	status=1
	verdict+=("wall $((wall / 60)) min $((wall % 60)) s is over the budget of $budget min")
fi
if [ "$stand_in" = yes ]; then
	# Whatever else is said, nothing was measured: the verdict never reads as a pass of the real gate.
	verdict=("STAND-IN: GATE_COST_CMD ran, not scripts/precommit.sh; NOT MEASURED (wall $((wall / 60)) min $((wall % 60)) s of the budget of $budget min says nothing of the gate)" "${verdict[@]}")
	[ "$status" != 0 ] || status=3
elif [ "${#verdict[@]}" -eq 0 ]; then
	verdict=("within budget: wall $((wall / 60)) min $((wall % 60)) s of $budget min, $jobs jobs")
fi

{
	echo "gate_exit=$rc"
	echo "jobs_requested=$jobs"
	echo "jobs_printed=${jobs_line:-}"
	echo "wall_seconds=$wall"
	echo "serial_seconds=$serial"
	echo "cpu_seconds=$cpu"
	echo "rss_max_mb=$rss_mb"
	echo "cache_mb=${cache_mb:-0}"
	echo "budget_minutes=$budget"
	echo "stand_in=$stand_in"
	case "$status" in 0) echo "result=pass" ;; 3) echo "result=stand-in" ;; *) echo "result=fail" ;; esac
} >"$report"
cat "$report"
for v in "${verdict[@]}"; do echo "gate-cost: $v"; done
echo "gate-cost: report $report, gate log $log; the empty build cache ($cache) can be removed"
exit "$status"
