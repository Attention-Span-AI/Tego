#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# timing-budgets.sh — the tree's absolute timing budgets, asserted as their specs write them (docs/BENCHMARKS.md,
# "Timing budgets in the test suites").
#
# Why it exists: ADR 0048 C8's exec costs, enforce-plane §10's plan fill, DGRAM-VERDICT's flood, the Rules page's
# 55k-line read and ADR 0023 P1's Borrow ratio (to a fixed workload, two atomic adds) are figures on the reference box
# (a developer laptop) with a Limit, most with a Target. A busy machine slows the code by a lower clock and a busy sibling
# hyperthread through the whole measurement, which no fastest-of-N removes: under 16 busy loops on the reference box
# C8's cases took 2.3 to 4.9 times their quiet figures even in the handling thread's own CPU time, and Borrow's ratio
# moved from 1.6-1.9 to 2.50. So in the unit gate (precommit, CI's test jobs, any go test) these tests hold their
# measurement only to ten times its Limit (testutil.CeilingFactor), and this script runs them with
# TEGO_TIMING_BUDGETS=1, which makes each hold its Limit (over it fails) and Target (over it prints TARGET-MISS) exactly
# as its spec writes them. Run it where nothing else runs: CI's bench-gate job runs it first, alone on the job's runner;
# on a developer's machine, `make budgets` with the machine otherwise idle. It prints the load average it started at,
# for the record.
#
# Method: each package's test binary is built (CGO_ENABLED=0, its build tags), then run once from its package
# directory with -test.run naming its budget tests, -test.v and -test.count 1, under TEGO_TIMING_BUDGETS=1. A
# budget test that fails, is skipped, reports no PASS, or never says it ran in budget mode fails the script: a
# budget that was not asserted is not met. A binary that does not build or exits non-zero fails it too.
#
# Usage: scripts/timing-budgets.sh [-o DIR]
#   -o DIR   where binaries and logs go (default: a new temporary directory, kept and named); an existing DIR must be
#            empty or one this script made
# Environment: GO (default go); TIMING_BUDGETS_TESTS replaces the test list (the self-test's fake packages).
# Exit: 0 every budget met; 1 a budget missed, or a budget test that did not build, failed, was skipped or did not
# run in budget mode; 2 usage.
set -euo pipefail

# The budget tests, one package and build-tag set per line: its directory, its tags ("-" for none), and the tests.
# A new absolute budget is a test that calls testutil.TimingMode and Mode.Judge, named here. internal/testutil's
# TestTimingBudgetsListsEveryBudgetTest fails when this list and the tree's TimingMode callers differ either way, or
# when a test is listed under tags its file does not build with.
default_tests='
internal/runtime/supervisor      -            TestExecCommandCostBudget TestExecCommandIndexCostBudget
internal/runtime/supervisor      integration  TestIntegrationUDPFlood
internal/runtime/enforce/cgroup  -            TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows
internal/platform/sys            -            TestBorrowCostRatio
internal/control/rulesview       -            TestInForceLongRunIsFast
'

GO=${GO:-go}

usage() {
	sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" >&2
	exit 2
}

out=""
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=${2:?}; shift 2 ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
done

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tests=${TIMING_BUDGETS_TESTS:-$default_tests}
out=${out:-$(mktemp -d "${TMPDIR:-/tmp}/timing-budgets.XXXXXX")}
# A DIR that holds anything and was not made here is refused rather than emptied.
if [ -e "$out" ] && [ ! -e "$out/.timing-budgets" ] && [ -n "$(ls -A "$out")" ]; then
	echo "timing-budgets: $out is not empty and is not a directory timing-budgets.sh made; not using it" >&2
	exit 2
fi
mkdir -p "$out"
: >"$out/.timing-budgets"
rm -f "$out"/*.test "$out"/*.log
echo "timing-budgets: $root, results in $out; load average $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)"

# judge LOG TEST...: one line per test, "ok", "TARGET-MISS" or "FAIL", from the -test.v output in LOG. The tests
# run one after another, so a log line belongs to the test whose "=== RUN" came last.
judge() {
	local log=$1
	shift
	awk -v want="$*" '
	BEGIN { n = split(want, w, " "); for (i = 1; i <= n; i++) known[w[i]] = 1 }
	/^=== RUN   / { cur = $3; next }
	/^=== (PAUSE|CONT) / { next }
	/^--- PASS: / { pass[$3] = 1; next }
	/^--- FAIL: / { fail[$3] = 1; next }
	/^--- SKIP: / { skip[$3] = 1; next }
	cur in known && /, budget mode\)$/ { mode[cur] = 1 }
	cur in known && /TARGET-MISS: / { sub(/^ *[^ ]+:[0-9]+: /, ""); miss[cur] = miss[cur] "\n    " $0 }
	END {
		for (i = 1; i <= n; i++) {
			t = w[i]
			if (fail[t]) printf "FAIL %s: failed\n", t
			else if (skip[t]) printf "FAIL %s: skipped, so its budget was not asserted\n", t
			else if (!pass[t]) printf "FAIL %s: did not run (no PASS line)\n", t
			else if (!mode[t]) printf "FAIL %s: passed without asserting a budget in budget mode\n", t
			else if (miss[t] != "") printf "TARGET-MISS %s:%s\n", t, miss[t]
			else printf "ok   %s\n", t
		}
	}' "$log"
}

status=0
findings="$out/findings"
: >"$findings"
i=0
while read -r pkg tags names; do
	[ -n "$pkg" ] || continue
	i=$((i + 1))
	bin="$out/$i.test" log="$out/$i.log"
	[ "$tags" != - ] || tags=""
	echo "== $pkg${tags:+ (tags $tags)}: $names"
	if ! (cd "$root" && CGO_ENABLED=0 "$GO" test -c ${tags:+-tags "$tags"} -o "$bin" "./$pkg"); then
		echo "FAIL $pkg${tags:+ (tags $tags)}: the test binary did not build" | tee -a "$findings"
		status=1
		continue
	fi
	regex="^($(printf '%s' "$names" | tr -s ' ' '|'))\$"
	rc=0
	(cd "$root/$pkg" && TEGO_TIMING_BUDGETS=1 "$bin" -test.run "$regex" -test.v -test.count 1 -test.timeout 10m) \
		>"$log" 2>&1 || rc=$?
	cat "$log"
	# shellcheck disable=SC2086 # names is a space-separated list of test names
	judge "$log" $names >>"$findings"
	if [ "$rc" -ne 0 ]; then
		echo "FAIL $pkg${tags:+ (tags $tags)}: the test binary exited $rc ($log)" >>"$findings"
	fi
done <<<"$tests"
echo "== findings"
cat "$findings"
grep -q '^FAIL' "$findings" && status=1
exit $status
