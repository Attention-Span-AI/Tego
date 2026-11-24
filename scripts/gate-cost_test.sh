#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests gate-cost.sh with a stand-in gate (GATE_COST_CMD) that prints what precommit.sh prints and takes no time: the
# gate runs with an empty GOCACHE of its own and the jobs it was asked for, its figures are read from its output, and
# a failed gate, another number of jobs, a wall over the budget, a running gate service and a used output directory
# each refuse or fail it. The budget's default is ci.yml's build-test timeout-minutes. The real gate is never run. A run
# with a stand-in is marked STAND-IN and exits 3, never 0 (it measured nothing); the same script run on a fixture tree
# whose scripts/precommit.sh is the stand-in (no GATE_COST_CMD) is a real-path run, and passes as before.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/gate-cost.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-gate-cost-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

# The stand-in gate: prints a jobs line (STAND_JOBS), two steps (the second FAIL when STAND_FAIL is set), whether its
# GOCACHE was empty when it started, and sleeps STAND_SLEEP seconds.
cat >"$tmp/gate.sh" <<'EOF'
#!/bin/sh
echo "precommit: jobs: ${STAND_JOBS:-$TEGO_PRECOMMIT_JOBS}, as TEGO_PRECOMMIT_JOBS says (cpus, memory and load are not consulted)"
[ -z "$(ls -A "$GOCACHE")" ] && echo "stand-in: GOCACHE empty" || echo "stand-in: GOCACHE NOT empty"
echo "stand-in: since=${TEGO_PRECOMMIT_SINCE-unset}"
sleep "${STAND_SLEEP:-0}"
printf '%-48s%s\n' "gofmt" "ok (30s)"
if [ -n "${STAND_FAIL:-}" ]; then
	printf '%-48s%s\n' "go vet" "FAIL (12s)"
	exit 1
fi
printf '%-48s%s\n' "unit tests" "ok (90s)"
echo "precommit: every step passed"
EOF
chmod +x "$tmp/gate.sh"

# run NAME WANT_EXIT [ARGS...]: gate-cost.sh with the stand-in, its output in $tmp/out, a fresh output directory.
run() {
	local name=$1 want=$2 got=0
	shift 2
	rm -rf "$tmp/o"
	GATE_COST_CMD="$tmp/gate.sh" GATE_COST_SERVICE="" "$script" -o "$tmp/o" "$@" >"$tmp/out" 2>&1 || got=$?
	if [ "$got" = "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $got, want $want" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}
expect() { # expect NAME PATTERN FILE
	if ! grep -q -- "$2" "$3"; then
		echo "FAIL $1: $3 lacks '$2'" >&2
		sed 's/^/     /' "$3" >&2
		fail=1
	fi
}

run "a stand-in gate within budget is marked STAND-IN and exits 3, not 0" 3 --jobs 3 --budget-minutes 5
expect "the figures are read from the gate's output" "serial_seconds=120" "$tmp/o/gate-cost.txt"
expect "the jobs it printed are recorded" "jobs_printed=3" "$tmp/o/gate-cost.txt"
expect "the output says STAND-IN and NOT MEASURED" "STAND-IN.*NOT MEASURED" "$tmp/out"
expect "the first line says the figures are not the gate's" "gate-cost: STAND-IN: GATE_COST_CMD replaced" "$tmp/out"
expect "the report marks the stand-in" "stand_in=yes" "$tmp/o/gate-cost.txt"
expect "the report does not say pass" "result=stand-in" "$tmp/o/gate-cost.txt"
if grep -q "within budget\|result=pass" "$tmp/out" "$tmp/o/gate-cost.txt"; then
	echo "FAIL a stand-in run says within budget or pass" >&2
	fail=1
fi
expect "the build cache was empty and the scoped mode was off" "GOCACHE empty" "$tmp/o/gate.log"
expect "an inherited TEGO_PRECOMMIT_SINCE does not reach the gate" "since=unset" "$tmp/o/gate.log"

TEGO_PRECOMMIT_SINCE=abc run "an inherited TEGO_PRECOMMIT_SINCE does not make it a scoped gate" 3 --budget-minutes 5
expect "the scoped base is dropped" "since=unset" "$tmp/o/gate.log"

# A wall over the budget: a copy of the script, in a fixture tree with its own ci.yml, whose clock started ten minutes
# before it did (the stand-in cannot take minutes).
mkdir -p "$tmp/fx/scripts" "$tmp/fx/.github/workflows"
# shellcheck disable=SC2016 # sed's pattern and replacement are the script's own text
sed 's/^start=\$SECONDS$/start=$((SECONDS - 600))/' "$script" >"$tmp/fx/scripts/gate-cost.sh"
chmod +x "$tmp/fx/scripts/gate-cost.sh"
grep -q 'SECONDS - 600' "$tmp/fx/scripts/gate-cost.sh" || { echo "FAIL the fixture copy's clock was not moved" >&2; fail=1; }
printf 'jobs:\n  build-test:\n    runs-on: x\n    timeout-minutes: 7\n  other:\n    timeout-minutes: 99\n' >"$tmp/fx/.github/workflows/ci.yml"
for c in "--budget-minutes 5|1|over the budget of 5 min" "--budget-minutes 11|3|STAND-IN" "|1|over the budget of 7 min"; do
	rm -rf "$tmp/o"
	got=0
	# shellcheck disable=SC2086 # the flags are words
	GATE_COST_CMD="$tmp/gate.sh" GATE_COST_SERVICE="" "$tmp/fx/scripts/gate-cost.sh" -o "$tmp/o" ${c%%|*} >"$tmp/out" 2>&1 || got=$?
	rest=${c#*|}
	if [ "$got" = "${rest%%|*}" ] && grep -q -- "${rest#*|}" "$tmp/out"; then
		echo "ok   a gate that took ten minutes, flags '${c%%|*}' (the fixture's build-test allows 7): exit $got"
	else
		echo "FAIL a ten-minute gate, '${c%%|*}': exit $got, want ${rest%%|*} with '${rest#*|}'" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
done

STAND_FAIL=1 run "a failed gate fails the run" 1 --budget-minutes 5
expect "the failure is named" "the gate failed (exit 1)" "$tmp/out"
STAND_JOBS=9 run "a gate that ran other jobs than it was asked fails" 1 --jobs 2 --budget-minutes 5
expect "the job mismatch is named" "jobs: 9, not 2" "$tmp/out"

# The default budget is ci.yml's build-test timeout-minutes.
want=$(awk '/^  build-test:/ { on = 1; next } on && $1 == "timeout-minutes:" { print $2; exit }' "$here/../.github/workflows/ci.yml")
run "the default budget is ci.yml's" 3 --jobs 1
expect "the report holds ci.yml's figure ($want)" "budget_minutes=$want" "$tmp/o/gate-cost.txt"

# The real path: the same script, with no GATE_COST_CMD, runs the tree's own scripts/precommit.sh; here the fixture's is
# the stand-in, so the figures are read and the run passes (exit 0) without the STAND-IN mark; over its budget it fails.
mkdir -p "$tmp/fy/scripts" "$tmp/fy/.github/workflows"
cp "$script" "$tmp/fy/scripts/gate-cost.sh"
cp "$tmp/gate.sh" "$tmp/fy/scripts/precommit.sh"
printf 'jobs:\n  build-test:\n    timeout-minutes: 7\n' >"$tmp/fy/.github/workflows/ci.yml"
got=0
rm -rf "$tmp/o"
env -u GATE_COST_CMD GATE_COST_SERVICE="" "$tmp/fy/scripts/gate-cost.sh" -o "$tmp/o" --jobs 2 >"$tmp/out" 2>&1 || got=$?
if [ "$got" = 0 ] && grep -q "within budget" "$tmp/out" && ! grep -q "STAND-IN" "$tmp/out" "$tmp/o/gate-cost.txt" && grep -q "stand_in=no" "$tmp/o/gate-cost.txt" && grep -q "result=pass" "$tmp/o/gate-cost.txt"; then
	echo "ok   the real path (the tree's own scripts/precommit.sh) is not marked and passes within budget"
else
	echo "FAIL the real path: exit $got" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
fi

# Refusals: a bad count, a used output directory, a running gate service (a stand-in unit through a fake systemctl).
run "a bad --jobs is a usage error" 2 --jobs x
run "an unknown flag is a usage error" 2 --nope
mkdir -p "$tmp/used" && : >"$tmp/used/file"
got=0
GATE_COST_CMD="$tmp/gate.sh" GATE_COST_SERVICE="" "$script" -o "$tmp/used" --budget-minutes 5 >"$tmp/out" 2>&1 || got=$?
if [ "$got" = 2 ] && grep -q "not an empty directory" "$tmp/out"; then
	echo "ok   a used output directory is refused and left alone"
else
	echo "FAIL a used output directory: exit $got" >&2
	fail=1
fi
[ -f "$tmp/used/file" ] || { echo "FAIL the used directory was emptied" >&2; fail=1; }
mkdir "$tmp/bin"
# shellcheck disable=SC2016 # the stand-in's own text
printf '#!/bin/sh\n[ "$1 $2 $3" = "--user is-active -q" ] && exit 0\nexit 3\n' >"$tmp/bin/systemctl"
chmod +x "$tmp/bin/systemctl"
got=0
rm -rf "$tmp/o"
PATH="$tmp/bin:$PATH" GATE_COST_CMD="$tmp/gate.sh" GATE_COST_SERVICE="some.service" "$script" -o "$tmp/o" --budget-minutes 5 >"$tmp/out" 2>&1 || got=$?
if [ "$got" = 2 ] && grep -q "a gate is running" "$tmp/out" && [ ! -e "$tmp/o/gate.log" ]; then
	echo "ok   a running gate service refuses the run before it starts anything"
else
	echo "FAIL the running service: exit $got" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
fi
exit "$fail"
