#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests what kill test 3 (test/e2e/kt3-overhead.sh) hands this harness, against the leftover the final review
# of the 2026-09-23 acceptance run found: with KT_PYDEPS set, kill test 3 passed `--cache <its own scratch
# directory>` holding only the python link, so run.sh looked for its npm cache there, primed it from the
# network on every run into a directory the exit trap then deleted, and printed "(network, once)" while doing
# so; on a machine with npm and no network the npm workload's budgeted rows became a skip.
#
# Kill test 3 runs as written, from a copy of test/e2e, with a stand-in for run.sh that records where the
# cache it was given leads and then exits 97, the code for "this machine cannot run the harness", which kill
# test 3 must report as its named skip. HOME is this test's own directory, so the default npm cache it points
# at is one this test can look at. No network, go, npm or root is needed.
#
# Usage: test/e2e/overhead/kt3_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$here/.."
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-kt3-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

mkdir -p "$tmp/e2e/overhead" "$tmp/pydeps/pip-bootstrap" "$tmp/pydeps/wheelhouse"
cp "$e2e/kt3-overhead.sh" "$e2e/lib.sh" "$e2e/kt-exit.sh" "$tmp/e2e/"
# The stand-in: resolve --cache's two subdirectories as run.sh would read them, before kill test 3's exit
# trap removes the scratch directory they live in.
cat >"$tmp/e2e/overhead/run.sh" <<'EOF'
#!/usr/bin/env bash
cache=""
prev=""
for a in "$@"; do
	[ "$prev" != --cache ] || cache="$a"
	prev="$a"
done
{
	echo "cache=${cache:-none}"
	if [ -n "$cache" ]; then
		echo "python=$(readlink -f "$cache/python")"
		echo "npm=$(readlink -f "$cache/npm" 2>/dev/null)"
		[ -d "$cache/npm" ] && echo "npm-dir=yes" || echo "npm-dir=no"
	fi
} >"$STUB_REPORT"
if [ -n "${STUB_TABLE:-}" ]; then
	out=""
	prev=""
	for a in "$@"; do
		[ "$prev" != --out ] || out="$a"
		prev="$a"
	done
	printf '%b' "$STUB_TABLE" >"$out"
	exit 0
fi
echo "run.sh: cannot run here: stand-in" >&2
exit 97
EOF
chmod +x "$tmp/e2e/overhead/run.sh"

# run_kt3 runs the copy of kill test 3 with a clean environment plus the given variables and prints its exit
# code; the stand-in's record is in $tmp/report.
run_kt3() {
	rm -f "$tmp/report"
	env -i PATH="$PATH" HOME="$tmp/home" TMPDIR="$tmp" STUB_REPORT="$tmp/report" "$@" \
		bash "$tmp/e2e/kt3-overhead.sh" >"$tmp/out" 2>&1
	echo $?
}
report() { sed -n "s/^$1=//p" "$tmp/report"; }

# 1. KT_PYDEPS set: python is the pydeps cache, npm is the npm cache under run.sh's default cache root, which
# exists before run.sh looks, and kill test 3 reports run.sh's 97 as its named skip with the reason.
mkdir -p "$tmp/home"
rc="$(run_kt3 KT_PYDEPS="$tmp/pydeps")"
[ "$rc" = 77 ] || fail "kill test 3 exited $rc on run.sh's 97, want 77 (a named skip): $(tail -3 "$tmp/out")"
grep -q '^SKIP: stand-in$' "$tmp/out" || fail "kill test 3's skip does not carry run.sh's reason: $(tail -3 "$tmp/out")"
[ -s "$tmp/report" ] || fail "run.sh was not run"
[ "$(report cache)" != none ] || fail "KT_PYDEPS set, but kill test 3 passed run.sh no --cache"
[ "$(report python)" = "$(readlink -f "$tmp/pydeps")" ] || fail "<cache>/python leads to $(report python), want $tmp/pydeps"
want="$(readlink -f "$tmp/home")/.cache/tego-overhead-bench/npm"
[ "$(report npm)" = "$want" ] ||
	fail "<cache>/npm leads to '$(report npm)', want the persistent default $want: run.sh would prime npm into a directory deleted at exit"
[ "$(report npm-dir)" = yes ] || fail "<cache>/npm is not a directory when run.sh reads it"

# 2. The npm cache already primed there is the one run.sh sees, not an empty one of its own.
mkdir -p "$want/cache" && : >"$want/cache/_cacache-marker"
rc="$(run_kt3 KT_PYDEPS="$tmp/pydeps")"
[ -e "$(report npm)/cache/_cacache-marker" ] || fail "run.sh's <cache>/npm is not the primed default cache"

# 3. Without KT_PYDEPS, or with TEGO_BENCH_CACHE naming the cache root, kill test 3 passes no --cache and
# run.sh keeps its own default, or that variable, for every cache.
rc="$(run_kt3)"
[ "$(report cache)" = none ] || fail "no KT_PYDEPS, but kill test 3 passed --cache $(report cache)"
rc="$(run_kt3 KT_PYDEPS="$tmp/pydeps" TEGO_BENCH_CACHE="$tmp/bench")"
[ "$(report cache)" = none ] || fail "TEGO_BENCH_CACHE set, but kill test 3 passed --cache $(report cache)"

# 4. The judge. A NOISY budgeted row is not judged, so one measurable row inside its budget must not let it pass:
# the test is a skip (77). An over-budget measurable row is still a fail (1), and a table of clean rows passes.
hdr='| Workload | Tier | Record | Bare median (spread) | Enforced median (spread) | Fixed cost | Marginal cost | Total overhead | Runs/pass x passes | Kernel | CPU |\n|---|---|---|---|---|---|---|---|---|---|---|\n'
row() { printf '| %s | %s | %s | 100.0 ms (±1.0) | 100.5 ms (±1.0) | n/a (no noop row) | n/a (no noop row) | %s | 20/pass x 2 | kernel | cpu |\\n' "$@"; }
noisy_row() { printf '| python | cgroup | full | — | NOISY: passes disagree (stand-in) | — | — | not published | 20/pass x 2 | kernel | cpu |\\n'; }
rc="$(run_kt3 STUB_TABLE="$hdr$(row python landlock off '+0.5%')$(noisy_row)")"
[ "$rc" = 77 ] || fail "one clean row and one NOISY budgeted row: exit $rc, want 77 (skip): $(tail -3 "$tmp/out")"
rc="$(run_kt3 STUB_TABLE="$hdr$(row python landlock off '+2.5%')$(noisy_row)")"
[ "$rc" = 1 ] || fail "an over-budget row beside a NOISY one: exit $rc, want 1: $(tail -3 "$tmp/out")"
rc="$(run_kt3 STUB_TABLE="$hdr$(row python landlock off '+0.5%')$(row npm cgroup full '+4.0%')")"
[ "$rc" = 0 ] || fail "all rows within budget: exit $rc, want 0: $(tail -3 "$tmp/out")"

# 5. Read the entire eligible-row inventory. These exercise the copied kill script, not an extracted
# parser; the producer above is still a disclosed stand-in, so none is a performance measurement.
failures=0
cases=0
judge() {
	local name="$1" want_rc="$2" table="$3" want_note="${4:-}"
	cases=$((cases + 1))
	rc="$(run_kt3 STUB_TABLE="$table")"
	if [ "$rc" != "$want_rc" ]; then
		echo "FAIL judge $name: exit $rc, want $want_rc: $(tail -3 "$tmp/out")" >&2
		failures=$((failures + 1))
	elif [ -n "$want_note" ] && ! grep -Fq "$want_note" "$tmp/out"; then
		echo "FAIL judge $name: missing '$want_note': $(tail -3 "$tmp/out")" >&2
		failures=$((failures + 1))
	else
		echo "ok judge $name"
	fi
}
clean="$(row python landlock off '+0.5%')"
missing='| python | cgroup | full | n/a (no bare row) | 100.5 ms (±1.0) | n/a (no noop row) | n/a (no noop row) | n/a (no bare row) | 20/pass x 2 | kernel | cpu |\n'
skip='| python | bpflsm | — | — | — | — | — | skipped: stand-in: no plane | — | kernel | cpu |\n'
judge selected-python-only 0 "$hdr$clean" '1 budgeted rows'
judge explicit-tier-skip 0 "$hdr$clean$skip" '1 budgeted rows'
judge only-explicit-skips 77 "$hdr$skip"
judge noop-cpu-controls 0 "$hdr$clean$(row noop landlock off '+900.0%')$(row cpu landlock full '+900.0%')" '1 budgeted rows'
judge finite-negative 0 "$hdr$(row npm cgroup summary '-1.0%')"
judge exact-budgets 0 "$hdr$(row python landlock off '+1.0%')$(row npm cgroup summary '+3.0%')$(row npm bpflsm full '+5.0%')"
judge observe-budget 0 "$hdr$(row python observe off '+0.5%')"
judge observe-over-budget 1 "$hdr$clean$(row npm observe full '+5.1%')" 'OVER BUDGET'
judge missing-bare 77 "$hdr$clean$missing" 'no bare baseline'
judge missing-bare-only 77 "$hdr$missing"
judge missing-bare-over-budget 1 "$hdr$(row npm cgroup full '+5.1%')$missing" 'OVER BUDGET'
judge noisy-bare 77 "$hdr$clean$(row npm cgroup full 'NOISY bare (passes disagree)' | sed 's/100.0 ms (±1.0)/NOISY bare (passes disagree)/')"
for pct in 'NaN%' 'nan%' '+Inf%' '-inf%' '1.2.3%' '+0.5% trailing' 'n/a' '' '1e309%'; do
	judge "invalid-total-$pct" 1 "$hdr$clean$(row npm cgroup full "$pct")" 'INVALID'
done
judge truncated-row 1 "$hdr$clean| npm | cgroup | full |\n" 'INVALID'
judge missing-end-delimiter 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/ |\\n$/\\n/')" 'INVALID'
judge unknown-record 1 "$hdr$clean$(row npm cgroup compact '+0.5%')" 'INVALID'
judge unknown-tier 1 "$hdr$clean$(row npm unknown full '+0.5%')" 'INVALID'
judge invalid-noisy 1 "$hdr$clean$(row npm cgroup full 'NaN% NOISY')" 'INVALID'
judge invalid-with-noisy 1 "$hdr$clean$(noisy_row)$(row npm cgroup full 'NaN%')" 'INVALID'
judge invalid-with-missing 1 "$hdr$clean$missing$(row npm cgroup full 'NaN%')" 'INVALID'
judge false-skip-record 1 "$hdr$clean$(row npm cgroup full 'skipped: stand-in')" 'INVALID'
judge skip-without-reason 1 "$hdr$clean${skip/stand-in: no plane/}" 'INVALID'
judge unknown-skip-record 1 "$hdr$clean${skip/— | — | — | — | —/unknown | — | — | — | —}" 'INVALID'
judge nonfinite-bare 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/100.0 ms/NaN ms/')" 'INVALID'
judge nonfinite-enforced 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/100.5 ms/Inf ms/')" 'INVALID'
judge signed-fixed-marginal 0 "$hdr$(row npm cgroup full '+0.5%' | sed 's/n\/a (no noop row)/-0.1 ms/; s/n\/a (no noop row)/+0.6%/')"
judge nonfinite-fixed 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/n\/a (no noop row)/NaN ms/')" 'INVALID'
judge nonfinite-marginal 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/n\/a (no noop row)/0.1 ms/; s/n\/a (no noop row)/Inf%/')" 'INVALID'
judge malformed-spread 1 "$hdr$clean$(row npm cgroup full '+0.5%' | sed 's/±1.0/±oops/')" 'INVALID'
echo "judge cases=$cases failures=$failures"
[ "$failures" = 0 ] || fail "$failures eligible-row judgements were wrong"

echo "ok kt3_test.sh"
