#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt3-overhead.sh — kill test 3 (P0-DESIGN §10 "3 overhead"; §9's budget "whole run, enforce-only /
# summary / full: < 1% / < 3% / < 5% on test/workloads/build"; §12 acceptance item 6).
#
# What it attacks: the claim that watching a run costs almost nothing next to running it. The
# measurement lives in test/e2e/overhead/ — four workloads, shuffled cell order, two passes, and a
# noop probe that splits each row's fixed per-invocation cost from its marginal per-syscall cost.
# This script is the kill test around it: it runs the harness and then judges the rows against §9,
# failing when a budget is exceeded instead of printing a table nobody checks.
#
# The judgement is on total overhead, because that is what §9's budget is written against. The
# fixed and marginal columns are printed beside it, since a workload short enough for the fixed cost
# to dominate says something different from one where the marginal cost does, and a reader deciding
# whether Tego is affordable needs to know which they are looking at.
#
# Exit codes are the kill-test convention of lib.sh: 0 pass, 1 fail, 2 skip.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$here/lib.sh"

case "${1:-}" in
  -h|--help) exec "$here/overhead/run.sh" --help ;;
esac

# The table this script judges is the one run.sh writes to --out. run.sh takes the last --out it is
# given, so a caller's own --out, which comes after this script's, is the file judged, and it is kept;
# judging this script's own file instead found it empty and called the run a skip.
results=""
prev=""
for a in "$@"; do
  [ "$prev" != --out ] || results="$a"
  prev="$a"
done
keep_results=1
if [ -z "$results" ]; then
  results="$(mktemp "${TMPDIR:-/tmp}/kt3-results-XXXXXX.md")"
  keep_results=0
fi
trap '[ "$keep_results" = 1 ] || rm -f "$results"; kt_cleanup' EXIT # lib.sh's own trap removes its scratch directory; keep it

# What the kill tests' own environment hands a kill test, passed to run.sh ahead of the caller's
# arguments so that an option given by hand still wins: the tego binary (TEGO_BIN, as kt_ensure_tego
# takes it), and the wheelhouse and pip test/e2e/pydeps.sh cached (KT_PYDEPS), which is the layout
# run.sh reads under <cache>/python. The kernel-matrix guest has both and no network or go; its noop and
# cpu workloads come prebuilt through TEGO_BENCH_BIN (test/vm/matrix.sh with VM_KT3=1).
#
# --cache moves every cache run.sh keeps, not only the python one, and this one is under KT_ROOT, which
# the exit trap removes. So <cache>/npm points at the npm cache run.sh would have used without --cache,
# under its default cache root (run.sh's --cache): with the python link alone, run.sh found no npm cache
# there, primed one from the network on every run into a directory deleted at exit, and on a machine with
# npm and no network skipped the npm workload's budgeted rows. The link's target is created first, since
# run.sh's `mkdir -p` of a dangling link fails; where it cannot be, the npm cache stays in KT_ROOT.
pre=()
[ -z "${TEGO_BIN:-}" ] || [ ! -x "$TEGO_BIN" ] || pre+=(--tego "$TEGO_BIN")
if [ -n "${KT_PYDEPS:-}" ] && [ -z "${TEGO_BENCH_CACHE:-}" ] &&
  [ -d "$KT_PYDEPS/pip-bootstrap" ] && [ -d "$KT_PYDEPS/wheelhouse" ]; then
  mkdir -p "$KT_ROOT/bench-cache"
  ln -s "$KT_PYDEPS" "$KT_ROOT/bench-cache/python"
  npm_cache="$HOME/.cache/tego-overhead-bench/npm"
  if mkdir -p "$npm_cache" 2>/dev/null; then
    ln -s "$npm_cache" "$KT_ROOT/bench-cache/npm"
  fi
  pre+=(--cache "$KT_ROOT/bench-cache")
fi

# Every argument is forwarded, so the kill test and a hand-run benchmark take the same options. The
# harness skips a tier this box cannot reach and says so in the row rather than failing the run. Its
# stderr goes through tee so that its reason can be read back when it exits 97: a machine without what
# it needs (go to build, python3, a sudo user as root) is lib.sh's named skip, where under `set -e` the
# missing tool used to end this script with 127, which the kill-test convention reads as a FAIL.
set +e
{ "$here/overhead/run.sh" "${pre[@]}" --out "$results" "$@" 2>&1 1>&3 3>&- | tee "$KT_ROOT/run.err" >&2; } 3>&1
rc=${PIPESTATUS[0]}
set -e
case "$rc" in
  0) ;;
  97) kt_skip "$(sed -n 's/^run.sh: cannot run here: //p' "$KT_ROOT/run.err" | tail -1)" ;;
  *) kt_fail "test/e2e/overhead/run.sh exited $rc before it wrote its table (its stderr above)" ;;
esac
cat "$results"

# Judge the rows §9 names. The budget is stated against test/workloads/build, which is the python
# and npm workloads; noop and cpu are controls and carry no budget of their own.
set +e
python3 - "$results" <<'PY'
import math, re, sys

BUDGETS = {"off": 1.0, "summary": 3.0, "full": 5.0}
JUDGED = {"python", "npm"}

TIERS = {"landlock", "cgroup", "bpflsm", "observe"}
NUMBER = r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)"

def finite(text, suffix):
    m = re.fullmatch(f"({NUMBER}){re.escape(suffix)}", text)
    return m is not None and math.isfinite(float(m.group(1)))

def median(text):
    m = re.fullmatch(f"({NUMBER}) ms \\(±({NUMBER})\\)", text)
    return m is not None and all(math.isfinite(float(v)) and float(v) >= 0 for v in m.groups())

over, noisy, missing, invalid, judged, skipped = [], [], [], [], 0, 0
for number, line in enumerate(open(sys.argv[1]), 1):
    text = line.strip()
    if not text.startswith("|") or text.startswith("|---"):
        continue
    cells = [c.strip() for c in text.strip("|").split("|")]
    if cells[0] not in JUDGED:
        continue
    if len(cells) != 11 or not text.endswith("|"):
        invalid.append(f"line {number}: incomplete budgeted row")
        continue
    workload, tier, record, total = cells[0], cells[1], cells[2], cells[7]
    name = f"{workload}/{tier}/{record}"
    # The renderer emits one explicit skipped row per unavailable tier/workload, without a
    # record mode or measurement. It is not a successful budgeted cell.
    if record == "—" and tier in TIERS | {"*"} and cells[3:7] == ["—"] * 4 and cells[8] == "—" and re.fullmatch(r"skipped: \S.*", total):
        skipped += 1
        continue
    if record not in BUDGETS or tier not in TIERS:
        invalid.append(f"{name}: unknown record mode/tier or malformed skip")
        continue
    if cells[3] == "—" and cells[4].startswith("NOISY: passes disagree (") and cells[4].endswith(")") and cells[5:8] == ["—", "—", "not published"]:
        noisy.append(name)
        continue
    if cells[3] == total == "NOISY bare (passes disagree)" and median(cells[4]):
        noisy.append(name)
        continue
    if cells[3] == total == "n/a (no bare row)" and median(cells[4]):
        missing.append(name)
        continue
    if not median(cells[3]) or not median(cells[4]) or not finite(total, "%"):
        invalid.append(f"{name}: malformed or nonfinite measurement")
        continue
    if not (cells[5] == "n/a (no noop row)" or finite(cells[5], " ms")) or not (cells[6] == "n/a (no noop row)" or finite(cells[6], "%")):
        invalid.append(f"{name}: malformed or nonfinite fixed/marginal cost")
        continue
    judged += 1
    pct, budget = float(total[:-1]), BUDGETS[record]
    if pct > budget:
        over.append(f"{workload}/{tier}/{record}: {pct:+.1f}% against a {budget:.0f}% budget")

if noisy:
    print("kt3: passes disagreed on: " + ", ".join(noisy), file=sys.stderr)
if missing:
    print("kt3: no bare baseline for: " + ", ".join(missing), file=sys.stderr)
for line in invalid:
    print("kt3: INVALID " + line, file=sys.stderr)
for line in over:
    print("kt3: OVER BUDGET " + line, file=sys.stderr)
if invalid or over:
    sys.exit(1)
# A noisy row or one without a bare baseline was not judged, so the whole test is a skip:
# one measurable row must not let unmeasured eligible rows pass as within budget.
if noisy or missing:
    print("kt3: budgeted rows could not be judged (noisy or missing bare baseline), so the budget is unverified", file=sys.stderr)
    sys.exit(2)
if judged == 0:
    print("kt3: no budgeted row was measurable on this box", file=sys.stderr)
    sys.exit(2)
print(f"kt3: {judged} budgeted rows all within §9; {skipped} explicit skips were not judged")
PY
rc=$?
set -e

case "$rc" in
  0) kt_pass "every budgeted row is within §9's overhead budget" ;;
  2) kt_skip "a budgeted row could not be measured here, so the budget is unverified (see the rows above)" ;;
  *) kt_fail "a budgeted row was invalid or exceeded its §9 overhead budget (see the rows above)" ;;
esac
