#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# m0-demo.sh — the M0 demo of docs/P0-DESIGN.md §12: run a real agent unchanged under a contract,
# show one refusal, run two agents concurrently, stop one of them, and print the ledger summary.
#
# It runs the system-Python workload in test/workloads/python-httpx under the tier-1 (Landlock)
# backend, as the invoking user: no root, no sudo, nothing installed. Everything it writes lives in
# one work directory it creates and (unless --keep) removes again.
#
# A binary handed in with --tego must itself be built with -tags tegotesthooks, or it anchors the chain in the
# invoking user's ~/.tego/chain.log.
#
# Usage: test/e2e/m0-demo.sh [--keep] [--work <dir>] [--tego <binary>]
#   --keep          leave the work directory (contracts, ledger, agent output) behind
#   --work <dir>    use this directory instead of a fresh mktemp one
#   --tego <path>  use an already-built tego binary instead of building one
#
# Exit 0 when every check passed; 1 with a named check on the first failure.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workload="$repo_root/test/workloads/python-httpx"

keep=0
work=""
tego=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1; shift ;;
    --work) work="${2:?--work needs a directory}"; shift 2 ;;
    --tego) tego="${2:?--tego needs a path}"; shift 2 ;;
    -h|--help) sed -n '3,19p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "m0-demo: unknown argument $1" >&2; exit 2 ;;
  esac
done

fail() { echo "m0-demo: FAIL: $*" >&2; exit 1; }
note() { echo "== $*"; }

command -v python3 >/dev/null || fail "python3 is required: the workload is a system-Python agent"

if [ -z "$work" ]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/tego-m0-XXXXXX")"
  [ "$keep" = 1 ] || trap 'rm -rf "$work"' EXIT
fi
mkdir -p "$work"
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the directory is made absolute.
work="$(cd "$work" && pwd)" || fail "cannot enter $work"
# config.Load refuses a layer whose file or directory anyone but its owner may write (spec/config/v0).
chmod 755 "$work"

if [ -z "$tego" ]; then
  note "building tego"
  # tegotesthooks lets TEGO_TEST_CHAIN_ANCHOR (below) keep the chain anchor in the work directory, so the
  # demo never appends to the developer's own ~/.tego/chain.log (internal/cli/anchor_testhook.go).
  ( cd "$repo_root" && CGO_ENABLED=0 go build -tags tegotesthooks -o "$work/tego" ./cmd/tego )
  tego="$work/tego"
fi
# A binary handed in with --tego that is not a test build ignores the variables below and anchors in ~/.tego: refused.
grep -aq TEGO_TEST_CHAIN_ANCHOR "$tego" ||
  fail "$tego is not built with -tags tegotesthooks: it would append this demo's runs to the invoking user's own ~/.tego/chain.log"
export TEGO_CONFIG="$work/config.yaml"
export TEGO_TEST_CHAIN_ANCHOR="$work/chain.log"
# ... and the own log: without it the demo's binary keeps none (a test build fails closed), with it tego.log is the demo's.
mkdir -p "$work/log-home"
export TEGO_TEST_OWN_LOG_HOME="$work/log-home"
# ... and the runtime directory: each run makes <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's
# crashed runs left there, so the demo's is its own, 0700 as tego requires (identity-config.md R27 clause b4).
mkdir -p "$work/run"
chmod 700 "$work/run"
export XDG_RUNTIME_DIR="$work/run"

mkdir -p "$work/agent"
cp "$workload/agent.py" "$work/agent/agent.py"
# The workload writes to $TEGO_TEST_OUT, defaulting to /tmp/tego-out, and TEGO_* names are
# reserved for the runtime, so a contract may not set one: the declared write directory is that
# default, which is what "the agent runs unchanged" means here.
out="${TEGO_TEST_OUT:-/tmp/tego-out}"
mkdir -p "$out"
# A summary.md left by an earlier demo must not stand in for this run's write.
rm -f "$out/summary.md"

cat > "$work/config.yaml" <<EOF
version: 0
ledger_root: $work/runs
stop_grace: 3s
EOF
chmod 600 "$work/config.yaml"

# The demo contract follows examples/agents/retriever.yaml's P0 subset, with what no laptop can
# provide left out: the profile it extends ships only as a compiler fixture
# (pkg/spec/agent/testdata/profiles/base/python-dev.yaml), and its
# /work/out, MCP server and model host need a machine this demo does not assume.
cat > "$work/agent/agent.yaml" <<EOF
version: 0
name: retriever-demo
command: ["python3", "agent.py"]
tier: landlock
fs:
  write: ["$out/"]
exec:
  allow: ["python3"]
env:
  pass: ["PATH", "HOME", "LANG"]
limits:
  memory: 2GiB
  pids: 256
  wall: 10m
  stall_after: 2m
record: summary
EOF

note "contract"
"$tego" compile "$work/agent/agent.yaml" --offline | sed -n '1,8p'

note "run 1: the agent, unchanged, under the contract"
set +e
( cd "$work/agent" && "$tego" run agent.yaml --offline -- python3 agent.py ) > "$work/run1.out" 2> "$work/run1.err"
run1=$?
set -e
sed -n '1,20p' "$work/run1.out"
echo "exit: $run1"
grep -q "refused as expected" "$work/run1.out" || fail "the agent did not see its write outside the contract refused"
[ -s "$out/summary.md" ] || fail "the agent could not write inside its declared write directory"

# The agent's python3 is found by a PATH search, and execvp calls execve once per directory it
# walks. Those candidates are recorded against the entry being searched for as `observed`, never as
# refusals (docs/p0/supervisor.md R28): an exec-not-allowed here would be the ledger blaming the agent
# for how execvp works. Only run 1's ledger exists at this point.
execrefusals="$(cat "$work"/runs/r-*/events.jsonl 2>/dev/null | grep -c '"reason":"exec-not-allowed"' || true)"
[ "$execrefusals" = 0 ] || fail "$execrefusals exec-not-allowed refusals for a granted python3"

note "run 2 and run 3: two agents at once"
( cd "$work/agent" && "$tego" run agent.yaml --offline -- python3 agent.py ) >/dev/null 2>&1 &
p2=$!
( cd "$work/agent" && "$tego" run agent.yaml --offline -- python3 -c "import time; time.sleep(30)" ) >/dev/null 2>&1 &
p3=$!
sleep 2

# The sleeping one is the stop target: whichever run still holds its lock.
target=""
for d in "$work"/runs/r-*; do
  [ -d "$d" ] || continue
  if "$tego" status "$(basename "$d")" --json 2>/dev/null | grep -q '"lock_held":true'; then
    target="$(basename "$d")"
  fi
done
[ -n "$target" ] || fail "no run was live to stop"
note "stop $target"
"$tego" stop "$target"
wait "$p2" || true
set +e
wait "$p3"
stopped_exit=$?
set -e
echo "stopped run exit: $stopped_exit"
case "$stopped_exit" in
  143|137) ;;
  *) fail "a stopped run exits 143 (SIGTERM) or 137 (cgroup.kill), got $stopped_exit" ;;
esac

note "status"
"$tego" status --all || true

note "ledger summary"
python3 - "$work/runs" <<'PY'
import json, os, sys
root = sys.argv[1]
for run in sorted(os.listdir(root)):
    path = os.path.join(root, run, "events.jsonl")
    if not os.path.exists(path):
        continue
    kinds, refusals, end, cmd = {}, [], None, None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn tail is expected on a live run, never an error
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
            if e["kind"] == "refused":
                refusals.append("%s %s (%s)" % (e.get("op"), e.get("target"), e.get("reason")))
            if e["kind"] == "run_end":
                end = e
            if e["kind"] == "run_start":
                cmd = " ".join(e.get("command", []))
    print("run %s  agent=%s" % (run, e.get("agent", "?")))
    print("  command: %s" % cmd)
    print("  events:  %s" % ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    if end:
        print("  end:     reason=%s exit=%s signal=%s escalated=%s" % (
            end.get("reason"), end.get("exit_code", 0), end.get("signal", 0), end.get("escalated", False)))
    else:
        print("  end:     (none: the run is live or was lost)")
    for r in refusals:
        print("  refused: %s" % r)
PY

note "every check passed"
[ "$keep" = 1 ] && echo "work directory kept: $work"
exit 0
