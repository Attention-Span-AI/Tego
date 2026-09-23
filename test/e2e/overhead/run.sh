#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — the overhead benchmark: what does running a workload under `tego run` cost against
# running it bare, per enforcement tier and record mode. docs/P0-DESIGN.md §9 sets the budget this
# checks (< 1% / < 3% / < 5% enforce-only / summary / full on test/workloads/build); this script is
# the thing that measures it and docs/BENCHMARKS.md is where the numbers get published.
#
# Four workloads (test/workloads/build/{noop,cpu,python,npm}), chosen to load enforcement
# differently:
#   noop   does nothing at all — isolates the run's fixed per-invocation cost (cgroup creation, the
#          Landlock ruleset, the seccomp filter, the ledger) with no duration to amortize it into.
#          bench.py render subtracts this, per (tier, record), from every other workload's own
#          delta to split one percentage into a fixed-ms term and a marginal, per-syscall term.
#   cpu    almost no syscalls of interest — the other control. If this row shows overhead beyond
#          the noop fixed cost, it is not coming from the paths the tiers actually intercept.
#   python pip install (offline, from a local wheel cache this script primes once) + pytest: open-
#          and exec-heavy, one subprocess per tool.
#   npm    npm ci (offline, from a local npm cache primed once): open-heavy (every installed file),
#          lighter on exec.
# Priming those caches is the one place this script touches the network, and only when the cache
# is not already populated (--cache, default ~/.cache/tego-overhead-bench, persists between runs).
# A pip/npm install that hits the real registry measures the registry's latency that day, not
# tego's; every timed run in the matrix is `--no-index`/`--offline` against the local cache so the
# number is comparable across machines and days.
#
# Matrix: for each workload, a bare baseline, then tiers landlock and observe in every record mode,
# and tier cgroup in every record mode when this machine reaches it. Tiers are probed with `tego
# doctor --json` rather than assumed — cgroup needs root (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN,
# fanotify) and bpflsm additionally needs `bpf` on the active LSM list (a GRUB change and a
# reboot), so on an unprivileged dev box only landlock and observe are reachable. Every tier this
# run does not measure gets one row per workload in the table that says why, not a silently missing
# one: a tier this machine cannot reach, and tier bpflsm even where it can, since there are no
# bpflsm cells here yet.
#
# As root, which tier cgroup needs: run it with sudo from a user account. A root `tego run` drops
# its agent to SUDO_UID and refuses to start without one (docs/p0/runtime-launch.md), so a bare
# baseline run as root would time a different user's process from the one tego runs. Every bare
# cell then runs as that user too (setpriv, as kill test 4's baseline does), the directories the
# agent writes are that user's, and the wheel and npm caches are copied into the work directory,
# where that user can read them.
#
# Measurement is hyperfine's, falling back to a built-in loop when hyperfine is not on PATH (see
# bench.py): warm up, then a fixed, reported number of runs, median and spread — never a single
# sample. The matrix is not run in a fixed order: every (workload, tier, record) cell, across every
# workload, is registered up front and handed to `bench.py run-matrix`, which shuffles the whole
# list independently for each of `--passes` passes (default 2) before timing anything. A fixed
# order (every workload's "full" first, "off" last, every time) lets a monotonic drift in ambient
# machine load over the run's several minutes masquerade as a record-mode effect — full always
# measured while the box is quiet, off always measured after something else has warmed up the
# scheduler. Two independently-shuffled passes catch that: a cell whose two passes disagree by more
# than their combined spread is reported as disagreeing, not averaged into a falsely precise number.
#
# Usage: run.sh [--keep] [--work DIR] [--tego PATH] [--workload-bin DIR] [--cache DIR]
#                [--warmup N] [--runs N] [--passes N] [--seed N] [--out FILE]
#   --keep          leave the work directory behind (contracts, ledgers, per-run output), with every
#                    timed run's ledger, where without it each is removed before the next run
#   --work DIR      use this directory instead of a fresh mktemp one
#   --tego PATH    use an already-built tego binary instead of building one
#   --workload-bin DIR
#                   use the noop and cpu binaries in DIR (CGO_ENABLED=0 builds of
#                    test/workloads/build/noop and cpu) instead of building them (default:
#                    $TEGO_BENCH_BIN); with --tego as well, the harness needs no go
#   --cache DIR     local wheel/npm cache root (default: $TEGO_BENCH_CACHE, else
#                    ~/.cache/tego-overhead-bench)
#   --warmup N      warmup runs per cell before the timed ones (default 3)
#   --runs N        timed runs per cell per pass (default 10; the CLI's own tunable, not
#                    hyperfine's default "run until confident", so the harness's own run count is
#                    always the one quoted)
#   --passes N      independently-shuffled passes over the whole matrix (default 2; see above)
#   --seed N        pin the shuffle's base seed for a reproducible order (default: random, printed
#                    to stderr so any run's order can be replayed)
#   --out FILE      write the markdown table here too (default: bin/overhead/<UTC date and time>.md)
# Exit 0 when the table was written; 1 on a failure, a timed run that failed included; 2 on a usage
# error; 97, with the reason on stderr after "run.sh: cannot run here: ", when this machine cannot
# run the harness at all (the code test/vm and test/e2e/pydeps.sh give "this box cannot").
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
overhead_dir="$repo_root/test/e2e/overhead"
workloads="$repo_root/test/workloads/build"
bench_py="$overhead_dir/bench.py"
# shellcheck source=test/e2e/get-pip.sh
. "$repo_root/test/e2e/get-pip.sh"

keep=0
work=""
tego=""
workload_bin="${TEGO_BENCH_BIN:-}"
cache="${TEGO_BENCH_CACHE:-$HOME/.cache/tego-overhead-bench}"
warmup=3
runs=10
passes=2
seed=""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1; shift ;;
    --work) work="${2:?--work needs a directory}"; shift 2 ;;
    --tego) tego="${2:?--tego needs a path}"; shift 2 ;;
    --workload-bin) workload_bin="${2:?--workload-bin needs a directory}"; shift 2 ;;
    --cache) cache="${2:?--cache needs a directory}"; shift 2 ;;
    --warmup) warmup="${2:?--warmup needs a number}"; shift 2 ;;
    --runs) runs="${2:?--runs needs a number}"; shift 2 ;;
    --passes) passes="${2:?--passes needs a number}"; shift 2 ;;
    --seed) seed="${2:?--seed needs a number}"; shift 2 ;;
    --out) out="${2:?--out needs a path}"; shift 2 ;;
    # The whole header down to its Usage block and exit codes, found by the line that ends it: a
    # fixed line range stopped short of the Usage block and would again as the header grows.
    -h|--help) sed -n '3,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d'; exit 0 ;;
    *) echo "run.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

note() { echo "== $*" >&2; }
fail() { echo "run.sh: FAIL: $*" >&2; exit 1; }
# sq quotes one word for the bash that bench.py and hyperfine run a cell's prepare and command in, which is where
# every path below ends up: --work, TMPDIR, --tego, --cache and the checkout may each hold a space, and a path
# split at one turned `rm -rf $work/...` into an rm -rf of the directory its first word names.
sq() { printf '%q' "$1"; }
# cannot is for what this machine lacks, not for something that broke: kill test 3 reads 97 as its
# named skip, where exit 1 would be a failure of the product under test.
cannot() { echo "run.sh: cannot run here: $*" >&2; exit 97; }

command -v python3 >/dev/null || cannot "python3 is required (bench.py and this box's pip bootstrap both need it)"
if { [ -z "$tego" ] || [ -z "$workload_bin" ]; } && ! command -v go >/dev/null 2>&1; then
  cannot "go is not on PATH; it builds tego without --tego and the noop and cpu workloads without --workload-bin"
fi
if [ -n "$workload_bin" ]; then
  for w in noop cpu; do
    [ -x "$workload_bin/$w" ] || fail "--workload-bin $workload_bin holds no executable $w"
  done
fi

# The user a root run drops its agent to, "" when not root (see the header).
agent_uid=""
agent_gid=""
if [ "$(id -u)" = 0 ]; then
  if [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" = 0 ]; then
    cannot "running as root without SUDO_UID: a root tego run drops its agent to the sudo user and refuses to start without one; run it with sudo from a user account"
  fi
  command -v setpriv >/dev/null 2>&1 || cannot "setpriv (util-linux) is not on PATH; as root the bare cells run as SUDO_UID through it"
  agent_uid="$SUDO_UID"
  agent_gid="${SUDO_GID:-$SUDO_UID}"
fi
# as_agent prefixes a bare cell's command so it runs as the user tego would run its agent as.
as_agent=""
[ -z "$agent_uid" ] || as_agent="setpriv --reuid=$agent_uid --regid=$agent_gid --clear-groups "
agent_owns() { [ -z "$agent_uid" ] || chown -R "$agent_uid:$agent_gid" "$@"; }
# owns_after prints the tail of a prepare command that hands the directories it recreated to that
# user; a prepare runs as root before every timed run and would otherwise leave them root's.
owns_after() {
  [ -z "$agent_uid" ] || { printf ' && chown -R %s:%s --' "$agent_uid" "$agent_gid"; printf ' %q' "$@"; }
}

if [ -z "$work" ]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/tego-overhead-XXXXXX")"
  [ "$keep" = 1 ] || trap 'rm -rf "$work"' EXIT
fi
mkdir -p "$work" "$cache"
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the directory is made absolute.
work="$(cd "$work" && pwd)" || fail "cannot enter $work"
chmod 755 "$work" # config.Load refuses a layer directory anyone but its owner may write

# Not a dated record file beside the e2e scripts, the default this had: that is where an acceptance run's record
# lives (test/e2e/README.md), under the same name, and tee would replace a record written the same day.
[ -n "$out" ] || out="$repo_root/bin/overhead/$(date -u +%Y-%m-%dT%H%M%SZ).md"
mkdir -p "$(dirname "$out")"

if [ -z "$tego" ]; then
  # The binary `make build` ships, static and with the tier-2 BPF objects (an untagged build is tier 1 only, so
  # doctor called tier cgroup "not built into this binary" even as root, and its skip rows named that instead of
  # what the machine lacks), plus tegotesthooks: the product anchors every run in the invoking user's own
  # ~/.tego/chain.log, which no setting redirects, so a benchmark of thousands of runs would fill the developer's
  # anchor with lines whose ledgers are removed as the benchmark goes (identity-config.md R27). The hooks build
  # adds descriptor-ownership checks (internal/platform/sys/fd_testhooks.go); test/vm/perf.sh measures the same build.
  note "building tego"
  ( cd "$repo_root" && CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf,tegotesthooks -trimpath -ldflags '-s -w' -o "$work/tego" ./cmd/tego )
  tego="$work/tego"
fi
# A binary handed in with --tego that is not a test build ignores the variables below and anchors in ~/.tego: refused,
# except on a disposable machine (the KVM guests set TEGO_DISPOSABLE_HOST).
if [ -z "${TEGO_DISPOSABLE_HOST:-}" ] && ! grep -aq TEGO_TEST_CHAIN_ANCHOR "$tego"; then
  echo "run.sh: $tego is not built with -tags tegotesthooks: it would append every timed run to the invoking user's own ~/.tego/chain.log" >&2
  exit 2
fi
qtego="$(sq "$tego")"
export TEGO_CONFIG="$work/config.yaml"
# The anchor's directory is tego's own: a write entry inside it is refused, and the workloads write under $work.
mkdir -p "$work/tego-own/home"
export TEGO_TEST_CHAIN_ANCHOR="$work/tego-own/chain.log"
export TEGO_TEST_OWN_LOG_HOME="$work/tego-own/home"
export HISTFILE=/dev/null
# Each timed run makes <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's crashed runs left there:
# the benchmark's is its own, 0700 as tego requires (identity-config.md R27 clause b4).
mkdir -p "$work/tego-own/run"
chmod 700 "$work/tego-own/run"
export XDG_RUNTIME_DIR="$work/tego-own/run"
cat > "$TEGO_CONFIG" <<EOF
version: 0
ledger_root: $work/runs
stop_grace: 3s
EOF
chmod 600 "$TEGO_CONFIG"

kernel="$(uname -sr)"
cpu="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')"
note "machine: $kernel / $cpu"

# --- tier probe (doctor --json is the one source of truth; never assume a tier from what the
# ticket happens to say about a typical box) -------------------------------------------------
doctor_json="$("$tego" doctor --json || true)"
tier_ok() {
  python3 -c "import json,sys; d=json.load(sys.stdin); print('yes' if d.get('tiers',{}).get('$1') else 'no')" <<<"$doctor_json"
}
tier_reason() {
  python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('missing', {}).get('$1')
print('; '.join(r) if r else 'not available (see tego doctor)')
" <<<"$doctor_json"
}
landlock_ok="$(tier_ok landlock)"
cgroup_ok="$(tier_ok cgroup)"
bpflsm_ok="$(tier_ok bpflsm)"
note "tiers: landlock=$landlock_ok cgroup=$cgroup_ok bpflsm=$bpflsm_ok (observe is always reachable: no probe, R17)"
[ "$landlock_ok" = "yes" ] || fail "landlock is not available on this machine; nothing in the matrix can run"

results="$work/results.jsonl"
cells="$work/cells.jsonl"
: > "$results"
: > "$cells"

# prune is the first, untimed step before every run of every cell: it removes the ledgers the runs before it
# left in the ledger root. Every timed run writes one, up to about 2 MB for npm or python at record: full, and
# at the default counts they come to about 550 MB in $work, which the exit trap deletes only when run.sh made the
# work directory itself: with --work nothing else removes them.
# In the kernel-matrix guest, whose /tmp is a tmpfs in its RAM, a timed npm run exited 137 (SIGKILL) about 17
# minutes in, twice, while the kept ledgers filled that /tmp, and with them removed the same run went to the
# end. What killed it was not isolated: replays did not bring it back, and 137 is also what a run's memory and
# pids caps give, and a global OOM kill. --keep keeps them all, as it says; pass it a --work that holds them.
# Only the path is quoted (sq), so the glob still expands.
prune=""
[ "$keep" = 1 ] || printf -v prune 'rm -rf -- %q/runs/r-*' "$work"
cell() { # cell WORKLOAD TIER RECORD PREPARE COMMAND
  local prepare="$prune"
  [ -z "$4" ] || prepare="${prepare:+$prepare && }$4"
  python3 "$bench_py" cell --workload "$1" --tier "$2" --record "$3" --prepare "$prepare" --command "$5" \
    >> "$cells"
}
skip() { # skip WORKLOAD TIER REASON
  python3 "$bench_py" skip \
    --meta "workload=$1" --meta "tier=$2" --meta "reason=$3" --meta "kernel=$kernel" --meta "cpu=$cpu" \
    >> "$results"
}

record_modes="full summary off"

# cgroup_contract writes the workload's contract again as agent.cgroup.yaml, pinned at tier cgroup.
# Its agent.yaml pins tier landlock, and `--tier cgroup` does not override a contract's pin: the
# two requests conflict and the run is refused (internal/runtime/enforce Select).
cgroup_contract() { # cgroup_contract DIR
  sed 's/^tier: landlock$/tier: cgroup/' "$1/agent.yaml" > "$1/agent.cgroup.yaml"
  grep -qx 'tier: cgroup' "$1/agent.cgroup.yaml" || fail "$1/agent.yaml pins no tier landlock to replace"
  ( cd "$1" && "$tego" compile agent.cgroup.yaml --offline >/dev/null )
}

# bpflsm_row writes the workload's one tier-bpflsm row: the reason the machine cannot reach it, or,
# where it can, that nothing here measures it, so a reachable tier is never silently missing.
bpflsm_row() { # bpflsm_row WORKLOAD
  if [ "$bpflsm_ok" = "yes" ]; then
    skip "$1" bpflsm "reachable here, but run.sh has no tier-bpflsm cells yet"
  else
    skip "$1" bpflsm "$(tier_reason bpflsm)"
  fi
}

# workload_binary puts the noop or cpu binary at $work/NAME-bin: the --workload-bin one, else a build.
workload_binary() { # workload_binary NAME
  if [ -n "$workload_bin" ]; then
    cp "$workload_bin/$1" "$work/$1-bin"
  else
    ( cd "$repo_root" && CGO_ENABLED=0 go build -o "$work/$1-bin" "./test/workloads/build/$1" )
  fi
}

# --- workload: noop (fixed-cost probe) ----------------------------------------------------------
# Bare-vs-enforced on a binary that does nothing is, by construction, the run's fixed per-invocation
# cost (cgroup creation, the Landlock ruleset, the seccomp filter install, opening the ledger) with
# no workload duration to amortize it into. render subtracts this, per (tier, record), from every
# other workload's own bare-vs-enforced delta to split one percentage into a fixed-ms term and a
# marginal, per-syscall term — a short workload's percentage is almost entirely this fixed cost, and
# without separating them a reader cannot tell whether a large percentage is "slow to start" or
# "slow per syscall it made," which matters for a comparison with other tools (a workload lasting seconds
# amortizes the fixed cost away; the budget in P0-DESIGN §9 is stated against the whole build).
run_noop() {
  note "workload noop: build"
  workload_binary noop
  local dir="$work/noop" qdir; mkdir -p "$dir"
  qdir="$(sq "$dir")"
  cp "$work/noop-bin" "$dir/noop"; chmod +x "$dir/noop"
  cat > "$dir/agent.yaml" <<EOF
version: 0
name: overhead-noop
command: ["./noop"]
tier: landlock
capture: off
env:
  pass: ["PATH"]
limits: { pids: 64, wall: 1m }
record: summary
EOF
  ( cd "$dir" && "$tego" compile agent.yaml --offline >/dev/null )

  note "workload noop: bare baseline"
  cell noop bare - "" "cd $qdir && ${as_agent}./noop"

  for r in $record_modes; do
    note "workload noop: landlock / record=$r"
    cell noop landlock "$r" "" "cd $qdir && $qtego run agent.yaml --offline --tier landlock --record $r -- ./noop"
    note "workload noop: observe / record=$r"
    cell noop observe "$r" "" "cd $qdir && $qtego run agent.yaml --offline --observe --record $r -- ./noop"
  done
  if [ "$cgroup_ok" = "yes" ]; then
    cgroup_contract "$dir"
    for r in $record_modes; do
      note "workload noop: cgroup / record=$r"
      cell noop cgroup "$r" "" "cd $qdir && $qtego run agent.cgroup.yaml --offline --tier cgroup --record $r -- ./noop"
    done
  else
    skip noop cgroup "$(tier_reason cgroup)"
  fi
  bpflsm_row noop
}

# --- workload: cpu (control) ------------------------------------------------------------------
run_cpu() {
  note "workload cpu: build"
  workload_binary cpu
  local dir="$work/cpu" qdir; mkdir -p "$dir"
  qdir="$(sq "$dir")"
  cp "$work/cpu-bin" "$dir/cpu"; chmod +x "$dir/cpu"
  cat > "$dir/agent.yaml" <<EOF
version: 0
name: overhead-cpu
command: ["./cpu"]
tier: landlock
capture: off
env:
  pass: ["PATH"]
limits: { pids: 64, wall: 1m }
record: summary
EOF
  ( cd "$dir" && "$tego" compile agent.yaml --offline >/dev/null )

  note "workload cpu: bare baseline"
  cell cpu bare - "" "cd $qdir && ${as_agent}./cpu >/dev/null"

  for r in $record_modes; do
    note "workload cpu: landlock / record=$r"
    cell cpu landlock "$r" "" "cd $qdir && $qtego run agent.yaml --offline --tier landlock --record $r -- ./cpu >/dev/null"
    note "workload cpu: observe / record=$r"
    cell cpu observe "$r" "" "cd $qdir && $qtego run agent.yaml --offline --observe --record $r -- ./cpu >/dev/null"
  done
  if [ "$cgroup_ok" = "yes" ]; then
    cgroup_contract "$dir"
    for r in $record_modes; do
      note "workload cpu: cgroup / record=$r"
      cell cpu cgroup "$r" "" "cd $qdir && $qtego run agent.cgroup.yaml --offline --tier cgroup --record $r -- ./cpu >/dev/null"
    done
  else
    skip cpu cgroup "$(tier_reason cgroup)"
  fi
  bpflsm_row cpu
}

# --- workload: python (pip install + pytest) --------------------------------------------------
prime_python_cache() {
  local pyc="$cache/python" req="$workloads/python/requirements.txt" stamp
  # The stamp is written last, after both directories are in place: a run killed part-way (network drop, OOM
  # kill, Ctrl-C) leaves no stamp, so the next run primes again instead of taking a truncated wheelhouse
  # for a primed cache.
  stamp="$(sha256sum "$req" | cut -c1-16)"
  if [ "$(cat "$pyc/.stamp" 2>/dev/null)" = "$stamp" ] && [ -d "$pyc/pip-bootstrap" ] && [ -d "$pyc/wheelhouse" ]; then
    note "python cache already primed at $pyc"
    return 0
  fi
  note "python cache: bootstrapping pip and downloading the wheelhouse (network, once)"
  mkdir -p "$pyc"
  rm -rf "$pyc/.stamp" "$pyc/pip-bootstrap.part" "$pyc/wheelhouse.part"
  local rc=0
  fetch_get_pip "$work/get-pip.py" 30 || rc=$?
  if [ "$rc" = 2 ]; then
    note "python cache: get-pip.py does not match the pinned sha256 (test/e2e/get-pip.sh); not running it"
    return 1
  elif [ "$rc" != 0 ]; then
    note "python cache: no network reachable to bootstrap pip; python workload will be skipped"
    return 1
  fi
  python3 "$work/get-pip.py" --target="$pyc/pip-bootstrap.part" --no-warn-script-location -q || return 1
  PYTHONPATH="$pyc/pip-bootstrap.part" python3 -m pip download --only-binary=:all: --require-hashes -d "$pyc/wheelhouse.part" -q -r "$req" || return 1
  rm -rf "$pyc/pip-bootstrap" "$pyc/wheelhouse"
  mv "$pyc/pip-bootstrap.part" "$pyc/pip-bootstrap"
  mv "$pyc/wheelhouse.part" "$pyc/wheelhouse"
  echo "$stamp" >"$pyc/.stamp"
}

run_python() {
  if ! command -v python3 >/dev/null; then
    skip python "*" "no python3 on this machine"
    return 0
  fi
  if ! prime_python_cache; then
    skip python "*" "no network to prime the local wheel cache and it was not already primed (see --cache)"
    return 0
  fi
  local pyc="$cache/python"
  if [ -n "$agent_uid" ]; then
    # The agent reads pip and the wheels as the user, and root's cache sits under /root.
    mkdir -p "$work/pycache"
    cp -rL "$pyc/pip-bootstrap" "$pyc/wheelhouse" "$work/pycache/"
    chmod -R go+rX "$work/pycache"
    pyc="$work/pycache"
  fi
  local dir="$work/python" qdir; mkdir -p "$dir/target" "$dir/tmp" "$dir/home"
  qdir="$(sq "$dir")"
  agent_owns "$dir/target" "$dir/tmp" "$dir/home"
  cat > "$dir/agent.yaml" <<EOF
version: 0
name: overhead-python
command: ["bash", "run.sh"]
tier: landlock
capture: off
fs:
  # /dev/null: pytest's logging plugin unconditionally opens a FileHandler on os.devnull when no
  # log_file option is set (_pytest/logging.py) - a real compatibility fact about running pytest
  # under a default-deny write policy, not a benchmark artifact, and worth a rule of its own so it
  # reads as deliberate rather than a stray broad grant.
  write: ["$dir/target/", "$dir/tmp/", "/dev/null"]
exec:
  # python3 is the workload proper; dirname and mkdir are run.sh finding its own directory and
  # creating target/tmp — both real exec-heavy cost of "a shell script installs things," so they
  # belong in the measurement rather than being engineered out of the workload.
  allow: ["python3", "dirname", "mkdir"]
env:
  pass: ["PATH"]
  set: { HOME: "$dir/home" }
limits: { pids: 64, wall: 2m }
record: summary
EOF
  cp "$workloads/python/run.sh" "$dir/run.sh"; chmod +x "$dir/run.sh"
  cp "$workloads/python/requirements.txt" "$dir/requirements.txt"
  cp -r "$workloads/python/tests" "$dir/tests"
  ( cd "$dir" && "$tego" compile agent.yaml --offline >/dev/null )

  local prepare
  prepare="rm -rf -- $qdir/target $qdir/tmp && mkdir -p -- $qdir/target $qdir/tmp$(owns_after "$dir/target" "$dir/tmp")"
  local args
  args="$(sq "$pyc/wheelhouse") $(sq "$pyc/pip-bootstrap") $qdir/target $qdir/tmp"

  # HOME as the contract sets it, so the bare run reads no pip configuration the run under tego
  # does not, and as root a HOME the user can reach.
  note "workload python: bare baseline"
  cell python bare - "$prepare" "cd $qdir && ${as_agent}env HOME=$qdir/home ./run.sh $args >/dev/null"

  for r in $record_modes; do
    note "workload python: landlock / record=$r"
    cell python landlock "$r" "$prepare" "cd $qdir && $qtego run agent.yaml --offline --tier landlock --record $r -- bash run.sh $args >/dev/null"
    note "workload python: observe / record=$r"
    cell python observe "$r" "$prepare" "cd $qdir && $qtego run agent.yaml --offline --observe --record $r -- bash run.sh $args >/dev/null"
  done
  if [ "$cgroup_ok" = "yes" ]; then
    cgroup_contract "$dir"
    for r in $record_modes; do
      note "workload python: cgroup / record=$r"
      cell python cgroup "$r" "$prepare" "cd $qdir && $qtego run agent.cgroup.yaml --offline --tier cgroup --record $r -- bash run.sh $args >/dev/null"
    done
  else
    skip python cgroup "$(tier_reason cgroup)"
  fi
  bpflsm_row python
}

# --- workload: npm (npm ci) ---------------------------------------------------------------------
prime_npm_cache() {
  local npc="$cache/npm"
  if [ -d "$npc/cache" ] && [ -n "$(ls -A "$npc/cache" 2>/dev/null)" ]; then
    note "npm cache already primed at $npc"
    return 0
  fi
  note "npm cache: priming (network, once)"
  mkdir -p "$npc"
  local tmp_proj="$work/npm-prime"
  mkdir -p "$tmp_proj"
  cp "$workloads/npm/package.json" "$workloads/npm/package-lock.json" "$tmp_proj/"
  if ! ( cd "$tmp_proj" && npm ci --cache "$npc/cache" --no-audit --no-fund --loglevel=error ); then
    note "npm cache: priming failed (no network or npm error); npm workload will be skipped"
    return 1
  fi
}

run_npm() {
  if ! command -v npm >/dev/null; then
    skip npm "*" "no npm on this machine"
    return 0
  fi
  if ! prime_npm_cache; then
    skip npm "*" "no network to prime the local npm cache and it was not already primed (see --cache)"
    return 0
  fi
  local npc="$cache/npm"
  if [ -n "$agent_uid" ]; then
    # npm writes its cache as the user the agent runs as, and root's cache sits under /root.
    mkdir -p "$work/npmcache"
    cp -rL "$npc/cache" "$work/npmcache/"
    npc="$work/npmcache"
    agent_owns "$npc"
  fi
  local dir="$work/npm" qdir; mkdir -p "$dir/project" "$dir/home"
  qdir="$(sq "$dir")"
  agent_owns "$dir/project" "$dir/home"
  cat > "$dir/agent.yaml" <<EOF
version: 0
name: overhead-npm
command: ["npm", "ci"]
tier: landlock
capture: off
fs:
  write: ["$dir/project/", "$npc/cache/"]
env:
  pass: ["PATH"]
  set: { HOME: "$dir/home" }
limits: { pids: 64, wall: 2m }
record: summary
EOF
  "$tego" compile "$dir/agent.yaml" --offline >/dev/null

  local prepare npmargs
  prepare="rm -rf -- $qdir/project && mkdir -p -- $qdir/project && cp -- $(sq "$workloads/npm/package.json") $(sq "$workloads/npm/package-lock.json") $qdir/project/$(owns_after "$dir/project")"
  npmargs="--offline --cache $(sq "$npc/cache") --no-audit --no-fund --loglevel=error"

  note "workload npm: bare baseline"
  cell npm bare - "$prepare" "cd $qdir/project && ${as_agent}env HOME=$qdir/home npm ci $npmargs >/dev/null"

  for r in $record_modes; do
    note "workload npm: landlock / record=$r"
    cell npm landlock "$r" "$prepare" "cd $qdir/project && $qtego run $qdir/agent.yaml --offline --tier landlock --record $r -- npm ci $npmargs >/dev/null"
    note "workload npm: observe / record=$r"
    cell npm observe "$r" "$prepare" "cd $qdir/project && $qtego run $qdir/agent.yaml --offline --observe --record $r -- npm ci $npmargs >/dev/null"
  done
  if [ "$cgroup_ok" = "yes" ]; then
    cgroup_contract "$dir"
    for r in $record_modes; do
      note "workload npm: cgroup / record=$r"
      cell npm cgroup "$r" "$prepare" "cd $qdir/project && $qtego run $qdir/agent.cgroup.yaml --offline --tier cgroup --record $r -- npm ci $npmargs >/dev/null"
    done
  else
    skip npm cgroup "$(tier_reason cgroup)"
  fi
  bpflsm_row npm
}

run_noop
run_cpu
run_python
run_npm

note "matrix built: $(wc -l < "$cells") cells; shuffling into $passes independent pass(es) and measuring"
seed_args=()
[ -n "$seed" ] && seed_args=(--seed "$seed")
python3 "$bench_py" run-matrix "$cells" --warmup "$warmup" --runs "$runs" --passes "$passes" \
  "${seed_args[@]}" --meta "kernel=$kernel" --meta "cpu=$cpu" >> "$results"

note "rendering table"
python3 "$bench_py" render "$results" | tee "$out"
note "results: $out (raw: $results, cells: $cells)"
[ "$keep" = 1 ] && note "work directory kept: $work"
exit 0
