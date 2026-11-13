# Overhead benchmark

> **Re-measure before quoting.** The overhead numbers below were taken on 2026-09-22, on one
> laptop, at tier landlock only; the engine has changed a great deal since and the root tiers were never measured.
> The "Timing budgets in the test suites" part is current.

The claim P0-DESIGN §9 makes is that enforcement costs little: whole-run overhead under 1% at the
enforce-only budget, 3% for `record: summary`, 5% for `record: full`, measured on
`test/workloads/build`. This page is that measurement, not a restatement of the claim. The harness
lives in `test/e2e/overhead/` (`test/e2e/kt3-overhead.sh` is the kill-test entry point;
`make overhead` runs it); the workloads it drives live in `test/workloads/build/`.

**Status: historical measurement against the settled tree of that date.** Two independent attempts (below) ran the full
harness — four workloads, shuffled cell order, two passes each, twenty timed runs per cell — on an
otherwise-idle laptop (load average ≈ 0.3–0.4) that still has a full desktop session resident (~9 of
14 GiB used, 4 GiB of swap fully committed). Most cells came back marked noisy: the harness's own
disagreement check, working as designed, refusing to publish a number two passes could not agree on.
The rows that did agree are reported below, in milliseconds where the row's purpose is to measure a
constant and never as a percentage when a percentage would mislead; every row that did not agree is
named, not hidden. This is not the harness failing — it is the harness telling the truth about what
this machine can and cannot hold steady.

## Method

Four workloads, chosen to load enforcement differently rather than to flatter it:

- **`noop`**: a static Go binary whose `main` does nothing. Bare-vs-enforced on this is, by
  construction, the run's fixed per-invocation cost — cgroup creation, the Landlock ruleset, the
  seccomp filter install, opening the ledger — with no workload duration to amortize it into.
- **`cpu`**: a fixed 1.8M-round SHA-256 chain, a static Go binary, no file writes, no execs, no
  connects. The other control: real duration, no syscalls of interest. If this row shows overhead
  beyond `noop`'s fixed cost, that cost is not coming from a path a tier actually intercepts.
- **`python`**: `pip install -r requirements.txt` (Flask 3.1.3 + pytest 9.0.3 and their full
  dependency sets, 12 wheels; the 2026-09-22 measurement below ran Flask 3.0.3 + pytest 8.3.3, 11
  wheels) into a fresh directory, then `pytest` against a small suite that imports and exercises
  Flask. Open- and exec-heavy: every installed file is opened once by pip and again by the
  interpreter's import machinery, one subprocess per tool.
- **`npm`**: `npm ci` (Express 4.22.3 + five small packages, 83 packages total; the 2026-09-22
  measurement ran Express 4.21.2, 79 packages) into a fresh project directory. Open-heavy, lighter
  on exec (npm and its lifecycle scripts run in-process; none of the chosen packages have
  install/postinstall scripts).

**Determinism.** A `pip install` or `npm ci` that hits the real registry measures the registry's
latency that day, not tego's. Every timed run in the matrix is offline: `run.sh` bootstraps a
local pip (the test machine's system Python ships no `pip` module — `get-pip.py`, once) and downloads the
pinned wheelhouse once (`pip download`, cached under `~/.cache/tego-overhead-bench` by default,
`--cache` to move it); the npm workload primes a local npm cache the same way and every timed
invocation runs `npm ci --offline`. Priming is the only network use; it is skipped when the cache
was already primed for the pinned files, whose digests it stamps (a changed pin primes again). Every
dependency is pinned to an exact version in
`test/workloads/build/{python/requirements.txt,npm/package.json,npm/package-lock.json}`.

**Measurement.** `hyperfine` when it is on `PATH` (`--warmup`, `--runs`, `--export-json`, read back
for the median/stddev/min/max and the raw per-run times it already computed); a built-in
warmup-then-measure loop (`test/e2e/overhead/bench.py measure`, timed with `time.perf_counter`)
when it is not, so the harness still produces numbers on a box without hyperfine. Either path fails
the run the first time the timed command itself fails, rather than averaging in a broken sample.

**Matrix and order.** For each workload: a bare baseline, then every (tier, record mode) pair this
machine can reach, probed with `tego doctor --json` rather than assumed. A tier this machine
cannot reach gets a row that says why, never a missing one. Every (workload, tier, record) cell
across every workload is registered up front and handed to `bench.py run-matrix`, which shuffles
the whole list independently for each of `--passes` passes (default 2) before timing anything — a
fixed order (every workload's `full` first, `off` last, every time, as the harness's first draft
ran it) lets a monotonic drift in ambient machine load over several minutes masquerade as a
record-mode effect. A cell whose two passes disagree by more than their combined spread (pooled
median and stddev over both passes' raw per-run times) is reported in the table as disagreeing —
"NOISY: passes disagree" — rather than averaged into a number that looks precise and is not.

**Fixed vs. marginal cost.** One percentage conflates "slow to start" with "slow per syscall it
made." The table instead carries, per row: the fixed cost in ms (from `noop`'s own bare-vs-enforced
delta at that (tier, record)), the marginal cost as a percentage of the workload
(`(delta − fixed) / bare`), and the total overhead as a percentage (`delta / bare`) — so a reader
can tell whether a workload's number is dominated by per-run setup or by per-syscall work, and
whether a short workload's percentage would shrink on a longer one.

## Machine

Kernel `Linux 6.17.0-41-generic`, CPU `Intel(R) Core(TM) i7-10870H CPU @ 2.20GHz` (16 logical
cores), 14 GiB RAM, Landlock ABI 7, cgroup v2 delegated. `tego doctor --json` on the test machine:
`"tiers":{"landlock":true,"cgroup":false,"bpflsm":false}` — **only `landlock` and `observe` were
reachable here.** `cgroup` needs root plus `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and fanotify
needs `CAP_SYS_ADMIN` too; this run had neither root nor non-interactive sudo. `bpflsm` needs
the same root, plus `bpf` on the kernel's active LSM list (`lockdown,capability,landlock,yama,
apparmor,ima,evm` — no `bpf`), which is a GRUB `lsm=` edit and a reboot away. Both rows are named as skipped in the table below, not silently absent.

This is a laptop with a full interactive desktop session on it, not a dedicated CI runner, and that
matters for reading the results: at measurement time, `free -h` showed ~9 of 14 GiB resident and the
entire 4 GiB swap partition committed (a desktop session and other jobs), even though CPU load average was low (0.3–0.4) throughout both
attempts. A 400ms–1s workload cannot be held steady across two independently-timed passes on a
machine in that state; the noisy-row count below is that fact showing up in the data, not a defect
in the harness. `test/vm`'s kernel-matrix CI job (P0-DESIGN §10) runs on a machine with nothing else
on it, and is where the rows this run could not hold steady should get a clean number.

## Results

Two independent attempts, same binary (built from the settled tree), same method,
run back to back. 24 enforced (tier, record) cells per attempt across the four workloads; 4 of 24
survived the first attempt, 5 of 24 survived the second. Every surviving row below names which
attempt it came from; every row that did not survive is listed in "Rows this machine could not
hold steady," with the reason, not omitted.

**The fixed cost, in milliseconds, never as a percentage.** `noop` (a binary that does nothing) went
from a 0.7 ms bare median to a 52.2 ms enforced median under `landlock`/`record: off` — a **51.5 ms**
fixed cost: cgroup creation, the Landlock ruleset, the seccomp filter install, opening the ledger,
once per run, before the workload's own syscalls enter into it at all. (Expressed as a percentage
this row is "+7027.8%," which is arithmetic, not information — the row exists to isolate the
constant, so the constant is what is reported.) Every other row's "Fixed cost" column below is this
same 51.5 ms figure, carried over from the one (tier, record) combination — `landlock`/`off` — where
the `noop` probe itself survived; the probe was noisy at every other (tier, record) pair in both
attempts, so the fixed-cost column is only filled in where it was actually measured, not assumed
constant across record modes.

**The headline row.** `npm` (`npm ci`, 79 packages, offline) under `landlock`/`record: off`, attempt
1: 745.5 ms bare → 817.0 ms enforced. Subtracting the 51.5 ms fixed cost leaves a **marginal cost of
2.7%** of the workload — the per-syscall cost of enforcement on an open-heavy install, separate from
the once-per-run setup. Total overhead for that row is 9.6%; attempt 2's independent re-measurement
of the same cell (no `noop` survived that attempt, so no fixed/marginal split) came back 780.1 ms →
828.9 ms, 6.3% total — a different sample, same shape, both single-digit-to-low-teens percent, not
the 361% the discarded pre-shuffle run reported.

| Workload | Tier | Record | Bare median | Enforced median | Fixed cost | Marginal cost | Total overhead | Runs/pass × passes | Attempt |
|---|---|---|---|---|---|---|---|---|---|
| noop | landlock | off | 0.7 ms (±0.1) | 52.2 ms (±5.2) | **51.5 ms — this row is the constant** | — | — | 20×2 | 1 |
| cpu | landlock | full | 306.2 ms (±5.3) | 362.2 ms (±6.8) | n/a (noop noisy at this cell) | n/a | +18.3% | 20×2 | 1 |
| cpu | landlock | full | 310.2 ms (±4.3) | 361.1 ms (±9.1) | n/a (noop noisy at this cell) | n/a | +16.4% | 20×2 | 2 |
| npm | landlock | off | 745.5 ms (±14.7) | 817.0 ms (±22.7) | 51.5 ms | **+2.7%** | +9.6% | 20×2 | 1 |
| npm | landlock | off | 780.1 ms (±23.6) | 828.9 ms (±22.4) | n/a (noop noisy at this cell) | n/a | +6.3% | 20×2 | 2 |
| npm | landlock | full | 780.1 ms (±23.6) | 870.9 ms (±34.8) | n/a | n/a | +11.6% | 20×2 | 2 |
| npm | observe | full | 745.5 ms (±14.7) | 796.7 ms (±15.8) | n/a | n/a | +6.9% | 20×2 | 1 |
| npm | observe | off | 780.1 ms (±23.6) | 794.6 ms (±13.6) | n/a | n/a | +1.9% | 20×2 | 2 |
| python | landlock | summary | 993.0 ms (±9.4) | 1117.9 ms (±59.7) | n/a | n/a | +12.6% | 20×2 | 2 |

**The two `observe` rows measured no recording at all, and need re-measuring.** When they were taken,
`--observe` installed no seccomp filter (the observe handle returned none, so the child
installed no listener and the runtime started no supervisor). Those runs paid for the launch, the
cgroup and the ledger, and for nothing per syscall. They stay in the table as measured, but they are
the cost of an unfiltered launch, not of observe mode, and their `full`/`off` difference (6.9%
against 1.9%) is two samples of the same unfiltered path: noise, not a record-mode effect. Observe
now installs tier 1's filter and runs the supervisor record-only (docs/p0/supervisor.md R30), so its
per-syscall cost should sit near `landlock`'s at the same record mode, less Landlock's own checks.
Neither `observe` figure should be quoted until `test/e2e/overhead/run.sh` has measured the rows again
on a build with that fix.

Two things worth noting in this small surviving set, both consistency checks the harness did not
have to pass and did:

- **`cpu`'s overhead is explained almost entirely by the fixed cost.** 51.5 ms fixed / ~308 ms bare
  ≈ 16.8%, and the two independent `cpu`/`landlock`/`full` measurements came back 18.3% and 16.4% —
  right at that predicted value, for a workload with no syscalls of interest beyond process start.
  That is the control working: a workload the tier should not touch shows overhead that is almost
  entirely the once-per-run setup cost, not a per-syscall one.
- **Wherever `full` and `off`/`summary` both survived for the same workload and tier, `full` came
  back higher**, the direction the seccomp filter and supervisor code predict ("record: off,
  investigated" below) and the opposite of what the discarded pre-shuffle run showed: `npm`/`landlock`
  11.6% (`full`) against 9.6% and 6.3% (`off`, two attempts). The `npm`/`observe` pair, 6.9% (`full`)
  against 1.9% (`off`), points the same way but is not evidence for it: those runs installed no filter
  (the note above), so record mode could not have changed what they did. Small sample, and one pair.

### Rows this machine could not hold steady

Of 24 enforced (tier, record) cells per attempt, 20 were marked `NOISY: passes disagree` in attempt
1 and 19 in attempt 2 — the two independently-shuffled passes' medians differed by more than their
combined spread, and per the harness's own rule that is reported as disagreement, not averaged into
a number. Every `noop` and `cpu` cell under `observe`, and every `record: full`/`summary` cell for
`noop`, and most of `python` in both attempts, fall in this set; the full list is in the raw results
(`test/e2e/overhead/run.sh --keep` retains `results.jsonl` and `cells.jsonl`). The reason is the one
named under "Machine" above: ~9 GiB resident and a fully-committed swap partition from an ordinary
desktop session is enough ambient variability that a 50 ms–1 s workload cannot be held steady across
two passes on the test machine, independent of how low the CPU load average reads. This is not a gap in
what was checked — it is what got checked, and it came back negative for reproducibility at this
box's current memory pressure.

`cgroup` and `bpflsm`: skipped entirely, all four workloads, both attempts — see "Machine" above for
why (root and, for `bpflsm`, a kernel command-line change this run could not make).

## record: off, investigated

The harness's first (discarded, pre-shuffle, single-pass) run showed `record: off` consistently
*slower* than `record: full` across all three workloads it measured that way — backwards from what
the mechanism should produce, and consistently so, which is what makes it worth answering directly
rather than waving off as noise.

**What the code actually does.** `internal/runtime/enforce/landlock/filter.go`'s `BuildFilter(arch,
full bool)` takes one boolean, and `internal/runtime/enforce/landlock/landlock.go` calls it with
`full := bd.rt.Record == agent.RecordFull` — so **`off` and `summary` compile to the exact same
seccomp filter**; only `full` differs, by additionally notifying on every `open`/`openat` regardless
of flags (`off`/`summary` notify only on a write-flagged open). At the kernel filter level, `off`
should never see *more* notifications than `summary`, and `full` should see the *most* of the
three, not the fewest.

At the notification-handling level (`internal/runtime/supervisor/fs.go`'s `emitFS`), `record: off`
does **not** take an early exit: `recordOpen`/`recordPath`/`recordRename`/`recordSymlink` all read
the syscall's path out of the target process's memory and continue the syscall *before* record mode
is ever consulted; `emitFS` then computes the advisory verdict (`c.fsVerdict`, a walk over the
compiled rule table) and only *after* that checks `!c.recording()` to decide whether to keep the
event or drop it. So `record: off` pays the same path-read and rule-walk cost as `summary` for every
notified syscall, and only skips constructing the ledger event at the very end — worth knowing
(a leaner "count-only" path for `off` is a real, if minor, opportunity), but it is symmetric with
`summary`, not with `full`, and it does not explain `off` costing *more* than `full`. (Exec handling
is the one place record mode changes real work earlier: `internal/runtime/supervisor/exec.go`'s
`recordExec` skips the extra identity reads when `!c.recording() && verdict == Allow`; that is a
cost `full`/`summary` pay and `off` does not, which — if anything — should make `off` cheaper still
on an exec-heavy workload.)

**Conclusion.** No slow path in `off` was found that would explain the observed ordering; every
code-level asymmetry found points the other way (`off` should be at or below `summary`, both at or
below `full`). The most likely explanation is ambient contention during that run: it measured
`full` first and `off` last for every workload, and machine load on the test machine drifted upward over
the run's several minutes (confirmed separately: unrelated `go test`/`golangci-lint` invocations and
another job were active on the test machine during parts of that run). That is precisely the
confound the shuffled, two-pass design above exists to catch, and the discarded run's table is not
published here for that reason.

**Demonstrated, not just asserted.** The two shuffled, two-pass attempts above are small evidence
for this rather than the full confirmation a clean matrix would give, but every pair of rows where
both a `full` and an `off`/`summary` measurement survived for the same workload and tier agrees with
the code-level prediction and disagrees with the discarded run: `npm`/`landlock` 11.6% (`full`)
against 9.6% and 6.3% (`off`). The `npm`/`observe` pair (6.9% against 1.9%) is left out of that
evidence: it was measured with no filter installed, so it says nothing about record modes. "A slow
path in `off`" stays ruled out as the mechanism; the discarded run's backwards ordering was contention.

## The activity stamp's cost on an open

A run with a `stall_after` has each allowed open, file operation and connect under `record: off` stamp its slot of
`tego_activity` (limits-check-doctor-cli.md R4). The record-off plan's budget for it is +25 ns an open on 6.17 and
+40 ns on 6.1. `TestActivityStampCost` (`internal/bpf`, root, KVM) measures what it adds to `tego_file_open`
itself, from the kernel's BPF run-time statistics (`kernel.bpf_stats_enabled`): a record: off run's row with the
flag against the same row without it, the two alternated over 9 rounds of 200,000 opens by a process of the run,
each read as its best round. The program's run time is where the stamp is, and the trampoline around it is the same
either way, so the difference carries none of an open loop's own noise; the rounds still move by about 10 ns with
the host's load, so a difference under that is no measurable cost. Over 25 ns (40 below 6.2) the test prints
`TARGET-MISS`; over 100 ns it fails.

| Kernel (KVM guest, 4 vCPUs) | Without the stamp | With it | Difference | Target |
|---|---|---|---|---|
| 6.17 (`lsm=...,bpf` boot), the clock read on every open (first build, withdrawn) | 68.0 ns | 92.8 ns | +24.8 ns | 25 ns |
| 6.17 (`lsm=...,bpf` boot) | 96.2 ns | 88.9 ns | -7.4 ns | 25 ns |
| 6.17 (default boot) | 82.0 ns | 86.3 ns | +4.2 ns | 25 ns |
| 6.1 (`al2023`) | 123.9 ns | 128.7 ns | +4.8 ns | 40 ns |
| 5.14 (`rhel-9`) | 109.5 ns | 108.2 ns | -1.3 ns | 40 ns |
| 6.8 (`ubuntu-24.04`) | 108.0 ns | 117.4 ns | +9.4 ns | 25 ns |
| 6.12 (`debian-13`) | 105.9 ns | 104.4 ns | -1.5 ns | 25 ns |
| 6.12 (`al2023-6.12`) | 85.5 ns | 96.3 ns | +10.8 ns | 25 ns |
| 7.0 (`fedora-7.0`) | 60.9 ns | 62.4 ns | +1.4 ns | 25 ns |
| 7.2 (`fedora-7.2`) | 48.6 ns | 47.2 ns | -1.4 ns | 25 ns |

The first build read `bpf_ktime_get_ns` on every call to decide whether 10 ms had passed, and met the 6.17 target by
0.2 ns: under kvm-clock the clock read is nearly all of it. The stamp now reads the jiffies (`bpf_jiffies64`, a load)
and returns when the slot already names the current jiffy, so the clock is read and the slot stored once a jiffy;
what an open pays is a test of a byte already loaded, an inlined array lookup, the jiffies load and a compare: at or
near the rig's resolution of about 10 ns on every matrix row (the largest, +10.8 ns on AL2023's 6.12, is under half
its 25 ns target), and inside each row's target.

## The activity stamp's cost on a TLS call and on a start

A `record: off` run with a `stall_after` and `capture: uprobe` has the shared TLS probes placed for its stall check
alone (capture-derive R4, activity-only), and each of its TLS calls that moves bytes stamps its slot of
`tego_activity`. The record-off plan prices that twice: a run process's TLS call may cost at most +50 ns over the
shared probe's trap, and placing the probes may add at most a median 30 ms to such a run's start where the kernel has
`uprobe_multi` (6.6 and later, RHEL 9's 5.14) and 150 ms on 6.1, whose probes are one perf event each. Both tests are
in `internal/runtime/capture/uprobe` (root, KVM) and print `TARGET-MISS` over the target.

`TestIntegrationRecordOffTLSCallCost` reads the probe programs' own run time from the kernel's BPF run-time
statistics, per TLS call of a CPython client making 3,000 16-byte echo round trips over one connection through the
host's libssl, with three rows alternated over 9 rounds and each read as its best round: the run's row with
`RunActivity`, the same row without it, and no row, a process outside every run, whose call pays the shared probe's
trap and the run-set miss (ADR 0026 (9)). It fails past 500 ns a call, and when the flagged rounds stamp nothing.

| Kernel (KVM guest, 4 vCPUs) | Probes | With the stamp | Without it | Outside every run | Over the shared probe | Target |
|---|---|---|---|---|---|---|
| 6.17 (`lsm=...,bpf` boot) | multi | 215.1 ns | 195.0 ns | 181.1 ns | +33.9 ns | 50 ns |
| 6.17 (default boot) | multi | 231.0 ns | 218.6 ns | 221.4 ns | +9.6 ns | 50 ns |
| 6.17 (`lsm=...,bpf` boot), a second run | multi | 267.6 ns | 243.1 ns | 207.9 ns | +59.8 ns (`TARGET-MISS`) | 50 ns |
| 6.17 (default boot), a second run | multi | 212.4 ns | 197.7 ns | 180.1 ns | +32.2 ns | 50 ns |
| 6.8 (`ubuntu-24.04`, `lsm=...,bpf`) | multi | 244.7 ns | 217.6 ns | 210.4 ns | +34.3 ns | 50 ns |
| 6.8 (`ubuntu-24.04`, default) | multi | 188.2 ns | 189.7 ns | 162.2 ns | +26.0 ns | 50 ns |
| 5.14 (`rhel-9`, `lsm=...,bpf`) | multi | 198.7 ns | 197.6 ns | 168.4 ns | +30.3 ns | 50 ns |
| 5.14 (`rhel-9`, default) | multi | 200.5 ns | 201.4 ns | 179.3 ns | +21.1 ns | 50 ns |
| 6.1 (`al2023`, `lsm=...,bpf`) | individual | 150.2 ns | 158.0 ns | 154.7 ns | -4.5 ns | 50 ns |
| 6.1 (`al2023`, default) | individual | 137.1 ns | 136.7 ns | 116.5 ns | +20.6 ns | 50 ns |

Every row but one is inside its target: the second run on 6.17's `lsm=...,bpf` boot measured +59.8 ns and printed
`TARGET-MISS`, where the first measured +33.9 ns; the process outside every run moved by 27 ns between the two runs, so
the rows carry the host's load, and the target is kept. The stamp's own share, the flagged row over the unflagged
one, is -8 to +27 ns: a test of a byte the program has loaded, an array lookup, a jiffies load and a compare, and once
a jiffy a clock read and two stores; the rest of "over the shared probe" is the run-set hit and the record-mode test
every run's call already paid before the stamp existed.

`TestIntegrationRecordOffActivityStartCost` times the uprobe source's `Start` for a `record: off` run with a stall
budget, which loads the capture object and places the probes, against the same run without one, which places none,
each round from no probe at all (the previous holder's detach has run: the cold start a solo run pays), the two kinds
alternated over 7 rounds; it fails past the pre-attach budget (1 s), which bounds what `Start` may spend placing.

| Kernel (KVM guest, 4 vCPUs) | Probes | With a stall budget | Without | Added (median) | Of it, the object's load | Target |
|---|---|---|---|---|---|---|
| 6.17 (`lsm=...,bpf` boot) | multi | 59.2 ms | 0.4 ms | 58.8 ms (`TARGET-MISS`) | 44.2 ms | 30 ms |
| 6.17 (default boot) | multi | 56.3 ms | 0.4 ms | 55.9 ms (`TARGET-MISS`) | 38.0 ms | 30 ms |
| 6.17 (`lsm=...,bpf` boot), a second run | multi | 69.9 ms | 0.5 ms | 69.4 ms (`TARGET-MISS`) | 47.8 ms | 30 ms |
| 6.17 (default boot), a second run | multi | 42.2 ms | 0.1 ms | 42.1 ms (`TARGET-MISS`) | 30.7 ms | 30 ms |
| 6.8 (`ubuntu-24.04`, `lsm=...,bpf`) | multi | 81.5 ms | 0.7 ms | 80.8 ms (`TARGET-MISS`) | 65.6 ms | 30 ms |
| 6.8 (`ubuntu-24.04`, default) | multi | 51.3 ms | 2.1 ms | 49.2 ms (`TARGET-MISS`) | 37.6 ms | 30 ms |
| 5.14 (`rhel-9`, `lsm=...,bpf`) | multi | 40.9 ms | 0.5 ms | 40.5 ms (`TARGET-MISS`) | 31.7 ms | 30 ms |
| 5.14 (`rhel-9`, default) | multi | 48.3 ms | 0.4 ms | 47.9 ms (`TARGET-MISS`) | 37.4 ms | 30 ms |
| 6.1 (`al2023`, `lsm=...,bpf`) | individual | 32.8 ms | 0.6 ms | 32.2 ms | 23.0 ms | 150 ms |
| 6.1 (`al2023`, default) | individual | 64.0 ms | 0.1 ms | 63.9 ms | 30.7 ms | 150 ms |

The 6.1 rows are inside their target; every `uprobe_multi` row misses its 30 ms by 10 to 51 ms, and the target is
kept, not raised. The placing itself (pre-attach of the host's libssl, one multi link a library) is 9 to 22 ms of it:
the rest is the capture object's cold load, the verifier's work on `uprobe_ssl`, which a `record: summary` run with
`capture: uprobe` pays at its `Start` in the same way, before this package as after it. The stamp did not add it, and
the activity-only source cannot skip it, since the probes it places are the ones every run of the build shares
(ADR 0026 (7)). No change here cuts it: on a `uprobe_multi` kernel the object loads the individual programs beside
the two multi dispatchers, which call them, so that a library whose multi attach fails can fall back (ADR 0026
(8)); loading those only on a fallback would cut the verifier's work by an amount not measured here, and is a change
to the shared attach path the stamp does not need (GAPS C35). Until then a stall-bounded `record: off` run's start costs what a capturing run's does.

## Telling tego of every read open for the reason channel (2026-10-25)

`reason.reads: on` has tier 1's seccomp filter notify every read open so that one the Landlock ruleset refuses gets
its line (ADR 0077). ADR 0077 set the rule for its default before measuring: `auto` means on only if the median adds
at most 25 µs an open and the offline Claude Code workload grows at most 5 %. `test/bench/read-notify/run.sh` (no
root; `opens`, `claude` or both) measures both under `record: summary` at tier landlock, `on` against `off`,
alternated: `opens` runs the opener, `test/workloads/read-opener` (20,000 opens of one file, pinned to CPU 1, its own median and p99) under
`tego run` with tego and its supervisor confined to CPUs 0-3, 20 times each; `claude` runs the interactive-claude
contract of `test/poc/interactive-claude` as `claude -p` against the model stand-in, one Bash tool call reading
2,000 small files with the shell's `read` builtin, and takes the median wall time. Each run records the 1-minute load
first; one started at load 2 or above is labelled `LOADED` and the script exits 3. Over the rule it prints
`TARGET-MISS` with its number.

| Run (16-CPU host, 6.17) | Load (1 min) | Per open, on | Per open, off | Added | Workload, on / off | Change |
|---|---|---|---|---|---|---|
| loaded1 | 3.3-4.2, `LOADED` | 21.2 µs (p99 72.2) | 2.0 µs (p99 4.3) | 19.2 µs | 990 / 687 ms | +44.1 % (`TARGET-MISS`) |
| quiet1 | 2.7-8.4, `LOADED` | 28.4 µs (p99 70.7) | 2.7 µs (p99 4.8) | 25.6 µs (`TARGET-MISS`) | 1,573 / 1,231 ms | +27.7 % (`TARGET-MISS`) |
| **quiet2**, the measurement | 1.64-1.83 | 19.2 µs (p99 59.7) | 2.0 µs (p99 3.3) | 17.2 µs | 804 / 674 ms | +19.3 % (`TARGET-MISS`) |

quiet2 ran with every repeat at load below 2 and is the measurement; the loaded runs measured more. The per-open
cost is inside its 25 µs, but the workload misses by far: Claude Code and its tool open about 2,700 files more than
the `off` run is told of, each now a round trip through the supervisor, and a model stand-in that answers at once
leaves nothing to hide them behind. So `auto` means off (ADR 0077), and compile's `reason-reads-off` line states
quiet2's figures (`agent.ReasonReadCost`, `agent.ReasonReadWorkload`). The targets stay; a faster notification
path that kept the workload within 5 % would move the default, not a relaxed target.

## A gap beyond "needs root" (closed since)

When these rows were measured, `internal/cli/run.go`'s `probeTiers` (the function `tego run` used to
decide what `--tier` may select) only ever populated `backend.TierLandlock` in the availability map it
built; it never read the doctor probe's `cgroup`/`programs`/`fanotify` results. `tego doctor --json`
on the test machine already reported `"tiers":{"landlock":true,"cgroup":false,"bpflsm":false}` with per-tier
reasons, but `tego run --tier cgroup` could not succeed whatever the privilege, and the comment above
`probeTiers` deferred the full derivation. That function no longer exists: `tego run` now
selects from the derivation `tego doctor` reports (`probeMachine`, which calls `doctor.Run` and uses
`Report.Probe`), so a tier doctor offers is a tier `--tier` may select. What tier 2 needs on a machine
is now what doctor lists: root, a build with the BPF objects (`enforce.Buildable`), and a kernel on
which D7 loads and attaches every tier-2 program. Earlier on 2026-09-22, in the KVM guest on the test machine's
6.17 kernel, D7 found the verifier refusing `cgroup/connect6` and `cgroup/sendmsg6`, so doctor, and
therefore `run`, did not offer tier cgroup there; that was measured before the `cgroup_net` fix to those two
programs. With the fix in the objects of this tree, `sudo tego doctor` in the same guest loads and attaches
all 22 hooks (the 16 tier-2 programs, and tier 3's six with a stand-in), reports `tier: cgroup`, and
`--require cgroup` exits 0.

## A workload-compatibility finding

`test/workloads/build/python`'s contract grants `fs.write` on `/dev/null` alongside its two real
output directories. Without that rule, every enforced run of the python workload failed with a
pytest `INTERNALERROR`: `_pytest/logging.py`'s `LoggingPlugin.__init__` unconditionally opens a
`FileHandler` on `os.devnull` when no `log_file` option is set, and Landlock's default-deny write
policy refuses that `openat` like any other write outside the declared directories — the bare run
never notices because `/dev/null` is world-writable at the Unix permission level, which Landlock's
ruleset sits above. This is not a benchmark artifact: any contract that runs pytest under the
Landlock tier needs this rule (or `log_file` pinned to something real), and it is exactly the kind
of thing this benchmark exists to surface before a user hits it. This is independent of the noisy
rows above: a reproducible run failure without the rule, not a timing question.

## Reproducing

```
make overhead                    # builds tego, primes the caches if needed, runs the shuffled matrix
test/e2e/kt3-overhead.sh --help  # --passes, --seed, --warmup, --runs, --cache, --work, --tego, --out
```

Run the whole thing twice back to back and diff the tables before trusting a number this harness
produces on a machine you do not know to be quiet: `bench.py render`'s "NOISY" rows are the harness
saying so itself, but a table with zero noisy rows on a loaded box is still worth a second look.

## Timing budgets in the test suites (2026-10-16, revised 2026-10-17)

A few tests hold code to an absolute figure with a Limit, most with a Target too, written as figures on the
reference host (the i7-10870H, 8 cores and 16 threads, that every one of them was measured on): ADR 0048 C8's per-exec
costs (`TestExecCommandCostBudget`, `TestExecCommandIndexCostBudget`), enforce-plane §10's plan at 1000 rows
(`TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows`), the datagram flood cell (`TestIntegrationUDPFlood`: the
target at most a tenth behind its 10 s schedule, a notification held under R22's 200 µs on average), and ADR 0023
P1's pin of Borrow at most 2.5 times two atomic adds (`TestBorrowCostRatio`), a ratio to a fixed workload, which a
busy machine moves as it moves a duration (below). The read of a 55k-line run from disk under 150 ms
(`TestInForceLongRunIsFast`, the Rules page's refresh) joined them on 2026-10-28, after it read 213 and 228 ms beside
the integration suites (70 ms alone). The line page's warm render of one line of a 12,000-line run under 25 ms
(`TestLinePageRenderBudget`, EVENT-PAGE) joined them on 2026-11-06, after CI's race job read 26.9 ms beside three other
packages' tests (0.9 to 2.2 ms on the reference box, 8.3 to 11 ms there under the race detector, which makes it about
seven times slower); under `-race` it renders and checks the page but judges no time. On 2026-10-16 the full gate
failed `TestExecCommandCostBudget` at +12.247 µs against its +12 µs limit while other jobs loaded the host; alone it
passed. Those budgets are now
asserted, exactly as written, only where the machine is quiet, and every other run holds the same measurements to a
ceiling ten times the Limit, on the measuring thread's own time where the cost is the calling goroutine's, with their
wall clock held to a hundred times it (`internal/testutil/timing.go`).

**What a busy machine does to a figure.** Each C8 figure was already the fastest of hundreds of interleaved A/B
rounds, and a preemption only ever adds to a sample, so the fastest sample escapes it. What it does not escape is a
lower all-core clock and a busy sibling hyperthread, which last through the whole measurement. Under 16 busy loops
(`bash -c 'while :; do :; done'`) on the reference host, the C8 cases took 2.3 to 4.9 times their quiet figures (3.4 to
3.9 at the medians of 20 runs) even in the handling thread's own CPU time (`CLOCK_THREAD_CPUTIME_ID`, which leaves out
every wait), up to 2.2 times their Limits (the unguarded case +15.4 to +26.1 µs of CPU time against +12); the
wall-clock fastest-of-N read the same, but for the 8192-argument case, whose 3 ms samples span scheduler slices: 3.2
times its Limit by the wall clock and 1.8 times in CPU time. With nothing but other work on the host (load
average 6 to 8), the unmodified C8 cases missed their wall-clock Limits in 3 runs of 12 (the unguarded case up to
+20.6 µs) and the index in 1 of 12 (1.44 µs against 1 µs). No statistic over samples taken on such a machine recovers
the reference host's figure.

An earlier design measured the machine instead: a fixed yardstick workload
probed beside or around the code, and each figure divided by the machine's slowdown against the reference host. It loosened the limits twice. Probed beside the code, the code under test slowed the yardstick (by up to 2.6
times beside the flood), so slower code loosened its own judgement; referenced to the host's fastest moment, the box as
found already read 1.1 to 1.5 times, so copies slowed to +12.5 to +15 µs passed the +12 µs limit. Fixed, it still
failed `TestExecCommandCostBudget` in 15 runs of 28 under the busy loops: the code's own sensitivity to a busy core is
not any yardstick's, and in a second mode the with-rules path slowed to +56 to +75 µs at the same probe readings. A
yardstick models the machine, and the code under test is not the model.

**Where each budget is asserted.**

- **Budget mode** (`TEGO_TIMING_BUDGETS=1`): the figure as its spec defines it, on the wall clock, against its Limit
  (over it fails) and Target (over it prints `TARGET-MISS`), by the same statistic as before: C8's exec cases the
  fastest of 400, 200 or 30 interleaved A/B rounds (the side that goes first now alternates), the index the median of
  seven 100 ms `testing.Benchmark` runs, the plan one plan, the flood its own pace and mean hold, Borrow's ratio the
  medians of five 100 ms `testing.Benchmark` runs of each side. Nothing divides, retries or widens a figure.
  `scripts/timing-budgets.sh` builds the tests and runs them this way, and fails when a budget test fails, is skipped,
  reports no PASS or never ran in budget mode. CI's bench-gate job runs it first, on its own runner with nothing else
  running, before the gate's builds and rounds, for every push and pull request (a new branch included), with
  `--hosted` (below); its findings go to the job summary, and a missed budget fails the job after the gate has run. On
  a developer's machine `make budgets` runs it; it is only meaningful with the machine otherwise idle, and prints the
  load average it started at. Any value of the variable other than `1`, `hosted` or unset fails the test, so a
  misspelled switch cannot leave a budget run holding only the ceilings. The script names its tests, and
  `TestTimingBudgetsListsEveryBudgetTest` (internal/testutil,
  every unit run) holds that list to the tree: it parses every `_test.go` file `./...` reaches and fails when a test
  that calls `testutil.TimingMode` is not listed, a listed test does not call it, a test is listed under build tags its
  file does not build with, `TimingMode` is called outside a test function, or a `testutil.Mode` is built by hand. A
  budget test left off the list would be held only to its ceiling everywhere.
- **Budget mode on a hosted CI runner** (`TEGO_TIMING_BUDGETS=hosted`, `scripts/timing-budgets.sh --hosted`;
  *2026-11-02*): every budget as written, but one whose cost is a handful of system calls and whose Limit the runner's
  figures missed (`testutil.Budget.SystemCalls`: C8's unguarded exec and its `#!/bin/sh` script) is held to
  `testutil.HostedSystemCallFactor` (2) times its Target and Limit, and its lines name the reference figure beside the
  scaled one. A quiet runner is still another machine than the reference box. GitHub's ubuntu-24.04 runner (an Azure
  VM, AMD EPYC 7763 or 9V74, kernel 7.0) made an open and a close (`BenchmarkOwnedOpenClose`, in the same bench-gate
  jobs) in 2.80 and 3.32 µs against the box's 1.13 µs, while it computes at about the box's speed (the index over 512
  patterns 499 and 513 ns against 476 to 499 ns; `TestBorrowCostRatio` 2.07 against 1.6 to 1.9). C8's cases that add
  system calls read 0.9 to 2.3 times their figures on the box there (the unguarded exec +11.5 and +13.7 µs against
  +6.9 µs, the script +35.1 and +30.3 µs against +15.6 to +16.4 µs, 16 arguments +18.0 and +19.9 µs against +10.8 to
  +11.8 µs, the floor's refusal at 8 arguments +11.5 and +13.7 µs against +8.5 to +12.4 µs), and the cases that copy
  and match argv 0.7 to 1.7 times. Held as written there, the unguarded and script cases missed their Limits on 2 of 10
  pushes to main (+13.7 µs against +12, +35.1 and +30.3 µs against +30), and the code was not slower: this tree's test
  and the one of 2026-10-17, run in turn ten times each on one host (at load average 16), read within 2 µs of each
  other in the three cases both have that add system calls. Twice keeps those two Limits 1.7 to 2.1 times the runner's
  own figures, where the box's are 1.7 to 1.9 times its figures, so a regression that makes either case cost more than
  that many times what it does fails on the runner as on the box; a smaller one, such as the 8,000-round copy (+7 µs,
  1.5 to 1.6 times the unguarded case there), passes budget mode on the runner and fails the job's comparison with
  the base (below). The 16-argument case and the floor's refusal at 8 arguments add the same reads but met their
  Limits on the runner with room (+30 and +20 µs, 1.46 to 1.75 times their runner figures), so they stay as written
  there: nothing showed those Limits wrong for it. Rejected: raising the two Limits for every machine (the box would
  then pass a regression twice the size); judging them on the runner against a yardstick of system calls measured
  beside them (the 2026-10-17 rejection of yardsticks holds); holding them on the runner only to the unit gate's ten
  Limits; scaling every case that adds system calls (two of them were never short of their Limits there); and cutting
  the with-rules path's system calls (the head's reopen, `fstat`, `fstatfs`, `pread` and `close` and argv's reads are
  each a check ADR 0048 (3) needs, and one fewer saves a fraction of a microsecond of a doubled cost).
- **The unit gate** (precommit, CI's test jobs, any `go test`): the same measurement, held to `testutil.CeilingFactor`
  (10) times the Limit, and where that figure is the thread's own time, its wall clock to `testutil.WallCeilingFactor`
  (100) times it. No `TARGET-MISS` is printed there, since its figure is not the one a Target is written in; its log
  line names the Limit and the switch that asserts it, and prints every figure of the measurement. A failure there
  means the code does or waits several times what its budget allows, whatever else the machine runs, but for the
  flood's pace, a pipeline's wall clock whose margin is the machine's (below).
  - Where the cost is the calling goroutine's (the C8 exec cases, the index, the plan, Borrow and the adds), the figure
    is the measuring thread's **own time** (`testutil.MinOfThread`, `Figure.Own`), the fastest of the same rounds (the
    plan the fastest of five, Borrow and the adds of 2000 interleaved batches). A sample's own time is its wall clock
    less the thread's run-queue delay over the sample, the second figure of `/proc/thread-self/schedstat`, which the
    kernel adds each time the thread gets a CPU back, beyond the CPU time the process's other threads had over the
    sample (`CLOCK_PROCESS_CPUTIME_ID` less the thread's own, read around it); the delay is read inside the wall-clock
    interval, so only waits inside it come out. That leaves out every wait for a CPU another process makes, which
    nothing bounds on a machine with more runnable threads than CPUs, and keeps the code's work, slowed only by the
    clock and the sibling hyperthread, which the hardware bounds (up to 4.9 times the quiet figure above, 2.2 times the
    Limit), and the work it hands to the process's other threads.
  - The other threads' CPU time stays in because a wait for work handed to another goroutine can be all run-queue delay
    (2026-10-17). Where the process has fewer CPUs than runnable threads (a cpuset, a 1 to 2 vCPU
    container, the busy-loop guest), even on an idle machine, the helper's wake-up takes the CPU from the waiting thread
    before it parks; the thread waits in the run queue for the helper's whole run, and its later futex sleep returns at
    once, so it never blocks. With the run-queue delay taken out whole, a wait for 500 µs of a helper's work read 3.7 µs
    of own time in a process held to one CPU and passed a 12 µs Limit's 120 µs ceiling, and the C8 copy that hands 500
    µs of work off in every command-rule decision passed the unit gate beside one busy loop on its CPU (+26 µs of own
    time). With the other threads' CPU time kept, the first reads 505 to 507 µs (with one P and with four, 3 runs of 3;
    `TestAHandOffShowsInTheOwnTime`) and the C8 copy +524 µs, failing its 120 µs ceiling, as it does on a free machine
    (+526 µs). On a machine whose other threads of the process run on another CPU at once, the kept time was no wait of
    the thread's, and keeping it is stricter, never looser (the own time is never over the wall clock); the clocks'
    reads add under a microsecond to it (0.8 µs on the reference host). A work that another thread of the process is
    still doing on another CPU when the sample ends counts up to the kernel's last update of that thread's time, its
    last tick (1 ms at `CONFIG_HZ=1000`) or switch.
  - A sample in which the thread **blocked** (a voluntary context switch, `getrusage(RUSAGE_THREAD)`'s `ru_nvcsw` moved:
    a sleep, a lock, a read that waits, a reply from another thread) counts whole on the wall clock, its waits for a CPU
    included. Its wait is the code's, and taking the run-queue delay out of it would let part of that wait hide: a
    thread woken during a sleep (a signal, a runtime wake-up) waits for a CPU and sleeps again, so the delay overlaps
    the sleep, and the fastest of many samples is the one where the most of it did. Measured: a copy of C8's path that
    slept 2 ms in every command-rule decision read +1.30 ms of own time with the delay taken out of every sample (load
    average 16), and reads +2.13 ms with blocked samples counted whole. The Go runtime's own preemption of a goroutine
    that has run for 10 ms parks a locked thread too, so a sample that long counts whole as well; the unmodified C8 path
    blocked in 1 or 2 of its 400 to 800 samples (both sides) at the cases of 8 to 128 arguments and in 9 to 11 of 60 at
    the 8192-argument cases, at load average 17, and the fastest of the rest is the figure (the log line counts them).
  - A wait can still hide whole in the own time where another process's work fills it and the thread never blocks,
    which takes another process wanting the thread's CPU, a busy machine: a thread another process's thread takes the
    CPU from just as its goroutine parks is still in the run queue when the wait ends, so it never blocks, and the
    whole wait is run-queue delay; and a wait that yields its CPU (`sched_yield`) instead of sleeping never blocks, so
    on a CPU another process keeps busy it is all run-queue delay too (the C8 copy that yields for 1 ms in every
    command-rule decision read +27.9 µs of own time and +1.04 ms of wall clock beside one busy loop on its CPU, and
    passed; on a free machine it spins, and fails at +958 µs). On a CPU
    shared with a spinning thread a 2 ms sleep before 4 ms of work read 4.02 ms of own time and 21.6 ms of wall clock,
    unblocked, in one of 24 runs of the testutil suite in the busy-loop guest, and in another a 5 ms sleep read 24.8 µs
    of own time in one sample of three; in the C8 copy that sleeps 2 ms in every command-rule decision, run under the
    busy loops, the 128-argument case read +308 µs of own time and +2.14 ms of wall clock in one run of four (the
    other cases read the sleep whole, +2.08 to +2.18 ms). So the unit gate holds the same measurement's **wall
    clock** as well, to `testutil.WallCeilingFactor` (100) times the Limit: the wall clock never hides a wait, and its
    fastest sample is the one the machine delayed least, which no run under the busy loops brought near a hundred
    Limits (the worst in the 2026-10-17 sweeps was 6.1 times its Limit, the 8192-argument cases', whose samples of
    milliseconds span scheduler slices; every other case's stayed under 2.3 times). Any wait of more
    than a hundred times a budget fails there on any machine; work, work handed to other goroutines, and every wait
    that no other process fills fail at ten times it in the own time. A wait between ten and a hundred Limits that
    another process fills without the thread blocking only budget mode sees.
  - Where the run-queue delay or the context switches cannot be read (no `CONFIG_SCHED_INFO`, a sandbox's `/proc`),
    every sample counts on the wall clock: stricter, never looser, and the log line says so.
  - The flood's pace and hold are a pipeline across the target, the kernel and the loop's workers, and no one
    thread's own time is either, so the unit gate holds them on the wall clock to 110 s and 2 ms; under 16 busy loops
    on the reference host they read 15 s and 120 to 130 µs, and in a 4-vCPU KVM guest with 16 busy loops 12 to 88 s and
    67 to 589 µs over three sweeps of 28 runs (the guest's four CPUs cannot keep 10,000 datagrams a second beside them,
    whatever the loop costs). The pace is the one unit-gate figure whose margin is the machine's: a pipeline across two
    processes and the kernel has no one thread's own time, so a machine that gives it about a tenth of the CPU it needs
    reaches the 110 s ceiling with no regression at all. The guest's worst, 88 s with a mean hold of 589 µs, came in one
    run of 84, at four runnable loops a vCPU while other work loaded the host too; at one loop a CPU, on the reference
    box, the flood took 15 s. Holding the pace on run-queue waits taken out would need the loop's workers' own threads,
    and the loop does not lock them (a sum over every thread of both processes takes out waits off the pipeline's path
    too, an idle goroutine's spinning thread among them, and so loosens the bound by an amount nothing caps). The
    harness lets the flood's target run for 170 s, the pace's ceiling and its own 60 s, and judges a target still
    sending when it is killed on the time it had run, so a flood too slow for its ceiling fails on the pace budget's
    message (supervisor.md's 2026-10-17 entry); with the harness's plain 60 s a flood slower than that failed only on
    the report the kill cut off. The test process's CPU time per datagram was rejected as the flood's measure: it read
    67 to 70 µs with the host as found and 77 µs under the loops, mostly the Go scheduler's own polling, so it measures
    the runtime, not the loop. **Open** (2026-10-17): the flood's unit-gate pace is not robust by
    construction. Its measured margin is 80% (88 s against 110 s), and a host oversubscribed past four runnable loops a
    vCPU can fail it with no regression. The figure that would leave the machine out is the loop's workers' summed own
    time per notification, held to ten times a per-notification limit that follows from the pace's schedule, with the
    110 s wall clock kept as the gross check; it needs the loop to lock its workers to their threads while the test
    runs, which it does not do today. Until then precommit and CI's build-test run the flood with this margin, and the
    11 s Limit is unchanged.

**Why the own time and the wall clock, and not one clock.** The first version of this design held CPU time alone in
the unit gate. It was first blind to a regression that waits, at any size: a copy that slept 2 ms in every
command-rule decision read +43 to +57 µs of CPU time (the sleep's own system calls) against the 120 µs ceiling and
passed, and one that slept 20 ms passed too. The wall clock alone sees that wait, but it also counts every wait for a
CPU, and on a machine with more runnable threads than CPUs a sample longer than a scheduler slice waits on every run:
one C8 run in a 4-vCPU KVM guest with 16 busy loops (an earlier build, 2026-10-17) read +7.33 ms of
wall clock for the bound-refused case whose own time was +2.02 ms, and the plan read 24.6 ms of wall clock for 6.1 ms
of its own (`TestOwnTimeLeavesOutRunQueueWaits`: 4 ms of work on one CPU beside a spinning process reads 5.8 to 8.0
ms of wall clock and 4.01 to 4.24 ms of own time). The own time at ten Limits holds the code's work, the work it hands
off and the waits it makes wherever another process's work does not fill them; the wall clock at a hundred Limits
holds every wait it makes, a hidden one included, and no run queue the sweeps saw came near it
(`TestASampleThatBlocksCountsWhole`, `TestAHandOffShowsInTheOwnTime`, `TestTheUnitGateSeesTheWaitsCPUTimeLeavesOut`).

Ten Limits: the worst C8 figure under the busy loops was 2.2 times its Limit in CPU time on the reference host and 2.3
times in own time in the guest, and a second, slower mode 6.3 times on the wall clock, so ten stays clear of them.
A smaller factor would fail a loaded machine, a larger one would let more through; neither changes a budget, which
budget mode holds as written. A hundred Limits on the wall clock is the same reasoning for a clock with no bound of its
own: sixteen times past the worst fastest wall-clock sample measured under the busy loops, and under the 167 times a
Limit that a 2 ms sleep is in the unguarded case.

**A ratio to a fixed workload is a budget too.** `TestBorrowCostRatio` divides Borrow's cost by two atomic adds',
measured in the same process, and its header said the ratio travels between machines. Between quiet ones it does
(1.6 to 1.9); a busy one does not slow Borrow as it slows the atomic adds: under the busy loops, with two test streams
beside them (load average 27 to 35), the ratio read 2.47 to 2.50 against P1's 2.5, by P1's own method and by the
interleaved least CPU time alike, and failed one run. The two atomic adds are a yardstick, and the first attempt's
finding holds for it. So the pin is held as the durations are: in budget mode as P1 writes it (the median of five
`testing.Benchmark` runs of each), against 2.5 (`Mode.JudgeRatio`); in the unit gate as the ratio of the two sides'
own times, the fastest of 2000 interleaved batches of 1000 calls of each, against 25, and of their wall clocks
against 250. `TestBorrowAllocatesNothing` and bench-gate's comparison of `BenchmarkBorrow` with the base still hold the
lease in every CI run.

**Relative bounds** need neither mode: both sides are the same code, and slow alike. Each scaling test ("cost does not
grow with the entries") now interleaves its two sides, the side that goes first alternating, and takes each side's least
thread CPU time over its samples (`testutil.MinOf`), where before each side was measured in turn on the wall clock.
pkg/spec's three scaling tests, whose samples are tens of milliseconds, read the process's CPU time (`getrusage`),
interleaved, written out there because pkg/ imports nothing under internal/. Every bound is unchanged. CPU time is right
for these and the own time is not needed: a relative bound holds how the work grows with the input, and a wait the same
on both sides moves neither side's work, on any clock; the wall clock was rejected for them because a sample of tens of
milliseconds waits for a CPU on an oversubscribed machine however many rounds run (one decode run reached the ×80 bound
by wall clock, two merge runs failed). What CPU time gives up is a wait that grows with the input, which these bounds no
longer see: each was written against work that grows (a scan where an index belongs, a check that resolves every rule
again, as their headers say), and the code the internal ones time waits on nothing, lookups in tables held in memory.
The own time was rejected for them too: their samples run for milliseconds, and on a machine with several runnable
threads a CPU a sample that long can pass the Go runtime's 10 ms of wall clock and be preempted, which parks the locked
thread and counts the sample whole, run-queue waits and all (the 8192-argument C8 cases, 1 to 2 ms of work, blocked in 7
to 21 of their 60 samples under the busy loops). `MinOf` takes the clock's own cost out of every figure, the fastest of
an empty sample taken in each round the way the others are and of 64 before them: a thread CPU clock read is a system
call, 0.5 to 0.7 µs on the busy box, and left in it reads a ratio closer to 1 than the code's own. `MinOfThread` does
the same for each of its figures.

| Test | Before | Now |
|---|---|---|
| `TestExecCommandCostBudget` | A/B interleaved, fastest of N, wall clock; `added > limit` failed | budget mode: the same, the first side alternating; unit gate: the same rounds' own time against 10 × the Limit, their wall clock against 100 × |
| `TestExecCommandIndexCostBudget` | median of 7 `testing.Benchmark` runs of 100 ms | budget mode: the same; unit gate: the fastest own time of 1000 batches of 256 decisions against 10 µs, their wall clock against 100 µs |
| `TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows` | one plan, wall clock | budget mode: the same; unit gate: the fastest own time of five plans against 2 s, their wall clock against 20 s |
| `TestIntegrationUDPFlood` | pace and mean hold, wall clock | budget mode: the same; unit gate: the same figures against 110 s and 2 ms, the target killed no earlier than 170 s; the count, line and refusal checks in both |
| `TestBorrowCostRatio` | median of 5 `testing.Benchmark` runs of each side, one side after the other, against 2.5 | budget mode: the same; unit gate: the ratio of the fastest own times of 2000 interleaved batches of 1000 calls of each side against 25, of their wall clocks against 250 |
| `TestInForceLongRunIsFast` (the Rules page, added 2026-10-27) | fastest of three reads of a 55k-line run, wall clock, against 150 ms | budget mode: the same; unit gate: the fastest own time of five reads against 1.5 s, their wall clock against 15 s |
| `TestAdvisoryCostDoesNotGrowWithEntries`, `TestFSIndexCostDoesNotGrowWithEntries`, `TestDenyReadMoveTargetCostDoesNotGrowWithEntries`, `TestDenyWriteTargetCostDoesNotGrowWithEntries` | best of 5, small table then large | the least thread CPU time of 20, interleaved |
| `TestMatchFSCostDoesNotGrowWithEntries`, `TestMatchExecCostDoesNotGrowWithEntries` | best of 3, small then large | the least thread CPU time of 10, interleaved |
| `TestDecideOpenCostDoesNotGrowWithEntries` | best of 9, small then large | the least thread CPU time of 9, interleaved |
| `TestDecodeScalesLinearlyInKeys` | best wall time of 9, small then large | the least process CPU time of 9, interleaved |
| `TestInterpreterCheckCostIsLinear` | best wall time of 3, small then large | the least process CPU time of 3, interleaved |
| `TestExtendsMergeCostIsLinear` | best wall time of 3, small then large | the least process CPU time of 5, interleaved |

`TestIntegrationFastPath` and `TestIntegrationFastPathOps` use the same split since 2026-11-04: budget mode
keeps their best of three against max(200 µs, 12 × a pipe ping-pong measured in the run), supervisor.md R22;
the unit/race gate holds that wall-clock round trip to `CeilingFactor` times 200 µs. A pipe ping-pong does
not measure the handler's instrumented CPU work: a loaded tagged race run measured 276–411 µs for the common
operations while its gauge stayed at 11–19 µs. Both tests are now in `scripts/timing-budgets.sh`, whose
uninstrumented build still asserts the original budget, and both keep their operation/notification checks.
The other tests that
assert a duration bound a timer or a hang (a 50 ms upstream timeout answered within 500 ms, a stop bounded at
seconds) with margins of five to ten times. The busy-loop runs found load-dependent failures that are no budget, each
fixed in its own commit with the same assertions: `TestHTTP2RefusalPreservesOneConnectionAndMeteredSiblings` counted
the upstream's calls as soon as the client had its 504 for a handed-off upload, before the upstream handler's read of
it had returned (19 runs of 20 failed); `TestPidfdOwnerForms` opened its own thread's id where an emulated pre-6.9
kernel opens only the leader's; `TestDenyWriteFixedPassCut`'s first entry spent its own 2 s on 15 walks of a symlink
chain that a loaded machine slows past it; `TestRunSetLiveKeepsARowWhoseCgroupIsNotVisibleYet` made its cgroup appear
from a goroutine that a loaded guest woke after the scrub's second listing, 50 ms later (it now appears right after
the first listing, through the scrub's own listing function, and the test holds the gap between the listings to at
least the 50 ms settle, so a scrub that does not wait still fails it;
`TestRunSetLiveKeepsARowWhoseCgroupWasMadeDuringTheWalk` holds `runSetLiveIn`, the wrapper `PurgeRun` runs, to at least
that settle, so a wrapper that passes less fails it).

**Slowed copies** (scratch builds, never in the tree: the tip's own tree with an environment-controlled hook at one
point of the measured path, a loop of dependent multiply-adds, about 0.85 ns a round on the reference host, or a
sleep). Budget mode ran with the reference host as found, other work at load average 5.7 to 8.1, on
2026-10-16, and on 2026-10-17 in a 4-vCPU KVM guest running nothing else (the host as found, load
average 7 to 19 from other work; 22 rounds over three boots), each slowed copy alternating with the unmodified
binary. The unit gate ran under 16 busy loops in the same guest on 2026-10-17, its figure the own time; one row is
the CPU-time gate of 2026-10-16 on the reference host, as marked. The unguarded case stands for C8's exec cases.

| Slowed copy | Test | Budget mode | Unit gate, 16 busy loops |
|---|---|---|---|
| 8,000 rounds before every command-rule decision (about +7 µs on the reference host) | `TestExecCommandCostBudget` | fails 12 runs of 12 on the host (+14.8 to +32.7 µs against +12) and 22 of 22 in the guest (+18.8 to +36.9 µs) | passes 4 of 4: +23.8 to +30.1 µs of own time against the 120 µs ceiling |
| a 20 µs sleep there | the same | fails 22 of 22 in the guest: +44.7 to +63.3 µs | passes 2 of 2: +66.1 to +68.2 µs of own time |
| 150,000 rounds there (about +130 µs) | the same | | fails 4 of 4: +220 to +237 µs of own time |
| a 500 µs sleep there | the same | | fails 4 of 4: +573 µs to +1.08 ms of own time |
| a 2 ms sleep there | the same | | fails 4 of 4: +2.08 to +2.17 ms of own time (the CPU-time gate of 2026-10-16 passed it at +43 µs) |
| a 20 ms sleep there | the same | | fails 2 of 2: +20.1 to +20.2 ms of own time, its wall clock over the 1.2 ms wall-clock ceiling too (the CPU-time gate passed it at +68 µs) |
| 800 rounds in each index decision | `TestExecCommandIndexCostBudget` | fails 12 of 12 on the host (1.07 to 2.91 µs against 1 µs) and 22 of 22 in the guest (1.26 to 2.99 µs) | |
| 12,000 rounds there | the same | | fails 4 of 4: 18.7 to 21.2 µs of own time against 10 µs |
| 250,000 rounds per planned row | `TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows` | fails 12 of 12 on the host (251 to 406 ms against 200 ms) and 22 of 22 in the guest (283 to 512 ms) | |
| 2,500,000 rounds per planned row | the same | | fails 4 of 4: 18.2 to 21.4 s of own time against 2 s (a plan that long blocks, the Go runtime parking the thread to preempt it, so its own time is its wall clock) |
| 30 rounds in each Borrow, before the lent call | `TestBorrowCostRatio` | fails 8 of 8 on the host (ratio 2.69 to 3.18 against 2.5) and 21 of 22 in the guest (2.50 to 4.37: one run read 2.50, at the limit, beside the unmodified 1.78) | |
| 12 rounds there | the same | passes 8 of 8 on the host: ratio 1.73 to 2.17, inside P1's own margin | passes 4 of 4 under 16 busy loops on the host: ratio 2.98 to 3.16 in CPU time against 25 (2026-10-16) |
| 400 rounds there | the same | | fails 4 of 4: ratio 44.8 to 45.9 of own times against 25 |
| 60,000 rounds at the top of each notification's handling (`Loop.handle`) | `TestIntegrationUDPFlood` | fails 12 of 12 on the host (12.3 to 21.4 s against 11 s; mean hold 156 to 281 µs) and 21 of 21 in the guest (15.7 to 30.2 s; 200 to 342 µs) | passes 2 of 2: 46.8 to 54.1 s against 110 s, mean hold 467 to 515 µs against 2 ms |
| a 0.7 ms sleep there | the same | | fails: killed at 170 s and judged on it, on the pace budget's message (on the host as found it finished in 120.3 s, over the 110 s ceiling) |
| a 1.2 ms sleep there | the same | | fails: killed at 170 s and judged on it; before the 2026-10-17 harness change it failed only on "target report: EOF" at 60 s |

In the same minutes the unmodified binaries passed budget mode on the host in 9 runs of 12 (C8's exec cases), 11 of
12 (the index, 323 to 865 ns), 12 of 12 (the plan, 1.6 to 5.4 ms) and 12 of 12 (the flood, 10.0 s, mean hold 40 to
61 µs), and in the guest in 9 of 22 (C8's exec cases, the unguarded case +9.2 to +20.6 µs), 18 of 22 (the index, 404
ns to 1.27 µs), 22 of 22 (the plan, 1.9 to 6.2 ms), 22 of 22 (Borrow, 1.12 to 2.17) and 18 of 22 (the flood, 10.0 to
20.7 s): the misses are the machine's load, which is why budget mode runs where the machine is quiet, and the guest's
four CPUs shared a host other work kept at load average 7 to 19. The comparison that load cannot blur is the paired
one: in each of the guest's 22 rounds both C8 copies read more than the unmodified run of the same round, the
8,000-round copy by +9.0 to +20.4 µs, and so did the index copy. A second series on the host, at load average 8.5 to
14.4, failed every slowed copy above 8 times of 8 (the Borrow copies as listed), and passed the unmodified binaries
in 5 of 8 (C8's exec cases), 6 of 8 (the index), 8 of 8 (the plan), 8 of 8 (Borrow, 1.40 to 1.71) and 7 of 8 (the
flood: one took 11.9 s). In the unit gate's guest runs the unmodified binaries passed every run: the unguarded case
+12.6 to +13.7 µs of own time, the index 504 to 590 ns, the plan 4.7 to 5.9 ms (16.5 to 16.7 ms of wall clock),
Borrow 2.34, the flood 29.7 to 30.7 s with a mean hold of 145 µs. `scripts/timing-budgets.sh` itself, run whole, met
every budget at load average 9 on the host (2026-10-16) and in four of nine runs in the guest (2026-10-17; the other
five missed C8's exec cases, four of them the index too and two the flood), listing the C8 cases' and Borrow's
`TARGET-MISS` lines. Budget mode's code is the same since 2026-10-16 (`Mode.Measure` in budget mode is `MinOf` on the
wall clock); only the unit gate's figure changed.

On a later tree, whose exec-walk changes are in the measured path, with
slowed copies made the same way from it, the proofs were run again on 2026-10-17. Budget mode, 12 rounds in the idle
4-vCPU guest on a host as found: the 8,000-round C8 copy failed 12 of 12 (the unguarded case +18.0 to +35.7 µs) and
the 20 µs sleep copy 12 of 12 (+43.9 to +67.9 µs), each reading more than the unmodified run in every round; the index
copy 12 of 12 (1.19 to 3.36 µs), the plan copy 12 of 12 (261 to 640 ms), the Borrow copy 11 of 12 (2.48 to 3.88: one
read 2.48, under the limit) and the flood copy 12 of 12 (16.0 to 34.7 s); the unmodified binaries met their budgets in
6 of 12 (C8's exec cases, the unguarded case +9.0 to +20.4 µs), 9 of 12 (the index), 12 of 12 (the plan, Borrow) and
10 of 12 (the flood), and `scripts/timing-budgets.sh`, run whole three times first, met every budget all three times.
The unit gate, on the host as found (load average 10 to 22): the copies that sleep 2 ms and 20 ms in every
command-rule decision failed (+2.19 ms of own time in the unguarded case against its 120 µs ceiling; the 20 ms copy's
wall clock +20.19 ms against its 1.2 ms ceiling too), and the flood copy that sleeps 1.2 ms a notification was killed
at 170 s and failed on the pace ceiling's message.

**Under load, 2026-10-16** (the CPU-time unit gate). With 16 busy loops running on the reference host, the touched
packages' test binaries, each built with `-tags integration` so that one run is the unit and the unprivileged
integration suite together, ran 28 times each in two concurrent streams, load average 21 to 62 with other
work. Every run passed but two of the supervisor's, in the same minute and for one reason that is no timing:
`TestEverySourceFileCarriesTheArchitectureTag` found the scratch file a slowed-copy build had put in the package
directory at that moment, so the supervisor's record is 26 of 28 there, and four more supervisor runs under the loops
passed. An earlier build failed twice in its first 32 runs of the same sweep, and both failures changed it:
`TestBorrowCostRatio` at 2.50 (a ratio to a fixed workload is a budget, above) and the read-cost test at 224 ns (the
clock's cost is now taken in the rounds).

**Under load, 2026-10-17** (the own-time unit gate). The busy loops now run inside a 4-vCPU KVM guest, so that they
load only the four host CPUs the guest has, and the oversubscription is four runnable loops a CPU where on the
reference box it was one; the host ran other work throughout. In the guest, as the invoking user, each touched
package's `-tags integration` test binary (internal/testutil, internal/runtime/supervisor,
internal/runtime/enforce/cgroup, internal/platform/sys, internal/policy/decide, internal/runtime/observe,
pkg/spec/agent, pkg/spec/record, internal/runtime/capture/forwarder) ran 28 times, one package at a time, with 16 busy
loops beside it, in four sweeps:

- The first, of an earlier build, passed every run of eight packages and failed internal/testutil
  twice in 28: two of its own new tests asked of a busy machine what it need not give (a thread sample's cost under
  half of one clock read; a try in five that waited without blocking), and both now hold what is true of every sample.
- The second, of a later build, passed every run of all
  nine packages, 252 of 252.
- The third, of a later tree still, ran the five packages whose test binaries that tree changed (internal/testutil and
  the supervisor, cgroup, observe and forwarder packages; the other four's code and dependencies are as the second
  sweep ran them) and passed 139 runs of 140. The cgroup package failed once, in
  `TestRunSetLiveKeepsARowWhoseCgroupIsNotVisibleYet`, whose own goroutine the guest woke too late (above); with that
  fixed, the package passed 28 runs of 28 under the same loops.
- The fourth, after the own time began to keep the process's other threads' CPU time, ran
  the four packages whose figures that changes (internal/testutil, the supervisor, cgroup and platform/sys packages)
  and passed 112 runs of 112. The C8 cases' own time was at most 1.9 times their Limits (the script, +57.4 µs against
  +30 µs; the unguarded case at most +19.7 µs), the 8192-argument case's wall clock at most 4.6 times, the index at
  most 623 ns, the plan at most 17.9 ms, Borrow's own-time ratio at most 2.36, and the flood 10.5 to 29.5 s with a
  mean hold of at most 171 µs.

Under the loops the unmodified figures stayed far under their ceilings: the worst own time 2.3 times its Limit (the
unguarded case, +27.5 µs against +12 µs), the worst wall clock 6.1 times its Limit (the 8192-argument cases), the
index at most 1.16 µs of own time, the plan at most 13.8 ms and Borrow's own-time ratio at most 2.9 (against 25). The
flood took 12 to 88 s against its 110 s ceiling and held a notification 67 to 589 µs on average against 2 ms (the
pace's margin is the machine's, above). A run of
`TestOwnTimeTakesOutTheRunQueueDelay` beside small fsync'd writes on the same disk found one more machine-made
failure, its stand-in rewritten through the filesystem's journal (53 runs of 200 failed); it is a memfd now, and
200 of 200 pass so.

**C8's exec path against the base (2026-11-02).** On CI's runner budget mode holds C8's exec cases to figures of
another machine, and its unguarded and script cases are held to twice them (`--hosted`, above), which a regression of
about +7 µs no longer reaches. So bench-gate (`scripts/bench-gate.sh`, ADR 0028 S1) also compares
C8's exec path with the base commit's, on the same runner in the same job: `BenchmarkExecCommandCost` handles one exec's
notification in a run with command rules, with real `process_vm_readv` reads of the process and a real head read as
the test makes them, for each case of `TestExecCommandCostBudget` whose op takes microseconds (the unguarded exec, the
script, 16 and 128 arguments, the exec the floor refuses at 8 arguments), and the gate fails a sub-benchmark more than
25% slower than the base's at p<0.01, as it does every hot path it gates. The comparison needs no figure of any
machine. On the runner the unguarded case's op takes about 14 to 17 µs (its with-rules figure in the 2026-11-02
bench-gate jobs), so the 8,000-round copy makes it about half again as long there; a quiet runner's ops of a few
microseconds that are mostly system calls vary by a few percent from round to round (`BenchmarkOwnedOpenClose` ±1 to 3%,
`NotificationRoundTrip`'s exec cases ±3 to 6%, in the same jobs). Proof, on the reference host at load average 24 to 27
from other jobs (spreads of ±10 to ±73%, and the copy's own loop slowed by the load too): `bench-gate.sh` with only this
benchmark, the 8,000-round copy (a loop of dependent multiply-adds at the top of `decideCommand`, built from this tree)
against the unmodified tree, failed 2 runs of 2 (the unguarded case +57.8% and +72.2%, p ≤ 0.007; 16 arguments and the
floor's refusal both times, the script once), and the unmodified tree against itself passed 2 of 2. A regression of up
to a quarter of an op, or one that creeps in over several commits each under it, passes the comparison; budget mode on
the reference box (`make budgets`) holds the figures as written.

**Accepted steps (2026-11-13).** A change that costs more on purpose, and says why, is entered in `bench-gate.sh`'s
accepted-step list: the base commit it is compared with, the package directory, the benchmark, the unit (B/op or
sec/op; allocs/op leaving zero, or a B/op of 0 that becomes non-zero, is never accepted), a ceiling in percent and the
reason. Against that base commit alone (a base checkout's HEAD; `BENCH_GATE_BASE_COMMIT` for `compare`), a failure the
entry matches is a note while it is at or below the ceiling, and still fails above it. So an entry expires by itself:
once its change has merged, the next pull request's base is another commit and the thresholds hold again. The gate
names, at the end of its findings, every entry that does not apply to the base it compared or that matched no failure,
and such an entry is removed. The first entries are v0.1.3's: a guarded exec is decided with two readers of the command
rules (ADR 0048), and against public main before it (f8efe5ca2ab8) the hosted runner measured `ExecCommandCost`'s B/op
at +10.53% for the script (4.008 to 4.430 KiB), +16.16% for 16 arguments (3.868 to 4.493 KiB) and +17.42% for 128
arguments (32.29 to 37.92 KiB), each at p=0.000 n=10, with allocs/op 59 to 66, 58 to 67 and 239 to 257 and sec/op
inside the gate (+3.70%, no difference, +11.18%); the unguarded exec and the floor's refusal were unchanged. Their
ceiling, +25%, leaves room for the spread between hosted runners and still fails a larger step.

**What it costs.** The unit gate no longer catches a regression of less than several times a budget, whether it works or
waits: the 8,000-round copy, about 1.2 to 1.5 times the unguarded Limit, passes it under the busy loops, as do a 20 µs
sleep in every command-rule decision and a 60,000-round loop in the flood's handler, and on a busy machine a wait of up
to a hundred Limits can pass where another process's work fills it without the thread blocking. Such a regression fails
budget mode on the reference box (`make budgets`, on an idle machine), and CI's bench-gate job on the push or pull
request that makes it: in budget mode where the runner holds the budget as written, and for C8's exec cases, of which
it holds the unguarded and script cases to twice their figures, in the comparison with the base
(`BenchmarkExecCommandCost`, above), which the 8,000-round copy fails. Budget mode is only as good as the machine is quiet: in the KVM guest above, idle but on a
host other work kept at load average 7 to 19, the unmodified C8 cases met their Limits in 9 runs of 22 and the whole
script in 4 of 9. CI's runner is not the reference host either: a runner slower than it, or a busy one, can miss a budget
the code meets on the reference host, and a faster one gives a regression more room, as the raw comparison in CI's test
jobs did before (it already ran these budgets there, beside other packages' tests). A budget the runner misses is a
finding to investigate, never a reason to relax it: the runner's misses of 2026-11-02 were its system calls, measured
in the same jobs, and the two cases they hit are held to twice their figures on a hosted runner alone (`--hosted`,
above), with the comparison against the base for what that leaves through; the budgets themselves are unchanged.

**The figures today** (budget mode on the reference host, the fastest of the rounds above, at load average 2.5,
2026-10-16): the unguarded case +6.9 µs (Target +6), the `#!/bin/sh` script +15.6 to +16.4 µs (Target +15), 16
arguments +10.8 to +11.8 µs, 128 arguments +22 to +23 µs, 8192 arguments +0.67 to +0.82 ms, past the bound +0.63 to
+0.72 ms; the index 323 to 865 ns with the host as found. The unguarded and script cases miss their Targets
(`TARGET-MISS`) and meet their Limits; ADR 0048's measurements at P1 (+5.3 to +5.5, +12.7 to +13.1 and +5.1 µs) were
taken before later fixes added reads to those paths. In the idle 4-vCPU guest (2026-10-17), the runs of
`scripts/timing-budgets.sh` that met every budget read: the unguarded case +9.5 to +11.4 µs, the script +22.2 to
+26.4 µs, 16 arguments +15.4 to +18.6 µs (Target +15), 128 arguments +31.9 to +38.3 µs, 8192 arguments +1.09 to +1.26
ms and past the bound +1.03 to +1.32 ms (both over their +1 ms Targets), the index 460 to 527 ns, the flood 10.0 to
10.2 s with a mean hold of 55 to 79 µs, the plan 2.3 to 5.9 ms, and Borrow's ratio 1.62 to 1.83. On the later tree
in the same guest, its three whole runs read: the unguarded case +8.0 to +11.6 µs, the script +18.8 to +26.7 µs, 16
arguments +12.9 to +18.3 µs, 128 arguments +26.3 to +37.4 µs, 8192 arguments +0.92 to +1.38 ms, past the bound +0.74
to +1.16 ms, the index 357 to 559 ns, the flood 10.0 s with a mean hold of 48 to 77 µs, the plan 1.9 to 2.6 ms, and
Borrow's ratio 1.74 to 2.00.

## Start latency and the cold start (guest perf suite)

This page measures whole-run overhead. A run's start, warm and cold, is measured by the tier-3 guest perf suite
(`make vm-perf`, `test/perf`) and recorded with its budgets in docs/p0/enforce-plane.md §10.1, which since 2026-10-19
also attributes the cold start per program, map, D7 hook and plane-probe mode ("Cold attribution").
