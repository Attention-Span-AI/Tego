# ADR 0148: A skipped deciding or tracking program ends the run, and the record says so

Status: **accepted 2026-11-11**; built (`internal/runtime/skips.go`, `internal/runtime/enforce/cgroup/skips.go`,
`internal/doctor/lsmrecursion.go`, the gap words of `internal/check/gaps` and the receipt). Closes the open half of
docs/GAPS.md C53 (b). Amends ADR 0024 (16) twice: its "LSM programs take no such check, so LSM mode is not affected"
holds only on kernels from 6.2 (6.1.54 in the 6.1 series), and on 7.0 not for the exec pin check, a tracepoint
program. Adds to ADR 0016's recorder accounting (C53 (c)), which it leaves as it was. Amended the same day after an
independent review (the "Review" notes below); amended 2026-11-12 for partial live writes, retained outage transitions,
proof prerequisites and windows, and doctor's listener-cleanup warning.

## Context

At the root tiers Tego's rules are decided by BPF programs the build shares: the plane's hooks (ADR 0024), its exec
pin check (ADR 0048 (3) P2), the listener cleanup (enforce-plane §2.20), the cgroup socket programs, and the program
that adds a run's child cgroups to the run set (`cgroup_track`). The kernel runs some program types under a guard
that skips a program already running on the CPU, and counts each skip in `bpf_prog_info.recursion_misses`. Where the
kernel preempts kernel code, a task preempted inside such a program holds the guard, and every other task reaching
the hook on that CPU before it resumes is skipped: the hooked action goes on undecided. ADR 0024 (16) measured this
for fmod_ret mode and rules that mode out where kernel code is preempted. ADR 0016's 2026-11-04 amendment counts the
recorder's skips. Until this ADR nothing noticed a skip of a program that decides or tracks: a run could end with
exit 0 and a verified chain after an action its contract refuses went through unrefused.

### What the kernel does, by program type

Read in the stable sources of v6.1, v6.1.53, v6.1.54, the 6.1 and 6.6 stable heads, v6.2 to v6.6, v6.8, v6.12,
v6.17, v6.18, v6.19, v7.0.14 and the 5.15 stable head (git.kernel.org stable tree, fetched 2026-11-11), and measured
on the guest kit's rows (`/proc/kallsyms`, the preemption mode). A guard is where the kernel can skip; whether a skip
is reachable depends on the calling context.

| Run path | Guard | Tego's programs on it | Reachable skip |
|---|---|---|---|
| Trampoline, recursion-checked entry (`__bpf_prog_enter_recur` from 6.2 and 6.1.54; `__bpf_prog_enter` before) | per program, per CPU | fmod_ret hooks; recorder fexit and fentry; `io_bind`/`io_listen` listener cleanup; **LSM hooks on kernels before 6.2 and 6.1.54** (and the 5.15 series, which never took the change) | where kernel code is preempted (measured, ADR 0024 (16), ADR 0016); otherwise only by nesting on one CPU |
| Trampoline, unchecked entry (`__bpf_prog_enter`, from 6.2 and 6.1.54: `bpf_prog_check_recur` false for LSM) | none | the LSM-mode hooks | none |
| Raw tracepoint (`__bpf_trace_run`) | per program, per CPU | tp_btf: the exec pin check (`sched_process_exec`), `cgroup_mkdir`, `cgroup_rmdir`, the recorder's exec and exit | before 7.0 a tracepoint calls its probes with preemption off (`guard(preempt_notrace)`): nesting only, which these tracepoints do not do. From 7.0 probes run under `guard(srcu_fast_notrace)` with only migration off, so where kernel code is preempted, `sched_process_exec`'s are reachable (process context). `cgroup_mkdir` and `cgroup_rmdir` are not: `TRACE_CGROUP_PATH` calls them inside `spin_lock_irqsave(&trace_cgroup_path_lock)` (and mkdir under `cgroup_mutex`), with preemption and interrupts off, in every version read |
| `trace_call_bpf` | one per-CPU `bpf_prog_active` shared by every kprobe, perf and syscall tracepoint program on the machine | the listener cleanup `sys_exit_bind`/`sys_exit_listen`; the recorder's exec results | syscall tracepoint programs run with preemption off, but bpf(2)'s map lookups, updates and deletes hold `bpf_prog_active` with only migration off (`bpf_disable_instrumentation`): where kernel code is preempted, any process preempted inside one skips them on its CPU (forced below), every version read through 7.0. On 7.2.9 syscall tracepoint programs no longer run through this path (review of 2026-11-13, below) |
| `bpf_prog_run_array_cg` | none | the cgroup socket, sockopt, sock_ops and skb programs | none |
| uprobe runners, iterators, `BPF_PROG_RUN` | none | the capture uprobes, the fill | none |

The kit's rows (2026-11-11): `__bpf_prog_enter_recur` is in `/proc/kallsyms` on RHEL 9's 5.14.0-687 (a vendor
backport), Amazon Linux 2023's 6.1.188, Ubuntu 24.04's 6.8, Debian 13's 6.12, Ubuntu 25.10's 6.17 and Fedora's 7.0
and 7.2, and not on Ubuntu 22.04's 5.15. The preemption mode is none on AL2023, voluntary on RHEL 9, Ubuntu 24.04 and
25.10 and Debian 13, lazy on Fedora 7.0 and 7.2; Ubuntu 22.04's 5.15 is not a preemptible build. Every 7.0 x86_64 and
arm64 kernel preempts kernel code (full or lazy; `none` and `voluntary` are refused); 7.0 is Fedora 44's and Ubuntu
26.04's kernel.

So, per root plane, on the product's default modes:
- LSM hooks (tier bpflsm, tier cgroup in LSM mode): no skip on any kit row. On a kernel before the exemption that
  preempts kernel code (5.19, 6.0, 6.1.0 to 6.1.53 booted `preempt=full`, or built `PREEMPT`), they can be skipped:
  doctor now refuses LSM mode there (decision 9).
- fmod_ret hooks: admitted only where kernel code is not preempted (ADR 0024 (16)): nesting only.
- The exec pin check: reachable on 7.0 and on any kernel that carries the srcu tracepoint change. Doctor now withholds
  its claim on a kernel that preempts kernel code (decision 10).
- The listener cleanup: reachable on any kernel that preempts kernel code, through `bpf_prog_active`.
- `cgroup_mkdir`: guarded, not reachable.
- cgroup socket programs: no guard.

What a skip of each does:
- an LSM or fmod_ret hook: the action goes on as if allowed;
- the exec pin check: an exec whose argv or image differs from what the supervisor decided runs instead of being
  killed before its first instruction, and its line says `argv_facts` `unproven` with gap `exec-pin-unproven` (the
  recorder's fold waits for the check's sample, ADR 0048 (8));
- the listener cleanup: a bind's decision marker outlives the bind, and the task's next `mknod(S_IFSOCK)` is taken
  for that bind;
- `cgroup_mkdir`: a child cgroup of the run would get no run-set row, and its tasks would be no run's.

How it is visible: `recursion_misses` per program instance, a u64 summed over CPUs that only grows while the
instance lives (`kernel/bpf/syscall.c` `bpf_prog_get_stats`); it needs `prog->stats`, not `kernel.bpf_stats_enabled`.
Link info carries nothing. The field is in `bpf_prog_info` from 5.12; on an older kernel the read returns 0, which
cilium/ebpf does not tell from "no skip". The counter is the program's, so it counts every task that reached the hook:
other runs of the build and tasks no run governs. Nothing in the kernel says whose a skip was.

Measured 2026-11-11 on Fedora 7.0.14 (`TEGO_VM_ROW=fedora-7.0`, lsm-bpf boot, product build), reading all 46 host-wide
links around `TestTier2ConcurrentRunsOfOneBuild`: in two 32-run rounds (64,000 watched opens each), `tego_file_open`
gained 2,215 and 2,422 skips, the recorder's tp_btf `tego_sched_exec` 1 in the first (that run's exec of `true` has
no line, and its record carries the recorder's shared-skip gap); every plane hook, the exec pin check and
`cgroup_mkdir` gained none. `TestPlaneRunExecPinRace` (5,000 attempts per cell, 2,517 and 2,462 kills) moved none.

## Decision

1. **Every root-tier run watches the programs its rules rely on.** The cgroup backend resolves them from the links its
   launcher holds (which keeps those instances attached for the run) and holds each program open, so the counter read
   is the one the hook runs: every plane hook of the run's mode when the plane decides it; the exec pin check when the
   run's slot is pinned and the run claims the kernel holds its execs (decision 10); the four listener cleanup programs
   when its row carries `RunListenerResults`; and `cgroup_mkdir`, since every run's row admits descendants. LSM hooks
   and `cgroup_mkdir` are read although no skip of theirs is reachable where the run is admitted: one `bpf(2)` call per
   program per reading is the cost, and a kernel that changed is then seen, not trusted. Programs whose path has no
   skip counter (the cgroup programs, the capture uprobes, the fill) are not read.
2. **The runtime reads the sums before it releases the agent, every 250 ms while the run lives, and once more after
   the drain**, when the run's last task is gone and none can reach a hook. A base that cannot be read refuses the
   run before the agent exists; a kernel whose BTF has no `bpf_prog_info.recursion_misses` is such a kernel, so no run
   reads 0 for "no skip". A tree that does not empty even after the kill makes the last reading not cover the run, and
   it is recorded as a failed reading.
3. **A move ends the run.** A deciding or tracking sum above its base, or a reading that fails, ends the run with
   reason `error` and a `kernel skips:` detail, and its tree is killed, as a lost membership row ends it
   (`cgroup-tracking-failed`). *Review:* the last reading is held to the same rule before `run_end`'s ending is
   computed, so a skip found only after an agent that exited before the first poll ends the run too, and a successful
   exit code never stands beside the line. The skip may not have been this run's; the run cannot show it was not, so
   it does nothing more under rules that may not hold. The skipped action itself already happened: the end follows it
   by the polling interval, nominally 250 ms, plus the poll's own scheduling delay, the counter reads, and the time the
   kernel takes to deliver the asynchronous kill to every task of the tree.
4. **The record says so, and only then.** After the drain the runtime writes, directly (a full queue cannot lose
   them), one `gap what=enforce` per class that moved: `why=bpf-decision-skip/shared-build` (count: the skips since the
   base; `decision_plane`: the run's mode) and `why=bpf-tracking-skip/shared-build`; and
   `why=bpf-skip-counter-unavailable` (no count) when any reading after the base failed. A run with no skip writes
   nothing new: its ledger, receipt and exit code are what they were. These are new `why` values of the existing gap
   line, no field, so no record minor is taken (spec/record/v1 README: a why is not a field); a ledger written before
   them simply has none.
5. **What the views say.** `internal/check/gaps` gives these gaps, including an adoption's restored-counter gap,
   their own class, `RulesUncertain`, read before any other: "the rules may not have held: the kernel skipped N
   executions of shared programs that decide this run's actions ... the skips may belong to other runs or ungoverned tasks", and never "no action known to be missing" beside
   it. The receipt lists it first in its coverage, field `refusals`, code `rules-uncertain`, so `coverage.complete` is
   false. The dashboard's line words say the same.
6. **Shared programs, several runs: a denial of service, bounded.** The delta cannot be assigned. Every run that relies
   on the program and lived while it moved reads the move, is ended, and carries the line with the skips its own window
   saw. Whoever can make a watched program skip can therefore end every run that relies on it: a denial of service on
   those runs, on purpose or not. Who can, as built (with decisions 9 and 10):
   - root, by any means (outside the threat model);
   - any process that holds `bpf_prog_active` while preempted, which is a bpf(2) map lookup, update or delete. That
     takes a usable map descriptor, not a privilege: `kernel.unprivileged_bpf_disabled` (2, disabled, on every kit
     row: RHEL 9, AL2023, Ubuntu 22.04, 24.04 and 25.10, Debian 13, Fedora 7.0 and 7.2) refuses only creating a map
     and loading a program (`map_create`'s and `bpf_prog_load`'s checks in 7.0.14's `kernel/bpf/syscall.c`, whose own
     comment says other actions depend on fd availability and bpffs access), while `map_update_elem` checks the
     descriptor's mode alone. So: a process that inherited a map descriptor, was passed one, or can open a pin in a
     bpf filesystem it may read (Tego's own are under `/sys/fs/bpf/tego`, root's alone); any user where unprivileged
     BPF is enabled; and Tego's own launchers (fills, grants, one pin write per exec of a pinned run, which an agent's
     execs cause), whose effect is not measured and was not seen in the reproductions. This reaches only the listener
     cleanup, so only runs with listener policy;
   - a launched agent at a root tier cannot: its seccomp filter's root arm answers EPERM to the bpf(2) syscall number
     itself, whatever the command (`RootDeny` in `internal/runtime/enforce/landlock/filter.go`), and the plane's `bpf`
     hook refuses every bpf(2) command of a task in a plane-decided run;
   - an adopted agent has no seccomp filter (none can be added to a running process). Under a boundary, once moved in,
     the plane's `bpf` hook refuses its every bpf(2) command, so it cannot reach a map from there; before the move, and
     in a record-only adoption, which no plane decides, it is a process of its user like any other, and with a map
     descriptor (above) it can make the listener cleanup skip and end the runs that rely on it;
   - through its own work, an agent reaches the shared programs: on a kernel that preempts kernel code it could make
     the exec pin check skip by exec pressure, which no longer ends runs there (decision 10; 5,000 racing exec attempts
     made no skip); the LSM hooks are not skippable where admitted; `cgroup_mkdir` is not reachable; fmod_ret hooks are
     admitted only where kernel code is not preempted.
   Proven: a root process forced the listener cleanup to skip and ended both a run whose agent was binding and one
   whose agent only slept (the ungoverned case). Not proven: that an ordinary user can do it at will where unprivileged
   BPF is enabled, or any rate of such ends on a busy host.
7. **Adoption (ADR 0055) records and never ends for a skip.** Ending an adoption releases the agent from every rule,
   the opposite of failing closed, and ADR 0055 never forces a release on the operator's agent. An adoption reads its base after
   its rules are prepared and before the agent is moved in (a base it cannot read refuses the adoption with the agent
   untouched) and keeps every rule on after a skip. *Review:* it keeps polling and reports while it lives, through the
   run's serialized ledger writer (as the DNS broker writes its decisions; the queue can drop a line when full): the
   first report as soon as `run_start` is on disk and there is anything to say (nothing is written before; what was
   seen is kept for it), then at most one report a minute. Each counter class advances only after its own line is
   written; a later failed write cannot duplicate that prefix. Any successful prefix starts the minute interval;
   a report with no successful line is retried at the next poll. Counter lines count the skips since that class's
   last successful write (about 1,440 lines a class a day under continuous skips, plus the last reading).
   Every observed outage retains an opening (`bpf-skip-counter-unavailable`) and its eventual closing
   (`bpf-skip-counter-restored`, counting that outage's failed readings), in order until the ledger accepts them.
   A short outage can put both lines in the next report, and several outages can put several pairs there; outage
   lines are additional to the counter-line bound. These are observed reading transitions, not exact outage times.
   The reporting interval, plus polling, scheduling, counter reads and ledger writes, delays their visibility in the
   ledger, `tego status` and the dashboard; an unavailable ledger can delay it further. Pending transitions use memory
   until written, so repeated outages during a prolonged write failure grow that backlog. The agent stays governed;
   the last reading writes the rest without waiting for the interval. A line the watcher cannot write never ends an
   adoption or releases its agent. A line the pipeline cannot write still ends the adoption and releases the agent,
   ADR 0055's rule, which this ADR leaves as it is.
8. **The test waiver.** A test build's `TEGO_TEST_PLANE_PREEMPT=waive` (ADR 0024 (16)) runs fmod_ret mode where kernel
   code is preempted, where its hooks' skips are the expected cost; ending those runs would end CI's fmod_ret cells
   on any busy runner. There a deciding skip of a fmod_ret run is recorded and logged and does not end the run; a
   tracking skip still does, and an lsm run is never waived. The waiver also keeps the exec pin claim (decision 10), so
   CI's exec pin cells run on its 7.0 runners. A product build has no waiver (`doctor.PlanePreemptWaived` is false).
9. **LSM mode where the kernel checks LSM programs (review).** Doctor reads the running kernel's `/proc/kallsyms`:
   `__bpf_prog_enter_recur` exists exactly where LSM programs are entered unchecked, a vendor backport included, so
   the version is not read. Where it is absent, or kallsyms cannot be read, LSM mode (and so tier bpflsm) is admitted
   only where the kernel is shown never to preempt kernel code, fmod_ret mode's rule, with the reason and the fix (a
   kernel from 6.2 or 6.1.54, or `preempt=voluntary`); fmod_ret's refusal offers LSM mode as its fix only on a kernel
   that exempts LSM programs. A pinned answer is held to the same reading. The test waiver does not lift it.
10. **The exec pin claim where its check can be skipped (review).** On a kernel that preempts kernel code, or is not
    shown not to, doctor withholds its exec pin cell with the reason in words ("the check after an exec is a
    tracepoint program this kernel can skip ... exec rules on argv stay best effort here"). No run there claims
    `exec.command_argv`, `exec.rules/argv` stays in `run_start.best_effort`, and an `exec.assurance: kernel` run is
    refused before the agent starts. The pins still apply: every exec the check holds says `kernel_pinned`, every one it
    kills is refused, and every one it missed says `unproven`. Such a run does not watch the check (decision 1): its
    record already says the rule is best effort, and ending runs on those skips would hand any process with exec
    pressure a way to end them.
    Doctor also warns, where preemption permits skips or its mode is unknown, that listener cleanup can be skipped,
    that these skips are detected, and that a detected shared skip ends launched runs relying on it. An adoption
    reports it without ending the agent. This states the remaining shared-run denial of service beside the withheld
    exec assurance; it does not claim the listener marker has been repaired.

## Options weighed

- **Mark only, never end.** Cheapest for availability. Rejected: an actor that can make a skip happen could repeat it
  for the life of the run, and every repeat would be one more action the rules refuse, each recorded but none
  stopped. Ending bounds it to one window per run.
- **End only the run the skip was.** Not possible: the counter is the program's, and a skip happens before the
  program could read run membership.
- **Remove the skippable dependencies.** The strongest answer where it exists, and taken where it can be without a
  new mechanism: the LSM hooks (decision 9), `cgroup_mkdir` (not reachable). Not built: moving the exec pin check to
  an LSM hook that runs after `exec_mmap`, `bprm_committed_creds`, which no exempting kernel can skip (its argv area is
  not yet at its final addresses then, since `setup_arg_pages` moves the stack later, so the check would read it
  through `bprm->p`; it changes ADR 0048's check point and needs its own cells on every row); and tying the listener
  cleanup's marker to one syscall, so that a stale marker decides nothing. With both, no deciding program a product
  run relies on could be skipped, and the shared end of decision 6 would have nothing left to answer.
- **Refuse the affected assurance or the tier where skips are possible.** Taken for the exec pin claim (decision 10)
  and for LSM mode on non-exempting preempting kernels (decision 9). Refusing the tier for the listener cleanup's
  path would refuse tier cgroup and bpflsm on every preemptible kernel, every 7.0 kernel included, for a skip that
  only a bpf(2) caller can make. Ending the runs that rely on it is the narrower answer, and it stands until the
  marker is tied to one syscall.
- **Poll faster.** One bpf(2) call per program per reading, about 30 on a plane run (doctor counted 27 attached hooks
  on Fedora 7.0, plus `cgroup_mkdir` and the listener cleanup where the run uses them): at 4 Hz under 150 calls a
  second a run. 50 ms (the tracking poll) would be five times that for an end 200 ms sooner, after the skipped action
  already happened. 250 ms stands.

## Released versions (v0.1.0 to v0.1.2)

They offer LSM mode wherever `bpf` is an active LSM and read no skip counter of a deciding program. Their documents
say LSM programs are never skipped (ADR 0024 (16); doctor's fmod_ret refusal recommends LSM mode "whose programs the
trampoline does not skip") and claim kernel exec assurance wherever the exec pin cell passes. As measured: on every kit
row their LSM hooks cannot be skipped (each row exempts LSM programs or does not preempt kernel code). Affected:
- LSM mode on a kernel before 6.2 and 6.1.54 that preempts kernel code (5.19, 6.0, early 6.1.y booted `preempt=full`
  or built `PREEMPT`): the hooks can be skipped, undetected;
- the exec pin claim on Fedora 44 and Ubuntu 26.04 (7.0, lazy): the check can be skipped, never forced or seen in this
  work; the exec's line would say `unproven`;
- the listener cleanup on any preemptible kernel, by a bpf(2) caller (forced by root in this work).

## Consequences

- On 7.0, a run with listener policy can be ended by a skip that was another run's, an ungoverned task's or Tego's own
  map traffic. No such skip was seen in the 32-run reproductions.
- On 7.0 no run claims kernel exec assurance; `exec.assurance: kernel` contracts are refused there before the agent
  starts.
- On a kernel before 6.2 and 6.1.54 that preempts kernel code, tier bpflsm and tier cgroup's LSM mode are refused.
- The record of a run with no skip is unchanged; `tego status`, the receipt and the dashboard say nothing new for it.
- Proven 2026-11-11 on Fedora 7.0.14 (product build, lsm-bpf boot, no waiver) by `internal/runtime/enforce/cgroup`
  `TestSkippedDecidingProgramEndsTheRun`. The skip is forced by a controlled workload beside the run, contained in
  the test and requiring root on the host, without changing any Tego program. Forced, three boots: one skip after
  8,209, 4,879 and 6,929 updates; the run ended at 3.75, 3.2 and
  2.2 s of a 20 s loop with `run_end` reason `error`, exit 125, detail `kernel skips: the kernel skipped programs that
  decide the run's actions 1 times ...`, one line `gap what=enforce why=bpf-decision-skip/shared-build count=1
  decision_plane=lsm`, and `tego receipt --json` coverage not complete with `refusals` `rules-uncertain`. Control:
  no watched counter moved, reason `exit`, no such line. Ungoverned: after 14,287 updates a process in no run was
  skipped once and the run whose agent only slept ended at 3.7 s with the same line.
  *Review, corrected 2026-11-12:* the agent writes `out/ready` once released and stops at `out/stop` or its own
  timeout. External snapshots cannot prove containment in the product's reading window: even a pending launcher
  completion can follow the final reading. They are diagnostics only. A forced proof now requires a deciding gap in
  the run's own record, and checks its error ending and incomplete receipt. On the proof boot (`TEGO_VM_ROW`
  fedora-7.0, `bpf` an active LSM), a guard registered before the prerequisites turns every helper skip into
  a failure, including missing python3 or no passing plane mode. Failing to record a forced skip also fails the proof.
  *Review, corrected 2026-11-13:* the proof above is of 7.0. The earlier text also named fedora-7.2 a proof boot; no
  run had forced a skip there, and none can by this method. In 7.2.9 the syscall tracepoint handlers call
  `trace_call_bpf_faultable` (`kernel/trace/trace_syscalls.c`; 7.0.14 calls `trace_call_bpf`), which runs each program
  under that program's own per-CPU guard (`bpf_prog_run_array_sleepable`) and does not consult `bpf_prog_active`, the
  guard the map updater holds. Measured on Fedora 7.2.9 (product build, lsm-bpf boot, no waiver): six forced windows
  on three boots (2 CPUs for 40 s and for 120 s, 4 CPUs for 40 s), between 78,873 and 515,094 map updates each, and
  the run's record has no deciding skip in any of them; the same build on 7.0.14 beside them recorded deciding
  skips after 33,166 updates (forced) and after 7,611 (ungoverned). A skipped execution is still possible on 7.2.9
  where the same program is entered again on a CPU on which it is already running; the kernel counts it on the
  program's own miss counter, the counter Tego reads on every kernel. One supplemental run on 7.2.9 took that route
  with a changed test workload using competing binders (product build and programs unchanged): the run's record
  has a deciding gap with count 8, the run ended with reason `error` within a second, and the receipt checks passed. That workload is one measurement and is
  not in this test. The repository's forced cases do not force a skip on 7.2: they skip there when nothing was
  forced, and the row's result says so.
  The updated proof is owed in a guest. Earlier run on Fedora 7.0.14: control 32.9 s,
  exit; forced, one skip after 872 updates, the run ended at 1.2 s, reason `error`, exit 125, one deciding line count
  1; ungoverned, one skip after 4,037 updates, ended at 3.0 s, the same. The same boot's doctor (product build) said
  "lsm mode ok (exec pins off: the check after an exec is a tracepoint program this kernel can skip, since its
  preemption model is not proven ...)" and listed exec command rules on argv as not held. The adoption sequence, `internal/cli` `TestIntegrationAdoptSkipIsRecordedAtOnce`, on the same kernel with the plane
  in fmod_ret mode (the test build's waiver and plane pin, on this test's tego commands only), a controlled workload beside the
  adoption, contained in the test (which runs as root): the first deciding line (13 skips) was in the ledger
  while the adoption lived and the agent was in its cgroup, `tego status` said the rules may not have held, a second line
  followed (17 skips in all), and the release ended the adoption with exit 0 and no error ending. Run again with the release checked before the agent stops: the first line carried 216 skips, a second followed
  (256 in all), and the released agent ran on in the cgroup it came from.

## Residuals (docs/GAPS.md C53)

- The skipped action is not undone and not named: the line says rules may not have held, not which action.
- A skip can still be another run's: an innocent run with listener policy is ended (decision 6).
- The exec pin check and the listener cleanup remain skippable programs; the options above remove them.
- A root user switching the kernel's preemption mode while a run or an adoption lives is C53 (a), unchanged; a guard
  that reuses a prepared LSM-mode backend does not re-read it (fmod_ret's does).
- Doctor does not check that the kernel counts skips; a run on a kernel without `recursion_misses` is refused at start.
- The recorder's own skips (C53 (c)) keep ADR 0016's accounting; a skipped tp_btf `sched_process_exec` on 7.0 loses
  an exec's line (measured above), which that accounting covers as recording uncertainty.

## Attacks on this design (2026-11-11)

1. **A counter that wraps, resets or is replaced on reload.** `misses` is a per-CPU u64 that only `u64_stats_inc`
   writes (`kernel/bpf/syscall.c`); nothing resets it, and at a billion skips a second it wraps in 584 years. Every
   loaded program has it: `bpf_prog_alloc` fails the load when it cannot allocate `prog->stats`
   (`kernel/bpf/core.c`), and only freed copies have it set to NULL. A reload is a new instance with a new counter:
   the watch holds the instance its launcher's own link runs (a held link keeps that instance attached for the run),
   so a replaced pin cannot swap the counter under it. A reading below the base, which therefore cannot happen, would
   count as one skip (`TestSkipDeltaNeverHidesASkip`).
2. **Programs shared with tasks no run governs.** Decision 6: a denial of service on the runs that rely on the
   program, shown by the proof's `ungoverned` case and bounded by who can make a watched program skip.
3. **A skip between the last reading and the run's end.** The final reading is made after the drain, once the run's
   cgroup is empty, when no task of the run can reach a hook, and it ends the run as the poll would
   (`TestSkipFinalReadingEndsTheRun`). A tree that does not empty even after the kill can: the run then records
   `bpf-skip-counter-unavailable` and ends (`TestSkipTreeThatOutlivesTheKillIsNotCovered`). A skip before the base is no
   run action: the agent does not exist yet. An adoption's final reading comes after its release, so it can count the
   released agent's skips too: an over-count, never an under-count.
4. **A kernel without the field.** Below 5.12 `recursion_misses` reads 0. The watch looks the member up in the
   kernel's BTF first and refuses the run when it is absent (`TestBuildSkipWatchFailsClosed`); the real lookup ran in
   every guest run above, where the watch was built.
5. **A kernel whose trampoline checks LSM programs.** *Review:* the first version of this ADR said no kernel read could
   skip an LSM program; v6.1's `__bpf_prog_enter` checks every trampoline program, and the exemption arrived in 6.2 and
   6.1.54. Decision 9 now refuses LSM mode on such a kernel unless kernel code is not preempted, from the kernel's own
   symbols, and the LSM counters are read anyway (decision 1).
