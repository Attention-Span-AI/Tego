# ADR 0022: a build stays attached while any run depends on it, lingers a bounded time after its last run, and is removed off every run's path

Status: accepted, partly implemented 2026-09-24 (proposed 2026-09-23). Amends ARCHITECTURE §6 (Pins) and §15.1; enforce-cgroup-observe R14, §3, E29, E33 and §9's lifetime condition. spec/config/v0 gains bpf.linger.

Decision: (1) A build's pinned objects (programs, maps, host-wide links) are never removed while its run_set holds a row for a cgroup that exists, whoever holds the build lock: the lower bound is every run the build enforces, one whose launcher died included. (2) Beyond that a build lingers for bpf.linger after its last run ends: a machine setting honoured only from /etc/tego/config.yaml, default 5m. 0 means removal at last out, done by that run's reaper. The last launcher out touches the build lock's mtime and removes nothing. (3) Exactly one linger timer per build. After its launcher has exited, a reaper takes LOCK_EX|LOCK_NB on /run/tego/bpf-<hash>.timer and exits if it cannot. The holder sleeps until the build lock's mtime plus linger. At that deadline it removes the build if LOCK_EX|LOCK_NB on the build lock succeeds, the run_set is empty and the mtime has not moved; otherwise it sleeps until the next deadline. It exits when the build is gone. (4) Removal never runs on a launcher's path. The build sweep runs in the reaper after its launcher has exited, in the timer, and in tego stop and gc. It removes a /sys/fs/bpf/tego/<dir> only if all of these hold: its build lock can be taken exclusively; its run_set holds no row for an existing cgroup (rows of vanished cgroups are deleted first); and it has been idle past bpf.linger. The same rule applies to this build and to any other. At most two builds linger per host; a third removes the one idle longest. tego gc --builds removes idle builds at once. (5) The run_set's key, a u64 cgroup id at maps/tego_run_set, is a contract across builds. A sweep of another build reads keys only, never values, and keeps the build when the map cannot be read, with a doctor row. (6) Only host-wide tracing and decision-plane links and their maps linger. Uprobes never do (ADR 0026), and cgroup links are per run (ADR 0020). (7) Until ADR 0026 removes the shared ring, an idle pinned build whose ring size differs from record.ringbuf is re-created rather than refused (E33). (8) The guarantee stated in ARCHITECTURE §6: no Tego program stays attached more than bpf.linger after its build's last run ended while that build's timer lives; otherwise it stays until the next reaper, tego stop or tego gc; and never is it removed while one of its runs lives. doctor lists attached builds with hash, mode, idle time and memlock. All state is in /run/tego (ADR 0034).

Why: [measured, six kernels, 1536M/2-vCPU guest] Five fentry detaches take 459 ms on 6.17, 599 on 6.8 and RHEL 9, 875 on AL2023 6.12, 1025 on AL2023 6.1, and 8 ms on x86_64 7.0. End to end, capture off, with runs 2 s apart and back to back: 256/768 ms on 6.17, 746/1305 on 6.8, 680/1296 on RHEL 9, 297/1317 on AL2023 6.12, 1292/1268 on AL2023 6.1, 236/236 on 7.0. With the build kept: 136-204 ms on every kernel, ledgers identical line for line. A SIGKILLed last launcher leaves 9 links and the ring on all six kernels.
[measured] Attach plus removal of the plane plus the fexit recorder (21-22 links):
- 6.8 and RHEL 9 in fmod_ret mode: 1.81 s + 1.81 s.
- RHEL 9 in LSM mode: 2.29 s + 2.29 s.
- 6.17: 0.03 s + 1.73 s (fmod_ret), 0.03 s + 2.2-2.3 s (LSM).
- AL2023 6.1: 0.02 s + 2.84 s (fmod_ret), 0.02 s + 3.61-3.73 s (LSM).
Removal of pinned links on 6.1 is synchronous in the unpinning process; on 6.8+ the deferred detach holds ftrace's direct_mutex. One timer per reaper would mean up to about 150 sleeping root processes at one run every 2 s (about 250 MB, 750 threads).
[documented] Each trampoline's ftrace_ops is FTRACE_OPS_FL_DYNAMIC, so unregistering runs synchronize_rcu_tasks_rude and synchronize_rcu_tasks under ftrace_lock and direct_mutex. 424f6a361096 (v7.0-rc1) gives x86_64 a single static ops, which arm64 lacks through v7.3-rc4.
[inference] The plane's fail-closed guarantee needs a lifetime bounded below by runs, not launchers. Two builds used alternately would thrash under an immediate other-build sweep.

Security argument: Removal requires the exclusive build lock (so no Prepare of that build runs meanwhile) and an empty run_set, so a build is never detached under a run it enforces. This is fail-closed by construction, where 'last launcher out' detached the record, and would detach the plane, under an orphan whose launcher had died. A cross-build sweep depends only on the key contract and keeps whatever it cannot read. Lingering programs return 0 on a run_set miss and decide nothing for the host. The lock and timer live in the verified /run/tego (ADR 0034), so no other user can split them.

Options considered: Chosen: a bounded linger with one timer per build, a keys-only sweep off every run's path, and the run-set lower bound.
Rejected:
- A (sweep only, no linger): 0.1-1.3 s a run on every kernel before x86_64 7.0 and on all arm64; with the plane, 1.8-3.7 s.
- C (tegod holds the links): bpffs pins already outlive processes; P3, with an API in the TCB.
- D (kprobe, kprobe_multi, tracing_multi): no bpf_d_path from kprobes; kprobe_multi is missing on both AL2023 kernels; 3-5x cost per hit; no multi form for fmod_ret; tracing_multi only from 7.2.
- G (wait for the kernel): RHEL 9 is supported until 2032; arm64 pays at every version.
- Keeping builds attached indefinitely: unbounded idle cost.
- A timer per reaper: up to ~150 sleeping root processes.
- The build sweep in tego run: puts a 2.8-3.7 s synchronous removal on 6.1, or direct_mutex contention on 6.8+, on the run's path.
- Removing other builds at once: two builds used alternately thrash.

Consequence: A run within the linger adopts the pinned build, with no load, verify, attach or detach on its path. The first run after an idle period pays attach once; removal moves to the reaper or timer.
Idle cost per host call while a build with ADRs 0016 and 0024 lingers (measured):
- Open: +197 ns (fmod_ret) or +222 ns (LSM) on 6.17; +218 ns on 6.8; +236 or +308 ns on 6.1.
- Anonymous mmap: +70 to +170 ns.
- mprotect: +76 to +118 ns (+18-24%).
- 5-op fs iteration: +1.2 to 1.5 µs (+11-18%).
- fork+exec: +3 to 8 µs.
- A stdlib compileall: within ±2% noise.
A removal holds ftrace's locks for 1.7-3.7 s, and other trampoline attaches on the host wait meanwhile. With the build kept a run costs 136-204 ms, which still exceeds kill test 4's go-kind margin (110-157 ms bare, 2x budget), so linger does not close R18 there; the ~140 ms floor and capture's per-run probes are named as the remaining budget items.

Implementation plan:

Step 1 (S, the leak): enforce/cgroup pins.go SweepBuilds(stateDir, bpffs, linger, now), called by the reaper after its launcher exits and by tego stop and gc, with a keys-only run_set read. Tests as root in GUEST and on MATRIX:
- SIGKILL the last launcher with linger 0: the reaper removes the build, bpftool link shows no tego link, and the directory is gone.
- Another build idle past linger is removed.
- A build with a live orphan run is kept.
- An unreadable run_set (a test build with a different key size) is kept, with a doctor row.
Step 2 (S, run-bounded): Detach's last-out check and releaseKernel also require an empty run_set. Test: launcher A is SIGKILLed with its agent alive (reaper held by a hook) and launcher B of the same build exits: the build stays. Once A's orphan is swept, the build goes.
Step 3 (M, linger):
- spec/config/v0 bpf: {linger: 5m}, read from /etc only; a user layer that sets it gets a compile note.
- The lock mtime; the timer file; the two-build cap; the doctor rows.
Tests:
- Two runs 2 s apart adopt with no load, verify or attach (136-204 ms expected).
- A run after the linger reloads.
- A third build evicts the longest idle.
- Killing the timer leaves the build until the next reaper, stop or gc.
Measure kill test 4 at tier cgroup on MATRIX with the build kept (§9's condition) and record what remains.
Docs: ADR 0022; ARCHITECTURE §6 Pins (item 8's guarantee) and §15.1 (cost table); enforce-cgroup-observe R14, §3, E29, E33, §9; spec/config/v0 (bpf.linger); OPERATIONS (gc --builds).

*Amended 2026-09-24 (kill test 4, tier cgroup):* Steps 1–3 are built in `internal/runtime/enforce/cgroup` (linger.go):
the last launcher out stamps the lock's mtime and starts the build's timer; `SweepBuilds` removes a build only under
its exclusive lock, with a keys-only run set naming no existing cgroup and past the linger, with the two-build cap;
`tego gc` sweeps as root and `gc --builds` skips the idle condition; `bpf.linger` is read from /etc only; (7)'s
re-creation of an idle build whose ring disagrees is in Prepare. Not built: doctor's rows (8), and the reaper of
ADR 0020, so a timer is started by the last launcher out itself rather than by a reaper after it exits. Measured on
6.17 in the 1536M/2-vCPU guest with the build kept: a root run of `true` at tier cgroup under kill test 4's kind of
contract took 140 ms, of which about 95 ms was the fanotify listener's loop waiting out its 100 ms poll timeout
after the run was cancelled; with a wake on cancellation (fanotify.go) the same run takes 45 ms (landlock: 19 ms).
So the ~140 ms floor this ADR names was mostly that wait, not the tier's cost.

*Amended 2026-09-24 (doctor rows):* (8)'s doctor rows are built: as root, `tego doctor` lists every build with its
hash, whether a launcher holds it, its idle time and when the linger removes it, its programs, links and capture probes
(ADR 0026 (7)) and its pin directory, text and `--json` (`cgroup.ListBuilds`); `tego gc --builds` removes idle ones
now. Memlock per build is not shown yet. A build's removal takes its `uprobes/` directory with it.

*Amended 2026-09-24 (ADR 0026 built):* (7) is withdrawn: ADR 0026 removed the shared ring, each run's rings are made at
its `Prepare` and removed at its `Detach`, so no pinned ring size can disagree with `record.ringbuf` and there is no
idle build to re-create for it (enforce-cgroup-observe E33). Doctor now shows each build's run rings and what they
charge against `bpf.ring_budget`; an idle build holds no ring.

*Amended 2026-09-24:* the timer and the capture probes' detacher
(ADR 0026 (7)) ran in the launcher's cgroup, so stopping the systemd unit, CI job or `systemd-run --scope` the
launcher ran in killed them, and the build's programs and a libssl's probes stayed attached host-wide until a gc.
Both now start in `tego.slice/helpers.scope` under the cgroup2 root (`internal/runtime/cgroup.StartHelper`, clone3
into it), which no unit owns; where the launcher cannot make or enter it the helper starts in the launcher's cgroup
as before and its environment says why (`TEGO_HELPER_UNPLACED`). And a helper killed all the same is made up for
off its own process: every `Prepare`, once it holds its own build's lock, sweeps the other builds as the timer would
(`SweepBuilds`: lock taken exclusively without waiting, run set empty of live cgroups, idle past the linger), a
run's capture source removes the probes of every library no run holds whose grace is over (`uprobe.SweepLibraries`),
and a root `tego doctor` does both, as `tego gc` does. That puts a removal on a run's path when, and only when, a
helper died, which (4) otherwise keeps off it. Root always sees and removes both: they are bpffs pins.

*Amended 2026-09-29 (ADR 0020 built):* the reaper's build duties are built (`cgroup.ReapBuild`): once a dead
launcher's run is purged and no launcher holds the build lock, the reaper stamps the lock's mtime and, at
`bpf.linger` 0, removes the build (`SweepBuilds`), or else starts the build's timer as a last launcher out does. A
run ended by its launcher leaves these to the launcher, as before.

*Note 2026-09-29:* an earlier move to `helpers.scope` left out ADR 0026's ring trimmer
(`tego __ring-trim`), which still started in the launcher's cgroup and so died with its unit, leaving a slot's rings
above the pool charged to `bpf.ring_budget` until a later reclaim or gc. It now starts there too; the timer, the
trimmer and the probe detacher share one spawn (`cgroup.StartHelperExec`).

*Note 2026-09-30:* a sweep that keeps a build because its run set names a live cgroup now stamps
the build lock's mtime: the build is not idle. Before, every later sweep, each `Prepare`'s on a run's start path
among them, listed the whole cgroup tree again for that build for as long as an orphaned run lived. The next sweep
now looks again a linger later, as the timer already did; (1) and (8) are unchanged.

*Note 2026-09-30 (P7, measured by the guest perf suite, enforce-plane §10.1; kernel 6.17.0-41, 4 vCPUs):* the cost of a run after the build is
gone is, at best of three after `tego gc --builds`, 1.8 s (tier cgroup, fmod_ret plane), 2.1 s (bpflsm) and 3.3 s (cgroup, LSM plane), of which
`trace_proc`'s load is 1.6 to 2.6 s, against 90 ms with the build kept; the first plane run of a boot takes 5.9 to 17 s more because doctor's D7
loads every program (7.8 s), which the run cache then keeps for the boot. "Up to 2.3 s" therefore holds for the plane's attach alone, not for the
run: the cold-start budget is a limit of 9 s (a guest test fails over it, `cold.<mode>.ms` in `test/perf`) with 2.3 s as the target, which the LSM
mode misses on this kernel. The linger stays `bpf.linger` 5 minutes: a run after a longer gap pays the cold figure once, and a shorter linger would
pay it more often for no lower idle cost the ADR could measure. (An earlier 400 to 900 ms of every warm start was a bug, not the linger: the
plane's objects were reloaded on each run; see enforce-plane §10.1.)

*Note 2026-10-19 (enforce-cgroup-observe R14):* a build's removal returns only
once the kernel has released the build's links. The timer's sweep, `gc --builds`, a reaper's `ReapBuild`, the sweep
of `Prepare` and `tego stop` for a build whose timer cannot start, and the last launcher out where `bpf.linger` is 0
open each link before they remove its pin and close it after, then wait (at most 30 s) until the kernel has freed the
programs those links ran. Before, the pin's removal left the release to the kernel's workqueue (6.8 to 6.17) or to an
RCU callback (RHEL 9's 5.14) after the removal had returned, and the next run's load waited for it in
`bpf_trampoline_get` (the 1.4 to 3.3 s of the note below). The teardown's cost is unchanged and stays off a run's
path where the build lingers: the timer pays it. With a linger of 0 the last run out pays it on its way out (0.1 to
6.1 s for the build on 6.17 and 5.14, 3.1 to 4.8 s with a plane) instead of the next run on its way in. Measured on
6.17's bpf boot, before and after, back to back: cold 7.52 / 6.42 / 7.03 s became 5.11 / 4.52 / 4.45 s (lsm /
fmod_ret / bpflsm), the settled figure, with 0.2 ms of teardown left when `gc --builds` returns (enforce-plane §10.1
"The teardown overlap, fixed"). The limit, the target and the linger are unchanged. The planes' links go first (R20),
not the tracing links first planned, and the fallback for a pin that cannot be opened as a link logs
nothing; R14's amendment says why neither changes what a removal leaves.

*Note 2026-10-19 (enforce-plane §10.1 "Cold attribution"):* the 09-30 figures above are stale. On the
same 6.17 guest the cold start is now 5.5 to 6.8 s (every mode misses the 2.3 s target) and the boot's first run 13.6 to
17.8 s (samples taken with the attribution on), and the attribution names three causes, each past its decision gate:
`trace_proc`'s verification (3.0 to 3.2 s with no wait in it), the removed build's teardown, which `gc --builds` and
this ADR's sweep leave to the kernel's workqueue so the next load waits 1.4 to 3.3 s on a trampoline's mutex (a cold run
after the 3.0 to 4.4 s teardown has finished takes 3.7 to 4.0 s), and doctor's probes closing their links on the first
run's path. The limit stays 9 s, the target 2.3 s and the linger 5 minutes; removal that finishes the teardown before it
returns is the next change.

*Note 2026-09-30:* `Prepare`'s sweep applied the lingering cap, so a run of a fourth build
removed the third of three builds idle inside their linger on its start path, though no helper had died. It now
removes only builds idle past the linger (`SweepOptions.ExpiredOnly`); the cap stays with the timer, the reaper, `tego
stop` and gc, as (4) and an earlier amendment say.

*Note 2026-09-30:* three gaps in the build duties. (a) A reaper did them only when
`PurgeRun` returned no error, so a failed ring trim or slot release after the run's cgroup was gone left the build
with a stale mtime and no timer; it now does them unless the cgroup is still listed (`ErrRunAlive`), since (1)'s
run-set check already guards the removal, and `ReapBuild` returns its errors for the reaper to log. (b) The lock's
exclusive takers other than a launcher (a sweep, the reaper, a ring reclaim's probe, `removeStaleState`) now check,
once they hold it, that its name still leads to their file, as a launcher does (`lockBuildExclusiveNB`). (c) A last
launcher out that asked `lastOut` during another process's momentary exclusive probe read itself not last; with a
linger it now stamps the idle start before it asks and asks once more 5 ms later.

*Note 2026-09-30:* the earlier note's (c) had the same race in a reaper: `ReapBuild` read a
momentary exclusive probe of the build lock (another build's sweep, doctor's `ListBuilds`, a ring reclaim's
`buildRunning`) as a launcher and left the build of its run, the last, attached with no timer and no idle stamp.
It now asks a busy lock four times, 5 ms apart, before it concludes a launcher holds it.

*Note 2026-10-05 (D1, D2, D4):* three defects in the timer (`runTimer`), (3) and (8) unchanged. (D1)
While a launcher held its build the timer backed off `max(linger, 1m)`. The leaving launcher's own timer exits on the
held timer lock, so with a linger under a minute (8)'s bound broke: a 10 s linger, a launcher leaving at +1 s, removed
at +60 s. It now backs off `max(linger, 1s)` and at each look probes its own build only (its lock taken exclusively and
let go at once, as a sweep's look does), sweeping again at the deadline the launcher's last-out stamp sets; the
launcher left no earlier than the look that found it held, so that deadline is no earlier than the next look, and
the build goes by its leave plus the linger and the timer's one second of slack (+12 s in the fake-clock test). A
build kept for a live run or an unreadable run set is still asked about `max(linger, 1m)` later: those looks list the
cgroup tree or open the pinned map. (D2) A timer that found its build gone returned still holding
`bpf-<hash>.timer`; a launcher that made the build again, ran and left last in that window started a timer that
exited on the lock, and the build lingered with no timer until the next Prepare, doctor or gc. The timer now lets the
lock go, then looks whether the build is there again and, if so, takes the lock again and keeps going, or exits when
the new timer took it first. It takes the timer lock only by a name that still leads to the file it locked, as a
build lock's exclusive takers do: a sweep unlinks a gone build's timer file when no one holds it. (D4) The timer
read the build lock's mtime by path; it now stats it relative to the verified directory's descriptor
(`hoststate.Dir.Stat`), as ADR 0034 (3) requires of every file in `/run/tego`. Tests:
`TestTheTimerKeepsTheBoundWhenALauncherLeavesWithinTheLinger`,
`TestTheTimerBacksOffALingerWithASecondsFloorAndProbesOnlyItsOwnBuild`,
`TestTheTimerTakesItsBuildBackWhenItIsMadeAgainAsItExits`, `TestTheTimerLeavesABuildMadeAgainToTheTimerThatHoldsItsLock`,
`TestStatLooksRelativeToTheVerifiedDescriptor`.

*Amended 2026-10-06 (D3):* `Prepare` re-arms a dead timer instead
of removing the build on the run's start path, which restores (4) on every kernel. An earlier fix's sweep in `Prepare`
removed an expired build itself: on 6.1 and 5.14, where an unpin detaches synchronously, that put 2.8 to 3.7 s on a
run's start whenever a helper had died, and, since a live timer sleeps a second past its deadline, also in that
second when none had (D3). `Prepare`, once it holds its own build's lock, now starts the timer of each other build
idle past its linger that no launcher holds and whose timer is not running (`rearmExpired`, the same exec into
`helpers.scope` as the last launcher out's), and the timer removes it; it removes a build itself only when the timer
cannot be started (an exec that fails, or a Go test binary that names no stage binary). Whether a timer runs and
whether a launcher holds a build are read from `/proc/locks` (an exclusive flock on the timer file's device and
inode; any flock on the build lock's), never by taking the lock: a momentary probe of the timer lock would make a
timer starting in that moment exit, as a probe of the build lock did to a last launcher out (the earlier note's (c)). The
table's format is stable since 2.6 and the same on 5.14 to 7.x and arm64; a table that cannot be read shows no
holder, so each build gets a timer, and one started beside a live timer exits on its timer lock (an exec, not a
removal). A timer writes its pid into its timer file, for doctor, and asks for a busy timer lock once more 5 ms later,
since a sweep's `removeStaleState` holds a gone build's timer file for a moment. A build gone with only its plane
directories left gets a timer too, whose first sweep removes them. Tests: `TestPrepareRearmsTheTimerOfABuildWhoseTimerDied`,
`TestPrepareLeavesAnExpiredBuildToItsLiveTimer`, `TestPrepareRemovesAnExpiredBuildWhoseTimerCannotStart`,
`TestRearmTimersStartsTheTimerOfEveryBuildWithout`, `TestRearmTimersStartsATimerWhenTheLockTableCannotBeRead`,
`TestRearmTimersSweepsABuildWhoseTimerCannotStart`, `TestParseProcLocksReadsHeldFlocksOnly`, `FuzzProcLocks`,
`TestTheLockTableShowsAHeldFlock`, `TestTheTimerWritesItsPidIntoItsTimerFile`, `TestATimerAsksForABusyTimerLockOnceMore`;
as root in the KVM guest, `TestIntegrationABuildWhoseTimerDiedIsRemovedAtTheNextPrepare` (a real timer removes the
build within 3 s of the next `Prepare`, whose `prepare.lock-slot` stays under 50 ms).

*Implementation note 2026-10-16 (Prepare's reading of a timer's liveness):*
`Prepare` no longer reads `/proc/locks`. Measured in the KVM guest with the start phases `prepare.rearm` and
`prepare.rearm.start` (inside `prepare.lock-slot`): when a build's timer had died, the re-arm pass took 7.9 ms of
the slot on 6.17 and 47.9 ms of its 48.1 ms on AL2023 6.1, against the slot's 50 ms target, of which the timer's exec
was 0.3 to 0.5 ms. The rest is the lock table's read (29 to 60 ms a read on its own on 6.1): `locks_start` takes `percpu_down_write(&file_rwsem)`, which
waits for an RCU grace period, and every flock on the host waits behind it meanwhile. `Prepare` now reads the pid a
timer writes into its timer file once it holds its lock, and takes the build as timed when that pid is a process
whose command line is `<exe> __bpf-linger <hash>` and whose real, effective, saved and filesystem uids are 0, read from
`/proc/<pid>/status` through one open of the process's directory (`timerRunning`, `isTimerProcess`). Neither lock is
taken, so the earlier note's (c) reasoning holds. The reading errs one way only: a timer it does not show (an older tego's
that wrote no pid, a pid of another pid namespace) gets a second timer, which exits on its timer lock; a user cannot
make a process that reads as root's timer, since status carries its own uids even when it made itself undumpable. A
build a launcher holds is no longer told apart on this path either: one that shows no timer gets one, which waits for
its launcher as any timer does (`runTimer`) and shows alive to the next `Prepare`. `/proc/locks` stays the reading
for a pass off the run's path (`RearmTimers`), and there only for builds whose timer file shows no live timer, read at
most once per pass. Rejected: keeping the table read on the run's path (2 ms under the target on 6.1, and a grace
period is longer on a loaded host); probing the timer lock for a moment (a timer starting in that moment exits); OFD
locks with `F_OFD_GETLK` (a query without taking the lock, but flock and OFD locks do not see each other, so timers of
older tegos would go unseen and the timer lock's format would change). Tests:
`TestRearmTimersStartsTheTimerOfEveryBuildWithout` (Prepare's form starts timers for the builds with no live pid,
reads no table), `TestRearmTimersReadsTheLockTableOnlyForABuildWithNoTimerShown`, `TestIsTimerProcessReadsUidsAndCommandLine`,
`TestIsTimerProcessKnowsARealTimer`, `TestPrepareLeavesAnExpiredBuildToItsLiveTimer`; in the guest,
`TestIntegrationABuildWhoseTimerDiedIsRemovedAtTheNextPrepare`, which also logs a lock-table read's cost (on 6.1 `prepare.lock-slot` is now 2.7 ms on the boot with `bpf` in `lsm=` and 4.2 ms on the default one).

*Implementation note 2026-10-16 (D6):* `tego stop` now does its part of (4) and (8). A root stop
(root of the initial user namespace, as gc's bpf sweep) whose run is stopped or not running, exit 0 and not
interrupted, starts the timer of every build that no launcher holds and whose timer is not running
(`cgroup.RearmTimers`: the timer's pid as `Prepare` reads it, then, for a build that shows none, `/proc/locks`, read
once; the same exec into `helpers.scope` as `Prepare`'s pass), inside its
linger as well as past it, since (8) bounds a build's stay only while its timer lives; the timer removes it at its
deadline and applies the lingering cap. Stop re-arms rather than sweeps, so its own latency is an exec per timerless
build, not a removal's 1.7 to 3.7 s; it removes a build itself only when the timer cannot be started, past its linger
only, as the timer would. Best effort: a failure is one `[io]` line on stderr and the exit is unchanged. A user's stop
does nothing here: the pins and the state directory are root's. Rejected: sweeping in stop (stop's latency becomes a
removal's on 6.1 and 5.14, and the cap is the timer's anyway); re-arming only expired builds, as `Prepare` does (a
build inside its linger whose timer died would then outlive (8)'s bound until the next Prepare after its deadline).
Stop names its own image as the timer's binary, and a Go test binary never starts itself as one (`timerExe`, shared
with `Prepare`'s pass): re-executed with `__bpf-linger`, internal/cli's test binary would have run its whole suite
detached, as root, in the guest. A `/proc` of a child pid namespace omits the locks whose holders it cannot see; read
there, the pass starts a timer that exits on its timer lock, or waits for the launcher, and removes nothing on that
reading. `Prepare` reports its pass as the start phases `prepare.rearm` and `prepare.rearm.start`, inside
`prepare.lock-slot`. Tests: `TestStopRearmsTheBuildTimersAsRoot`, `TestStopLeavesTheBuildsAloneUnprivileged`,
`TestStopExitsZeroWhenTheBuildPassFails`, `TestRearmTimersStartsNoTestBinaryAsATimer`; as root in the KVM guest,
`TestIntegrationStopRearmsABuildWhoseTimerDied` (the real binary's stop of a run that is not running; the timer it
starts removes a build whose timer died within 3 s).

*Implementation note 2026-10-17:* two consequences of
starting timers from `Prepare`, at the start of a run rather than on a launcher's way out, are closed. (a) At a
`bpf.linger` of 0, the old rule under which no build has a timer, `Prepare`'s pass starts none: every build is past a
linger of 0 and the pass reads no lock table, so it had given every other build in use a timer, which found the build
busy and took its lock every second for as long as its runs lasted. It now removes each other build that no launcher
holds itself (`sweepBuild`, which leaves a held one to its launcher), as the sweep before the re-arm did. Rejected:
skipping the pass at 0 (a build a dead launcher left would stay attached until a gc); keeping the timers and saying
so (per-second lock probes the linger-0 model does not foresee). (b) A detached helper is now waited for in a
goroutine of its starter instead of released (`rcgroup.StartHelper`, `reapHelper`): a timer `Prepare` started exits
a linger later, or at once on a busy timer lock, and each stayed a zombie child of `tego run` until the run ended,
since the launcher reaps only its agent's cgroup tree. A starter that exits first leaves the helper to init, as
before. Rejected: a double fork (a second process per helper, and an intermediate one to reap all the same). The
ADR 0021 start-site row of `startTimerProcess` now names `Prepare`'s pass (before Arm's first mark) and stop
(no group) among its callers. Tests: `TestPrepareAtLingerZeroStartsNoTimer`, `TestStartHelperReapsItsHelper`.

*Implementation note 2026-10-19:* the re-arm pass (`rearmTimers`, behind
`Prepare`'s pass and `tego stop`'s `RearmTimers`) refuses a state directory of the caller's own beside pins under
the host's bpffs with `ErrHostState` (`lockRootOf`) before it lists a build, as every other entry point does since
pins there lock in `/run/tego` only (ADR 0034). Without it the pass listed the pins first and gave
any other error, or none when no build was pinned. `Prepare` had already refused the pairing before its pass; stop
passes the host directory. Test: `TestHostPinsLockOnlyInTheHostStateDir` (its `RearmTimers` row).

*Implementation note 2026-10-20 (D5):* doctor's build rows are complete for
(5) and (8). `cgroup.ListBuilds` takes the states of the sweep doctor runs just before it (doctor keeps sweeping as gc
does, the cap included; only its report changes) and gives each build no launcher holds the reason that sweep kept it
(`kept`): a run it enforces is alive, or its run set cannot be read, with what the read met (`kept_cause`; the sweep's
`BuildState.Cause`), or the error a sweep met on it. Neither keep is overridden by `gc --builds`' Force, so such a row
no longer says gc removes it. A row says whether the build's timer runs and its pid, read as `Prepare` reads it (the
pid in its timer file, that process's command line and uids; `timerPID`), never by taking or probing a lock and never
from `/proc/locks`, whose read waits for an RCU grace period (note 2026-10-16); a timer of an older tego that wrote
no pid shows as none. A row gives the build's memlock: the fdinfo `memlock` of every program and map pinned under the
build and its plane directories, of every program a pinned link attaches and of every map those programs use, each
id once (a map the build and its plane share is counted once); the run rings, reached only through their outer map,
stay `ring_bytes`. An object whose pin cannot be opened or whose fdinfo reports no memlock (RHEL 9's 5.14 for some map
types) is counted in `memlock_unreported`, and a build with nothing reported shows `n/a`, never 0. Rejected: summing
only the pinned maps and programs (the `.rodata`/`.bss` maps the programs use, and the program of a link whose
program pin is gone, are charged all the same); counting the rings in memlock (they are charged to `bpf.ring_budget`
and shown there already); a `linger_left_s` field (the row's text says it, and `idle_s` with the machine's linger
gives it). Tests: `TestListBuildsSaysWhyABuildIsKeptWhetherItsTimerRunsAndWhatItCharges`,
`TestASweepKeepsABuildWhoseRunSetCannotBeReadAndSaysWhy`, `TestDoctorBuildsGolden` (text and `--json` goldens); as
root in the KVM guest, `TestIntegrationABuildWhoseRunSetCannotBeReadIsKeptAndShown` (step 1 test 4: a run set of key
size 4 pinned under a build past its linger; the sweep, Force, a real `tego gc --builds` keep it, a real `tego doctor
--json` row names it) and `TestIntegrationBuildMemlockIsBpftoolsSum` (a real build's memlock equals the sum bpftool
reports for the objects it finds from the same pins).

*Implementation note 2026-10-20 (C8):* steps 1-3 are tested through the real
binary, as root in the KVM guest, with `bpf.linger` set by `TEGO_TEST_LINGER` (a test build's machine config hook,
as `/etc/tego/config.yaml` would set it, ignored under AT_SECURE; it composes with `TEGO_TEST_PLANE`). The
launcher hands its linger to its reaper and to the build's timer, so both follow it. Every run of the package's
binary is of one build, so each test first ends the timers earlier tests left for it, which sleep to a linger of
their own and hold the timer lock. `TestIntegrationLingerZeroKillRemovesTheBuild` (step 1 test 1): at linger 0 the
only launcher is SIGKILLed; once its reaper is let go the build and its plane directories are gone, no link the
kernel holds attaches a program of the build (`link.Iterate`), and no timer runs.
`TestIntegrationABuildOutlivesItsLastLauncherWhileAKilledOnesRunLives` (step 2, at linger 0 and 2 s): A is
SIGKILLed with its reaper held, B of the same build runs and exits, and the build stays with A's run links past B's
linger; after A's reaper purges A's run the build goes, at once at 0, by the reaper's timer at 2 s and never inside
the linger. `TestIntegrationAKilledTimerLeavesTheBuildUntilStop` (step 3): a run at linger 5 s exits, its timer (in
`tego.slice/helpers.scope`) is SIGKILLed, the build stays past the linger, and a root `tego stop` of the finished
run starts the timer again, which removes it. Verified 2026-10-20 in the KVM guest on both boots of 6.17, RHEL 9's
5.14 and AL2023's 6.1, untagged and `tegobpf`. On 6.1 a removal of the build (57 programs) took 7 to 10.5 s from the
reaper's release, longer than the 1.7 to 3.7 s measured on 2026-09-24 for a build with a plane: at linger 0 the reaper
removes the build itself before it exits, so the tests wait for its exit up to `teardownWait` beyond their 10 s. C8, the file-capability two-uid test and its conditional fix of the pin
modes, is not built: ADR 0042 (accepted 2026-10-05, O1) answered "No" to multi-user file-capability hosts and withdrew the file-capability
copy, which is now refused at start for every command but `version` (ADR 0042 (3)(a),
`TestFileCapabilityCopyIsRefused`, root-must-pass), so no second uid's launcher can reach a build another uid
pinned; every tier-2 and tier-3 launcher is root and its pins are root's. The test and the fix belong to the ADR that
may bring a single-administrator file-capability copy back (ADR 0042 (3)(c), whose conditions already name ADR 0034's
two-uid tests).

*Implementation note 2026-10-20 (step-2 kill test):* the step-2 test at
a linger of 2 s found (8)'s bound broken where the 2026-10-05 note left the timer's other back-off: the last launcher
out started the build's timer, which found A's orphaned run alive and backed off `max(linger, 1m)`; A's reaper then
purged the run, stamped the lock and started a timer that exited on the held timer lock, so the build stayed attached
up to a minute after its last run ended. Between its minute-apart looks at the run set the timer now reads the build
lock's mtime once a linger, a second at least (`lockMtime`, through the verified directory's descriptor); a new stamp
(the reaper's `ReapBuild`, or a launcher leaving last) sends it back to wait out the linger from that stamp, so the
build goes by the stamp plus the linger and the second of slack. A run that ends with no reaper alive stamps nothing,
and its build keeps the minute's back-off: (8)'s "while that build's timer lives" holds, and the reaper is what ADR
0020 provides for every orphan. The cost is one `fstatat` a linger. Rejected: the run-set look every linger (two
listings of the whole cgroup tree a linger, which the minute floor exists to avoid); waking the running timer from the
reaper (a signal to a pid read from the timer file, a second path to the same deadline). Test:
`TestTheTimerKeepsTheBoundWhenTheRunItWaitedForIsReaped` (fake clock: 10 s, reaped at +1 s, removed by +12 s), failing
before the change at +60 s; `TestTheTimerRetriesASweepThatCouldNotListTheBuilds` now sees its minute as two 30 s looks.

*Implementation note 2026-10-20:* doctor's sweep answers why it kept a build only
for one past its linger: it leaves a build inside its linger before reading the run set, while `gc --builds`' Force
reads it and keeps the build for a live run or an unreadable run set. So in step 2's state (A's launcher killed, its
reaper alive, B out last) the row said gc removes the build now and gc removed nothing. `ListBuilds` now reads the run
set of every build no launcher holds that the sweep did not keep (inside its linger, or not named), read-only (the
pinned map opened `BPF_F_RDONLY`, no row of a gone cgroup deleted), and lists it `kept` as Force would. A kept row
also says whether its timer runs, as every other idle row does. Rejected: softening the row's text to "unless a run
it enforces is alive" (doctor would still not know, and the operator would have to find out); a sweep mode that reads
the run set inside the linger (it stamps the lock on a live run, which is the sweep's business, not a report's).
Tests: `TestListBuildsSaysWhyABuildIsKeptWhetherItsTimerRunsAndWhatItCharges` (lingering live, lingering unreadable,
unswept), `TestDoctorBuildsGolden`; as root, `TestIntegrationALingeringBuildALiveRunNeedsIsListedKept` (a real build
inside its linger whose run set names a live cgroup, and a gone one whose row the listing leaves).

*Implementation note 2026-10-20 (a memlock of 0):* `memlock_unreported` counted every object whose memlock was 0, as cilium's `Memlock()` reports a 0 as absent; the
three empty LPM tries every build holds (`tego_net_cidr`, `tego_net_ingress`, `tego_unix_names`) say `memlock: 0`
in their fdinfo on 6.17, 6.1 and 5.14 alike, so every healthy build read "with 3 objects unreported", and the
2026-10-20 note's "RHEL 9's 5.14 for some map types" was those tries. The `memlock:` line is now read from the
object's own fdinfo (`fdinfoMemlock`): a line that says 0 is a 0, and only a missing line or a pin that cannot be opened
is unreported. Tests: `TestFdinfoMemlockTellsAReportedZeroFromNone`, the listing test's empty trie; as root,
`TestIntegrationBuildMemlockIsBpftoolsSum` and `TestIntegrationPlaneBuildMemlockIsBpftoolsSum` (with the host's plane,
whose maps the build shares) now require no object unreported.

*Implementation note 2026-10-20 (the kill tests' cells):* the kill tests now run in every cell the machine offers (`killCells`): tier cgroup with each
decision-plane mode the machine passes pinned by `TEGO_TEST_PLANE` (lsm, fmod_ret; the fanotify listener where it
passes none), and tier bpflsm where doctor offers it; a cell the machine lacks is logged, never skipped silently. The
cells share one build of the binary, each with a project, ledger root and config of its own (`reapEnv.fresh`). The
waits for a build's removal after the timer or a stop allow the kernel's teardown up to `teardownWait`, as the
reaper's waits do (6.1 took 10.6 s against a 13 s bound). Verified 2026-10-20 in the KVM guest, untagged and
`tegobpf`: 6.17 with bpf an active LSM (cgroup-lsm, cgroup-fmod_ret, bpflsm) and without (cgroup-fmod_ret; doctor
offers no lsm plane or tier bpflsm there). The same kill, listing and memlock tests passed, on both boots and in the
same cells, on the matrix rows rhel-9 (5.14), al2023 (6.1), ubuntu-24.04 (6.8), al2023-6.12 (6.12) and fedora-7.0
(7.0), with no object unreported and memlock equal to bpftool's sum with and without a plane. Not run: arm64, which
the VM matrix has no row for (`test/vm/fetch-kernel.py --list` is x86_64 only), so the arm64 cell stays open
until the matrix gains one.

*Implementation note 2026-10-20:* a build's memlock reads each object's fdinfo
wholly inside `internal/bpf`'s `MapFD` or `ProgramFD` lend (`readFdinfo`: open, read and close before the lend
returns). An earlier version opened `/proc/self/fdinfo/<n>` inside the lend and read it after, on the ground that the
open resolves the path at once; that holds for `/proc/self/fd/<n>` but not for fdinfo, which procfs looks the number
up for again at each read (fs/proc/fd.c `seq_show`), so a read after the lend would describe whatever file then held
the number, or fail once it was free. No caller reached it (each one closes the object only after `mapObject` or
`programObject` returns), but the lend did not cover the use. `bpf.Memlock`, which charges a run's rings against
`bpf.ring_budget`, read its map's fdinfo through `m.FD()` with no lend at all; it now reads it the same way inside
`MapFD`, and `internal/bpf`'s unleased `fd` site in `tools/fdcheck/baseline.txt` is gone. Open for ADR 0023's fdcheck:
its `lentSinks` admit `unix.Open`, `Openat` and `Stat` of any path built from a lent number, which is right for
`/proc/self/fd/<n>` and not for `/proc/self/fdinfo/<n>`, where only a read inside the lend is a use of it. Tests:
`TestReadFdinfoReadsTheLentNumbersOwnFdinfo` (a pipe's write end whose number then gets a read-only `/dev/null` by
`dup2`: an fdinfo opened before and read after says `O_RDONLY`, the old pattern's wrong file, while `readFdinfo` has
read it before it returns and says `O_WRONLY`; a `readFdinfo` that returns without reading fails it); as root, the
memlock and ring tests above.

*Implementation note 2026-11-02 (the lock table read in pieces):* `tego stop`'s pass (`RearmTimers`) could take a
build its launcher held for one with no holder, and start its timer. `/proc/locks` is a seq_file over the host's
list of locks: each `read(2)` prints at most a page of lines (the seq_file buffer, 4 KiB on amd64) from one view of
the list, then lets the list go, and the next `read(2)` goes on at the next line's position in the list as it then
stands (`fs/locks.c` `locks_start`/`locks_stop`, `fs/seq_file.c` `seq_read_iter`). Locks let go between two reads
ahead of that position move the lines after them up, and the lines that were next are never printed, whoever holds
them. The pass read the table with `io.ReadAll`, whose first reads ask for 512 bytes, so it had a seam every eight
lines or so, and on GitHub's runners `TestRearmTimersStartsTheTimerOfEveryBuildWithout` saw its held build lock
left out (build-test and root-suites, 2026-11-02: "timers started: [deadpid expired gone held lingering]"); a pass
on a host whose other processes take and let go flocks meets the same. The table is now read a page or more per
`read(2)`, which leaves no seam in a table of up to a page, and a file the first read shows no holder of is looked
up again in a second read whose first `read(2)` asks for half a page, so that its seams fall half a page of lines
from the first read's (`lockHolders`). A lock either read lists is held: it was at a moment of the pass, and its
holder (a launcher, which starts the timer when it leaves, or a timer) answers for the build. A lock held all along
is missed by both reads only if half a page of the locks listed before it came or went between them; the pass then
starts a timer, which exits on the timer lock or waits for the launcher, as on any reading that shows no holder. A
pass whose first read shows the holder of every build it asks about reads once; one that starts a timer reads twice,
a second grace period on a path off any run's. Rejected: reading until two reads agree (a lock let go and taken again
at the same place in the list repeats a seam's loss in the next read, so agreement proves nothing, and the reads
are unbounded); reading descriptors' `fdinfo` (every descriptor of every process on the host, since the holder of a
build lock is not known); probing the lock (note 2026-10-16). On a 6.17 development host, with four goroutines taking and
letting go flocks, the old read left one of twenty held flocks out in three of four one-second runs; the new reading
left none out in twenty, its second read finding what the first missed in up to 37% of a run's passes. Tests:
`TestTheLockTableShowsEveryFlockHeldThroughChurn`, `TestRearmTimersLooksAgainWhereTheLockTableShowsNoHolder` (the
first read leaves out the held build's lock and an older tego's timer lock: the old pass started both timers),
`TestTheLockTableIsReadAPageAtATime`, `TestRearmTimersStartsTheTimerOfEveryBuildWithout` (the real table, read twice),
`TestRearmTimersStartsATimerWhenTheLockTableCannotBeRead` (read once).
