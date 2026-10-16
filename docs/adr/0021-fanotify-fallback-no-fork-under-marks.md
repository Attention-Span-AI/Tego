# ADR 0021: one arming point after the stage's exec, and no process start while fanotify marks exist

Status: accepted 2026-09-29 (proposed 2026-09-23), with the implementation amendments below; (2)-(4) implemented 2026-09-29, (5) with ADR 0028 S3 on 2026-10-04, (1) but for naming its hazards; (5)'s guest cells for every mutation it names run since 2026-10-06; the pairs harness built and the PIE run met on GUEST 2026-10-19; open: the pairs runs at full count, (6) and (7) (2026-10-06 notes). Amends ADR 0011 (fanotify as tier 2's open/exec mechanism), enforce-cgroup-observe R8 (the stage exemption, ErrStageLinked, ErrStageDenied) and E39, runtime-launch §4.1. FEATURES E9b keeps fanotify with a condition; E14 is unchanged.
Amended in part by ADR 0040 (accepted 2026-10-05): (5)'s "as it already does for deny_write (R15c)" no longer describes an admitted mechanism; the listener-only fallback refuses a contract with built-in `deny_write` targets before launch.
That amendment is superseded by ADR 0041 D1 (a) (accepted 2026-10-05): by default (5)'s R15c refusal is again the fallback's mechanism for those targets, best effort and disclosed; only `fs.assurance: kernel` refuses the contract there.

Decision: (1) Until ADR 0024's plane is selected on a host, fanotify stays tier 2's open and exec mechanism; from then on it runs only where doctor's mode probe finds no plane mode, and for E14's P2 file asks. The capability line says decision_plane: fanotify and names its hazards (E15, E16, E34, E35, E37, E40). (2) E39 is closed by ordering. At tiers 2 and 3 the launcher arms enforcement after the child stage's first execve has returned (signalled by the stage writing the notify fd number on the control pipe) and before it acks: in the fallback, arming places the group's marks; with a plane, arming inserts the run's run_set row (ADR 0024). (3) While any mark of its group exists, the launcher starts no process. Every process start in non-test code goes through one function, internal/platform/proc.Start, which refuses while a process-wide armed flag is set. Lint (forbidigo) bans os/exec, os.StartProcess, syscall.ForkExec, syscall.StartProcess and the clone, clone3, fork and vfork syscalls outside that package. The reaper (ADR 0020) and every helper start before arming; no build sweep starts a process. (4) The stage exemption's ignore mark, checkStage, ErrStageLinked and ErrStageDenied are removed: the group never sees the stage's exec or its loader, and a deny_read over the tego binary is decided like any other file. (5) The fallback converges on the plane's semantics (ADR 0028 S3): the supervisor refuses, itself and best effort, any mutation that the root walk refuses and Landlock would allow (a write, create, delete, rename or mkdir in a deny_read tree nested in a write entry), as it already does for deny_write (R15c). (6) Condition for E70 (P2): in the fanotify fallback, privileged commands are started by a helper forked before the marks, never by the launcher. (7) Removal condition: when every matrix row, amd64 and arm64, selects a plane mode for one release, the listener's enforcement role is deleted, and only E14's ask path keeps the code.

Why: [measured, E39 in the spec] tier2-pairs.sh stacks show the cycle: the stage waits in fanotify_get_response from do_open_execat; the launcher's forking thread waits in vfork; its other threads are parked while the runtime stops the world; the other launcher waits in openat on the first one's group. The guest froze at pair 5, and at pair 14 with the exemption removed. [documented] A whole-guest freeze with two concurrent tier-2 runs of one build, 3 in about 250 pairs, fits the same shape.
[inference, from the same stacks] The cycle needs this group's marks to exist while this launcher is in a vfork window; with marks placed after the stage's exec and no fork while they exist, it cannot form with a second tego file or with a third-party listener that opens on a marked mount.
[documented] Today the engine's only process start is exec.Command in internal/runtime/launch/launcher.go. [inference] A guard inside launch alone would be bypassed by the next process start elsewhere, and E70 is exactly such a start; only a process-wide, lint-enforced choke point holds.
[documented] The memfd-stage alternative is not small (stageFilter, the inherited descriptor, a fallback where vm.memfd_noexec=2).

Security argument: No verdict on the agent's actions changes: the agent does not exist until the ack, which comes after arming. The stage's own opens between its exec and the ack are tego's code. The guard is fail-closed and mechanical: a process start while armed fails the run rather than risking the host, and lint makes every start pass through it. E15, E16, E34, E35, E37 and E40 remain stated hazards of the fallback only; ADR 0020's reaper narrows E15.

Options considered: Chosen: arming after the stage's exec, plus a process-wide no-fork-under-marks guard.
Rejected:
- A stage exec'd from a sealed memfd: per-run copy, a vm.memfd_noexec=2 fallback, a stageFilter change, the exemption kept for the fallback.
- A listener in a process that never forks: a second process and IPC in the TCB, E40 untouched.
- A guard inside internal/runtime/launch only: bypassed by any other package's process start.
- Deleting fanotify now: E9b's deny would be absent where no plane mode loads, and E14 needs the listener.

Consequence: E39 closes for every tego file and every third-party listener, and the freeze's likely cause with it. The release build no longer has to be static and non-PIE for tier 2; ErrStageLinked and ErrStageDenied disappear. One arming point serves the fallback and the plane.

Implementation plan:

- internal/platform/proc: Start(cmd) with the armed flag (atomic); lint rules; migrate every os/exec use in non-test code (launch, doctor, cli) to it.
- internal/runtime run.go: split prepareEnforcement so the handle's Arm() runs after WaitNotifyFD and before Ack, and sets the armed flag in the fallback; ADR 0020's reaper starts before the stage.
- enforce/cgroup fanotify.go: remove the ignore mark, admission by identity, checkStage, ErrStageLinked and ErrStageDenied; remove enforce.Buildable's StageLinking check for tier cgroup.
- Tests: rewrite TestStageExecUnderGCNeverWaitsOnItsOwnGroup for the new order; a unit test that proc.Start refuses while armed; test/vm/tier2-pairs.sh with two copies of one build at two inodes, and with a helper third-party permission listener whose decisions open files on /, 1,000 pairs each in GUEST (6.17) and on MATRIX's AL2023 6.12 under the watchdog; the two-run freeze reproduction under the watchdog (500 pairs, no stall); a dynamically linked PIE tegobpf build runs tier cgroup.
- Item 5 lands with ADR 0028 S3.
Docs: ADR 0021; ADR 0011 amended; enforce-cgroup-observe R8 collapsed and E39 closed; runtime-launch §4.1; FEATURES E9b and E70 conditions.

*Amended 2026-09-29 (T1, TIER3-PLAN §11):* accepted as written. Checked against what landed since: the process
starts ADR 0026's notes added (`tego __uprobe-detach` and `tego __ring-trim`) happen after the run's enforcement is
released, so no mark of the launcher's group exists, and they go through (3)'s choke point like every other start.
(2)'s arming point is ADR 0024 (10)'s; item 5 still lands with ADR 0028 S3. Not built when this note was written:
`proc.Start` and its armed flag, the lint rule, the split `Arm`, and the removal of the stage exemption.

*Amended 2026-09-29 (implemented):* what the implementation changed.
- (2) The arming point is enforce.Armer, which runtime.arm calls once WaitNotifyFD has returned and before the recorder starts and the ack. **Amended:** in the fanotify fallback, Arm also inserts the run's run-set row and adopts its existing descendants, not the marks alone. The recorder keys on that row too: inserted at Prepare, it recorded the stage's exec of /proc/self/exe as the run's first `source=kernel` exec (stageFilter hid it from the capture followers only). Arming the row with the marks keeps tego's exec out of every record, gives the plane (T6) the arming point it needs, and makes the plane's "row inserted at Arm" today's behaviour. Prepare still loads, writes the verdict rows, places the rings and creates the group, and Attach still binds the network programs before the stage exists. A run with no cgroup id is now refused at Prepare. A failed Arm fails the run before run_start.
- (3) proc.Start is gated by a process-wide nesting count under a read/write lock. Start holds the read side across the fork and the child's execve, and Arm takes the write side, so a start that passed its check has finished its exec before the first mark exists. The listener arms before its first mark. It disarms when unmarkAll has removed every mark, or when the group closes, or when a first mark the kernel refused leaves none. **Amended:** Start also returns the started process's Identity, its pid and its start time from /proc/<pid>/stat, read before the caller can reap it, with Identity.Same and FS.Alive for any pid kept across time. launch.Child.StartBootNS now comes from it, and launch's own stat reader is gone. The run lock's check was already by start time (runtime.OpenStopTarget).
  Lint: depguard bans os/exec outside internal/platform/proc (test files, internal/testutil, tools/ and test/ excepted). forbidigo, with types analysed, bans exec.Cmd's Start, Run, Output and CombinedOutput, os.StartProcess, syscall.ForkExec and StartProcess, and SYS_CLONE, CLONE3, FORK and VFORK. Commands are built with proc.Command (type proc.Cmd). Migrated: the launcher, runtime/cgroup.StartHelper (the linger timer, the uprobe detacher, ADR 0020's reaper), tier 2's ring trim and doctor's plane-probe child. The reaper starts after Prepare and before the stage, so before Arm. Every other helper starts after Detach has closed the group, and uprobe's detacher waits for StartDetaches.
- (4) Done. Removed: the ignore mark, admission by (device, inode), openStage, checkStage, StageLinking, ErrStageLinked, ErrStageDenied and Buildable's linking check. BuildFix no longer asks for a static build. The shipped builds stay static and non-PIE (docs/VERSIONING.md), but tier 2 no longer needs it.
- Tests. Unit: TestStartRefusesWhileArmed, TestArmWaitsForAStartInFlight, TestIdentityNamesOneProcessAcrossPidReuse, TestArmIsTheOneArmingPoint, TestArmWithoutAGroupArmsNothing, TestDecideEventAdmitsNoStageExec. Unprivileged, with a real stage: TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck (at Arm, the one child runs the tego binary: exec'd, not yet acked) and TestIntegrationFailedArmFailsTheRunBeforeTheAgent. Root, in the KVM guest: TestTier2ArmsAfterTheStageExec, TestStageExecUnderGCNeverWaitsOnItsOwnGroup (rewritten for the new order), TestUnmarkAllFlushesOnlyTheMountMarks and TestStartIdentityOutlivesPidReuse. All pass as root in the 6.17 guest (plain and tegobpf builds), as do the launch, runtime/cgroup and proc suites whole and the enforce/cgroup tegobpf suite after the five tests that read the run-set row or the marks right after Prepare were given an Arm.
- **Conditions, not yet met:**
  - The tier2-pairs.sh runs (two copies of one build at two inodes, and a third-party listener, 1,000 pairs each in GUEST and on MATRIX's AL2023 6.12) and the 500-pair freeze reproduction;
  - a dynamically linked PIE tegobpf build run at tier cgroup in the guest;
  - item (5), with ADR 0028 S3;
  - item (6), a FEATURES E70 condition;
  - item (7).

*Note 2026-09-30:* Identity.Same and FS.Alive are removed. No production code called them, and they read a zero StartBootNS as a real start time while Identity's doc called zero "not known". Callers compare starts with proc.SameProcess; Start never returns an identity whose start it could not read (ErrIdentity).

*Amended 2026-10-05 (the third-party listener):* the helper the Tests bullet and the first condition name, "a third-party permission listener whose decisions open files on `/`", is built: `test/vm/cmd/permlistener`, one static Go binary that cross-builds for arm64. Its `allow-touch` mode is the shape the cycle above needs: it marks the mount of `/` for `FAN_OPEN_PERM` and `FAN_OPEN_EXEC_PERM`, and each open or exec by another process is decided by a worker that opens and reads files on that mount, then answers `FAN_ALLOW`. Its own opens are answered on its reader, an event no decision answers in 10 s is let through and counted `late`, and each event is answered once, so the helper cannot be the stall the run is looking for. Its `deny -path P` mode, the same binary, is ADR 0017's space 6. Unit tests stand a socketpair in for the group; four root tests (test/vm/root-must-pass.txt) run it against the kernel on a tmpfs of their own. The conditions above are unchanged: no pairs run has started it yet (`tier2-pairs.sh` will, and so will the conformance cell), so the third-party half of the first condition is still to be recorded.

*Amended 2026-10-05 (the start sites):* (3)'s lint and (6)'s condition are one mechanism now. Every call of `proc.Start`, and of `cgroup.StartHelper` and `StartHelperExec`, the one wrapper over it that tego's detached helpers start through (a run's reaper, the build's linger timer and ring trimmer, a library's probe removal), is a reviewed site. `.golangci.yml`'s forbidigo rule refuses it from any file its start-site exclusions do not name, and `TestEveryProcessStartSiteIsListed` (`internal/platform/proc/sites_test.go`) holds the same list by function and by count over every Go file of the module whatever its build tags (the lint reads two tag sets and never `tegotesthooks`), each row saying when its start runs against `proc.Arm`: the child stage, the reaper and doctor's probes start before the first mark, the linger timer, the ring trimmer and the uprobe detacher once the last is gone, and `StartHelper`'s own start is guarded by `ErrArmed` for whatever moment its callers choose. `TestLintExclusionsAreTheStartSites` holds the config to that list. A start from a supervisor's ask handler, the shape E70 would take, now fails lint and the test before a run can meet `ErrArmed`; E70's broker is a new row, and starts before the stage in every mode. (6) stays a condition on E70, which is not built. Not covered: a raw `Syscall` with a literal clone number, which no constant names and review would see.

*Amended 2026-10-05 (the freeze and arming tests are held as root):* test/vm/root-must-pass.txt now names six more tests, so CI's root-suites job fails when one of them skips. They are the four root tests of the order against the kernel's fanotify that the Tests bullet and E15, E35 and E40 name beside `TestTier2ArmsAfterTheStageExec` and `TestStartIdentityOutlivesPidReuse`, which it already held (`TestStageExecUnderGCNeverWaitsOnItsOwnGroup`, `TestKilledListenerReleasesTheMount`, `TestUnmarkAllFlushesOnlyTheMountMarks` and `TestStoppedListenerHoldsItsMountUntilContinued`), and the two arming tests (`TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck` and `TestIntegrationFailedArmFailsTheRunBeforeTheAgent`). The first four skip wherever `fanotify_init` is refused, the last two wherever the tego binary they start a stage of cannot be built or Landlock is off, and `go test` exits 0 over a skip, so a runner image that changed under the job went on passing with (2) and (3) unchecked there. Each passed as root in a KVM guest set up as a hosted runner is (`VM_CGROUP=service`, `TEGO_VM_LSM=kernel`, `TEGO_VM_LOCKDOWN=none`) and in the default guest, on 6.17, in the plain and the `tegobpf` build of its package. The hosted-runner guest had to be corrected first: its second process in the service cgroup was a child of the suite, and the arming tests, which count their own children, failed on it (test/vm/README.md).

*Amended 2026-10-06 (the start sites follow their wrappers):* the list of the 2026-10-05 note on the start sites names a start through the three calls lint can name, `proc.Start`, `cgroup.StartHelper` and `StartHelperExec`. An unexported function that makes one of them (`startHelperIn`, `startHelperProcess`, `startOnKeptThread`, the run's reaper's, the uprobe detacher's and doctor's) is called by its bare name inside its own package, which no forbidigo pattern matches, so a new call of it from another file of that package, an arm-time path for one, passed lint and the test with the start behind a row nobody read again. `TestEveryProcessStartSiteIsListed` now follows a start one function out: each function a row says makes one of those starts is itself found by its bare name in its own package's directory (an unexported method as the name of a selector there), and each of its callers is a row with the relation of its own: the child stage (`Launcher.Start`), the reaper (`runner.startReaper` and `runner.startDNSReaper`) and doctor's probes start before the first mark; the linger timer (`startTimerProcess`), the ring trimmer (`Handle.parkRings`) and the uprobe detacher (`StartDetaches`) once the last is gone. The function's own row is `guarded`, and a row is `guarded` exactly when the scan follows its function, so every `guarded` row has callers' rows that say when. A file needs an exclusion in `.golangci.yml` only for a row whose call lint names: `rings.go` has a row, for its call of `startHelperProcess`, and no exclusion. `TestLintExclusionsAreTheStartSites` holds the config to that and refuses any other exclusion that includes forbidigo. Not covered, beside the raw `Syscall`: what calls the function a row names as the place a start is decided (`Launcher.Start`, which another package calls and no scan by name can tell from any other `Start`, and `startTimerProcess`, which its own package does): that is the order of the run's lifecycle, which (2) fixes and the arming tests check.

*Amended 2026-10-06 (arm64 evidence):* item (7) names arm64 among the rows, and none of the tests above had run on an arm64 kernel. They do now, in CI: `ci.yml`'s `build-test-arm64` runs, as root on GitHub's arm64 runner through `test/vm/root-suites.sh` (as the root-suites job does: the helpers a test builds are built by the runner user and served to root by `go-shim.sh`), `TestStageExecUnderGCNeverWaitsOnItsOwnGroup`, `TestKilledListenerReleasesTheMount`, `TestUnmarkAllFlushesOnlyTheMountMarks`, `TestStoppedListenerHoldsItsMountUntilContinued`, `TestTier2ArmsAfterTheStageExec` and `TestStartIdentityOutlivesPidReuse`, and, unprivileged in the user manager, `TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck` and `TestIntegrationFailedArmFailsTheRunBeforeTheAgent`; the job fails unless each passed, so a skip is no pass. That is the first evidence for (2) and (3) on arm64, whose argument holds there as on amd64 (Go's `forkExec` clones with `CLONE_VFORK|CLONE_VM` on both). Nothing has run on arm64 yet: the result is the CI log, the only source of arm64 evidence (a TCG guest was set aside as too slow for the suites and as adding no kernel the runner lacks). The conditions above are unchanged, and `tier2-pairs.sh` on the runner is not built.

*Amended 2026-10-05 (the kernel matrix, item (7)'s column):* (7)'s condition, "every matrix row, amd64 and arm64, selects a plane mode", is readable now. `make vm-matrix` keeps, per row and per boot, `cgroup_mode` in summary.json and in its report: the decision plane tier cgroup decides opens by (`lsm`, `fmod_ret`, or `fanotify`, the fallback; `none` where doctor offers no tier cgroup), read from the "decision plane:" clause of doctor's D7 line as root (`test/vm/doctor-facts.sh`, held to lines doctor printed in guests), beside the Landlock ABI. A row whose column says `fanotify` on any boot keeps the listener's enforcement role alive. The arm64 hosted runner is not a matrix row, so its half of (7) stays with the CI step that runs there. The Ubuntu 22.04 row is doctor-only (its Landlock ABI 1 offers no tier, so no plane is selected and (7) has nothing to judge there): it is not the natural fallback row the pairs runs were to use.

*Amended 2026-10-06 (what is built and what (1) says):* the notes above, read against the code, where (b)'s list was completed.
- (5) is built, with ADR 0028 S3 (implemented 2026-10-04 per ADR 0028's Status), and leaves the conditions list:
  `fallbackMutation` (`internal/runtime/supervisor/fs.go`) runs on every exit of `decideFS` and refuses, best effort,
  a mutation the root walk refuses and Landlock allows; `TestFallbackMutationConverges` holds `mkdirat`, `unlinkat`,
  `truncate` and `mknodat` to it, and the conformance cells `mkdir-in-deny-read-nested-in-write` and
  `unlink-in-deny-read-nested-in-write` (`Source: "ADR0021(5), ADR0028 S3"`) run on `TestConformanceKernel`'s
  fanotify axis. Still open of it when this note was written: guest cells for the other mutations (5) names, a
  create (`creat`, `O_CREAT`), `rmdir`, a symlink, link or rename into the tree, and `RENAME_EXCHANGE`; the
  2026-10-06 coverage note below adds them.
- (4) leaves the release build's linking a release choice only. `enforce.Buildable` has no linking check
  (`internal/runtime/enforce/buildable.go`), and neither the stage's binary nor its loader is ever asked about, so a
  dynamically linked or PIE tegobpf build constructs tier cgroup like a static one. The shipped builds stay static
  and non-PIE (`Makefile` `build`, `docs/VERSIONING.md` §5) for portability, not for tier 2. The PIE run in the guest
  stays a condition: it is the evidence that the order holds for such a build, not a requirement on the release.
- (1), restated as the code has it. fanotify decides a tier-cgroup run's opens and execs (a) where doctor's mode
  probe finds no plane mode, (b) on a host where a plane mode passes, for a table the plane cannot hold: more rows
  than a slot holds, or more keyed paths than the launcher's descriptor budget (`decide.ErrPlaneCap`, `FitFDs`); an
  exec entry that does not allow (`decide.ErrPlaneExecVerdict`); name entries past the plane's name caps
  (`decide.ErrPlaneNameCap`); more Unix listener rows than `decide.PlaneListenRowsMax`; one inode under two fs
  entries (`ErrPlaneSharedInode`, `cgroup.PlaneHoldable`); or, for a table with a `deny_write` target, a mount table
  that cannot be read (`cgroup.ErrMountTable`) (`holdablePlaneRows`, `internal/runtime/enforce/adapters.go`, and
  `choosePlane`, `internal/runtime/enforce/cgroup/planerun.go`). `choosePlane` logs the reason and the run's
  `decision_plane` says `fanotify`, while tier bpflsm refuses such a table instead; and (c) for E14's asks, which
  are not built (P2): fs.ask's approval scopes, built since (agent-contract R22), are the seccomp supervisor's
  (`askOpen`), not the listener's. A table with built-in `deny_write` targets runs on the listener
  with the supervisor's best-effort refusal (R15c), disclosed in `run_start.best_effort`, unless its contract says
  `fs.assurance: kernel`, which refuses it before launch (ADR 0041 D1 (a); `RuleTable.DenyWriteNeedsPlane`).
- (1)'s "the capability line names its hazards" cannot hold as worded: `run_start.capabilities` is one boolean per
  row of spec/backend/CAPABILITIES.md. The hazards are named in the spec (enforce-cgroup-observe E15, E16, E34, E35,
  E37, E40), and doctor's plane clause names one of them, that the fallback does not scale (`internal/doctor/plane.go`).
  Naming the rest where a user meets the fallback, in doctor's plane clause, `tego status` and an additive
  `run_start` field, is open.
- The conditions, as of this note: the `tier2-pairs.sh` runs and the 500-pair freeze reproduction (the script does not
  yet force the fallback or start the third-party listener); the PIE run; (5)'s remaining guest cells (met: the 2026-10-06 coverage note below); (6), a
  standing E70 condition that lint and `TestEveryProcessStartSiteIsListed` hold; (7); and (1)'s hazard naming.

*Amended 2026-10-06 ((5)'s coverage):* (5) names "a write, create, delete, rename or mkdir", and its tests held four syscalls at unit level and four actions in the conformance cells. Both now cover each syscall that makes one, in the forms listed here (a 2026-10-17 note added the legacy forms and two flag forms the first table left out, and another the write opens without `O_CREAT`). `TestFallbackMutationConverges` (internal/runtime/supervisor) drives thirty forms on x86-64 (twenty on arm64, whose table has no legacy form) against a deny_read nested in a write entry, a write entry regranted inside it and a directory beside it: mkdir and mkdirat, unlinkat with and without `AT_REMOVEDIR`, the legacy rmdir, truncate, mknodat, the legacy creat, openat with `O_CREAT`, with `O_CREAT|O_EXCL`, with `O_WRONLY`, with `O_RDWR`, with `O_WRONLY|O_TRUNC`, with `O_RDONLY|O_TRUNC` and with `O_WRONLY|O_TMPFILE`, symlinkat, linkat, renameat and renameat2 into the tree (the destination end), renameat2 with `RENAME_EXCHANGE` both ways, renameat2 with `RENAME_NOREPLACE`, linkat with `AT_SYMLINK_FOLLOW`, and the legacy open with `O_CREAT` and with `O_TRUNC`, unlink, mknod, symlink, link and rename; an exchange with the regrant is refused too, by supervisor R15d, which refuses a move of any name beneath an unenforced deny_read and so does compile --test's tier cgroup column. `TestFallbackMutationLeavesOthersAlone` holds the guard: a run a plane decides, tier landlock, a read-open and a chmod are continued. The conformance actor gains two ops, `creat` (the legacy syscall on x86-64, its flags on an openat on arm64) and `exchange` (renameat2 with `RENAME_EXCHANGE`); the oracle's invariants and effect judge read both; and the fs fixture gains six cells under its nested deny_read: creat, rmdir, symlink, link into it and exchange into it, refused at tier cgroup, and chmod, allowed at every tier (no tier below the plane decides one). fsplan's YAML table already held a create, a truncate and a rename into it. No cell found a mutation the supervisor continued, so supervisor/fs.go is unchanged and BenchmarkFanotifyRoundTrip cannot have moved. TestConformanceKernel passes with an empty baseline, `TEGO_CONFORMANCE_BUDGET=strict` and `VM_BOOTS=both`, in KVM guests on 6.17 (the lsm-bpf boot: landlock, the listener, fmod_ret, lsm and tier bpflsm; the default boot: landlock, the listener and fmod_ret), on MATRIX's al2023-6.12 and on rhel-9 (5.14, Landlock ABI 6), the same axes on each, every axis within budget. With ADR 0028 S3's guest evidence, item (5) of the conditions list above is met. *Checked again 2026-10-16:* `TestFallbackMutationConverges` fails on fourteen of its cells (x86-64's) with `fallbackMutation` disabled (the two exchange cells are R15d's too), and passes with it; in KVM with `VM_BOOTS=both` and `TEGO_CONFORMANCE_BUDGET=strict`, the supervisor's two tests and `TestConformanceKernel` pass on 6.17, al2023 (6.1, Landlock ABI 2), al2023-6.12 and rhel-9, no fail-open and no effect on any axis, every new mutation cell refused on the listener (`seccomp`) and on the plane axes (`kernel`) and allowed at tier landlock, and the chmod cell allowed on every axis. The baseline is no longer empty: ADR 0048's six execrules ledger entries came with the command-rule grid, none a fail-open, scoped to kernel 5.15 and later (ADR 0048's 2026-10-16 note), without which rhel-9 failed on them as entries that now pass. supervisor/fs.go is unchanged by these cells. *Checked again 2026-10-16:* (1)'s list still is the code's (`holdablePlaneRows`, `CompilePlane`, `choosePlane` are unchanged there) and fs.ask's scopes are still `askOpen`'s; supervisor/fs.go is still unchanged; in KVM on 6.17 with `VM_BOOTS=both` and `TEGO_CONFORMANCE_BUDGET=strict`, `TestFallbackMutationConverges`, `TestFallbackMutationLeavesOthersAlone` and `TestConformanceKernel` pass on both boots, with the same axes, results and two baselined execrules disagreements per plane axis as above.

*Amended 2026-10-16:* two gaps in that coverage's evidence. The creat cell did not hold (5)'s claim that a refused creat leaves no residue: the effect judge took an empty file a refused creat left on the listener as the listener's stated residue (`RESIDUE`, only logged), and the cell pinned no errno, so the listener's own `FAN_DENY` after the create (`EPERM`, doctor's `FAN_DENY_ERRNO=false`) passed as the supervisor's refusal. With `fallbackMutation` disabled in a 6.17 KVM guest the cell still passed while mkdir, unlink, rmdir, symlink and link-into failed. Now `judgeEffect` gives a creat no residue (the filter notifies every creat, the legacy syscall and arm64's `O_CREAT` open alike, and the supervisor refuses it before the kernel acts), and the cell's tier cgroup column, which tier bpflsm's and the plane axes' copy, wants `EACCES`, the supervisor's and a plane hook's. Rejected: the errno alone, which a listener that answers with `FAN_DENY_ERRNO`'s `EACCES` would meet while leaving the file. With `fallbackMutation` disabled the cell now fails twice (`FAIL-OPEN ... effect: the action was refused but out/keys/kcr.txt exists`, and errno 1 against the wanted 13) beside the five other cells; with it, `TestConformanceKernel` passes on 6.17 with `VM_BOOTS=both` and `TEGO_CONFORMANCE_BUDGET=strict`, the creat cell refused with errno 13 on every axis but tier landlock and its effect held. Second, `TestFallbackMutationConverges` let its three legacy-only cases (mkdir, rmdir, creat) `t.Skip` on arm64, nine subtests that CI's arm64 unit skip gate does not allow; its table now leaves them out on any architecture but x86-64, and `TestFallbackMutationCasesDispatch` holds the table to both architectures' dispatch tables (sixteen cases on x86-64, thirteen on arm64, then; twenty-five and fifteen, then thirty and twenty, after the 2026-10-17 notes).

*Amended 2026-10-17:* two more gaps in that evidence, closed. First, fsplan's `nested-denied-create` (an `O_CREAT|O_EXCL` open under the nested deny_read, the path arm64's creat takes too) passed with `fallbackMutation` disabled, as the creat cell had: the effect judge still took an empty file a refused `O_CREAT` open left on the listener as its residue, and the cell pinned no errno. The judge now grants no axis a residue (ADR 0017's 2026-10-17 note), and the cell's tier cgroup want pins `EACCES`, which tier bpflsm and the plane axes take (`TestFallbackCreateCellsWantTheSupervisorsErrno` holds both create cells). Second, the 2026-10-06 coverage note said `TestFallbackMutationConverges` covers each syscall that makes a mutation, and its table left out the legacy open with `O_CREAT` and with `O_TRUNC`, unlink, mknod, symlink, link and rename, and the flag forms renameat2 `RENAME_NOREPLACE` and linkat `AT_SYMLINK_FOLLOW`; a probe found each refused, so this was a gap in the evidence, not a bypass. The table now drives them: twenty-five forms on x86-64 and fifteen on arm64, and with `fallbackMutation` disabled twenty-three of the x86-64 forms fail at `secret/x` (all but the two exchanges, which R15d refuses), the nine added ones among them. The note's "every new cell refused" now names chmod as the cell allowed on every axis. *Checked 2026-10-17:* in KVM on 6.17 with `VM_BOOTS=both` and `TEGO_CONFORMANCE_BUDGET=strict`, `TestFallbackMutationConverges` (seventy-five subtests), `TestFallbackMutationLeavesOthersAlone`, `TestAlternateRefusal*` and `TestConformanceKernel` pass on both boots, the lsm-bpf boot running landlock, the listener, fmod_ret, lsm and tier bpflsm and the default boot landlock, the listener and fmod_ret, with no fail-open, effect, problem or finding on any axis and the two baselined execrules disagreements per plane axis; both create cells are refused with errno 13 on the listener (`seccomp`) and on the plane axes (`kernel`). With `fallbackMutation` disabled `nested-denied-create` now fails, as a fail-open (an empty `out/secret/create.txt` is left) and on its errno (1 against the wanted 13), beside the ten other cells under the nested deny_read.

*Amended 2026-10-17:* three gaps between the docs and the code, closed. First, the 2026-10-06 coverage note said `TestFallbackMutationConverges` covers every form the filter notifies, and its table held no write open without `O_CREAT`, although the filter notifies every open with a `WriteFlagMask` bit (`O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`, landlock/filter.go); on arm64, which has no legacy open, no truncating open was driven at all. A probe found each refused, so this was a gap in the evidence, not a bypass. The table now drives openat with `O_WRONLY`, `O_RDWR`, `O_WRONLY|O_TRUNC`, `O_RDONLY|O_TRUNC` and `O_WRONLY|O_TMPFILE`, not as legacy forms, so arm64 drives them too: thirty forms on x86-64 and twenty on arm64 (`TestFallbackMutationCasesDispatch`). With `fallbackMutation` disabled twenty-eight of the x86-64 forms fail at `secret/x`, the five added ones among them, and with it all ninety subtests pass. The note now names the forms it drives rather than claiming every form. Second, `.goreleaser.yaml` still said a static, non-PIE build is required because tier 2 refuses a dynamically linked tego, against (4) above, VERSIONING §5 and the Makefile; its comments now say static and non-PIE is a release choice for portability, with this ADR's PIE guest run the open condition, and the flags are unchanged. The same stale claim stood in CI's race job comment (tier 2 "refuses to launch a dynamically linked child stage") and in the conformance actor's and `TestActorIsStatic`'s comments ("what tier 2 needs"), and all three now give their real reasons. Third, enforce-cgroup-observe's refused-create paragraph said a create, delete, rename or mkdir beneath the nested deny_read stays Landlock's union's, in the code and in `Evaluate`'s `cgroup` column; since (5) and ADR 0028 S3 the supervisor refuses them before the kernel acts and `Evaluate` refuses them through the root walk, and the paragraph now carries a dated amendment saying so.

*Amended 2026-10-17:* the 2026-10-06 note above says `fallbackMutation` "runs on every exit of `decideFS`". It runs on every exit but two: a notification that went stale around its walk, which is answered as gone, and a walk that reached an object with no path in this process's view (`errOtherView`: a pipe or socket behind `/dev/stdout`, an unlinked file, or a file linked elsewhere), whose line keeps the spelling's refusal or is `observed` under `path-unreliable` and whose syscall is continued. A nameless object's write-open must run, and a file linked elsewhere is reached, with namespaces refused, only by the pathname race supervisor R15c names. A walk that failed other than as the task's lookup fails (`EMFILE`, `ENOMEM`, `EIO`, `EXDEV`) is refused under `path-unreliable` (supervisor R15's amendment of the same day; `TestFallbackMutationWalkFailures`). No behaviour changed.

*Amended 2026-10-17 (ADR 0023 C3, the descriptor lint):* two changes to (3)'s and (6)'s lint, neither to what it
refuses. `.golangci.yml`'s tagged run now builds `tegotesthooks` as well (ADR 0023 A3), so the forbidigo rules
here, and the start-site rule with them, also see the non-test files only that tag builds (twelve on the tree, which
the 2026-10-05 note above says the lint never read; `TestEveryProcessStartSiteIsListed` reads every file whatever its tags, as
before). And the blanket exclusion for test code, internal/platform/proc, internal/testutil, tools and test is
scoped to `text: ADR 0021`: it lifts this ADR's rules there and no other, so proc is under ADR 0023's descriptor
rules. `TestLintExclusionsAreTheStartSites` holds both: the exemption's text must match every ADR 0021 message, and
the one other kind of forbidigo exclusion it admits, ADR 0023's per-package and permanent ones, must match none.

*Amended 2026-10-19 (the pairs harness):* the harness the conditions name is built, and the runs
before it do not count: the 2026-10-05 runs did not force the fallback, so a host where a plane mode
passed may have run no fanotify group at all. `test/vm/tier2-pairs.sh` now pins the decision plane with the
test-hooks build's `TEGO_TEST_PLANE` (`PLANE`, `fanotify` by default; no `bpf.plane: fanotify` config value is
added) and proves per pair, from each run's ledger before cleanup removes it, that `run_start` names that
`decision_plane`, that the agent's one read of a `deny_read` file on `/` (nested in a write entry, so Landlock
leaves it to the plane) is refused once by that plane's mechanism (`source` `fanotify` on the fallback), that a
`run_end` follows, and that no exec line names the stage; a pair that lacks one prints `PAIRS-ASSERT-FAIL` and ends
the run with no `PAIRS-DONE`. `COPY_B=1` runs a pair's launchers from two inodes (the copy is renamed in, since an
earlier phase's linger timer may still execute the old one), `LISTENER=` runs `test/vm/cmd/permlistener` (a Go
helper) beside them and the watchdog kills it separately, after the launchers, and `SELF_DENY=1` runs (4)
for the launcher's own binary. `test/vm/pairs.sh` (`make vm-pairs`) builds the static and the PIE binary (both
`tegobpf,tegotesthooks`; `test/vm/cmd/elfinterp` refuses a PIE with no `PT_INTERP`), boots one guest per variant
and boot and reads each console into a `summary.json`. The harness found one defect on the way: doctor's run-probe
cache named its entry by build and privilege, not by binary, so two inodes of one build evicted each other's entry
and every pair paid two cold plane probes (about 13 s a pair; fixed with limits-check-doctor-cli R27's per-binary
name, 2026-10-19). Evidence, GUEST 6.17.0-41, both boots (`PAIRS_BOOT=both`), `PAIRS_N=50`: every variant passed
with no watchdog line, 1,100 pairs, every pair's ledger asserted: two-inodes and third-party 150/150 each per boot
(the listener saw 10,617 and 10,990 tego events, none answered late), guest-freeze 100/100, plane-control 50/50 (lsm on
the bpf boot, fmod_ret on the default boot), and pie 100/100. The pie variant's count is its full count (50 pairs
pinned to fanotify, 50 on the probe's mode, with `SELF_DENY` before each phase): **the PIE condition is met on
GUEST.** Still open: the full-count runs (two-inodes and third-party at 1,000 pairs, guest-freeze at 500) on GUEST and on
MATRIX's AL2023 6.12; (6); (7).

*Amended 2026-10-19:* the per-pair proof had
four gaps, closed in `test/vm/tier2-pairs.sh`. First, nothing tied a run to the launcher that made it: in kill mode
the killed launcher's complete run stood in for the survivor's, whose run could then have had no refusal, or one
from another mechanism, and the pair still passed. A run is now its launcher's by `run_start`'s `launcher_pid`;
every started run is owed the proof but the run of a launcher that exited non-zero, and every launcher that exited
0 is owed a run of its own (under `MODE=timeout`, where `$!` is timeout's pid, every started run is owed). Second,
the proof read only the ledger: no launcher's output, which is the agent's stdout, may now hold the secret's
content, and the self-deny agent opens the binary with its shell's redirection and prints whether the open went
through, which must say `refused`. Third, the kill phases killed 100-900 ms after the second launch, after most
warm runs had ended (a 6.17 probe at `AGENT_SLEEP=0.05`: 4 of 30 pairs lost a launcher), so a phase of 50 kills
was about 7. The kill point is now drawn from the previous pair's length, `PAIRS-DONE` counts the kills that
landed and those that hit a started run, `summary.json` keeps both, and a kill phase where fewer than `KILL_MIN`
percent (50) of the pairs lost a launcher fails. Fourth, `tier2-pairs_test.sh` never ran `self_deny` nor any
exec line of the stage, so either check could be deleted unnoticed; it now runs both, and a mutant of each new
check is caught. Evidence, GUEST 6.17.0-41, both boots, `PAIRS_N=50`, after the change: every variant passed
again with no watchdog line (1,100 pairs); the kill phases lost a launcher in 38, 44, 35 and 48 pairs of 50
(two-inodes and third-party, bpf boot then default boot), 82 of those 165 kills after the run's `run_start`; the
pie variant's self-deny run saw its open refused in all four phases. The PIE condition stays met on GUEST.

*Amended 2026-10-19:* an earlier note excused the
proof of any launcher that exited non-zero, as killed or as failed in a pair its count would fail; in kill mode the
count passed a pair when either launcher exited 0, so a launcher that failed without being killed was owed nothing
and its pair passed (a survivor that exited 1 with no refusal, or with no run at all, gave `PAIRS-DONE 1/1`), and a
137 of the launcher the SIGKILL did not target (tego's own exit when its agent is cgroup-killed) counted as a
landed kill. The loop now records which launcher it kills; a kill-mode pair passes only when both launchers exited
0 but that target, which may exit 137, and only the target's 137 counts as a landed kill (`PAIR <i> rc=<a>,<b>
kill=<a|b>`). The excuse stands, and is now true in every mode: a non-zero launcher's run is owed nothing because
its pair fails unless it is the kill's target. The kill point is drawn by `kill_draw`, which
`tier2-pairs_test.sh` runs over spans from 0 to 3,600,000 ms (format, bounds, coverage, both targets), and the
fixture loop checks that the first pair draws from 900 ms and the next from the first one's length. `KILL_MIN`
stays 50 %: at the low end of the landing rate seen on 6.17 (70 %), a 50-pair phase misses it about once in 1,000
phases, a 10-pair one about once in 20, which the script's header says; kill phases are meant to run 50 pairs or
more. Rejected: holding a failed launcher's run to the full proof in `assert_pair` (its run holds only where it
failed, and the pair's verdict already fails it); applying `KILL_MIN` only from 20 pairs (a gate relaxed to hide a
sampling tail).
Found by a 6.17 smoke run (two-inodes and third-party, both boots, 50 pairs): in 2 of the 4 kill phases
(both two-inodes) the agent of the launcher the kill ended printed the secret (`PAIRS-ASSERT-FAIL what=secret-read
launcher=b`, pairs 13 and 29, `rc=0,137 kill=b`). That is not a new hole but enforce-cgroup-observe §6 E15's stated
P0 limit, which ADR 0020 narrows to the reaper's reaction time on the fallback: a `SIGKILL`ed launcher's group
closes with its descriptors, the kernel releases its pending opens with an allow, and the agent's `cat` (a child of
its shell, so no `PR_SET_PDEATHSIG` of its own) runs undecided by fanotify until the reaper kills the cgroup.
An earlier fix's output check failed every such read. Now, on the fallback, a read in the output of kill mode's target
that exited 137 is printed as `PAIRS-KILLED-READ` and counted in `killed_reads` (in `PAIRS-DONE` and
`summary.json`, which warns), never passed as refused; a read by any other launcher, or by the target on a plane
(which outlives its launcher, ADR 0020), still fails the pair. Rejected: keeping the failure (the harness would
fail a run for a limit the spec states, at random); dropping the output check for killed launchers (the window
would go unmeasured).

*Amended 2026-10-19:* the harness kept passing pairs it should have failed, and each
fix closed one case. The cause they share is the model, not the cases: the verdict on a pair was put together in
three places that each held part of the evidence, and an excuse granted in one place stood on a check made, or not
made, in another. `assert_pair`'s run loop owed nothing for the run of a launcher that exited non-zero; its output
loop excused the killed launcher's read; the pair loop decided from exit statuses alone which non-zero launchers the
pair forgave; and under `MODE=timeout` complete runs were counted instead of being tied to launchers. The evidence
was also judged before it was final: a killed launcher's reaper closes its run after the launcher's wait returns
(ADR 0020 (3)), and until then the run's agent can still write to the launcher's output. The latest case:
the killed-read excuse never looked at the killed run, so a run whose ledger said fanotify refused the very read its
agent's output shows went through (a ledger that says something other than what happened, ADR 0016) passed as E15's
window, and so did a read in a run its launcher had closed while its listener was answering.

The corrected model, now `tier2-pairs.sh`'s `settle`, `assert_pair` and `judge`: each launcher gets one verdict from
all of its evidence at once, by a closed table, and nothing outside the table passes.
1. The pair settles first: it waits up to `SETTLE` seconds (10, below `STALL`) for every started run's `run_end`,
   which the reaper writes only once the run's cgroup is empty; from then on the ledger is whole and no process of
   the run writes to the output.
2. Every started run reports the pinned plane, refuses the path at most once and only by that plane's mechanism,
   holds no other verdict on the path and no exec line of the stage, and is exactly one launcher's by `run_start`'s
   `launcher_pid`. Under `MODE=timeout` a shell between timeout and the launcher writes its pid and execs the
   launcher, which keeps it, so no run is anonymous in any mode. Directories with no `run_start` number at most the
   launchers that exited non-zero with no started run.
3. Each launcher's verdict, from its exit status, whether the kill targeted it, its own run and its effect (the
   agent's `PAIRS-READ opened` or `refused`, and the secret's content in its output; the self-deny agent says the
   same of its open):

   | exit | kill's target | its run | its agent's read | verdict |
   |---|---|---|---|---|
   | 0 | either | one refusal, `run_end` reason `exit` | refused | `complete` |
   | 137 | yes | none | not run | `killed-early` |
   | 137 | yes | one refusal, `run_end` reason `exit` (killed after it closed the run) | refused | `killed-in-run` |
   | 137 | yes | `run_end` reason `orphaned` | not through | `killed-in-run` |
   | 137 | yes | `run_end` reason `orphaned`, no refusal of the path, on the fallback | through | `killed-read` |
   | any other | – | any | not through | `failed`: the pair fails |

   Any other combination is a `PAIRS-ASSERT-FAIL` that prints the evidence it judged. The pair passes when no verdict
   is `failed`; `kills`, `kills_started` and `killed_reads` count the target's verdicts, and `killed-read` is printed
   as `PAIRS-KILLED-READ`. `killed-read` is E15's stated window and nothing wider: the fallback only (a plane
   outlives its launcher), a read no line of the run refused (the listener records a refusal after its
   `FAN_DENY`), in a run its reaper closed (the launcher died with the run open).

Rejected: excusing the killed read only when the run holds no refusal (it closes that case and keeps the
model that produced it, as each earlier fix did); one table in the pair loop beside `assert_pair`'s
excuses (two places again); keeping timeout's count of complete runs (the last proof not tied to its launcher);
judging without settling (a killed run's `run_end` and its agent's last output come after the wait; an earlier fix's probe
saw a killed run's `run_end` still pending when it was judged); wanting `orphaned` of every killed run (a launcher
killed between its `run_end` and its exit leaves a whole run); judging from the output alone or the ledger alone
(each shows a lie of the other: a ledger that says refused of a read that went through, an agent whose word is
missing). `tier2-pairs_test.sh` holds the table whole: every combination of one launcher's evidence (exit 0, 1 or
137; the kill's target or not; sixteen ledgers; five outputs; on the fallback and on lsm; beside a whole or a killed
launcher), 4,800 of them, 728 passing, is run through `assert_pair` as written and compared with the table written
out a second time in the test. The harness before this change passes 366 of those combinations that the
table fails, and fails none it passes: the read beside a refusal and in a run its launcher closed, a read with no
run, a killed run its reaper never closed or that ended in tego's own `oom` (a 137 that was no kill of the
script's), a killed run's refusal by another mechanism or an allowed line of the path, and a launcher that exited 0
whose agent never said its read was refused or whose run an `orphaned` or `oom` end closed. Stand-in reapers that
write the agent's last output and then `run_end` 0.5 s after their launcher exited show the settling: that read is
E15's window in a run with no refusal and fails beside one, and judged at once (`SETTLE=0`) such a run fails for its
missing `run_end`. Each check of the table and of the loop has a mutant `tier2-pairs_test.sh` catches (twenty-eight).
Evidence, GUEST 6.17.0-41, `PAIRS_N=50`, both boots, every pair judged by the table: two-inodes, third-party, guest-freeze
and plane-control passed on both boots and pie on the default boot (1,000 pairs, no `PAIRS-ASSERT-FAIL`, no
watchdog line), so a real run meets every row it is held to (`run_end` reason `exit`, the agent's `PAIRS-READ
refused`, no other verdict on the secret, `MODE=timeout`'s launcher pids); the four kill phases lost their target in
38, 43, 48 and 44 pairs of 50 (13, 15, 23 and 21 of those runs had started), and each held one `killed-read`, a
run with no refusal of the secret and a `run_end` reason `orphaned`, which is the row the table gives E15's
window. On the bpf boot pie's second phase (auto, so lsm) stalled at its pair 7: the PIE launcher sat with every
thread in a futex wait and its stage blocked reading the control pipe for its ack, with no fanotify group in the
guest, while the other launcher's run completed; the watchdog's `SIGKILL` ended it and the guest moved on at once.
The report's `SIGQUIT` had printed no goroutines, because `tego run` forwards `SIGQUIT` to its agent and lives on;
the report now prints the pair's ledgers and sends `SIGABRT`, the Go runtime's own, with `GOTRACEBACK=all`
exported, so the next stall names the waiting goroutine. Two reruns of pie alone on the bpf boot, at 200 and 400
pairs a phase, passed 400/400 and 800/800: one stall in 1,257 pie pairs on that boot. That hang is the launcher's,
not the harness's, and is open. With the report changed, two-inodes, third-party and pie passed
again on both boots (800 pairs, `PAIRS_N=50`, no watchdog line): the kill phases lost their target in 34, 42, 45 and
46 pairs of 50, with 1, 3, 1 and 0 `killed-read`s, and pie's self-deny run was complete in all four phases. The
PIE condition stays met on GUEST. (Kill phases here and above: two-inodes then third-party, each on the bpf boot
then the default one.)

*Amended 2026-11-01 (the self-deny proof after R10):* agent-contract R10 now refuses a write entry at or over the file
tego runs from, which stopped both proofs of (4) at compile: `SELF_DENY`'s contract wrote over TEGO's directory, and
`TestTier2ArmsAfterTheStageExec` ran its binary from beneath `./out/`. The deny stays nested in a write entry, as both
need so that Landlock leaves the read to the plane, and now names a hard link to the file tego runs from, in a
directory of its own: the launcher's inode under a name R10 does not follow (GAPS C45), made before any group exists.
A plane keys that inode as before. The fanotify fallback decides by name, so there the read is refused by the denied
name. The stage's exec keeps its proof under either: `exec.allow` does not name tego, so an exec decided before arming
would be refused whatever its name, and no exec line may name it. What no longer has a proof is a `deny_read` written
on the binary's own path through the plane: it cannot be nested, so Landlock refuses that read first and the plane
decides nothing. `TestPairsContractsCompile` compiles the harness's contracts as `tego run` does, since only a guest
runs them, and holds the self-deny entry nested. The pie evidence in the notes above was taken before this change;
the link has not been run in a guest as of this note.
