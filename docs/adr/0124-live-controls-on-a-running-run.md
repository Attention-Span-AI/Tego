# ADR 0124: Live controls on a running run: pause, and read and write blocks

Status: **accepted 2026-10-27**; built. Records the boundary of these controls;
who may use them is ADR 0123. Amended 2026-11-11 (below): a block "Also apply now" places for a program removed from
the contract refuses what the run's contract granted under that entry, not every name of the program's file.

## Context

Before this record a person could change a running agent in one way only: a live block (`tego block`, the run page's Block
now) of a program, a destination or a whole path. A Never allow on the event page changed the contract for the
next run and left the running one as it was, so a "never" took effect only after a restart. Two more
controls were asked for: freeze a run where it stands and let it go on, and make every narrowing edit apply to the
running run where the tier can enforce it. Both are new ways for something outside the run to change what a
governed process can do while it runs, so they need a stated boundary: who applies them, what makes them take
effect, what is recorded, and what they cannot promise.

## Decision

1. **One channel, owned by the launcher.** A pause, a resume and every live block are written to the run's
   `live-block.json` under the ledger root (the agent cannot write it) by `internal/control/runact` or the CLI,
   under one lock and one serial sequence. Only the run's own launcher reads it and applies each change, in serial
   order, one ledger line per change: `gap what=enforce`, why `live-block-added`, `live-block-removed`,
   `run-paused`, `run-resumed`, `pause-failed` or `resume-failed`, carrying `live_block` or `live_control
   {op, by, serial, at}` (record minor 24, `spec/record/v1/README.md`). Nothing writes the kernel state on the
   launcher's behalf, so the ledger line and the effect cannot disagree about which change took.
2. **Pause is the run's own cgroup freezer.** The launcher writes `cgroup.freeze` of the run's `run-<id>.scope`
   and nothing above it, and writes `run-paused` only after `cgroup.events` says `frozen 1`. A freeze it cannot
   apply writes `pause-failed` (the agent keeps running) and is retried with backoff until withdrawn. A run whose
   request waits for a person cannot be frozen (the waiting thread sits in the kernel), so the dashboard offers no
   Pause then. `tego stop` thaws first, so SIGTERM reaches a handler; a run that ends paused is thawed with no
   line.
3. **Read and write blocks narrow, never widen.** `read:<path>` refuses opens that read at or under the path, and a
   rename or link with either end there; `write:<path>` refuses changes there (open for write, create, unlink,
   rename and link at either end, mkdir, mknod, symlink, truncate, attribute changes). For every path kind a rename
   of a folder above the block is refused too. Removing a block removes only what it added. A read block is
   refused where tego does not see the run's reads (`[reads-unseen]`): it would refuse nothing. A write block is
   not offered where a kernel decision plane (`lsm`, `fmod_ret`) decides file changes without asking the
   supervisor.
4. **A capability mark, and fail closed for older launchers.** A launcher that reads a pause makes an empty
   `live-control` file in the run directory once its live-block poll runs over a cgroup of its own; `tego pause`,
   `tego resume` and the dashboard refuse a run without it (`[no-pause]`). A run whose `run_start.record_minor` is
   below 24 is refused read and write blocks (`[launcher-too-old]`), and the dashboard offers it the path block
   instead. An older launcher that meets a field it cannot read refuses the whole overlay (`live-block-unreadable`)
   and keeps the blocks it last enforced; the refusal before writing keeps a person from believing a block or a
   pause is in force when it is not.
5. **The dashboard says what is true now.** A block reads Waiting until its gap line exists, In force after; a block
   on a `tego watch` run is a mark, recorded and not enforced; a pause reads Paused only after `run-paused`.

## What this does not cover

- **A same-user process outside every run** can write `live-block.json`, the mark, or the run's `cgroup.freeze`
  directly (ADR 0123). The mark is a hint about the launcher's ability, not an authority.
- **A watched run is unconfined:** its marks refuse nothing, and its agent can leave the run's cgroup and so escape
  a pause.
- **An agent that keeps a request waiting all the time cannot be paused.** Deny it for the run or stop it.
- **A pause does not stop time-based limits:** `limits.wall` keeps counting; `tego status` may call a long pause
  `stalled` once `limits.stall_after` passes.
- **Write blocks on a tier-3 plane** refuse only the changes that still reach the supervisor; `tego block` does not
  refuse one there yet.

## Consequences

- A Never allow takes effect on the running agent at once ("Also apply now", a `read` block), with the
  same record as any other live block, and the next run gets the contract change.
- `tego` and `tego-control` must be rebuilt together, and runs started by an older `tego` restarted, before read
  and write blocks or a pause can reach them.
- Every live change is one ledger line in serial order, so `tego events --kind gap` replays exactly what was in
  force at each line.
- An Undo of a rule change that placed live blocks can lift them through the same channel
  (`runact.Block` with add false, which leaves a pause ask as it is), acknowledged like a widening and journaled on
  the undo; it never lifts a block on an ended run or one another standing change placed. (Amended 2026-11-20 below:
  it lifts only a block it can show its change made, and a Redo puts back what the Undo lifted.)

## Amendment 2026-11-11: a block from a rules change refuses what the removed entry granted

*Status: accepted 2026-11-11; built.*

**Context.** A live block on an absolute program path matches the file the path leads to by its identity (device
and inode), under every name the file has. That is right for a block a person places (`tego block <run> exec
/bin/ls`, Block now): Tego cannot know whether a multi-call program pins what it does to the name it is run by
(Ubuntu's patched uutils does, busybox and upstream uutils read `argv[0]`), so it fails closed on the file. But
"Also apply now" used the same block for an `exec.allow` entry removed from the contract. On Ubuntu 25.10 and 26.04
`/bin/ls`, `/bin/sleep` and about 113 other names are hard links of one uutils file, so removing `/bin/ls` refused
`/bin/sleep` and every other applet in the running run, while the next run's contract still allowed them. That
broke the rule this record's Consequences state for "Also apply now" (it places a block only where it refuses
nothing the new contract allows; `internal/control/rules/alsonow.go`, `blockOf`). A real run refused `/bin/sleep`
404 times under `live.block[exec:/bin/ls]`, and the agent's wait loop spun on refused sleeps.

**Decision.**

1. **A derived block refuses the removed entry's grant.** A block the rules editor places from a contract change ("Also
   apply now", Apply now; `runact.BlockFromContract`) on an absolute program path is written with `match: link`
   (`liveblock.MatchLink`). The supervisor refuses an exec under it when the running contract grants that exec under
   its `exec.allow` entry at the block's value (`entryGrants`, `liveblock.Grant`), as `execGranted` grants it: by the
   inode and the resolved path the loop fixed for the entry when the run started (the walk's image is that file and
   the walk reached it at that path, in the supervisor's own view), or by the spelling for an entry it could not
   stat then. Every other exec is left to the contract. The grant is the run's own, not what the value leads to when
   the block is placed: an agent that writes a folder the entry passes through can repoint a link there during the
   run, and the running run still grants the entry's file at its old path, so that is what the block refuses. (A first
   build matched the path the value led to when the launcher read the block; a review showed that a repointed link
   then let the old grant through, and offered no block at all when the entry was repointed at a kept name.)
2. **A person's block keeps matching the whole file.** `tego block` and Block now are unchanged and still say so ("one
   file with 115 names here"), now naming a few of the other names and the bare-name command that refuses one name.
   A person's add of a path held as a link block makes it a whole-file block (it refuses more); a derived add never
   narrows a held whole-file block.
3. **Fail closed where the grant is not known.** Where the running contract holds no file entry at the block's value
   (the run started under other rules), the link block matches as a person's does, the whole file the value leads to
   when the launcher reads it. The dashboard offers the block whenever the entries' text does not keep the program:
   it does not skip it because another kept entry leads to the same file now, since the run's own grant is fixed at
   its start and the dashboard cannot see it. Where a kept entry was fixed to the same file at the same path
   (busybox's applets, each a link to `/bin/busybox`; `/bin/ls` beside `/usr/bin/ls` on a merged `/usr`), the
   supervisor cannot tell it from an entry removed without a block, so the block refuses that file there for both,
   as the whole-file block did, though the next run would run it.
4. **An older launcher never meets it.** The overlay that holds a link block is version 5 (`VersionLink`). A launcher
   that reads it makes the run directory's `live-link` mark once its live-block poll runs (`MarkLink`), as `live-real`
   works for version 4. `BlockFromContract` writes a link block only to a run with the mark, and the whole-file block
   (version 1, as before) otherwise: never a block an older launcher would refuse to read, and never no block.
5. **No record change.** The refused line is unchanged: its rule names the blocked value, its `path` the program that
   ran. Readers say why when the two differ, through one function (`liveblock.SameFileNote`): `tego run`'s summary,
   `tego receipt` and the dashboard's refused rows read "/bin/sleep: refused, same program file as /bin/ls, which is
   blocked".

**Why this is not a loosening of what the contract says.** The block refuses less than the whole-file block did, so
this is a narrower refusal, recorded here as the quality bar asks. It loosens nothing the contract says. The removed
entry granted the running run one file at one path, fixed when the run started (`execGranted`; a hard link of a
granted file is refused by the supervisor and by the plane), and the block refuses every exec that grant admits, by
every spelling that reaches it: the name, a symbolic link to it, `/proc/self/fd/N` of a descriptor opened there,
and the old path after the agent repointed a link under the entry. Whatever the derived block leaves alone is
granted by another entry of the running contract, or refused by it under its own rule (a hard link the agent makes
in a folder it writes, the dispatcher name `/usr/bin/coreutils`), as the next run's contract refuses it. It may refuse
more than the next run (the kept entry on one path above). Two cases where the running run still runs a program the
next run would refuse are not this block's, and were there before it (read in the code, not run): an entry the rules
keep whose link the agent moved, since the next run fixes its grant afresh; and a removed entry the dashboard offers
no block for because a kept folder entry's text holds it while its link leads out of that folder
(`execStillAllowed` reads the entries' text only). `TestLiveLinkBlockRefusesWhatTheNewContractRefuses`,
`TestLiveLinkBlockKeepsToTheRunsOwnGrant` and `TestLiveLinkBlockOnARealKernel` compare the running contract plus the
block with the next run's contract case by case.

**What it does not change.** Every tier enforces live exec blocks in the same place: the supervisor's exec decision
(tier landlock; at the root tiers the fast exec handover to the plane is off while a program is blocked, so the same
code decides). It is decided on the supervisor's walk of the copied pathname, so it is best effort against an agent
that races the exec, as every live exec block was (`supervisor/liveblock.go`). Which applet a multi-call binary runs
is still its own choice from `argv[0]`, which no exec rule sees (SEMANTICS §4): on busybox or an upstream uutils build
that dispatches on `argv[0]`, a name the new contract keeps can run the removed applet, in the running run and in the
next run alike. A block on a run started by an older tego refuses the whole file, as before this amendment.

## Amendment 2026-11-11 (second): a paused run whose launcher dies is lost, never thawed

*Status: accepted 2026-11-11; built.* Closes GAPS C42.

**Context.** A pause is the launcher's: it freezes the run's own cgroup, and only it reads the overlay that asks for a
thaw (Decision 1, 2). If the launcher dies while the run is paused (SIGKILL, a crash, an OOM kill), nothing reads the
overlay any more. Read in the code on 2026-11-11, before this amendment:

- **What enforces what once the launcher is gone.** At tier landlock and observe the launcher is the supervisor: it
  answers every seccomp notification (exec rules, asks, the supervisor's file and network checks) and writes the
  record. Landlock and the seccomp filter stay with the agent's processes, and a notified syscall fails with `ENOSYS`
  once the listener closes (ADR 0013), but nothing decides an ask, nothing refuses on the supervisor's checks, and
  nothing records. At the root tiers the plane's rows and the run's links are pinned and stay in force (ADR 0020), but
  exec decisions, asks and the record are still the launcher's. So a run thawed without its launcher runs with part of
  its contract undecided and none of its actions recorded, at every tier.
- **What happens today.** At tier cgroup and bpflsm the run's reaper (ADR 0020 (2), (3)) sees the launcher's pidfd
  close and writes `cgroup.kill` into the run's scope: a fatal signal ends a frozen task without returning it to user
  space, so the paused processes die frozen, and the reaper writes `run_end reason=orphaned` with the `launcher-lost`
  gap before it (record-ledger R6). At tier landlock and observe there is no reaper unless the run holds a DNS broker
  endpoint (ADR 0020's 2026-10-05 note). The child stage dies on its `PR_SET_PDEATHSIG` (`SIGKILL`); its descendants
  stay in the scope, frozen, until the next sweep (`tego run`, `tego stop`, `tego gc`), which also writes
  `cgroup.kill` and never thaws (`killOrphan`). Nothing in Tego writes `cgroup.freeze` 0 of a run but its own launcher.
- **What a person saw.** `tego status` said `lost` with no word that the run had been paused or that its processes were
  still there; the dashboard's Lost badge said "nothing runs it any more"; `tego resume` said "not running"; `tego stop`
  ended it and said "not running". A lock held by a process other than the launcher (a process of the run that took
  it after the launcher died) read as live, and `tego pause` and `tego resume` wrote the overlay for it.

**Decision.**

1. **Tego never thaws a run whose launcher is gone, at any tier.** A thaw with no launcher would let the agent run with
   no one deciding its held actions and nothing recording them. No command and no dashboard control thaws such a run,
   and a lost run is ended with `cgroup.kill`, never by a thaw followed by a signal: a fatal signal ends a frozen task
   without returning it to user space. At tier cgroup and bpflsm the reaper does that within milliseconds of the
   launcher's death, as for any orphan. At tier landlock and observe what is left waits for the next sweep. *Corrected
   in review round 1 (below):* this does not make a paused run stay frozen until its launcher dies. A stop thaws the
   run before it signals and writes no line for it (`thawForStop`), and lines queued when the launcher dies are lost,
   so the last pause line is the last state recorded, not proof of the freezer's state; and a watched run's processes
   were never confined to its cgroup.
2. **Detection is the launcher's identity, never a bare pid.** `runlock.LauncherOf` says alive, gone or unknown. Gone:
   the lock is free, or the process the lock line names is gone (no stat line), has exited and is not reaped yet (its
   pidfd polls readable: a zombie holds no lock), or is another process by its start time. Unknown: the identity cannot
   be read (a restricted procfs, a malformed or released stat line: `ErrUnverified`), or a live process that does not
   hold the lock, or another pid namespace. Nothing is called lost, refused as lost, killed or reclaimed on unknown;
   the controls treat it as live. `tego stop` and the sweep's `reclaimHeld` share the same check
   (`OpenStopTargetFor`): before review round 1 every stat read error counted as gone there too.
3. **The words say what is recorded and what the scope shows now.** A run is **lost, last recorded paused** when its
   launcher is gone, it has no `run_end`, and its launcher's last pause line held it paused (`run-paused`, or
   `resume-failed`, with no `run-resumed` after it). `tego status` reads the run's scope (`cgroup.events`, the scope
   `tego stop`'s backstop finds by run_start's cgroup id) and shows STATE `lost, frozen` only when the scope is frozen
   now, `lost` otherwise; under the table it says the last recorded state was paused and what the scope shows now
   (frozen, NOT frozen and running with no launcher, empty, or unreadable), and names `tego stop <run>`; exit 1;
   `--json` adds `launcher_gone: true` and `scope_now` (`frozen`, `running`, `empty`, `unknown`). `tego pause` and
   `tego resume` refuse it, `[lost-paused]`, exit 1, and write nothing; a lock held by a process that is not the
   launcher reads the same way, in the dashboard too. The dashboard, which does not read cgroups, shows "Lost, last
   recorded paused" and says the current state is not known there and that `tego status` reads it; once ended, an
   `orphaned` end whose last pause line held the run paused says that and that Tego closed the orphaned record
   (`LiveFacts.EndedPaused`). It does not infer the cleanup method from those lines.
4. **One command ends it: `tego stop <run>`.** It reads the scope first, its sweep kills what is left and closes the
   record, and it reads the scope again before reporting what is left and the orphaned record's closure. Exit 0 requires
   both a closed record and a scope confirmed absent or empty. A scope already absent or empty needs no kill; an ended
   state alone does not prove a kill ran. If the later scope read shows processes, stop reports them and exits 125,
   `[lost-paused]`. If that scope cannot be read, stop says it cannot tell whether it is empty and uses the same status.
   A sweep that could not close the record leaves the run lost, and stop says so, `[lost-paused]`, exit 125.
   `tego gc` and the next `tego run` end it the
   same way. The dashboard does not link the engine and so cannot sweep (ADR 0100): it names the command.
5. **The record: no new mechanism.** The run is ended by the writer every unclean end already uses: the reaper or the
   sweep opens the ledger, resumes its chain (a torn tail is discarded), appends `gap what=record why=launcher-lost`
   and `run_end reason=orphaned`, and anchors the head in the owner's `chain.log` (record-ledger R6, ADR 0020 (3)).
   `tego events --verify` verifies it as any orphaned run: it proves no line changed after it was written, not that
   the record holds every line. The last recorded pause is read from the lines already there; no field is added.
6. **Compile checks cgroup mount grants within its stated boundary (review round 1, narrowed round 6).** The compiler
   kept write grants off `/sys/fs/cgroup` by its path only, and Landlock grants a write through any other mount of the same filesystem. A
   governed agent granted a folder that held a bind mount of the user's delegated cgroup tree, or a second `cgroup2`
   mount, could write another run's `cgroup.freeze` and thaw it, before or after that run's launcher died, and change
   any cgroup of the user it reaches (members, limits, `cgroup.kill`). R10 now checks these grants within ADR 0059's
   [compile-time mount boundary](0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).

**Tests and proof.** `TestLauncherGone` (`internal/runlock`: a free lock, the holder's own line, no line yet, a pid
that is gone, the holder's pid with another start time, a live process that does not hold the lock),
`TestStatusShowsLostWhilePaused`, `TestPauseResumeRefuseALostPausedRun`, `TestStopEndsALostPausedRun`
(`internal/cli`), and the dashboard's `TestLostPausedRunWords` (`internal/control/web`). The guest proof is
`test/e2e/kt-pause-orphan.sh`, run in a KVM guest (this box's kernel, 6.17.0-41-generic, `bpf` in `lsm=`, 3 GB, 4
vCPUs) on 2026-11-11, at tier landlock as the user and at tier cgroup as root, both passing (the first build, whose
words review round 1 changed):

- **Live launcher, both tiers.** `tego pause` confirmed `run-paused`; for 3 s neither beat file grew and neither
  process's CPU time moved (landlock 51 and 48 ticks, cgroup 44 and 43), `cgroup.events` said `frozen 1`; `tego
  resume` confirmed `run-resumed` and both moved again within 2 s (`frozen 0`); a second pause froze it again. This is
  the first run of pause and resume at a root tier.
- **Launcher SIGKILLed while paused, tier landlock.** The top process died on its `PR_SET_PDEATHSIG`; the child stayed,
  frozen (`frozen 1`), its CPU time 297 ticks before the kill and after it, both beat files unchanged (360 and 414
  bytes) through the kill, the status checks and the stop. The scope's `usage_usec` moved 249 µs after the kill: the
  kernel's exit of the killed top process, which ran no user code (its beat file did not grow). `tego status` printed
  `lost, paused` and the line under the table, exit 1; `--json` `{"state":"lost","paused":true,"launcher_gone":true}`;
  `tego resume` was refused `[lost-paused]`, exit 1; `tego stop` printed `lost while paused: ... (run_end orphaned)`,
  and then both processes and the scope were gone. The record ends `gap`, `gap`, `run_end` (`launcher-lost` among
  them) and `tego events --verify` passed.
- **Launcher SIGKILLed while paused, tier cgroup.** Within 5 s the reaper had killed both frozen processes and removed
  the scope; the beat files were unchanged (324 and 378 bytes). `tego status` said `done`, `orphaned (125)`, and
  `tego resume` `[not-running]`. The record ends `launcher-lost` and `run_end orphaned` and verifies.

**What this does not cover.** A same-uid process outside every run can still write the frozen scope's `cgroup.freeze`
(What this does not cover, above): Tego never thaws an orphan, but it cannot stop another process of the user from
doing so. A run governed by a Tego older than this change can do the same through a write grant that reaches a cgroup
mount by another path (decision 6): every release from v0.1.0 to v0.1.2 compiles such a grant. A mount made after a
run's compile, by a process outside it, is not seen. At tier landlock and observe what is left of a lost run waits for
the next sweep, which a person or the next `tego run` starts; no timer ends it. What `tego status` says of the scope
is true when it reads it.

### Review round 1 (2026-11-11)

An independent review found the first build overstated what the record proves and judged a launcher gone on evidence
that does not show it. Corrected above: decision 1 no longer says the processes never run again (a stop's thaw before
the launcher's death, or lost queued lines, leave a record that says paused over a scope that runs); the words name
the last recorded state and read the scope for the current one; an unreadable stat line is unknown, never gone, in
`LauncherOf`, `tego stop` and the sweep; a zombie launcher is gone; the dashboard reads a non-launcher's lock as lost;
and decision 6 addresses cgroup mount aliases within the referenced compile-time boundary. Tests:
`TestLauncherOfUnknownAndExited` (an unreadable and a malformed stat line are unknown, a zombie launcher whose lock another process holds is gone), the status case "thawed by a stop
before the launcher died" (scope running: STATE `lost`, `scope_now: running`), and `kt-pause-orphan.sh` part 5 in the
guest. Each new unit test fails on a copy with the change taken back (runlock: an unreadable and a malformed stat line
read gone, the zombie alive).

Guest, 2026-11-11 (KVM, 6.17.0-41-generic, the fixed head): `kt-pause-orphan.sh` passed at tier landlock (as the user)
and cgroup (as root). Parts 1 to 4 as before, now with STATE `lost, frozen` and `scope_now: frozen` at landlock. Part 5,
landlock: paused, a stop with a 120 s grace started, the launcher killed: the record said paused, the child's CPU time
moved from 247 to 448 ticks in 2 s, and `tego status` said `lost`, `scope_now: running`, NOT frozen; its beat file did
not grow, since with no launcher a syscall the supervisor decided fails `ENOSYS` (ADR 0013). `tego stop` then ended it.
At cgroup the reaper ended it. Decision 6, same guest: existing mount aliases could bring another run's controls
within reach of a write grant in v0.1.0 to v0.1.2. v0.1.3 refuses grants that reach them, within the documented
mount boundary. The v0.1.2 exposure and the fixed refusal were measured at tier landlock and cgroup, including after the other
run's launcher died; the fixed run was refused before it started (exit 125, `contradiction` naming the `cgroup2`
mount), and the paused run stayed frozen in all three cases.

### Review round 2 (2026-11-11)

- **Unknown stays visible.** `runlock.LauncherCheck` keeps the check that failed. `tego status` shows a run whose
  launcher cannot be judged as its state with `(launcher unknown)`, says which check failed and what to do (make
  `/proc/<pid>/stat` readable, or run the command in the launcher's pid namespace), and adds `launcher_unknown` to
  `--json`; `tego pause` and `tego resume` warn `[launcher-unknown]` and still write the request, which only a live
  launcher answers; the run page says the launcher is not confirmed. Nothing is ended or reclaimed on unknown.
- **The scope's state is known or unknown, never guessed.** The scope lookup (`tegoruntime.RunScope`) skipped a
  candidate it could not `Lstat` or whose cgroup id it could not read, so `tego status` said "no process is left" of a
  scope it could not see. It keeps why (`orphanScopeChecked`), and status reads that as unknown. Review round 3
  extends that same check to sweep: discovery and events-read failures retain the record and live retry entry;
  they do not return successful cleanup, append an end or collect the run.
- **Part 5 of the guest check** waits for the scope to say `frozen 0` after the stop starts, before it kills the
  launcher, and wants two numeric, rising CPU readings of the thawed child.

Tests: `TestStatusShowsAnUnknownLauncher` (a lock line naming a live process that does not hold the lock),
`TestReadScopeKeepsUnreadableApart` (the stop's own discovery over a stand-in cgroup tree: frozen, absent, EACCES),
`TestRunPageSaysTheLauncherIsUnknown`.

### Review round 3 (2026-11-12)

Sweep uses the checked scope discovery for lost and ended runs. A scope access error, failed cgroup-id lookup or
failed `cgroup.events` read is unknown. `killOrphan` wraps it with `errOrphanAlive`, and ledger hooks preserve the
failure, leaving the record and retry entry for a later pass. A successful retry may then kill, end and collect it.
Ended retention invokes the hook under its removal lock, lends the original directory and refuses a replacement
at its name. A missing cgroup manager also retains ended runs for retry. Tests use real directory discovery and events reads: `TestKillOrphanKeepsScopeReadErrors`,
`TestSweepRetainsScopeReadErrorsForRetry`, `TestEndedListedRetainsScopeReadErrorsForRetry`,
`TestSweepRetainsEndedScopeReadErrorsForRetry`, `TestSweepKeepsEndedRunsWithoutACgroupManager`. The kernel check is owed
in a guest: deny scope traversal or the events read after launcher death, run stop/gc, verify no end or deletion,
restore access, repeat, and verify `cgroup.kill` empties it without thaw and cleanup succeeds.

Review round 5 supersedes the earlier free-lock aging policy for damaged ledgers: unknown state retains the record
and reports the error. A free lock proves no launcher holds it, rather than proving no descendants remain. Restore
ledger access or repair the record and retry. This retention rule does not repair arbitrary damaged records.

### Review round 5: classify again under the removal lock (2026-11-12)

A retention sample made before the removal lock cannot choose cleanup. GC reads the current state through that
locked directory's descriptor. A run that became lost receives the lost-run hook; a newly lost transition stays
for the next ordinary sweep to close and anchor its record. An ended transition receives the ended hook. Cleanup
errors, incomplete cleanup and unknown state retain the record for retry. Empty-run cleanup checks its contract
through the descriptor too. A present unreadable or invalid contract is uncertainty, not a missing scope.
`TestGCRetentionRechecksEmptyTransitions` deterministically starts with an empty sample and changes the locked
record to lost or ended, including cleanup errors. `TestGCRetentionKeepsAnUnknownLockedState` and
`TestGCKeepsARunWhoseStateCannotBeRead` cover unreadable state. Kernel race execution is owed in a guest.

Scope discovery also preserves a failed run_start identity read, a failed run-directory owner stat and an
unavailable or malformed root-launch record. It searches other verified roots, so a matching ordinary user scope
remains usable; with no verified match the record and retry entry stay. Adoption-scope stat and cgroup-ID read
failures retain the run instead of treating it as a non-adoption. Tests are `TestRunScopeKeepsAnUnreadableRunIdentity`,
`TestRunScopeKeepsAnUnknownRunDirectory`, `TestSweepRetainsUnknownRootLaunchRecords` and
`TestSweepRetainsUnknownAdoptionScope`. These additional kernel checks are owed in a guest.

### Review round 10: historical orphaned records do not prove a cleanup method (2026-11-12)

An `orphaned` end with a last recorded pause proves what the ledger says, not how cleanup ran or whether the
processes stayed frozen. Before review round 3, some scope discovery or read errors still allowed a sweep to close
the orphaned record without confirming cleanup. No record field distinguishes those historical ends from later
ones. The dashboard therefore says the last recorded state was paused and Tego closed the orphaned record; it does
not assert `cgroup.kill` from an orphaned end alone. `TestLostPausedRunWords` supplies only the pause, launcher-lost
gap and orphaned end, requires that record-only wording, and rejects a cleanup-method claim.

The stop's text reports record closure without claiming a cleanup method. After the sweep it reads the
scope again and states what that reading shows: absent or empty, still frozen, still populated, or unknown.
A scope already absent or empty needs no `cgroup.kill`. The implementation attempts to kill a populated scope before
closing its record; closure alone does not establish the later scope state. `TestStopEndsALostPausedRun` requires
record-closure text and rejects a kill-method claim. `TestStopLostPausedReadsScopeAfterSweep` changes the scope during
the sweep and pins all four later readings and, after review round 12, their exit statuses.

The ended-run cleanup hook conservatively retains the record while its recorded launcher process is still alive,
even if the scope is absent: the launcher may still be between closing its writer and releasing kernel state.
A long-lived library launcher can therefore delay retention until it exits. The record has no separate
cleanup-complete fact. This existing limitation is recorded in GAPS C42; this round changes no cleanup rule.

### Review round 12: a stop succeeds only with a confirmed empty scope (2026-11-12)

The scope reading after the sweep decides whether a lost-paused stop completed, even when the orphaned record closed.
An absent or empty scope succeeds, exit 0. A populated scope, frozen or running, gives `[lost-paused]`, exit 125.
An unreadable scope says `cannot tell whether its scope is empty` with that same diagnostic and status. This uses
the existing CLI error status (`identity.ExitError`, R25), not a new code, and preserves the reported scope and record
facts. `TestStopLostPausedReadsScopeAfterSweep` pins empty, frozen, running and unreadable results; its three failure
cases return 0 without this change. Real scope transitions after the sweep remain owed in a guest.

## Amendment 2026-11-20: whose block an Undo lifts, a Redo that puts it back, and a lift the journal always shows

*Status: accepted 2026-11-20; built.*

**Whose block.** The overlay keeps one entry per key and no word of who wants it, so an Undo could not tell the block
its change placed from one a person placed later (or before) with the same key, and lifted both. A rules change's
placement now records, in the journal's live outcome, the identity of the add that made the block (`liveblock.Own`: the
overlay file's `epoch`, the add's serial and the instant it was recorded; `runact.Blocked.Own`,
`liveblock.Overlay.AddIdentity`) and who made it (`by: change`); a placement that finds the block held (`Blocked.Fresh`
false) is journaled as `held`, with `ok` false, and owns nothing. An Undo lifts a block only while the overlay's newest
change for that key is the add the journal names, all three parts alike (serials start again at 1 in a file that was
removed and written again, and the tool itself tells people to remove an unreadable one), and the removal repeats the check under the overlay's lock
(`runact.UnblockOwned`), so a person lifting and placing the block again between the offer and the lift is a refusal
(`runact.ErrOverlayMoved`) and the block stays. Whatever cannot be shown to be the change's own stays in force, said so in
the answer: this includes every block placed before the journal kept serials. The overlay's format gains one optional
top-level field, `epoch`, a random id a rules change's placement asks for when it adds (`Overlay.EnsureEpoch`); an
overlay no such placement wrote has none and is byte for byte what it was, the version stays 5, and a launcher or writer
from before reads the file as before. A writer from before drops the field when it rewrites the file; no block is then
shown to be anyone's until a newer placement makes a new epoch, so ownership fails closed. A placement over a block that
is held but not in force (ended, or dormant under an unblock for a while) re-arms it, and the block is the change's.

**Redo.** Undoing an Undo (a revert of a revert) narrows the file again; it now also places again the blocks that Undo
lifted: the revert's own journal lines, `by: undo`, finished, on runs of the same file that still run and do not hold the
block now. A block a person placed again since is theirs and is left alone; a block a person lifted by hand, or one an Undo
without the lift box left, is not the Undo's lift and is not put back. What it places is its own: recorded `by: redo` with
its serial, and the Redo's Undo lifts it by the same rules.

**A lift the journal shows.** A lift loosens, so no lift is in force that the journal does not show. An Undo whose own
journal line failed (`rulefile.ErrJournal`) lifts nothing and puts nothing back (the blocks stay, and the answer says so);
a lift or a placement is made only after a line saying it was begun (`pending`) is in the journal, and the line that says
how it ended follows. When the second line cannot be written, the first stays, and History shows the lift as begun with its
end not recorded, which is the truth, and the answer says the outcome is missing. A begun line is replaced in History by the
line that finishes it (`rulefile.Fold`).

**Older readers.** The journal stays at version 1, the record at minor 41, and every new outcome field (`by`, `serial`,
`held`, `pending`) is optional (`internal/rulefile/doc.go`, "Live outcomes and older readers"). A tego that knows only
`run`, `block`, `ok`, `err` and `lift` reads a new line as follows: a placement (by a change or a Redo) as placed, which
it is; a held block, a failed lift, a begun lift or a begun placement as not placed (and a lift as not lifted), with the
line's own words; a finished lift as lifted. One that predates `lift` (a build before 2026-10-27, never released) reads a
finished lift as a block placed: "blocked" of a block that is gone. No older reading says "allowed" of a block that holds.
The older reader's own Undo, which knows nothing of owners, may still lift a same-key block a person placed (the old
behaviour); the new rules are the new tego's.

**Review fixes (2026-11-20).** The latest placement of a block on a run counts for an Undo, not the first
(placed, lifted by hand, placed again by Apply now). A change that found the block already held (`held`) still counts as
asking for it, so another change's Undo leaves it. A Redo says which blocks it did not put back and why (run ended, run
not readable, already held, journal unreadable, journal does not hold the undo) in `Reverted.Restored`.

**Not covered.** A block the change's own add made that a later add of the same key changed (a person extending its limit)
no longer shows the change's serial and is left in force. The rule-change journal does not show a block a rules change placed
when the journal could not be written after the placement (Also apply now): the run's ledger records every block change
by serial (the launcher's gap lines), and the save's own answer carries the journal error.

## Amendment 2026-11-21: path, read and write blocks in the kernel decision plane (A35)

*Status: accepted 2026-11-21; built. Supersedes the "Write blocks on a tier-3 plane" line of "What
this does not cover" for launchers that make the `live-plane` mark.*

**Defect.** At tiers cgroup and bpflsm with a decision plane (`decision_plane` lsm or fmod_ret) the seccomp filter
no longer notifies write opens and fs mutations (`planeSkips`): the plane decides them in the kernel from rows fixed at
launch. A live block was applied by the supervisor alone, so on such a run it refused only what still reached the
supervisor, and the 2026-11-20 wording fix ("Partly in force") said so. A person's block on a running agent must also
stop the changes, and the reads, the kernel decides alone.

**Decision.** On such a run a path, read or write block is also put in force in the plane, by the run's own launcher,
in the kernel, on the objects the block's path names when it lands.

1. **Rows.** Each slot gets a second inode-keyed map, `tego_plane_blocks` (an inner `HASH` per slot in a
   `HASH_OF_MAPS`, created once per slot and build and kept with the slot as `tego_plane_rows` is, ADR 0025 (1)), with
   at most `TEGO_PLANE_BLOCK_ROWS_MAX` (1024) rows. A row is keyed by a `struct inode *` that only the kernel sees
   (ADR 0025), or, for a name that does not exist yet, by a mix of its directory's `struct inode *` and the name's key,
   top bit clear, so the two forms never meet. It carries the key inode's identity (`i_ino`, `i_generation`, `s_dev`;
   the directory's for a name row), the run's gen, the CLOCK_BOOTTIME instant before which it refuses nothing (a dormant
   block, ADR 0125 decision 4; 0 for now), and up to three live-block ids: the block that refuses reads there, the one
   that refuses changes there, and the one whose path runs through the object (a guard). Flags say whether the row
   refuses at the object itself (`SELF`), beneath it (`BENEATH`), only for the walk inside one superblock
   (`MOUNT_ONLY`), and whether it is a name row.
2. **What a block keys.** For each spelling of the block (its value, its `Real`, and every other name the mount table
   gave the file, `Resolved.Others`, which includes a bind of a part of the tree elsewhere), the launcher walks the path
   element by element, as the kernel's lookup does (each link followed, at most `liveblock` RealPath's budget), and
   opens an `O_PATH|O_NOFOLLOW` descriptor of every element that exists:
   - the object the path leads to is the **target**: `SELF|BENEATH`, with the block's read or write id (a path block
     both), and the block's id as its guard too;
   - every directory and every link the walk passed through is a **guard**: its own rename, unlink and rmdir are
     refused while the block stands, so the path keeps landing where it landed when the block was placed (the
     supervisor refuses the rename of a folder above a block for the same reason, `MatchWithin`);
   - where an element does not exist, the deepest existing directory and the missing element's name are a **name
     row**: creating that name (mknod, an `O_CREAT` open, mkdir, symlink, the new end of a link or a rename) is refused,
     whichever block kind it is, so nothing the plane has not seen comes to exist at or above the block. When that
     element is not the last one this refuses a little more than the supervisor does (making the block's missing folder);
     the person's block names the rule, and the launcher keys the real objects at the next poll once they exist;
   - every mount whose mount point lies at or beneath a target is keyed at its root as `MOUNT_ONLY|SELF|BENEATH`, for the
     attribute hooks that walk inside one superblock (setxattr, removexattr, the ACL hooks), as the contract's own rows
     are (`PlaneRows.Mounts`).
   Rows of one object from several blocks are one row, the union of their ids and flags, the earliest instant.
3. **Fill.** The launcher holds every descriptor while its rows exist and fills the rows through the plane's own fill
   (`tego_plane_fill`, iter/task_file over its own descriptor table, templates keyed by its tgid and carrying the run's
   gen; ADR 0025 (2)), so no key reaches userspace. It deletes rows the same way (a `DEL` template on the descriptor
   still held), then closes the descriptor: a pointer is never reused under a live row of its run.
4. **Check.** Every plane fs hook asks the blocks after the contract's own decision allowed and was settled (before it
   is recorded, so the verifier walks the check on one path), when the slot's block
   state (`tego_plane_block_state`, one per slot, userspace-written, of the run's gen) says blocks are on. A global
   function walks from the object to the namespace root, crossing mounts as the contract walk does, up to
   `TEGO_PLANE_WALK_MAX` levels, and looks each level's inode up: at the object itself a `SELF` row of the asked class,
   or a guard for a move or removal; above it a `BENEATH` row. It does not stop at the contract's nearest row: a nearer
   `fs.write` entry does not reopen a blocked folder. The classes per hook: `file_open` read and/or write by its
   `f_mode` (an exec's image open reads); mknod, mkdir and symlink write, plus the name row at the new name; unlink
   and rmdir write plus guard; rename both ends read, write and guard, plus the name row at a negative destination;
   link the source read and write, the new name read, write and the name row; the truncates, chmod, chown, the xattr
   and ACL hooks write. A hit refuses with the hook's own reason and rule `live.block[<kind>:<value>]`
   (`TEGO_PLANE_RULE_LIVE_BLOCK | id`, 0x4000 and an id below it, which fits the 16 bits a recorder fexit's header
   carries; the launcher's id table names it, `observe.Recorder.SetLiveBlockRule`); a row whose key inode no longer carries its
   identity refuses `identity-mismatch`; a walk that cannot reach the root (disconnected, past the bound) refuses
   `path-unresolved` while a block of the asked class is on. Each row carries the classes it refuses at its object and
   beneath it as two masks the fill derives, so a level costs one test; a name row's name key is its length and first
   32 bytes mixed, read in four words with no loop, so two names in one directory that share both share a row, which
   only refuses more. The walk is a second form-d walk (ADR 0024 (1)) in each fs program: measured, it adds about 3,100
   verified instructions on 6.17 and 4,400 on Fedora's 7.0.14, where every bpf_loop callback is verified as a loop;
   the plane's root-test budget grows by 8,000 for it (ADR 0024, verifier budget amendment 2026-11-21).
5. **Bound and overflow.** A block the plane cannot hold whole (the map full, a path the walk budget cannot resolve, a
   descriptor that cannot be opened, a mount point beneath a target that cannot be opened (one gone since Prepare holds
   nothing), other names of the file the mount table could not list in full, more than `TEGO_PLANE_BLOCK_ID_MAX`, 16383,
   ids in a run) sets the slot state's overflow bit for its class
   (read, write): every plane-decided action of that class is then refused under the block's rule, so the block is
   in force, broader than asked, never narrower. The bit is cleared only after every row it stood for is in.
6. **Order and the ledger.** The plane follows the same entries the supervisor's Set is compiled from (`store`): the
   overlay as last read (an unreadable overlay keeps the last blocks; a removed or recreated one, b2's `epoch` and
   serials included, drops what it no longer lists), less blocks whose `until` has ended (removed at that poll, at
   most half a second late, which only refuses longer), with a dormant block's `from` as its rows' instant (its pin on
   CLOCK_BOOTTIME). Tightening goes state first, then rows; loosening rows first, then state. The `live-block-added`
   line is written after the rows are in, so "in force" is never claimed before the kernel holds it. A launcher that
   cannot write its block state at all ends the run (reason error) rather than claim a block it cannot hold. The launcher
   resolves every block again on each poll (a few lstat calls), so a name that came to exist is keyed by its object.
   A walk only adds: every object a block has keyed stays keyed, by the descriptor that pins it, until that block is
   removed, wherever the object has moved since (a rename racing the first fill, a host-side rename of an ancestor, an
   editor's save by rename), so a block follows the object it landed on; a row the map had no room for is held with its
   descriptor and tried again on each pass, its class refused whole meanwhile. A later walk that meets a held object in
   a weaker role (a moved target met as a guard) adds its row to the held one and never replaces it. The launcher walks
   again after every pass that put a row, before the `live-block-added` line, until a pass puts none: such a pass met
   only objects already keyed, which the run can neither move nor replace, so the path's object is keyed (amended
   2026-11-22: two passes were not enough against an agent that renames a fresh file over the path during every fill). A sync that is still putting rows after `blockSyncPasses` (8) passes refuses every block's classes whole
   before it returns, and in each pass after, until a sync settles. The rows grow with what the blocks touched, within
   item 5's bound.
7. **Writers.** Such a launcher makes the run directory's `live-plane` mark once its poll runs; `livestatus` reads a
   path or write block on a run with the mark as In force (a path block's reads included, since the plane decides
   reads), and Also apply now offers a write block there. A run without the mark (an older launcher) keeps "Partly in
   force".

**Where the guarantee sits.** In the kernel, on the object the kernel resolved, for every task in the run's cgroup:
children, threads, an exec'd image and a process adopted into the run later (ADR 0055) are decided by the same
run-set row. The supervisor keeps applying the block to what still reaches it.

**What changes for users.** On a plane run a block follows the file, not the spelling: a hard link made before a block
on that file, and the file under a moved ancestor, stay blocked (a hard link made before the block to a file *inside* a
blocked folder is another name in another folder, which no row above it keys: it is not refused, as the supervisor's
path match does not refuse it either; a link made after the block is refused at the link); a rename or removal of a folder (or link) the block's path runs
through is refused; a read block also refuses deleting or replacing the blocked file (the kernel cannot follow a file it
has not seen, so it does not let the name be freed); and any block refuses creating its own missing name, and the first
missing folder above it.

**Threat model and how this could be wrong.**
- *A plane-decided mutation that misses the check.* Candidates: an `O_CREAT` refused only at `path_mknod` on the parent
  (the walk starts at the negative dentry, so the parent is depth 1 and the name row depth 0); rename's second end; a
  `RENAME_EXCHANGE` destination; `linkat(AT_EMPTY_PATH)` (an `O_TMPFILE` linked by descriptor goes through
  `security_path_link`); `ftruncate` on a descriptor opened before the block (`file_truncate`, or `path_truncate` below
  6.2); `fchmod`/`fchown` (`path_chmod`/`path_chown` on the file's path); `fsetxattr` (the inode hook); an io_uring op (the
  same hooks); a mount crossing. The source test holds every fs hook to the call, and the root test drives each class.
- *An object reached outside the blocked tree.* A bind of a part of the tree elsewhere is a spelling of `Others`; a mount
  made after the block is not seen (GAPS C68, as for the supervisor), and neither is a host-side rename of an ancestor,
  until the next poll re-keys the path's new objects; the old ones stay blocked (item 6: a walk only adds), which
  `TestPlaneBlocksKeepTheFileUnderAMovedAncestor` and the root test's host-side move hold.
- *Key reuse.* Rows are keyed by an inode the launcher pins with a descriptor. Between a launcher's death and the reaper's
  `cgroup.kill` nothing pins it: an evicted inode's address reused by another inode meets the row and refuses
  (identity-mismatch), and the blocked file read back in under a new address is not met. That window is the residual
  below; contract rows are unaffected (the domain pins them).
- *A torn read of the block state.* Userspace writes it whole while hooks read it; each field a hook reads is a word, and
  every transition is ordered so that a stale or partial read can only refuse more: on before rows, overflow before a
  failed row is given up, off and clear only after the rows are gone or in.
- *A stale row.* Rows carry the run's gen; a slot's next run ignores them, and its Prepare's clear deletes them.
- *A removal that fails.* The rows stay (refusing) and the descriptors stay open; the next poll tries again. The
  supervisor's Set has already dropped the block, so the run refuses more than its overlay says until then, never less.

**Residuals.**
- A descriptor opened for writing before the block keeps writing, and a shared writable mapping keeps changing the file:
  no hook sees `write(2)`, as at tier landlock.
- A name made by a process outside the run inside a blocked folder is blocked (beneath the folder); a name made outside
  the run at a block's own missing name is met by the name row only for creations by the run, and its contents are keyed
  at the next poll (at most half a second).
- A block is on a path, as the person names it, not on the object they saw: when the file is somewhere else at the
  instant the launcher walks (an agent renaming it to and fro), the block lands as a name row at the path and the moved
  file was never the blocked object. Pinning the object the person saw would need its file handle passed with the block
  (`name_to_handle_at`, opened by the root launcher with `open_by_handle_at`); not done.
- A block keeps every object it keyed until it is removed, an orphan too: each host-side atomic replace of a blocked
  file (an editor's save, a git index write, logrotate) adds one unlinked inode, pinned with its descriptor and its disk
  space, to the block's rows. Not released even when it has no name left, since a descriptor of it held by the agent (an
  O_PATH one reopened through `/proc/self/fd`) would then write it unrefused. About 1024 such replaces in one run fill
  the slot's map, and the block's class is then refused whole for the rest of the run (item 5): fail closed, broader
  than asked.
- While any block is on, every plane-decided file action of the run deeper than `TEGO_PLANE_WALK_MAX` (64) levels
  below the namespace root is refused `path-unresolved`, anywhere in the run: the block walk goes to the root and cannot
  say no block lies above a level it cannot reach. Fail closed; deep trees (nested `node_modules`) can reach it.
- Timestamps and inode flags: `utimensat` (`touch`, which needs only write permission) and the `FS_IOC_SETFLAGS` /
  `FS_IOC_FSSETXATTR` flags that need no capability still change a write-blocked file's metadata, since no plane hook
  covers `inode_setattr` for times or `file_ioctl` (ADR 0024's note of 2026-10-05 for `deny_write`); a write block's
  "In force" covers the file's contents, names, mode, owner and extended attributes, not these.
- Between a launcher's death and the reaper's kill, a row's inode is pinned by nothing (above).
- A dormant block whose `from` the wall clock reaches before CLOCK_BOOTTIME does (a wall clock stepped forward) comes
  back in the plane at the next poll, at most half a second after the supervisor's.
- A launcher in a time namespace with a boot-time offset cannot give the kernel a dormant block's instant: its dormant
  blocks keep refusing in the plane until they begin (fail closed).
- Plane runs whose launcher predates this keep the 2026-11-20 words.
