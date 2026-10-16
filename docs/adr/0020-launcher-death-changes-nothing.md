# ADR 0020: a launcher's death changes nothing the kernel enforces, and a reaper ends the orphaned run at once

Status: accepted 2026-09-29, implemented 2026-09-29 at tier 2 (the fanotify fallback) with the departures in the implementation note below; (3)'s release of rows and rings amended 2026-09-29 (note below); (2) to (4) extended 2026-10-05 to a run with a DNS broker endpoint, at every tier (note below). Proposed 2026-09-23. Amends ADR 0013 (the 'optional later' reaper is built), enforce-cgroup-observe E38 and E15, runtime-launch §6 case 13 and I7.
Amended by ADR 0042 (accepted 2026-10-05): the file-capability residual and kill tests are conditioned; under tegod each run's instance starts the reaper.

Decision: (1) The run's cgroup links (connect4/6, sendmsg4/6, bind4/6, connect_unix, sendmsg_unix and ADR 0018's sock_create and, from 2026-10-17, setsockopt) are pinned under <bpffs>/tego/<bpf_hash>/links/run-<id>/ as they attach; Detach unpins them. (2) At tiers 2 and 3 the launcher starts tego __reap --run <id> after Prepare and before the child stage, through proc.Start (ADR 0021), so before arming, and never waits on it. The reaper runs in a new session and its own cgroup, tego.slice/tego-reap.slice/reap-<id>.scope, with oom_score_adj -1000 where the launcher holds CAP_SYS_RESOURCE. It inherits exactly three descriptors, each a sys.FD released into ExtraFiles (ADR 0023): a pidfd of the launcher (pidfd_open(getpid()) in the launcher before the start, never pidfd_open(getppid()) in the reaper, which races with the launcher's death), an O_PATH descriptor of the run directory, and the verified /run/tego descriptor (ADR 0034). It closes every other descriptor with close_range at start and accepts no other input. (3) When the pidfd becomes readable, the reaper sweeps its one run: it takes runs/<id>/lock and exits if the ledger has run_end; otherwise it writes cgroup.kill, waits for cgroup.events populated 0, appends run_end reason=orphaned, removes the run cgroup, and only after that rmdir has succeeded unpins links/run-<id>, deletes the run's run_set rows and clears the slot's plane rows in the kernel (ADR 0025 (1) as amended). The slot's row maps and rings stay in their outers for the slot's next run (ADR 0026's 2026-09-25 and 2026-09-29 notes); ADR 0026's reclaim and trim remove them. A run whose cgroup cannot be removed keeps its links and rows, and its slot stays held. All ledger I/O goes through the ledger package's descriptor-relative, O_NOFOLLOW discipline (internal/ledger handover.go) from the inherited run-directory descriptor, never by re-resolving a path. It then does ADR 0022's build duties or exits. (4) If the reaper cannot be started: in the fanotify fallback, where it is the only narrowing of E15, Prepare fails; with a plane mode, the run records gap what=enforce why=reaper-unavailable and proceeds. (5) watchCgroup's give-up path records gap what=record why=cgroup-events-unavailable instead of a run-log warning (ADR 0015). (6) SweepRun (the reaper's and tego gc's) finds a run's links through run_start's bpf_hash, never through the hash of the binary doing the sweep. (7) Stated: under the file-capability path the reaper cannot lower its oom_score_adj (no CAP_SYS_RESOURCE), so one OOM kill can take it with the launcher; the next sweep then collects the run.

Why: [documented] A bpf_link is freed on its last close (af6eea57437a) and today's run links are unpinned, so a SIGKILLed launcher takes network enforcement off a run whose processes live until the next run, stop or gc (E38).
[documented, fs/notify/fanotify/fanotify_user.c] fanotify_release answers pending permission events FAN_ALLOW (E15).
[measured] A SIGKILLed last launcher leaves its build's 9 links and ring on all six kernels (ADR 0022).
[measured] A helper exec'd from the tego binary idles at 6.1 MB RSS (1.6 MB anonymous) with 5 threads.
[documented, internal/ledger/handover.go, inference] The launcher writes the ledger through a dirfd walk with O_NOFOLLOW; a privileged reaper that re-resolved runs/<id> by name would give a same-uid process a symlink target to write through.
[documented] cgroup.kill is asynchronous, so rows and links must outlive the processes they govern.
[inference] Once links are pinned, every enforcement at tiers 2 and 3 is kernel-resident; the reaper is needed for promptness and the record, and in the fallback it is the only closure of E15.

Security argument: Network enforcement is fail-closed by construction once links are pinned. Links and rows go only after the run's processes are provably gone. The reaper runs as root but takes no input, holds only three inherited descriptors, acts on one named run after verifying its ledger, never follows a path it did not open, and does only what tego gc already does. In the fallback a run without a reaper does not start. Stated residual: in the fallback, if the launcher and the reaper die together (a cgroup-wide OOM kill, systemctl stop of a unit holding both, or an OOM kill in file-capability mode), E15's allow window lasts until the next sweep.

Options considered: Chosen: pinned run links plus a per-run reaper with a minimal inherited descriptor set.
Rejected:
- tegod as the owner of run lifetimes: a long-lived daemon with an API inside the TCB.
- A reaper inside the run's cgroup: killed with the run.
- No reaper, the sweep only: orphans run until the next tego command.
- The reaper resolving the run directory by path: a symlink target for a privileged writer.
- The launcher waiting on the reaper's start-up: Go start-up on every run's critical path.

Consequence: E38 closes. E15 closes wherever ADR 0024's plane runs and narrows to the reaper's reaction time in the fallback. The orphan window becomes milliseconds, at the cost of one small root process (about 6 MB RSS, 5 threads, measured) per live tier-2 run. A killed run's pinned links cost nothing once its cgroup is removed, and the sweep removes them.

Implementation plan:

- enforce/cgroup attach.go: pin each run link as it attaches, with an idempotent unpin in Detach (I10). Fold in E36's doctor attach probe (a throwaway connect4 and sock_create on a scratch cgroup).
- internal/runtime/sweep.go: SweepRun(ctx, id) with item 3's order and item 6's lookup by bpf_hash.
- internal/runtime/reap.go and a hidden cmd/tego __reap: clone3 with CLONE_INTO_CGROUP into the reap scope through proc.Start, then setsid, close_range and the pidfd wait.
- internal/runtime/cgroup: create tego-reap.slice.
- runtime.watchCgroup: the gap line.
Unit tests:
- watchCgroup's gap.
- The reaper refuses to act on a ledger with run_end.
- A runs/<id> swapped for a symlink after start is never followed.
- The inherited descriptor set is exactly three.
As root in GUEST and on MATRIX:
- SIGKILL the launcher while a test hook holds the reaper: the run's refused connect stays refused.
- Release the hook: run_end orphaned is written within 100 ms, and the cgroup and links/run-<id> are gone.
- An agent stuck in D state keeps its links and rows.
- SIGKILL the launcher and the reaper together: the next tego gc sweeps the run.
- systemctl stop of a scope holding the launcher.
- The fallback refuses Prepare when __reap cannot start (a test hook makes the start fail).
- A file-capability copy passes the same kill tests.
Docs: ADR 0020; ADR 0013 amended; ARCHITECTURE §6 (supervisor death, liveness and the orphan sweep); runtime-launch §6 case 13 and I7; enforce-cgroup-observe E38 and E15.

*Amended 2026-09-29 (T1, TIER3-PLAN §11; accepted):* (3) said the reaper deletes the run's "plane rows and rings".
Since ADR 0026's 2026-09-25 amendment a slot keeps its rings, and since ADR 0025's 2026-09-29 amendment it keeps its
row maps, both because an outer update waits an RCU grace period; the reaper's release is the run_set rows, the
link pins and the in-kernel clear of the slot's rows, in (3)'s order. A clear the reaper does not finish is harmless:
the slot's next run has another gen. Nothing else changed; the text is final, and the reaper is being built.

*Amended 2026-09-29 (implemented at tier 2):* built in `internal/runtime/enforce/cgroup` (kernel.go and pins.go pin
and unpin `links/run-<id>`; reap.go `PurgeRun`, `ReapBuild`), `internal/runtime` (reap.go `ReapMain`, `sweepRun`,
the launcher's `startReaper`; sweep.go `purgeOrphan`), `internal/ledger` (`OpenAt`, `Writer.OpenDirPath`) and
`cmd/tego` (`__reap`). No plane mode exists yet, so every tier-2 run is the fanotify fallback and (4)'s refusal
applies: a reaper that cannot start fails the run, exit 125. Departures, each forced by the code as it stands:
- (2) The reaper runs in `tego.slice/helpers.scope` through `cgroup.StartHelper` (clone3 into it), beside the
  linger timer and the probe detacher (ADR 0022's 2026-09-24 amendment), not in a `reap-<id>.scope` of its own: a
  process cannot remove the cgroup it is in, so a per-run scope outlives its reaper with nobody left to remove it,
  one leaked cgroup per tier-2 run. proc.Start (ADR 0021) and sys.FD (ADR 0023) are not built; the start is an
  `exec.Cmd` with ExtraFiles, `Setsid` and stdio on /dev/null, and the reaper writes its own `oom_score_adj`.
- (2) Two inherited descriptors, not three: the launcher's pidfd (fd 3) and an `O_PATH` descriptor of the run
  directory (fd 4), opened through the ledger Writer's own descriptor (`Writer.OpenDirPath`), never by path.
  `/run/tego` is opened by name and verified (`hoststate.Open`), as every launcher opens it: the slot table, rings
  lock, build lock and timer functions all take the state directory that way, and `/run` is root's, so no same-uid
  process can swap it. The rest (run id, agent, run directory name for messages, cgroup mount, path and id, build
  hash, bpffs, state directory, `bpf.linger`, chain anchor) is argv, fixed by the launcher before the child stage
  exists; a malformed field makes the reaper do nothing. `close_range` is a pass over `/proc/self/fd` that closes
  every descriptor above 4 but the Go runtime's poller (`closeStrayFDs`).
- (3) The run's scope is the launcher's path with the launcher's cgroup id: a scope of that name with another id is
  never touched. `cgroup.kill` is repeated every 5 s while the scope stays populated, so the reaper does not give
  up on a tree in D state; nothing is purged meanwhile. A lock another process holds (a process of the tree that
  took it, or a racing sweep) is retried for 5 s once the tree is gone. A ledger with `run_end` whose scope is gone
  was torn down by its launcher, and the reaper exits; one with `run_end` and its scope still there (a launcher
  killed between `Close` and its cleanup) is killed and purged without a new line. A ledger with no `run_start` is
  left for retention, as the sweep leaves it.
- (3) The release is `PurgeRun`: the run's link directory; the run-set rows of vanished cgroups (keys only); and,
  for this binary's own build only (the row layout is not a cross-build contract, ADR 0022 (5)), the verdict rows
  and counters of every slot whose launcher is dead and that no run-set row carries, each slot claimed in the slot
  table for the purge and freed after; then `TrimRings`. Pool rings stay at their slot, per the T1 note above.
  `PurgeRun` itself refuses while a cgroup of the run's id exists, whoever calls it.
- (3) The build duties: when no launcher holds the build lock, the reaper stamps its mtime and, at `bpf.linger` 0,
  runs `SweepBuilds`; otherwise it starts the build's timer process (`__bpf-linger`) rather than becoming the timer,
  which would keep a `__reap <id>` process alive for the linger naming a run that has ended.
- (6) `tego run`/`stop`/`gc` sweeps, as root, purge the same once they have removed an orphan's scope, from
  `run_start.bpf_hash` (`purgeOrphan`); `tego doctor` lists each build's run link directories.
- Built 2026-10-16 (ADR 0018 PR 2): E36's doctor attach probe is D7's cgroup rows, `connect4` and
  `sock_create` among them, which name an attach conflict as a run does (`cgroup.AttachConflictHint`); and ADR 0018's
  `sock_create` link is pinned with the run's others (`TestNetLinksOutliveTheLauncher` refuses a socket after the kill).
- Built 2026-10-17 (ADR 0018 (7)): `cgroup/setsockopt`'s link is pinned with them too, and its D7 row names a conflict
  the same way (`TestNetLinksOutliveTheLauncher` refuses a `TCP_ULP` after the kill).
- Not built: the MATRIX rows; the file-capability kill tests; `systemctl stop` of a
  scope holding the launcher; a D-state cell.
Measured as root in the 6.17 KVM guest (4 vCPUs), `TestTier2ReaperEndsAnOrphanOnlyOnceItsTreeIsGone`: with the
launcher SIGKILLed and the reaper held, the run's connect4 program stays attached to its scope, its links pinned
and its run-set row present while the descendant lives; released, the reaper wrote `run_end orphaned` in 9-23 ms
and the descendant, scope, links, row and reaper were gone 33-47 ms after release (four runs, both suites), inside
the 100 ms the design asks. Also as root:
`TestTier2ConcurrentReapersEndAnOrphanOnce` (two reapers and `tego gc` racing: one `run_end`),
`TestTier2AReapersDeathLeavesTheRunToTheSweep`, `TestTier2RunRefusesWithoutItsReaper` (exit 125, no `run_start`),
`TestTier2ANormalRunLeavesNoReaper`; unprivileged, the argv round trip, the descriptor set, a symlink swapped in
for `runs/<id>` never followed, an ended run left alone, and `watchCgroup`'s gap (`internal/runtime/reap_test.go`).

*Amended 2026-10-05:* a run with an owned DNS broker endpoint
(`net.dns.mode: broker`, [network controls](../p0/network-controls.md) R8) gets a reaper at every tier, `landlock`
and `observe` included, to remove that endpoint once the run tree is gone. The reaper's mechanism, its one-run
scope and its descriptor discipline are unchanged; what it is handed and when it exists grow, and (2) to (4) read
so for such a run:
- (2) The reaper starts after `Prepare` whenever the handle is tier 2's (`ReapTarget`) or a DNS directory is held
  (`startReaper`, `internal/runtime/reap.go`). Beyond fds 3 and 4 it inherits two more: the held DNS socket
  directory (fd 5) and the verified root-owned `/tmp` parent (fd 6). Its argv grows from 13 to 16 fields: the
  directory's name (`tego-dns-<digits>`) and the socket's device and inode. A malformed field still makes it do
  nothing. The "exactly three descriptors" of (2) and the security argument, already two in the implementation
  note above, are four for such a run.
- (2) At tier `landlock` or `observe` there is no `ReapTarget`: the reaper runs as the launcher's user and, when that
  is not root, in the launcher's own cgroup (`cgroup.StartHelper`'s fallback), where it cannot lower its
  `oom_score_adj`. A unit stop or OOM kill that takes both leaves the endpoint and the orphan to the next sweep, as
  (7) states for the file-capability path.
- (3) On the launcher's death it sweeps the run as (3) says: `cgroup.kill`, `run_end reason=orphaned`, the scope's
  removal. With no `ReapTarget` it purges no kernel state and does no build duties. Only then does it remove the
  endpoint, after checking the parent, the directory and the socket against the identities it was given
  (`cleanupReapDNS`); a replaced object is left alone. At tiers `landlock` and `observe` this ends a broker run's
  orphan at once, where runtime-launch case 13 left it to the next sweep.
- (4) A reaper that cannot be started for a DNS endpoint fails the run before `run_start`, exit 125, at every tier.
  Without that cleanup a killed launcher leaves a socket and directory under `/tmp` that no sweep removes, because
  the sweep never scans `/tmp` (R8). In practice a start fails only when `pidfd_open(self)`, the run directory's
  descriptor or the fork/exec fails: a helper cgroup that cannot be made falls back to the launcher's own.
Cost: one detached helper per live broker run at tier 1. Tests: `TestDNSReaperMetadataDescriptorsAndStartupRollback`
(no handle and a DNS directory: the reaper is attempted, sees fds 0 to 6, and a failed start fails the run),
`TestDNSReaperPreservesForeignSocketAndDirectory` and `TestDNSReaperWaitsForActualLauncherDeathBeforeCleanup`
(`internal/runtime/dns_reap_test.go`), and, as root, `TestDNSBrokerOrphanCleanupOnRealKernel` at tiers `landlock`,
`cgroup` and `bpflsm` (`dns_lifecycle_integration_test.go`). Ordinary runs keep the 13-field, two-descriptor
contract (`TestTheReaperInheritsExactlyTwoDescriptors`). The dns-5 note below moves this reaper's start before
`Prepare` and gives it a fifth descriptor, the target handoff pipe (fd 7).

*Amended 2026-10-05:* a run with a cooperating DNS broker (`net.dns.mode: broker`) starts its
reaper right after the broker binds `/tmp/tego-dns-N/dns.sock`, before Prepare, not after it: the endpoint must
exist before Prepare (the tiers' rules name it), and a launcher SIGKILLed or OOM-killed while Prepare loads and
attaches left the directory and socket with no reaper to remove them, since nothing else knows their names. The
reaper's Prepare-dependent argv (build hash, bpffs, state directory, linger, slot, plane mode) is not known then,
so that reaper starts with an empty target and inherits a fifth descriptor, the read end of a pipe (fd 7), through
which the launcher's `startReaper` hands it the tier's `ReapTarget` after Prepare in one write of at most PIPE_BUF
bytes, all of it or none, and then closes it. Once its launcher is gone the reaper reads that pipe without
blocking: a target there is used as (3) uses argv's; none (a launcher that died during Prepare, or a tier with no
kernel state) leaves the tier's state to the sweep and `gc`, as (4)'s unstartable reaper does, while the reaper
still ends the run and removes the endpoint. A DNS reaper that cannot start fails the run before Prepare.
`TestDNSReaperExistsBeforePrepare` and `TestDNSReaperTargetHandoff` (unprivileged) and
`TestDNSBrokerOrphanCleanupOnRealKernel` (root, all three tiers) cover it. Runs without a DNS broker are unchanged.

*Amended 2026-10-05 (ADR 0023's acceptance note, correction of fact):* (2)'s "each a sys.FD released into
ExtraFiles" is not yet true: the reaper's pidfd and run directory (the implementation note's two descriptors) are
bare numbers handed to ExtraFiles, and ReapMain's `closeStrayFDs` returns silently when /proc/self/fd cannot be
read. It becomes true at ADR 0023 C9 (the self-pidfd from `sys.PidfdOpenProcessFD`, each descriptor released into
ExtraFiles, `sys.CloseInheritedFrom` failing closed with exit 125, `sys.Inherited` with kinds), which also
supersedes the departure above that says sys.FD is not built.

*Amended 2026-10-05 (ADR 0042 (3)(c), (7)(b)):* (7), the Security argument's file-capability residual and the "Not
built: the file-capability kill tests" line are conditioned by ADR 0042 (3)(c): no file-capability copy runs in this
release (it is refused at start), so those kill tests are owed only if that path returns by its own ADR. Under
tegod, when a trigger builds it, each run's instance starts `tego __reap` exactly as a sudo launcher does, one
lifetime model.

*Amended 2026-10-19 (implementation note, ADR 0023 C9):* sys.FD is built for the reaper, so (2)'s "sys.FD (ADR 0023)
is not built" no longer holds for its descriptors. The launcher's pidfd is born an owner
(`sys.PidfdOpenProcessFD`) and released into the File ExtraFiles passes, with the run directory and, for a run with
an owned DNS broker endpoint, the socket directory, its /tmp parent and the handoff pipe, whose two directories are
owners released into Files as well. The reaper's start-up sweep is `sys.CloseInheritedFrom`, its first descriptor
operation, and it then owns each inherited number through `sys.Inherited` with the kind its launcher passed (pidfd,
directory, directory, directory, FIFO). A sweep that cannot list `/proc/self/fd` (it returned silently before) and a
number that is not its kind both end the reaper with exit 125 before it waits on, reads, sweeps or unlinks anything:
what it would act on could be another file, and the run is then left to the next sweep, as for a reaper that died.
