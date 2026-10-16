# ADR 0055: adopt an agent that is already running: move its own process tree into a run, record it from the kernel, never kill it

Status: **accepted 2026-10-16** (stage 2 of ADR 0054); `tego adopt`, the guard (`tego agents --follow --adopt --uid`), the release request, the reaper and the scope guard are built and run as root on the real kernel; the pre-armed standby scope (question 3), network rules on an adopted process (question 4) and plane hooks holding its mount topology (question 6) are not built. Amends in part ADR 0054 (stage 2 holds no network rule).

Stage 2 of ADR 0054: "decided only after stage 1's evidence: put the matched agent in a fresh cgroup of its own and
attach the root tiers' programs". Measured, built and tested as a POC (2026-10-06), merged on 2026-10-16, where the scope guard was reviewed and tightened
(Decisions 2 and 6, "The scope guard").  The operator's manual is docs/OPERATIONS.md "Adopting an
agent that is already running".

## The ask

The goal: "Tego sits on the machine, notices an agent starting anywhere, records what it does from the
kernel, and can deny what it must not touch." `tego agents [--follow]` (stage 1) only detects. A process that is
already running cannot be given a seccomp filter, Landlock or another environment: whatever governs it has to be root's
and the kernel's. The question was whether the tier-2 programs, unchanged, can govern such a process, and how much.

## What was measured

All on 6.17.0-41-generic in KVM guests (`test/vm/kvm-run.sh`, 2 GiB, 4 vCPUs), on both boots the test machine can have: the
kernel's own LSM list (no BPF LSM, the decision plane in fmod_ret mode) and with `bpf` added (LSM mode). Two sources:
the probe `test/vm/cmd/adoptprobe` (written first, for the questions below), and the root integration tests of the
built feature (`internal/cli/adopt_integration_test.go`, six tests, pass on both boots). Probe output is
reproducible with the commands at the end.

**(a) A live tree can be moved into a fresh run cgroup and recorded afterwards.** One write of a pid to the new
cgroup's `cgroup.procs` moves the whole process, every thread (5 of 5 threads of a Go agent); a process the agent
forks after the move is born in the run's cgroup (a cgroup is inherited at fork). A two-process tree moved in two
passes over /proc in 8.7-21 ms, most of it the /proc scan. The tier-2 trace programs are host-wide and filter by one
lookup of `bpf_get_current_cgroup_id()` in the run set, so a run-set row inserted after the move (Arm, 0.3-1.6 ms)
makes them record the moved tree from then on: execs, opens and connects appear with the agent's own pid and its
children's, a child's `parent_exec_id` chaining to the agent's. No BPF object changed. The recorder's process cache
rebuilds an adopted pid from /proc, so an adopted process needs no exec record to be attributed.

**(b) What was opened before the adoption is invisible.** A read through a descriptor opened before the move
produced no record (the record sees opens, not reads); a file under a `deny_read` rule opened before the move stayed
readable through its descriptor while the plane refused a fresh open of it (the plane has no `file_permission` hook,
the documented tier-3 residual). Sockets are worse: a socket keeps the cgroup it was created in (`sk_cgrp_data`), and
the cgroup `connect4`/`sendmsg4` programs run on the socket's cgroup, not the caller's. Measured under a contract that
allows one TCP destination: a connect to another destination from a socket made **after** the move was refused
(EPERM); the same from a socket made **before** it **succeeded**; UDP the same. `trace_proc`'s `security_socket_connect`
fentry, keyed by the task's cgroup, recorded all three connects, with verdict `observed`: it runs before `connect4`
decides, and without the launch path's supervisor nothing writes the kernel's refusal back onto the line. So network
rules cannot be held on an adopted process honestly (which sockets they govern depends on when each was made, and the
ledger cannot tell). They are refused (Decision 5).

**(c) The window between noticing and recording.** Measured from the identification of the process to the arm:
49-75 ms when the tier-2 build is warm (Prepare 7-52 ms; another run, or the build's 5-minute linger, holds it), 3.6-6.2
s when it is cold (Prepare loads, verifies and attaches every program). Everything the agent does in that window is not
recorded, and the ledger says so: a `gap what=record why=adoption-pre-attach` naming the agent and counting the
processes adopted, whose exec ids carry their start times (so each one's unrecorded span is from its start to the
gap line's time). Contain first: the tree is moved right after it is identified, before Prepare, so whatever it forks
meanwhile is born inside and recorded from the arm on, with no chase after children. A busy agent (a shell starting
`cat` in a tight loop) adopted mid-run: after the attach every action was either recorded or counted lost, never
silently dropped: probe, 548,233 opens recorded and 125,045 counted `ringbuf-full` of 672,861 made after a mark;
integration, 1,149-1,178 `cat` execs recorded of 1,114-1,149 made after the mark, none lost.

**(d) The terminal's cgroup is shared; only the agent's tree moves.** The members are the agent and its descendants
still in the agent's cgroup, found from /proc, parents first, again until none is left behind (bounded, 16 passes,
4,096 processes). Its parent shell, a sibling in the same session scope and a descendant someone placed in another
cgroup (a `systemd-run --scope`, a container) never move: measured, the shell and the sibling stayed. Refused outright,
whoever asks: pid 1, kernel threads, thread ids, tego itself (this process, tego's binary by file identity, any
program named tego), any ancestor of the caller (its shell, sudo, sshd, a multiplexer, the user manager), a systemd
manager (`init.scope`), a process in another cgroup or pid namespace (a container's), one already inside a run or an
adoption, one in no cgroup v2 hierarchy, and (since 2026-10-16) one in the cgroup2 root, which a release could not
give it back to. A consequence for systemd: while adopted the agent is in
`tego.slice/tego-<agent>.slice/adopt-<run>.scope`, outside its session scope, so a logout's `KillUserProcesses`
and the session's accounting no longer cover it; the release puts it back. *Amended 2026-10-17:* a process whose thread-group leader has exited while other threads of it run (`pthread_exit`
in `main`, a raw `exit(2)` of the leader) reads in `/proc/<pid>/stat` as a zombie, `Z`, with its live threads in
`num_threads`; the walk dropped every `Z`, so such a process and every child its threads forked were neither moved
nor counted in `adoption-not-moved`, and ran outside the boundary while the ledger said the tree was adopted (no
privilege needed). In a guest of 6.17 the exited leader stays in the cgroup it was in (its `/proc/<pid>/cgroup` and
the source's `cgroup.procs` keep naming it), a write of its pid to another `cgroup.procs` moves its live threads, from
a frozen cgroup too, the destination's `cgroup.threads` lists them and its `cgroup.procs` does not, the leader's
`exe`, `cmdline`, `ns/*`, `fd` and memory are gone, and each live thread's `/proc/<tid>` answers for the process. So
`Z` with more than one task is now a member like any other: it is identified, and its cgroup, mappings and
namespaces are read, through a live thread of it (checked to be of that thread group and to have the start time it
was read with), its pid is written to move it, and a release finds it in the run's `cgroup.threads`. Only a zombie
whose whole group has exited is gone. Rejected: counting it in `adoption-not-moved` and leaving it where it is, which
leaves code the agent runs outside the boundary on purpose for a trick that needs no privilege. *Amended 2026-10-17:*
the dual case, a leader that exits in the run's cgroup after the move,
leaves that cgroup's `cgroup.procs` naming the exited leader while its group has a live thread anywhere (the kernel's
`css_task_iter` lists a dying leader with live members), so a release that read `cgroup.procs` took the process for
one left in the scope after it had moved the thread out: the scope and record were kept, and `run_end` said a process
stayed. The processes in a cgroup are now the thread groups of the live tasks its `cgroup.threads` lists, which skips
every dying task; `cgroup.procs` is read only where `cgroup.threads` cannot be (before 4.14). The guard's scan
(`tego agents --follow --adopt`) read every `Z` as gone too, uncounted, so it never saw an agent whose main thread
had exited before it looked: its signature, cgroup and run id are now read through
a live thread under `/proc/<pid>/task` (which the kernel resolves only within that thread group), checked to be the same
task once read, and the guard adopts it by its pid.

**(e) Liveness without being the parent.** A pidfd became readable 0.5 ms after the agent exited; `waitid(P_PIDFD)`
answered ECHILD (only the parent reaps, so no status there); `cgroup.events` said `populated 1` while children lived
and `populated 0` once the tree was gone. The run ends on the latter. The exit status comes from the kernel's process
events (the proc connector, root's `CAP_NET_ADMIN`) when they were read, which the guard always does and `tego adopt`
does when it can; otherwise run_end says the status is unknown. It is the root's own: the guard keys it by the
watcher's session, and `tego adopt` keeps the first exit of the pid once the listener is subscribed and the root is
read again alive with its start time, and nothing after it (amended 2026-10-16: it kept the last exit
of the pid, so a later process that reused it while the root's descendants kept the run going put its status in
run_end); a root gone by then, or gone when the kernel dropped events, leaves the status unknown. *Amended 2026-10-17:*
an earlier amendment made a process whose leader exited a member
for every read ((d)), but every reader of the process events still took the leader's exit event for the process's
end, which it is not: the watcher reported `agent_exited exit=0` for an agent whose main thread had exited while its
thread ran on, and stopped following what that thread forked; it never reported the end of an agent its scan had
found with its main thread gone (the only exit event left is the last thread's, which it skipped as a thread's), and
that stale session hid a later agent given the pid; `tego adopt` kept the main thread's code for run_end, and the
guard took the watcher's (reproduced as root in a guest of 6.17: a python agent whose main thread exits with 0 and
whose thread ends it with `exit_group(3)`, `wait` status 3, run_end 0). The model now, one rule (`procconn.Group`) that
the watcher and an adoption's exit watch both apply: a process is its thread group, and it ends with the first exit
event of any task of it after which no task of it runs (`/proc/<pid>` gone, dead, a zombie that counts one task, another
start time, or a zombie leader none of whose other tasks runs, which a tracer's unreaped zombies are); the kernel sends
a task's event after it has released the task, so the end's event reads the group gone (measured in a guest of 6.17,
two runs on each boot of 40 processes of each shape: the last task's event read gone in all 160 of each, a leader's
while its thread ran in none; the main thread's `exit_group(2)` had ended the group by the first event read in 0 to 3
of a run's 40). An exec by any task of the process makes that task its leader under the leader's pid once every other task
has exited (`de_thread`), so what was read of its tasks before is forgotten (a non-leader exec, Go's `syscall.Exec`
from another thread, is also a leader's exit event of a process that runs on, and the watcher used to end its session
there too). The status a waiter reads is the group's
exit code after a group exit (`exit_group`, or a fatal signal) and the leader's own code
otherwise, while each event carries its own task's code, so tego states only what the codes agree on: the leader's code when every other task read exiting after the leader carries
the same; else (the leader exited first with one code and a thread ended the group with another, or the leader's exit
was never read) the status is unknown, and the line says why. The guard no longer takes the watcher's `agent_exited`:
each of its adoptions has an exit watch the guard feeds from its watcher's own events (`watcher.Options.Tap`) from the
moment the agent is identified, as `tego adopt` feeds its own listener's; an exit watch goes on folding in the root's
exits until the status is asked at the run's end, so a thread's exit read after an end its leader's event took, with
another code, makes the status unknown rather than the leader's. Rejected: keeping the leader's exit as the end and
adding a thread's for a leader-exited process only (two rules: the shape that kept failing); `/proc/<pid>/stat`
field 52, which is the leader's own `exit_code`, not the group's, and reads 0 to a reader without ptrace access;
`PIDFD_INFO_EXIT` (6.15), the leader's code too, and on no older kernel of the matrix; counting a process's threads
from fork events to know its last one, which an overrun or a scan breaks; and a fixed wait after the end for later
events, which bounds nothing. What remains: when the leader exits first and the rest of the group has ended before tego
reads the leader's exit, the end is read at the leader's event, and its code is the status unless a disagreeing exit of
the rest is read before the status is: at once for the watcher's line, at the run's end for run_end. *Amended
2026-10-19: this paragraph's end and status rules,
and its residual, are replaced by what follows.* Reading `/proc` when an event is handled tells the state when it is
read, not when the event was sent, and three shapes broke on it. A thread's exec zaps the live leader (`de_thread`, the
zapped tasks' code 0); when that exit event is read after the exec'd program has ended, `/proc` already reads gone, so
the end was taken there with code 0 and the program's own exit was dropped as a later process's: run_end and
`agent_exited` said 0 for a program that exited 3 or died of SIGSEGV (reproduced as root in a guest of 6.17 with a
python agent whose worker thread runs `os.execv`: the kernel's sequence is the leader's exit 0, the exec, the
program's exit, and `tego adopt`'s exit watch gave 0 in 1 of 90 runs, the watcher in 4 of 40). An exec that fails
after `de_thread` (its task dies of SIGSEGV with no exec event) left the watcher's session open forever, the dying
task's exit dropped as a later process's. A thread's `exit_group(3)` whose event is read once the group is gone ended
the process before the leader's event, next in the socket, was read: unknown with a false note (3 to 5 runs of 60).
And the premise that a signal code proves a group exit is false: `SECCOMP_RET_KILL_THREAD` (and an oops) kills one task
alone, so a leader killed alone by SIGSYS gave signal 31 for a process `wait(2)` reports exited 0. The model now, still
one rule (`procconn.Group`) for the watcher and the exit watches: the end is told by the events alone. A Group holds the
set of the process's tasks that run, from its leader alone at the fork or exec it was followed from, or from a listing
of `/proc/<pid>/task` read after the listener was subscribed (dead tasks and zombies left out, as their events may have
been read) for a process found running (the watcher's scan, the guard and `tego adopt` when they identify the root);
each Fork event of a thread adds it, each Exit event of a member takes it out, and the exit that empties the set is the
end. An Exec event resets the set to the leader alone. The kernel fills an event's timestamp (CLOCK_MONOTONIC) before
it reads the task's pid, and a zapped leader preempted while its event is filled can have it sent after the exec's
event with the leader's pid in it: an exit filled before the Exec of an exec that ended other tasks says nothing. A
second exit of the leader's pid with no Fork of the pid read between is the failed exec's death after `de_thread` (the
task took the leader's pid), and of the two the one filled later is the end. A listing that finds no task (the process
ended between the scan's read of `/proc` and the listing) leaves its next exit to end it, unknown; the watcher lists
only what a scan newly follows, so a process followed from its events keeps their account. Lost events relist the
tasks (`Group.Resync`): while the leader runs nothing dropped says anything of the status, once it has exited the
status is unknown. The status: the leader's code when every exit read after the leader's carries the same code (a
dumped core's bit aside), signals like any other code; else unknown; codes read before the leader's exit say nothing
(they are of tasks that left alone, or of a group exit that gave the leader the same code). So a status tego states
is the one `wait(2)` reports: with no group exit `wait` reports the leader's own code, and a group exit gives its code to
every task it ends, the leader's and every later one too. This takes the option rejected above, counting threads from
fork events, with what that rejection said breaks it answered: a scan lists the tasks of what it finds, and an overrun
relists them. Rejected now: holding the watcher's line back a while after an end read at a leader's exit (a fixed wait
bounds nothing, and the end no longer comes early); reopening a group that an Exec after its end shows was zapped
(right for that shape, but a scan's late end and one more shape stay wrong). What remains: the status is unknown,
never another, when the leader's exit was not read (it had exited before the process was followed), when the kernel
dropped events after it, or when the codes after it disagree. Measured on the real kernel in a KVM guest of 6.17, both
boots, 30 runs of each python shape per boot with every event folded only after `wait(2)` returned (so read as late as it gets): a worker's `os.execv` of a program that exits 3, of one that kills itself with SIGSEGV, and of a file whose exec fails after `de_thread`, and a worker's `exit_group(3)`: the status known in 30 of 30 each, always `wait`'s; the main thread's own exit 0 then a worker's `exit_group(3)`: unknown in 30 of 30; a thread killed alone by SIGSYS before `exit_group(0)`: the SIGSYS exit read in 20 of 20 runs, the status unknown in 20 of 20, never SIGSYS (`TestIntegrationAProcessEndsAtItsEventsWithAStatusWaitAgrees`, `TestIntegrationAThreadKilledAloneGivesNoSignal`).

*Amended 2026-10-20.* Two claims of
the paragraph above were false. "Codes read before the leader's exit say nothing": `exit_code` is fixed when `do_exit`
starts and the event is filled after `exit_notify`, so a worker's `exit_group(3)` that begins while a slow main
thread's own `exit(0)` is in `do_exit` is read first, and `wait(2)` reports 3 (reproduced in the KVM guest, 6.17, both
boots: 20 of 20 runs read the worker first; Group said 0). And "with no group exit `wait` reports the leader's own
code": from Linux 5.19 `synchronize_group_exit` (kernel/exit.c) sets `SIGNAL_GROUP_EXIT` as the last task starts
`do_exit` with that task's code, so `wait` reports the last task to *begin* exiting, which the read order does not
show either. And the group had no lower bound: a group started from a listing or at an exec took a zapped main
thread's exit, filled before the listing or the Exec and read after it, as its end. The rule now
(`procconn.Group`): every group has a lower bound `since`, the timestamp of the fork or exec it was followed from, or a
CLOCK_MONOTONIC reading (less the time namespace's offset, `/proc/self/timens_offsets`) taken before `/proc` listed its
tasks; an event filled before it never ends the group, gives it a code or adds a task (a task listed running reaches
`exit_notify`, and fills its exit, after the listing). The listing (`procconn.List`) is taken again when a task
changed under it (read dead or gone since enumerated, as `de_thread`'s tid swap does; or new in a second
enumeration), and a listing that stays unstable, or one that found the leader exited (an exec may be swapping the
tids), checks the exit that would end the group with a fresh listing. The status is known only when the leader's exit
was read and every other exit read since carries the same code (core bit aside), whichever was read first; a code is
left out only when a later fork of the process (a thread or a child) was filled after its exit, since the forking task
then ran on, so the left-out task neither began exiting last nor set a group exit the others did not die of; the
leader's own code is never left out (before 5.19 it is the status when no group exit happened). A listing in which no
task ran outside `do_exit` (`PF_EXITING`, stat field 9) gives no status, as its deciding exit may predate `since`. What
remains, and what no event can tell: a fatal signal or another thread's `exit_group` that arrives while a task is
between its own `exit(2)` (or seccomp's `SECCOMP_RET_KILL_THREAD`) and `do_exit`'s first lock sets the group's code
while that task's event carries its own (`complete_signal` still finds the task wanting the signal); with every other
compared task dying of the group's code the disagreement shows, and only when every compared task raced so is a wrong
status stated ("racing exit": a window of a few hundred nanoseconds per task). The cost of never stating another
status: a process whose threads exited on their own with another code shortly before its end, with no fork after them,
is unknown, and so is a failed exec whose zapped main thread's exit named the swapped tid. Rejected: a fixed wait or
timestamp window (`do_exit` can take arbitrarily long); reading `group_exit_code` from the tier-2 recorder's
`sched_process_exit` record for an adoption (exact on 5.19 and later, kept as the follow-up of this residual for root
tiers, as it needs the record plumbed to the adoption's run_end); `PIDFD_INFO_EXIT` (6.15 and later only, and it
records the leader's own `exit_code` when the leader exits last). The rule is checked by an exhaustive model
(`internal/watch/procconn/model_test.go`): up to three tasks with at most one each of exec (successful or failing after
`de_thread`), `exit_group`, `SECCOMP_RET_KILL_THREAD` and the leader's own exit, the others' own exits or none, a
thread made or a child forked during the run, a SIGKILL from outside, and a reader that follows from the fork, from a
listing taken at any point, or from an Exec event; each exit's timestamp, pid read and send are separate steps; every
interleaving is explored and checked against `wait_task_zombie` on a kernel before 5.19 and on one from it: the group
never ends before every task passed `exit_notify`, it has ended once every event is read, and a status it calls known is
`wait`'s outside the racing-exit residual.

**(f) The adopter's death.** With nothing done about it, SIGKILLing the adopter left the run-set row in place, and
with network programs 8 pinned links and a `connect4` attachment on the run's cgroup; the agent stayed in the run's
cgroup, recorded into a ring nobody read, and the build stayed attached (its linger never removes a build whose run
set names a live cgroup). Root can list all of it (`ls /sys/fs/bpf/tego/<hash>/links/`, `bpftool cgroup tree`, the
run set) and remove it (move the processes out, `rmdir` the scope, `cgroupenforce.PurgeRun`), which the probe did.
Hence an adoption reaper (Decision 4); measured with it: nothing left attached, the agent alive and back where it was.

**(g) A boundary through the decision plane.** Tier 2 without Landlock cannot refuse a write (fanotify's open event
carries no access mode). The decision plane can, for every task in the run's cgroup: an unprivileged agent adopted under
a contract with a workspace, a denied file and an exec allow-list had, in both plane modes (fmod_ret and LSM), a fresh
read of the denied file refused (EACCES), a write outside the workspace refused, an unlisted program refused, and the
workspace write and the listed program allowed; each refusal is a ledger line with `mechanism: plane`. After the
release the same write outside the workspace succeeded again.

## Decision

1. **Adoption is a move into a fresh cgroup, then tier 2 armed there**, with the BPF objects as they are:
   `tego.slice/tego-<agent>.slice/adopt-<run id>.scope` under the cgroup2 root. It is not `run-<id>.scope` on purpose:
   the sweep and `tego stop` kill a launched run's scope whose launcher is gone (ADR 0020), and an adopted agent is
   the operator's own process.
2. **Contain first, record from the arm, say what is missing.** Order: identify (pid and start time), lock the
   identity host-wide, make the scope, write the root-only record, start the reaper, move, then Prepare, Attach, Arm,
   start the recorder, run_start. Right before the move, under a host-wide move lock (`/run/tego/adopted/moves.lock`,
   held by every adopter while it rechecks and moves), the root is read again and every rule of (d) and the owner
   filter of (6) is applied to it again: a root that exec'd tego, changed its user or namespaces, or was taken by
   another adoption since it was identified is refused then, and nothing moves. Two adoptions whose trees overlap (the
   guard adopting an agent and, at once, an agent that agent started) so never both write one process, which would
   leave both ledgers saying it was theirs. Before each write to `cgroup.procs` the member's start time is read again
   behind a pidfd: a root whose pid names another process moves nothing; a member's reused pid is skipped and said; a
   write that landed on a pid reused within it is put back.
3. **A normal ledger run.** Same lock, live index and chain; `tego status|events|drift <run>` read it. run_start's
   `launcher_pid` is the adopter, `command` and `cwd` the agent's own, `capture` off, no limits, and a capability line
   that claims only what an adopted process can be given. Then one `exec` line per moved process with `by: adoption`
   (its `exec_id` carries its start time; no exec was seen), and the gaps `adoption-pre-attach`, `adoption-not-moved`
   and `adoption-open-sockets` (`what=record`) and, for a boundary, `adoption-no-syscall-filter` (`what=enforce`, once:
   what only tier 1's filter refuses is not held; "What it does not do") and `adoption-open-descriptors` (`what=enforce`: files
   held across a rule, open for writing outside every write entry or under a deny_read entry, and, since 2026-10-16,
   mapped: a shared writable mapping outside every write entry, any mapping under deny_read). *Amended 2026-10-16:*
"across a rule" is the plane's own answer, read from the rows the run's programs hold
   (`decide.CompilePlane`, `DecideObject`), never a second model of them: a file held, or mapped at all, where the
   plane refuses a read (a deny_read entry, a name entry such as the built-in `.env` list), and one held for writing,
   or mapped shared and writable or may-write (`VmFlags mw`: mprotect could make it writable with no open, and the
   plane decides `file_mprotect` for `PROT_EXEC` alone), where it refuses a write: outside every write entry, or a
   deny_write target beneath one, which the hand-written test it replaces missed (an agent holding its repository's
   pre-commit hook or `~/.bashrc` open for writing kept writing it unsaid). Under `/dev` only the terminal and the byte
   sinks (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`,
   `/dev/console`, `/dev/pts/*`) are left out for a write, as a launched run's agent inherits and writes them with no
   decision either; `/dev/shm` is storage and counts. A file on a kernel-internal mount, which the plane passes as no fs
   decision, never counts. *Amended 2026-10-16:* that is the kernel's answer, never a name list: a held file (a descriptor's device, a stat through
   `/proc/<pid>/fd/<n>`) or a mapping (the smaps line's device) is on no path exactly when its device is one of the
   kernel-internal superblocks tego finds in its own process, once, by making one object of each kind and reading its
   device: a memfd (the shmem mount behind memfds, System V segments, shared anonymous memory and most GPU drivers'
   objects), a memfd of each huge page size (hugetlbfs' internal mounts, which `MAP_HUGETLB` memory and `SHM_HUGETLB`
   segments use too), shared anonymous memory and the AIO ring. Those superblocks are mounted only by the kernel
   (`kern_mount`), no namespace shows them and none can clone them (`may_copy_tree` refuses a mount of the internal
   namespace), so every file on them is one the plane passes (`tego_no_path`: an `S_PRIVATE` inode, an `SB_NOUSER`
   superblock, or a pseudo dentry on an `MNT_INTERNAL` mount). Every other file is a path the plane decides, whichever
   mount reaches it: a file held from a chroot, through a lazily unmounted mount or a detached bind, and a btrfs file
   (whose `st_dev` is its subvolume's anonymous device). *Amended 2026-10-16:* the
   count asks the rows about such a file only by a name that is a path of it in tego's namespace. `/proc` names a
   held file by `d_path` from tego's root, through the mount it was opened through, and for a detached mount (an
   `open_tree` clone, a lazily unmounted bind) that name stops at the mount's root: `~/.ssh/id_ed25519` held through a
   clone of `$HOME` is named `/.ssh/id_ed25519`, which no rule names, while the plane's walk (`tego_walk_step`) still
   meets `~/.ssh`'s row and refuses a read of it (reproduced as root in a KVM guest: the count left it out). So a held
   file's mount id (`statx` `STATX_MNT_ID` through `/proc/<pid>/fd/<n>`, or through `/proc/<pid>/map_files/<range>`
   for a mapping, which root may follow) must be a mount of tego's own `/proc/self/mountinfo`, and a name that is not
   deleted must still lead to the same file (device and inode); otherwise the file is unnamed and its process is
   counted in `adoption-descriptors-unread`, never taken as holding nothing across a rule. A file whose mount is
   tego's is asked about by its name and by each path through another mount of tego's namespace of the same
   filesystem that shows its directory (a bind of a directory above it): the walk meets every directory between the
   file and its mount's root, which a rule may name through that other mount. A chroot's holder needs neither: `/proc`
   names its file from tego's root, the full path. The same test counts unread a mapping whose `map_files` entry
   leads through a mount no line of tego's mountinfo shows for another reason, such as overlayfs's private mount of
   a layer on a kernel that maps the layer's own file, and a pseudo file of an internal superblock tego does not
   probe: fail-closed, never a file taken as across no rule. A kind the kernel refuses to make (no
   hugetlb, an exhausted `aio-max-nr`) adds no device, and a pseudo file of an internal superblock tego does not probe
   (a dma-buf, secretmem, a driver's own shmem mount) is counted (in `adoption-descriptors-unread`,
   its mount being in no line of tego's mountinfo): the count can be high, never low. Rejected: the name
   list it replaced (`/memfd:`, `/SYSV`), which counted the AIO ring (`/[aio]`), hugetlb memory (`/anon_hugepage`) and
   drivers' shmem objects as files held across a rule and left out a file named `/SYSVfake` on a mounted filesystem;
   and, after one day, the holder's `/proc/<pid>/mountinfo` (a mount or device it does not show was no path), which
   shows only the mounts under the holder's root and none that is detached, so the files of a chrooted holder, of a
   lazily unmounted mount and of a detached bind of btrfs were dropped from the count with nothing in
   `adoption-descriptors-unread` (reproduced as root in a KVM guest; `TestIntegrationNoPathChrootedHolder`,
   `TestIntegrationNoPathLazilyUnmounted` and `TestIntegrationNoPathDetachedBind` fail with that rule). Rejected too:
   comparing only the name's device and inode with the held file's (a deleted file held through a detached
   mount has no name to compare, and on btrfs a mapping's smaps device is the superblock's while a stat gives the
   subvolume's), and counting an unnamed file as held across a rule (`adoption-open-descriptors` would then say a rule
   covers a file no rule could be asked about). *Amended 2026-10-17:*
   "never low" held only for names, and only of what `/proc` lists. The plane keys a file entry's row on the inode
   (`tego_walk_step` looks the object's own inode up first, enforce-plane "another name of a keyed file"), so it
   refuses a read of `~/.netrc` by a hard link the agent made in its workspace before the adoption, which no rule
   names: the count asked the rows by the link's name and counted nothing (reproduced as root in a KVM guest, and for a descriptor on the host by `TestIntegrationAdoptCountsAHardLinkOfAKeyedFile`). The
   count now also asks the rows by the path of each fs row keyed at the held file's inode: the device and inode a
   statx through `/proc/<pid>/fd/<n>` or `map_files` gives (`adopt.FD.ID`, `adopt.Mapping.IDs`), against the files
   the plane's fill wrote its rows at (`enforce.PlaneKeyedReporter`, the identity its check holds each row to), so a
   keyed file renamed since the fill is asked about by the row's path too. And a file registered with an io_uring
   instance (`IORING_REGISTER_FILES`) is read and written through the ring with no descriptor or mapping `/proc`
   lists (reproduced on the host, unprivileged): a process holding a ring whose fdinfo counts a table of registered
   files (`UserFiles`, of any size, a sparse table being filled by later updates), or whose fdinfo shows none after
   three reads (the kernel prints a ring's state only when it takes the ring's lock at once; no kernel before 5.9
   prints it), is counted in `adoption-descriptors-unread`, record-only or boundary, as is, for a boundary, one
   mapping a ring (by the smaps line's device and inode) it holds no descriptor of (a ring registered with itself,
   `IORING_REGISTER_RING_FDS`, and closed). What `/proc` lists of no process is not counted and is said so: a
   descriptor in flight in a unix socket's queue (`SCM_RIGHTS` sent and not yet received), a ring registered with
   itself and neither held nor mapped (`IORING_SETUP_NO_MMAP`), a file another kernel object holds. Rejected: asking
   the rows by the paths the ring's fdinfo prints for its registered files (a `d_path` tego cannot stat, so a name
   it cannot check is the file's, the earlier rule), and statting each row's path at the count instead of asking
   the fill (a keyed file renamed after the fill would be missed). *Amended 2026-10-17:* the walk looks
   each directory above the object up by its inode too, so a `deny_read` directory renamed after the fill (the agent
   runs unconfined until the arm) refuses a read of each file in it under its new name, which the count, asking by
   the held file's own inode only, missed. The count now looks each directory a held file's name passes through up
   in tego's namespace (an `lstat`, once per directory per count) and, where a row is keyed at it, also asks the rows
   by the file's path beneath that row's path (`TestAdoptAsksTheRowsByEachKeyedDirectoryAboveTheName`). And a ring's
   device and inode tell two rings apart only where each ring has an inode of its own: a kernel whose io_uring makes
   its instances on the kernel's shared anonymous inode (`fs/anon_inodes.c`, the inode an eventfd has) gives every
   ring the same identity, so a ring the process only maps would match the descriptor of another ring it holds, and
   its registered files would go unsaid. Tego learns the shared inode from an eventfd of its own; a ring on it, or
   any ring where that could not be learnt, has no identity (`adopt.FD.ID` empty), so a mapped ring matches no
   descriptor and its process is counted in `adoption-descriptors-unread` (`TestARingOnTheSharedAnonInodeHasNoIdentity`;
   `TestRingIdentityOnTheRealKernel` logs which kernel rows share it). Rejected: matching rings by the number of
   their mappings (one ring is mapped up to three times, and a process may map one twice). *Amended 2026-10-17:* "what `/proc` lists" was read as the leader's
   table, and a descriptor `/proc` could not name was dropped. A descriptor whose link `readlink` refuses for a reason
   other than its closing (a file open at a path longer than `PATH_MAX`: `ENAMETOOLONG`), or whose fdinfo cannot be
   read (its flags, so whether it writes, unknown), was left out of the listing with nothing said, so a hard link of
   `~/.netrc` held at such a path in the workspace counted neither held nor unread (reproduced on the host). It is now
   listed as unread (`adopt.FD.Unread`) and its process counted in `adoption-descriptors-unread`; only `ENOENT`, a
   descriptor closed since the listing, is left out. And `/proc/<pid>/fd` is the thread group leader's table: a thread
   that unshared its table (`unshare(CLONE_FILES)`, allowed in a threaded process) holds descriptors only
   `/proc/<pid>/task/<tid>/fd` lists, and a leader that exited lists none (reproduced on the host: a key held in a
   thread's own table counted nothing). The listing now reads each task's table too, skipping one `kcmp(KCMP_FILES)`
   says is the leader's, reading one it cannot compare (no `CONFIG_KCMP`, no ptrace read access), each descriptor
   once, and counts a process whose task directory or a live task's table cannot be listed unread
   (`TestFDsReadsEveryTasksTable`, `TestFDsReadsAThreadsOwnTableOnTheKernel`, `TestFDsSaysADescriptorItCannotName`,
   `TestFDsSaysADescriptorWhoseNameIsTooLong`, `TestAdoptCountsADescriptorItCannotNameUnread`, and a row of
   `TestIntegrationAdoptCountsAHardLinkOfAKeyedFile`, as root, for the link at a path past `PATH_MAX`). Mappings are the
   process's (threads share one memory map), so smaps is read once. Rejected: reading every task's table without
   `kcmp` (a process of a hundred threads and thousands of descriptors would be read a hundred times over), and
   counting a descriptor `/proc` cannot name as held across a rule (no rule could be asked about it; unread says so).
   And what /proc names of a process in a mount namespace other than tego's is not a
   path of tego's namespace, so such a process's files are not counted by name: it is counted in
   `adoption-descriptors-unread`, its sockets still counted; `Check` does not refuse it (a snap's terminal and a
   sandboxed tool live in mount namespaces of their own, and the plane decides them by their own mount tree).
   Rejected: refusing such a process (most snap-launched terminals' agents), and reading its paths through
   `/proc/<pid>/root` (a chroot's answer, not a namespace's). Rejected: counting every shared mapping (fontconfig's caches
   and other read-only shared maps would make the gap say what is not so), and a blanket `/dev` exemption. Descriptor
   and mapping lists stop at 4,096 entries per process; a process past either cap, or whose list could not be read,
   is counted in `gap adoption-descriptors-unread` (`what=enforce` for a boundary), never taken as holding only what
   was read. The ledger format is unchanged: these are existing fields and new `why` values. *Amended 2026-10-17:*
"each descriptor once" merged the entries of two tables by
   number, name and flags before each file's identity was read, but two tables can hold two different files under one
   number and one name (a name deleted and made again, a hard link of a keyed file opened at that name and unlinked:
   reproduced on the host), and the count asks the rows by the inode too, so the keyed file was counted neither held
   nor unread; and two io_uring instances under one number, which share a name, were merged, so a second table's
   ring with registered files was lost. The entries are now merged after marking, a file only with another of the
   same number, name, flags and identity, and a ring, an unread descriptor or a file with no identity never: listed
   twice, the count errs upward (`TestFDsListsTwoFilesUnderOneNumberAndName`, `TestFDsNeverMergesTwoRings`). A
   process whose leader exited has no table or memory of its own left: its tasks' tables and a live thread's smaps are
   read (What was measured, (d)). *Amended 2026-10-17:* the cap counted what
   was listed, and every thread that called `unshare(CLONE_FILES)` holds a copied table kcmp tells from the leader's, so
   M such threads cost M full tables of reads (a readlink, an fdinfo and a statx each) before the adoption recorded and
   answered a release (measured on the host: 200 copies of 4,000 took 11 s). At most 16,384 descriptors are now read of
   one process across its tables; past that the listing stops and the process is counted in
   `adoption-descriptors-unread` (`TestFDsBoundsItsReadsAcrossCopiedTables`).
4. **Never killed.** The tree ending ends the run (`exit`). SIGINT, SIGTERM, `tego stop <run>` and `tego adopt
   --release --pid <pid>` release it: the scope frozen while its processes leave (`cgroup.freeze`, so nothing forks
   meanwhile), each moved back to the cgroup it came from (or the nearest ancestor that takes a process, never the root
   cgroup; one nothing takes stays released in the scope, counted by `gap adoption-left-in-scope`, and the scope and
   the adoption's record stay, the record marked released, so a later `tego adopt --release --pid <pid>` or the reaper
   moves it out from the record, asking nothing of the ended adoption; *amended 2026-10-16*: the record used to go, and
   nothing could move it out), the scope thawed and removed (`stopped`). While such a process stays, `tego agents`
   reports it governed by the ended run and the guard refuses it under `governed`. The adopter's death
   is its reaper's (`tego __adopt-reap`, a helper started before the move, as ADR 0020's): it releases the tree, writes
   `orphaned`, removes the scope and purges the run's kernel state. If adopter and reaper both die, nothing records the
   agent (a boundary's plane rows go on refusing, unrecorded) until it is released: by `tego adopt --release`, or by a
   root sweep (`sudo tego gc`), which releases it from the record as the reaper would and only then lets run_end
   `orphaned` be written. Until then the run reads lost, never ended; no sweep ever kills it. *Amended 2026-10-16:* the
   sweep used to end such a run `orphaned` while the agent stayed in the scope (it looked for a launched run's
   `run-<id>.scope` only), so the ledger said the run had ended while the plane still refused. Rejected: ending it
   anyway with a detail (still a ledger that says ended over a holding scope), and an unprivileged sweep releasing it
   (the scope and record are root's).
   **A release is a request one adoption answers.** `tego stop <run>` and `tego adopt --release --pid <pid>` signal
   nothing: they write `/run/tego/adopted/<run>.release` (root's, 0600, naming who asked) and wait, up to 30 s, for the
   adoption's record to go, or to be marked released (*amended 2026-10-16*: a release that left processes
   in the scope keeps the record, which the request used to wait out for its whole 30 s and then report as a failure
   that had not happened; the released record is now the answer, the request is removed with it, and the requester
   says at once that the run ended with N processes left, exiting non-zero). A failure after the move and before
   run_start whose release leaves processes keeps the record too, marked released and unstarted (it used to be removed
   with the run directory, so nothing could release them and the guard refused them as governed for ever); the
   failure's error says what stays, and the later release writes no run_end, since no run exists. Rejected: keeping
   the run directory of a run that never started so the release could end it (a ledger with no run_start). That adoption alone answers it (it looks every 200 ms), so a guard holding other adoptions,
   and the guard itself, run on, which a SIGTERM to the adopter would not allow. An adoption whose adopter is gone is
   its reaper's; with the reaper gone too the requester releases it from the record itself, holding the adopted
   process's lock. run_end says who asked and that the agent was never killed. A scope root emptied by hand while the
   agent runs on ends the run `stopped`, saying so, not `exit`.
   **A boundary adoption is released on its adopter's death too** (decided 2026-10-16;
   the draft's question 1). Rejected: killing it, as a launched run is (tego did not start the agent, and a tego
   crash must not end the operator's session); keeping the plane's rows until a person releases it (the plane would go
   on refusing with nobody recording the refusals, so the ledger would no longer say what happened, and nothing would
   say the run had ended). The release is never silent: run_end `orphaned` says the agent was released unconfined.
5. **Record-only by default; a boundary holds only what the decision plane decides.** With `--boundary`, every rule
   that cannot be added to a running process is refused, named, before anything happens: a `net:` section (b), `fs.ask`
   and `ask` (the supervisor), `env`, `models` and `capture` (the forwarder), `limits`, `gate`, `mcp`, `docker` and
   `containers`, a tier other than cgroup, and every exec command rule (`exec.deny`, `exec.ask`, an `exec.allow` entry
   with argument words: ADR 0048 decides argv on the supervisor's copy, and the plane holds image rows only; amended
   2026-10-16, when `exec.deny: [rm -r]` was found adopted and held by nothing). What remains (fs.write and the
   refusal of every other write, deny_read with the built-in list, exec.allow's programs, exec.anonymous, keyring) is
   held by the plane, and a boundary adoption is refused
   unless a plane mode decides it (fmod_ret or LSM; the fanotify fallback cannot refuse a write). A record-only adoption
   drops the deny_read row the compiler always adds for tego's own records: at tier 2 with no plane it would be a
   fanotify mark that refuses the agent's reads and arms the adopter.
   **The table is the agent owner's** (amended 2026-10-16). The contract compiles against the
   passwd home of the uid the adopted process runs as: `~` in it, the built-in deny_read list (`~/.ssh`, `~/.aws`,
   `~/.netrc`, `~/.gnupg`, the browsers' profiles) and deny_write's names in the home (shell startup files, the global
   git config's hooks) are the agent's own; the ledger, the chain anchor and tego's own state stay the adopter's
   machine's, and (amended 2026-10-16) the owner's own `~/.tego` (its earlier runs' events and
   blobs, its log) is read-denied beside them, as its own launched run denies it (agent-contract R6a): the compiler
   denied only the anchor's directory, so under the guard `/root/.tego` was denied and the owner's was not. That deny,
   like every R6a deny, attaches to a directory that exists, and an adoption keeps its table for as long as it runs.
   *Amended 2026-10-16:* so a boundary adoption makes the owner's `~/.tego`
   before it compiles, where nothing is there, as the owner's first `tego run` would (mode 0700; as root, owned by
   the owner and its passwd group, made with `mkdirat`, which follows no link at the name, and chowned through an
   `O_NOFOLLOW` descriptor; one that cannot be chowned is removed again); and it requires `~/.tego` (followed, as the
   compile resolves it) to be the same directory on both sides of the compile, refusing the boundary, named, when it is
   no directory (a file, a dangling link), cannot be made (a home root may not write) or changed meanwhile. An owner
   whose passwd home does not exist (a service user's `/nonexistent`, as nobody's in
   `TestIntegrationAdoptBoundaryRefusesThroughThePlane`) has no records there, and tego makes no home: the boundary
   compiles with no such deny, is refused if the home appears during the compile, and the guard compiles the table
   again once the home exists. A single `tego adopt` keeps its table, so a home made while it runs, and a `tego run`
   of that owner's into it, would leave that run's records readable to the agent; making a home under a root-owned
   parent needs root. Before
   this, an adoption that started while the owner had never run tego ran on a table with no such deny, and the
   records of the owner's first run were readable to the agent for the rest of the adoption. The guard compiles its
   tables at its start: a table whose owner's `~/.tego` is no longer the directory it denies (removed, replaced, or no
   directory now) is compiled again before the next adoption, which makes the directory again where it is missing,
   and an adoption whose table cannot be compiled again fails rather than run under the old one (which compiled again only once a missing directory appeared). An adoption already running
   keeps its table: the agent cannot itself replace the directory, as a boundary refuses every write outside its write
   entries and a write entry at or inside `~/.tego` is a contradiction (below). Rejected: only saying that running
   adoptions keep the records readable (it leaves R6a's cross-run read open for the length of an adoption), and testing
   that `~/.tego` exists rather than that it is a directory (a file or a dangling link there compiled with no deny and
   was never compiled again). Only that directory is rechecked: a built-in deny_read path made
   after the guard started (a new `~/.aws`) is covered from the guard's next start, as a deny_read glob covers the
   files that exist when it is compiled (SEMANTICS §2). Rejected: a row for the missing directory keyed on its
   parent and name (the plane's rows are inodes that exist; ADR 0043's name entries match a name under a whole
   subtree, which would deny every `.tego` beneath the home), and compiling the table at every adoption (a compile
   runs the `.env` scan and the globs, up to 2 s each, while the agent runs unadopted).
   *Amended 2026-10-17:* every check above runs before the move, while
   the agent is unconfined, and so it stays until the arm: Prepare keys the row at whatever the path names when it
   opens it, and a path gone by then keys nothing, with nothing said (planPlaneFill's `Absent`). So the adopter
   requires the plane's row for `~/.tego` to be at the directory the table was compiled against (`AdoptSpec.Keyed`):
   after Prepare and before the attach, the files the fill wrote its rows at (`enforce.PlaneKeyedReporter`) must hold
   that path at that device and inode, or the adoption fails, named (`ErrAdoptUnkeyed`), the tree given back; from the
   fill on, a rename of the directory moves the deny with it, since a row keys an inode (`TestPlaneRunKeyedFilesAreTheInodesItDecides`
   shows it on the kernel). The sentence above that the agent cannot replace the directory holds from the arm on.
   Rejected: rechecking the path's stat after Prepare (a directory swapped away and back between the fill and the
   check would pass with the row on another), and marking the keyed path required in the fill (the fill's plan is the
   launched run's too, where a missing implicit entry is no error). *Amended 2026-10-17:* the row check alone left the window between the fill and the arm open:
   the agent can rename `~/.tego` away then, with or without a new directory at its name, and the row, keyed on the
   old inode, passes while the owner's next `tego run` writes into a directory no row keys (reproduced as root in a
   KVM guest on both plane boots: the read of a file in the fresh `~/.tego` succeeded). So after the arm, from which
   the plane refuses the agent a rename, removal or replacement of the keyed directory, the adopter also requires the
   path (followed, as the compile resolved it) to lead to the row's device and inode; one that does not fails the
   adoption, named (`ErrAdoptUnkeyed`: removed or replaced after the plane keyed it), and the tree is given back
   (`TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere`). The option rejected above checked the path alone and
   before the arm; both checks together, the second after the arm, leave no window the agent can use (amended
   2026-10-17: when `~/.tego` is itself a directory; a link at
   that name to one, which the owner may have made or the agent may put there between the fill and the arm, followed
   led to the row's inode, but the link is under no row, so under a write entry over the home the plane let the agent
   unlink it and make a fresh directory there once armed, and the owner's next records there were readable,
   reproduced as root in a KVM guest on both plane boots. The compile and the check after the arm now read the name
   itself, not followed (`lstat`), and a `~/.tego` that is a link refuses the boundary, named, before anything moves,
   or fails the adoption after the arm, with the tree given back. Rejected: a row at the link's own inode that refuses
   its rename and removal, as R11 does for a `deny_write` file's ancestors, which needs a fill-plan change for a case
   an owner fixes by making `~/.tego` a directory, and refusing only a link under a write entry, which would need the
   adopter to mirror the plane's write decision). And the row
   required is the `deny_read` row at that directory whether built in or the contract's own: a boundary that declares
   `deny_read` of the owner's `~/.tego` gets no built-in row beside it, and the check was silently skipped for it
   (`TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome`). And root's chown of the `~/.tego` it makes
   goes through a descriptor opened after the `mkdirat`, so a directory the owner renamed in at the name meanwhile
   (one directly in its home, owned by someone else) was chowned to it: the group is now looked up before the
   `mkdirat` (only when nothing is at the name yet: a `~/.tego` already there is neither made nor chowned, so a uid
   whose passwd group cannot be found is not refused for it), and what the descriptor opens is chowned only when it is what that `mkdirat` makes (tego's uid's, no
   group or other mode bits, empty); anything else refuses the boundary, named, and is left as it is
   (`TestMakeOwnRecordsGivesAwayOnlyTheDirectoryItMade`; the row of another uid's directory as root). Rejected: making
   the directory as the owner (`setfsuid` on a locked thread), which needs no chown but checks the home's group write
   against root's supplementary groups, not the owner's. And root makes `~/.tego` only in a home the owner
   may write by its mode (it owns it, which lets it chmod it, or its group or other write bit admits the owner):
   making one, owned by the owner, in a root-owned home (a service account's `/` or `/var/www`) handed it a writable
   directory it could not make itself, for records no run of its own could have written there. Such an owner's table
   compiles with no deny of it, as for a missing home, and is stale, so the guard compiles it again, once a
   `~/.tego` is there; a home only an ACL lets the owner write is taken as one it may not (ACLs are not read), so a
   single `tego adopt` of such an owner leaves records its first run makes there readable to the agent while it
   runs, as for a missing home. Rejected: refusing the boundary for such an owner (a service account's agent could
   then never be adopted under one), and making the directory root's (the owner's runs could not write it).
   The table used to compile against the adopter's home, so under the guard's root unit every adopted agent's own
   credentials stayed readable (the list named `/root/.ssh`), and `sudo tego adopt --uid 1001` by uid 1000 denied uid
   1000's, while run_start claimed `fs.deny_read`. `tego adopt` compiles for the process it identified; the guard
   compiles one table per listed `--uid` at its start. The recheck before the move refuses a root whose owner changed
   since it was identified, even to another admitted uid (rule `uid`), so no agent is held to another user's lists. A
   boundary for an owner with no home in the passwd database is refused, named. Rejected: refusing every adoption of
   another user's process (the guard's whole use), and compiling per agent in the guard (3-6 s of compile on each
   adoption's path, for a table that depends only on the owner).
   *Amended 2026-10-16:* a boundary write entry at or inside the owner's
   `~/.tego` is a contradiction (agent-contract R10), as the owner's own launched run refuses the same entry for the
   anchor directory it holds. Before this it dropped R6a's deny of that directory (a directory a write entry needs is
   not denied) with only a `ledger-readable` warning, and the agent could read and write the owner's records, chain
   anchor and machine config. An entry above it (the home) keeps the deny, nested, which the plane holds at tier
   cgroup, as the home is an ordinary write entry wherever the anchor is not in it. Rejected: refusing an entry above
   it too (a launched run whose anchor is elsewhere compiles `fs.write: [~]`, and the nested deny holds there).
6. **Another user's process only when its owner is named.** `tego adopt --pid` adopts a process whose real,
   effective and saved uid are one and the same uid of: the invoking user (the user sudo ran tego for, or root when
   root runs it directly) or a `--uid` given on the line. Root naming a pid is not by itself consent to move another
   user's agent: `sudo tego adopt --pid <pid>` adopts the operator's own, and anyone else's needs `--uid <owner>`
   (refused otherwise under rule `uid`, naming the `--uid` that would admit it). A process whose three uids differ (a
   set-user-id program) is never adopted. `--release` takes no `--uid`: releasing only gives the agent back.
   Rejected: no owner check (the draft's; a root typo or a recycled pid moved another user's process) and `--uid`
   always (`sudo tego adopt --pid` of one's own agent is the common case and its owner is already known).
7. **The guard is the detector with `--adopt`, foreground.** `tego agents --follow --adopt --uid <uid>...` adopts each
   agent it reports outside every governed run whose real, effective and saved uid are one listed uid (root's only with
   `--uid 0`); `--adopt` without `--uid` is refused, since any local user can name a program `claude`. Each agent is
   considered once (never retried), one identity is never adopted twice (an in-memory registry here, the host-wide
   identity lock and the cgroup check across processes), at most 32 adoptions at once, a refusal or failure is one
   line. ADR 0042 holds: no daemon; `docs/poc/tego-guard.service.example` runs the foreground command under systemd.
8. **Scope boundary.** Only the agent's own tree is touched, only to move it between cgroups. Root can see
   and remove all of it: the scopes under `tego.slice`, the records in `/run/tego/adopted/` (root's alone), the pins
   under `/sys/fs/bpf/tego/`. Nothing is pinned to hide, nothing resists root.

## The scope guard (2026-10-16)

An adoption may only take what these rules allow, and each is enforced in code with a test (internal/watch/adopt
`Check`, `UIDs`, `Move`; internal/runtime `adoption.move`; internal/cli `adoptionRules`):

| Never adopted | How it is told | Where |
|---|---|---|
| pid 1 | the pid | `Check`, rule `init` |
| a kernel thread | no `/proc/<pid>/exe` (a process whose program cannot be read is refused the same way) | `kernel-thread` |
| a thread id | `Tgid` differs from the pid | `thread` |
| tego itself | this pid; tego's binary by device and inode; any program named `tego` | `tego` |
| an ancestor of the caller | the caller's parent chain up to pid 1 (its shell, sudo, sshd, a multiplexer, the user manager) | `ancestor` |
| a service manager | its cgroup is an `init.scope` | `service-manager` |
| another namespace's process | its cgroup or pid namespace inode differs from the caller's, or cannot be read | `namespace` |
| an already-governed process | its cgroup is, or is below, a run's scope where tego makes one: `tego.slice/tego-<agent>.slice/run-<id>.scope` at the cgroup2 root or in a user's delegated subtree, `tego.slice/tego-<agent>.slice/adopt-<id>.scope` at the root only, or Docker's `tego/<agent>/<id>` at the root (amended 2026-10-16: any component of that name used to count) | `governed` |
| a process in no cgroup v2 hierarchy | `/proc/<pid>/cgroup` names no v2 path | `no-cgroup` |
| a process in the cgroup2 root | its cgroup is `/`: a release never writes the root cgroup, so it could not be given back (added 2026-10-16) | `root-cgroup` |
| another user's process | its real, effective and saved uid are not one uid of the invoking user and `--uid` (the guard: `--uid` only) | `uid` |

The rules are applied when the process is identified and again right before the move, to the process as read then,
under the host-wide move lock (Decision 2). Each member's write to `cgroup.procs` is preceded by a pidfd and a re-read of
its start time and its cgroup (still the root's), and followed by the pidfd's liveness, so a pid reused at any point
moves nothing or is put back. A release does the same for each process it finds in the scope (amended 2026-10-16): it is held by a pidfd and written only while the cgroup of a live thread of it still says the scope, and a
write that landed on a pid reused within it is put back in its parent's cgroup. The processes in the scope are the
thread groups of the tasks its `cgroup.threads` lists, and a process's cgroup is a live thread's (amended 2026-10-17:
this said `cgroup.procs` and `/proc/<pid>/cgroup`, which are now
read only where `cgroup.threads` cannot be; for a process whose leader exited elsewhere both name the old
cgroup, What was measured, (d)). Before, a member that died between the
read and the write (SIGKILL reaches a frozen process, and with no `cgroup.freeze` nothing holds the tree), its pid
taken meanwhile, had that unrelated process, of any user, moved by root into the cgroup the tree came from. Only root of the initial user namespace adopts (exit 125 `[privilege]` otherwise).

A run's cgroup is read from where tego makes one and nowhere else (amended 2026-10-16). The rule used
to take any path component named `run-<id>.scope`, `adopt-<id>.scope` or a bare run id, and every run id is readable
in `/proc/<pid>/cgroup`: a user could make `app.slice/adopt-<another user's run>.scope` in their own delegated subtree,
and `tego adopt --release --pid` of a process put there released that other user's adoption; a self-made
`run-<id>.scope` kept a process out of the guard and of `Check`. Now `tego adopt --release --pid` needs the process to
be in an adoption scope at its own place, and in the scope the run's root-only record names. What stays: tego's own
unprivileged runs live in their user's delegated subtree, so the same shape built there by that user still reads as a
run, which keeps that user's own process out of the guard; the guard is no boundary against the user who owns the
agent (it can rename the program too), and no other user's adoption is reachable that way.

The rules name the process asked for. Its descendants move when, and only when, they are in the root's own cgroup,
whatever they run and whoever they run as (a set-user-id child the agent started, a `tego run` launcher the agent
started): they are the agent's tree, and skipping one by its name would let an agent keep a child out of the record
by calling it `tego`. A descendant in another cgroup (another run's scope, a container, a `systemd-run --scope`,
`init.scope`) is never moved and is counted in the record (`adoption-not-moved`). An ancestor of the caller cannot be a
descendant of an admitted root, since the root would then be an ancestor too. Residuals, said rather than fixed: a
process can exec between the last recheck and its write (microseconds; its identity is still checked, its program is
not); a process the agent started that was reparented away from the root before the move (its parent exited, as a
daemonised child's does) is no descendant by /proc's parent links, so it is not moved and not counted in
`adoption-not-moved` (`AdoptSpec.Extra` would take identities a caller followed by fork events, but no caller passes
any yet, the guard included); and the source cgroup is not frozen (Alternatives), so a member forked
after the last pass is caught only by the next one, up to 16.

## What it does not do

- It cannot record or decide anything the agent did before the attach, nor reads, writes and sends through descriptors
  it already held, nor loads and stores through files it had mapped (a mapping outlives its descriptor, and no LSM hook
  sees a store to a shared writable mapping). It cannot give a running process a seccomp filter, so nothing that
  only tier 1's filter refuses is held on it, whatever the contract says: System V IPC (a contract refuses it unless
  it sets `ipc: true`), the socket families outside the network rules (the family allowlist: AF_VSOCK, AF_PACKET,
  AF_TIPC, SCTP and the rest), io_uring, openat2, open_by_handle_at, clone3, the terminal-input ioctls. A boundary
  adoption's ledger says so after run_start (`gap what=enforce adoption-no-syscall-filter`), and the notice before the
  move (amended 2026-10-16: only the last three were named, and SysV IPC and the families went
  unsaid). Rejected: refusing every boundary that does not set `ipc: true` (the families cannot be set at all, since
  a `net:` section is refused, so a disclosure is needed whatever is refused). Nor can it give Landlock,
  no_new_privs, a new environment, or the forwarder (so no model traffic capture).
- *Amended 2026-10-16.* It does not hold the mount topology. Tier 1's filter refuses new mount
  and user namespaces and every `setns` (enforce-cgroup-observe E24), and Landlock refuses `mount(2)`, because the
  file rules are paths on one mount tree. The plane has no mount or namespace hook and its walk follows the process's
  own mount tree (`mnt_parent` at each mount root), so an adopted agent that can mount (root, or one that can make a
  user namespace, where the kernel and its LSMs allow that) can make a mount after the attach that puts a file where
  the contract's paths do not reach it, and the plane's condition "neither the agent nor its launcher can mount"
  (enforce-plane §2 condition 2) does not hold for it. The notice names this before the move and
  `adoption-no-syscall-filter` covers it in the ledger. Decided: kept as disclosed, not
  refused. Rejected: refusing a boundary adoption wherever unprivileged user namespaces are available (no host
  setting tells it reliably: AppArmor's restriction admits profiled helpers, a root-owned agent needs none, and on most
  distributions' defaults it would refuse every boundary adoption, a scope cut); changing
  the host's user-namespace settings (host-wide control, out of scope). The fix that would hold it is a plane hook
  refusing mounts and namespace changes to the run's tasks (question 6). *Amended 2026-10-17:* shown
  on the kernel as root in KVM guests (`TestPlaneRunWalksTheMountTreeAsItStands`; 6.17.0-41 in both plane modes, and
  AL2023 6.1, which loads no overlay module): after the fill, a directory outside every write entry bound beneath one
  is written through, and an overlay whose lower layer is a `deny_read` directory is read through its merged path
  (the plane decides the user's open on the overlay's own inode and skips overlayfs' open of the layer, enforce-plane
  §2.12). A bind of what the rows key by inode is not enough: a `deny_read` directory or a `deny_write` target bound
  beneath a write entry is still refused. So the residual reaches reads too, not only writes, and the notice names
  both kinds of mount.
- No network rule (b). A boundary adoption is tier cgroup with the plane; tier 3 is out of scope.
- It is fail-open on the adopter's death, a boundary adoption too: the reaper releases the agent unconfined (the
  launch path kills instead), and run_end `orphaned` says so (Decision 4).
- It never adopts another user's process unless `--uid` names its owner, and never a process the scope guard refuses.
- The exit status is the proc connector's, when it was read and its tasks' codes agree on it (What was measured, (e));
  a status a dropped event lost, or one the codes do not say, is unknown.
- `tego stop` never signals the adopter and never kills an adopted agent: it leaves a release request that this
  adoption alone answers (Decision 4).

## Alternatives considered

- **Attach to the agent's existing cgroup, no move.** The cgroup is the terminal's session scope (or a desktop app
  scope holding every tab): its programs would govern the shell and every other process in it. Rejected.
- **Freeze the source cgroup during the move.** Freezes the operator's shell and every sibling. Rejected; passes over
  /proc with the pid-plus-start-time check instead, and the run's own cgroup is frozen during a release only.
- **Kill the agent when the adopter dies (ADR 0020's choice for launched runs).** Turns a tego crash into the loss of
  the operator's session for a process tego never started. Rejected, for boundary adoptions too (Decision 4).
- **Hold network rules with the cgroup programs anyway.** They govern sockets made after the move only, and the record
  cannot tell which. Rejected until a kernel-side connect result is recorded (a new program, out of this package).
- **ptrace or seccomp injection into the running process.** Intrusive, fragile, and the opposite of consensual audit.
  Rejected.
- **A resident daemon.** ADR 0042: no daemon until a named trigger fires. The guard is a foreground command.

## Questions

1. ~~Is fail-open on the adopter's death right for a boundary adoption?~~ Decided
   (Decision 4): released, never killed, and said.
2. ~~Should explicit `tego adopt --pid` also require `--uid`?~~ Decided (Decision 6):
   only for a process that is not the invoking user's own.
3. Not built, out of scope here: the cold-start window (3.6-6.2 s) could fall to milliseconds with a pre-armed standby scope the
   guard keeps ready (the agent moved into an armed scope at once, the run's ledger written behind it). Not built.
4. Not built, out of scope here: network rules on adopted processes need either a kernel record of the connect's result or a
   supervisor-like seam; both are new code (a BPF change for the first). Not built.
5. ~~Accept this as ADR 0055 and stage 2 of ADR 0054?~~ Accepted 2026-10-16; ADR 0054's
   P0 rows are unchanged (FEATURES W5).
6. Holding the mount topology on an adopted process with decision-plane hooks on mounting and on namespace changes
   (`sb_mount`, `move_mount`, `sb_pivotroot`, `userns_create` where the kernel has it), in both plane modes on every
   matrix row, needs new BPF code and a load test of every row. Not built.

## Verification at acceptance (2026-10-16)

At the merged tip with the scope guard's fixes (Decisions 2 and 6), in KVM guests on 6.17.0-41-generic: the six
adoption tests of `internal/cli/adopt_integration_test.go` (record, killed adopter, busy agent, boundary through the
plane with the `--uid` refusal, the guard with two agents and `tego stop` of one, `tego adopt --release` live and
orphaned) and `TestIntegrationAgentsFollowSeesAFakeAgentOnTheRealKernel` pass from the `tegobpf` build on both boots
(fmod_ret and LSM plane modes); the untagged build skips the six as listed in test/vm/root-skips.txt. Unit tests with
`-race`. Mutants, each killed by a test: before the merge, thirteen (the move's identity checks, the
tree walk, the registry, the host-wide identity lock, the guard's filter, `Check`'s governed rule, the boundary
refusals); at this tip, five more: the release request (`releaseRequested` ignoring its run, so
`TestReleaseAdoptionReleasesItsRunAlone` fails), the recheck before the move, the move lock, the owner filter and the
root-cgroup rule.

## Implementation notes

- 2026-10-16: the notice and `adoption-no-syscall-filter` name the
  namespace arm and the mount topology ("What it does not do"); an adopted owner's own `~/.tego` is read-denied
  (Decision 5); "no path" in `adoption-open-descriptors` is read from the process's mount table (replaced, below), and a process in
  another mount namespace is counted unread (Decision 3). Tests: `TestNoPathOnTheRealKernel` (a memfd, shared
  anonymous memory and the AIO ring on this kernel), `TestNoPathIsTheKernelsInternalDevices` (then named for the mount table),
  `TestAdoptBoundaryNamesThePlaneAndItsRows`, `TestAdoptCountsAProcessInAnotherMountNamespaceUnread`,
  `TestTheHomesTegoIsReadDeniedWhenTheAnchorIsElsewhere`, `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome`,
  `TestAdoptNoticeNamesWhatOnlyTheFilterHolds`; each fails with its change reverted.
- 2026-10-16: "no path" is a device of the
  kernel-internal superblocks tego probes in its own process, no longer a mount the holder's mountinfo does not show
  (Decision 3); the guard compiles a table again once the owner's `~/.tego` appears (Decision 5). Tests:
  `TestIntegrationNoPathChrootedHolder`, `TestIntegrationNoPathLazilyUnmounted`, `TestIntegrationNoPathDetachedBind`
  (tmpfs and btrfs; root, KVM guest, 6.17.0-41-generic: the first, the second and btrfs fail with the mountinfo rule),
  `TestNoPathIsTheKernelsInternalDevices` (a fake `/proc` whose descriptors' devices are or are not internal, so a
  decision that always or never says no path fails), `TestNoPathOnTheRealKernel` (a hugetlb memfd and a `/dev/shm`
  file added), `TestGuardRecompilesATableWhoseOwnersRecordsAppeared` (renamed from
  `TestGuardRecompilesATableWhoseOwnersRecordsChanged`) and
  `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome` (an owner with no `~/.tego`). `internal/watch/adopt`
  joined root-suites (test/vm/suites.sh).
- 2026-10-16: the count asks the rows about a held file
  only by a name that is a path of it in tego's namespace, and by its paths through the other mounts of its
  filesystem (Decision 3, `internal/watch/adopt/names.go`); a boundary adoption makes the owner's `~/.tego` before it
  compiles and refuses one that is no directory, and the guard recompiles a table whose directory was replaced
  (Decision 5); a boundary write entry at or inside the owner's `~/.tego` is a contradiction (Decision 5,
  agent-contract R10). Tests: `TestIntegrationAdoptCountsAFileHeldThroughAnotherMount` (root, KVM guest, 6.17.0-41:
  a key under `deny_read` held read-only by a child process, by a descriptor and by a read mapping, directly, through a
  detached clone, a lazily unmounted bind and a mounted bind of its parent; the clone and
  lazy rows count nothing, unread included, and the mounted-bind rows are not counted. The guest also showed a
  mapping's `map_files` entry looked up by the smaps range, which pads an address to eight hex digits where
  `map_files` does not, so the process of every executable that is not position-independent counted unread; the
  range is unpadded now), `TestANameIsAPathOnlyThroughTegosOwnMounts`, `TestFSNamesWhatItListsThroughTegosMounts`,
  `TestAdoptAsksTheRowsOnlyByNamesOfTheFile`, `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome` (an owner with
  no `~/.tego` gets one, denied; a file or dangling link there is refused), `TestGuardRecompilesATableWhoseOwnersRecordsChanged`,
  `TestIntegrationBoundaryAdoptionMakesTheOwnersRecords` (root: the directory is the owner's, and a link there is not
  followed) and `TestTheHomesTegoIsReadDeniedWhenTheAnchorIsElsewhere` (write entries at and inside it); each fails
  with its change reverted.
- 2026-10-17: the count asks the rows by the keyed
  inode too, and counts unread a process whose io_uring registered files it cannot list (Decision 3); the adopter
  requires the plane's row for the owner's `~/.tego` at the directory compiled against, and root makes that directory
  only in a home the owner may write (Decision 5). `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome` failed as
  root (it replaced the passwd home lookup and not the group lookup, so the root path looked uid 1001 up on a guest
  that has none): it now stands in both, and makes its homes the owners' as root. Tests:
  `TestIntegrationAdoptCountsAHardLinkOfAKeyedFile` (a hard link of a deny_read file held by a descriptor, and as
  root by a mapping; failed before the change), `TestAdoptAsksTheRowsByTheKeyedInode`,
  `TestAdoptCountsARingItCannotReadUnread`, `TestRingRegisteredFilesIsTheFdinfosTable`, `TestMapsNamesEachRingItMaps`,
  `TestRingOnTheRealKernel` (a ring and a registered file on this kernel), `TestFDsCarryTheHeldFilesInode`,
  `TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere`, `TestPlaneKeyedIsWhereTheFsRowsAreWritten`,
  `TestPlaneRunKeyedFilesAreTheInodesItDecides` (root, KVM: the fill's identities are a stat's, and the plane refuses
  a hard link of a deny_read file and a deny_read directory renamed after the fill), `TestHomeWritableByIsTheModeTheOwnerHas`,
  `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome` (an owner whose home it may not write) and
  `TestIntegrationBoundaryAdoptionMakesTheOwnersRecords` (root: nothing made in a root-owned home, the directory made
  in one the owner's group may write); each fails with its change reverted.
- 2026-10-17: the count also asks the rows by the path beneath each
  row keyed at a directory a held file's name passes through (a `deny_read` directory renamed after the fill), and a
  ring on the kernel's shared anonymous inode has no identity, so a ring its process only maps counts it unread
  (Decision 3). Tests: `TestAdoptAsksTheRowsByEachKeyedDirectoryAboveTheName` (count 0, want 3, before the change),
  `TestARingOnTheSharedAnonInodeHasNoIdentity` (the ring kept its inode with the shared one stood in for by it, before
  the change), `TestRingIdentityOnTheRealKernel` and a row of `TestAdoptCountsARingItCannotReadUnread` (a ring with
  no identity, held and mapped, is unread). The mount-topology residual ("What it does not do") is shown on the
  kernel by `TestPlaneRunWalksTheMountTreeAsItStands`, and the notice names the overlay read. KVM guests: on
  6.17.0-41, both boots (lsm=...,bpf and the default list), the whole `internal/watch/adopt` suite, the adoption
  tests of `internal/runtime` (the held-file and hard-link root tests included) and of `internal/cli` (both builds),
  and `TestPlaneRunKeyedFilesAreTheInodesItDecides` and `TestPlaneRunWalksTheMountTreeAsItStands` in both plane
  modes pass; on the matrix rows AL2023 6.1 and RHEL 9 5.14 the whole `internal/watch/adopt` suite passes (the NoPath
  root tests included, which had run on 6.17 only), as do the keyed and mount-tree plane tests on AL2023. Rings have
  an inode of their own on 6.17, Ubuntu 24.04's 6.8, AL2023's 6.1 and RHEL 9's 5.14 (io_uring enabled for the probe:
  RHEL 9 sets `kernel.io_uring_disabled`, so its ring tests skip in the suite, as btrfs and overlay subtests do on
  rows whose guests load no module, test/vm/root-skips.txt). On Ubuntu 22.04's 5.15 (a doctor-only row) two rings and
  an eventfd share one inode, which an earlier rule would have taken for one ring; the ring tests pass there with
  this rule (a guest of that kernel, the package's test binary run with `-test.run Ring`).
- 2026-10-17: the listing reads
  every task's descriptor table and lists a descriptor `/proc` cannot name as unread (Decision 3); after the arm the
  owner's `~/.tego` path must still lead to the keyed directory, the contract's own `deny_read` of it is the row
  required, and root chowns only the empty directory its `mkdirat` made (Decision 5). Tests, each failing before its
  change: `TestFDsSaysADescriptorItCannotName`, `TestFDsSaysADescriptorWhoseNameIsTooLong`,
  `TestFDsReadsEveryTasksTable`, `TestFDsReadsAThreadsOwnTableOnTheKernel`,
  `TestAdoptCountsADescriptorItCannotNameUnread`, the after-the-fill rows of
  `TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere`, the declared rows of
  `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome` and `TestMakeOwnRecordsGivesAwayOnlyTheDirectoryItMade`;
  and, as root, the row of `TestIntegrationAdoptCountsAHardLinkOfAKeyedFile` for a link at a path past `PATH_MAX`
  and the row of `TestMakeOwnRecordsGivesAwayOnlyTheDirectoryItMade` for another uid's directory.
- 2026-10-17: a process whose leader
  exited while its threads run is moved, read and released through a live thread, and the watcher's tree keeps it
  (What was measured, (d)); the descriptor
  listing merges two tables' entries only by the held file's identity, never rings (Decision 3); a `~/.tego` that is
  a link refuses a boundary, at the compile and after the arm (Decision 5). Tests, each failing before its change:
  `TestAProcessWhoseLeaderExitedIsAMember`, `TestMoveMovesAProcessWhoseLeaderExited`,
  `TestMapsReadsAProcessWhoseLeaderExitedThroughItsThread`, `TestSnapshotKeepsAProcessWhoseLeaderExited`,
  `TestFDsListsTwoFilesUnderOneNumberAndName`,
  `TestFDsNeverMergesTwoRings`, the link row of `TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere` and the link
  rows of `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome`; and, as root in a KVM guest of 6.17 on both
  boots, `TestIntegrationAdoptMovesAProcessWhoseLeaderExited` (a python agent whose main thread exits, holding a
  file and a shared mapping from its thread: identified, moved with its child, listed, released).
- 2026-10-17: a release counts the
  processes of the scope from its `cgroup.threads` (What was measured, (d)); the descriptor listing's cap of 4096
  counts what is listed after two tables are merged (Decision 3); the guard's scan reads an agent whose leader exited
  through a live thread (ADR 0054's amendment of this date; `TestScanFindsAnAgentWhoseLeaderExited`, and without
  privilege on the running kernel `TestIntegrationFactsReadAnAgentWhoseLeaderExited`). Tests that fail before the change, or
  without each earlier fix they guard: `TestReleaseOfAProcessWhoseLeaderExitedInTheScope`, `TestFDsCapsTheMergedListing`,
  `TestReleaseLeavesAProcessWhoseLeaderExitedCounted`, `TestMoveRechecksTheCgroupOfAProcessWhoseLeaderExited`,
  `TestMapsNamesAProcessWhoseLeaderExitedThroughItsThread`, `TestALeaderExitedProcessIsReadOnlyThroughAThreadOfIt`,
  `TestAdoptionOfAProcessWhoseLeaderExited` and the name row of `TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome`;
  as root in a KVM guest, `TestIntegrationReleaseAfterTheLeaderExitedInTheScope` (a python agent adopted whole whose
  main thread then exits: the release leaves nothing and the scope is removed).
- 2026-10-17: a process ends with its last
  task, and its status is what its tasks' codes agree on, by one rule (`procconn.Group`) for the watcher and the exit
  watches of `tego adopt` and the guard (What was measured, (e); ADR 0054's amendment of this date); the guard feeds
  its adoptions' exit watches from its watcher (`watcher.Options.Tap`), and its session-keyed statuses are gone; the
  "process gone" test is `proc.Stat.Gone` everywhere in the watch packages (`adopt.Gone` and `adopt.LeaderExited`,
  and the watcher's copies, deleted); the descriptor listing reads at most 16,384 entries across a process's tables
  (Decision 3); the release's text names `cgroup.threads` (The scope guard, the paragraph on each member's write). Tests that
  fail before the change: `TestGroupEndsWithItsLastTaskAndSaysOnlyAStatusTheEventsAgreeOn` (new type),
  `TestAnAgentFoundWithItsLeaderGoneEndsWithItsLastThread`, `TestAnAgentWhoseMainThreadExitsRunsOnInItsSession`,
  `TestALeaderThatWentFirstGivesOnlyAStatusTheCodesAgreeOn` (renamed), `TestAThreadThatRunsAProgramAfterItsLeaderWentFirstEndsWithIt`,
  `TestExitWatchTakesTheEndOfTheWholeProcess` and `TestFDsBoundsItsReadsAcrossCopiedTables`; and, failing without the
  part of the change each guards (applied one at a time), `TestAProcessWhoseTasksAreAllZombiesHasEnded`,
  a reused-pid row of the watcher (deleted with the `/proc` read it tested), `TestWhatAnEndNeedsIsForgottenWithItsProcess`,
  `TestTheTapIsToldEveryEventAndEveryLoss` and the reused-pid, lost-events and zombie rows of the exit-watch tests; `TestGuardExitStatusIsTheAdoptedAgentsOwn` replaces the session-keyed
  test. As root in a KVM guest of 6.17 on both boots: `TestIntegrationWatcherFollowsAnAgentWhoseMainThreadExits`,
  `TestIntegrationWatcherEndsAnAgentFoundWithItsMainThreadGone`, `TestIntegrationAGroupReadsGoneAtItsLastTasksExitEvent`
  (the measurement in (e)) and `TestIntegrationExitWatchReadsTheWholeProcessEnd`.
- 2026-10-19: a process's end is told
  by its events alone, from the set of its tasks that run, and its status by one agreement rule for every code, signals
  too (What was measured, (e), the amendment of this date). `procconn.Group` keeps the set (`NewGroup` from a listing,
  `Thread`, `Exec` with the event's timestamp, `Exit`, `Resync`); `adopt.Ended` and the watcher's `gone` (the
  handling-time `/proc` reads) and `tree.Tree.StartTime` are deleted, `adopt.LiveTasks` lists a root's tasks for an
  exit watch, and the watcher lists the tasks of what a scan newly follows, and of everything it follows after lost
  events. Tests that fail before the change: every row of `TestTheEndIsTheEventsNotWhatProcShowsWhenTheyAreRead` (the
  zap read late gave code 0, the failed exec left the session open, the thread-first `exit_group(3)` gave unknown, the
  leader killed alone gave signal 31), the SIGTERM row of `TestALeaderThatWentFirstGivesOnlyAStatusTheCodesAgreeOn`,
  the SIGKILL-alone, zap, failed-exec and killed-alone rows of `TestExitWatchTakesTheEndOfTheWholeProcess`, the s5 and
  c5 rows of `TestGroupEndsWithItsLastTaskAndSaysOnlyAStatusTheEventsAgreeOn` (and, without the timestamp rule, its
  three timestamp rows), and both rows of `TestAProcessThatEndsDuringAScanIsEndedByItsExit` (a process that ended
  between a scan's two reads left its session open). The watcher's reused-pid test of an earlier fix is deleted with the
  `/proc` read it tested; `TestTheScanListsTheThreadsTheEventsDidNotSay` and `TestGroupAfterDroppedEvents`
  cover the listing. As root in a KVM guest of 6.17 on both boots: `TestIntegrationAProcessEndsAtItsEventsWithAStatusWaitAgrees`
  (the python shapes of the reviews, in a loop, against `wait(2)`), `TestIntegrationAThreadKilledAloneGivesNoSignal`,
  `TestIntegrationWatcherReportsTheStatusOfAProgramAThreadRan` and `TestIntegrationExitWatchGivesTheStatusOfAProgramAThreadRan`.
- 2026-10-27 : the exhaustive model's three-task
  scenarios found that `procconn.NewGroup` ended a process at an unstable listing that read no task running, though
  `List` says an unstable listing's end is checked with a fresh one: an exec's `de_thread` moved the exec'ing thread to
  the leader's tid between the listing's reads of the two, so it was read at neither (fates exit0, exit0, exec or a
  failed exec, a thread made during the run, a listing reader). `NewGroup` and `Resync` now check such a listing with
  the fresh listing their reader gives (`confirmUnlisted`), as an emptied set of an unstable listing is checked. The
  two-task model runs by default; the three-task one takes longer than go test's 10-minute default on a loaded box and
  runs with `TEGO_TEST_EXIT_MODEL=full`.
- 2026-10-25: `GovernedBy` and `AdoptionScopeRun`, the "already-governed" rule of the scope guard's
  table, moved unchanged to `internal/runscope` (ADR 0100 (7)), with their tables (TestGovernedByUnchanged). `Check`
  still applies it under the rule `governed`; the watcher and the adoption reaper call it there. `ScopeName` stays in
  internal/watch/adopt. The broad `runscope.LooksGoverned` beside it serves refusals at Tego's own sockets only; no
  adoption, release or `tego stop` reads it.

## How to reproduce the evidence

```sh
# the probe (one guest, both boots by TEGO_VM_LSM):
CGO_ENABLED=0 go build -tags tegobpf -o bin/adoptprobe ./test/vm/cmd/adoptprobe
TEGO_VM_LSM=lockdown,capability,landlock,yama,apparmor,ima,evm test/vm/kvm-run.sh bin/adoptprobe | grep PROBE
TEGO_VM_LSM=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf test/vm/kvm-run.sh bin/adoptprobe | grep PROBE
# the feature's root tests, both boots:
VM_BPF=yes VM_BOOTS=both VM_RUN='TestIntegrationAdopt|TestIntegrationGuard|TestIntegrationAgentsFollow' \
  test/vm/root-suites.sh internal/cli
```
