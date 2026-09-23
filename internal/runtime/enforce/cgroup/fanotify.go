// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Fanotify constants the x/sys/unix package does not name.
const (
	// fanMetadataVersion is FANOTIFY_METADATA_VERSION: the ABI this listener understands. The kernel
	// refuses to talk to a listener that does not match, and a record claiming another version is not one
	// this code may respond to.
	fanMetadataVersion = 3
	// fanMetadataLen is sizeof(struct fanotify_event_metadata).
	fanMetadataLen = 24
	// fanPermMask is every permission event this listener asks for.
	fanPermMask = unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM
	// fanReadBatch is the most records one read(2) returns. It is small on purpose: loop() checks the
	// overdue count only between reads, so one read's records are part of how far the count can pass its
	// ceiling (fanOverdueOvershoot, §6 E34). A 64 KiB buffer let one read hand off 2,730 records past the
	// check; this one lets it hand off 64, at the price of one read(2) per 64 events rather than per 2,730,
	// which is small beside the decision each event costs.
	fanReadBatch = 4 * fanotifyWorkers
	// fanReadBuffer is the read(2) buffer: fanReadBatch whole records, since this group reports no info
	// records and each event is exactly fanMetadataLen bytes.
	fanReadBuffer = fanReadBatch * fanMetadataLen
	// fanOverdueOvershoot is how far the overdue count can pass the ceiling before loop() sees it: one read's
	// records, plus the decisions already queued or deciding when the check passed (§6 E34).
	fanOverdueOvershoot = fanReadBatch + 2*fanotifyWorkers
	// fanPollTimeoutMS bounds how long a blocked read delays noticing context cancellation should the wake pipe's
	// write be lost; the wake is what ends a cancelled loop's poll (loop).
	fanPollTimeoutMS = 100
	// fanotifyWorkers is how many permission decisions loop() may have in flight at once.
	//
	// A FAN_MARK_MOUNT mark covers the whole mount (fanotify_mark(2)), so on an ordinary single-root box
	// this listener answers every open and every execve on the machine its marks ask about (§6 E34). The
	// ones their path allows are answered on the read loop (settleByPath); the pool is for the rest, whose
	// decision can wait on a membership read. handle() blocks until its
	// decision returns or the deadline fires, so answering from the read loop itself made the deadline of
	// §6 E16 bound only one decision: the opener at position N of a read batch waited N deadlines, and one
	// process stuck in D state (an unreachable NFS mount, a frozen container) stopped every open on the
	// filesystem, not just its own. Deciding off the read path bounds that by the batch's depth over this
	// width instead (§6 E35).
	//
	// A fixed small pool rather than a goroutine per event: an unbounded fan-out driven by every process on
	// the host is its own denial of service, and the path verdict answers most events before they reach it.
	//
	// The pool bounds the decisions an opener is waiting on, not the ones handle() has answered at E16's
	// deadline and left running: a read blocked in the kernel cannot be interrupted, and before 6.8 every
	// /proc/<pid>/cgroup read waits on the one cgroup_mutex, so a held mutex leaves one such decision behind
	// per membership read a worker starts. The overdue ceiling bounds those instead: sized to the thread
	// budget by newFanotifyListener, at most fanotifyOverdueCeiling (§6 E34).
	fanotifyWorkers = 16
	// fanotifyOverdueCeiling is the most decisions answered at E16's deadline that may still be running
	// before loop() gives the group up (§6 E34, §7). Each keeps two goroutines, the /proc/<pid>/cgroup
	// descriptor its read goes through and, blocked in that read, an OS thread. The launcher aborts when it
	// cannot have another thread: the Go runtime at runtime/debug.SetMaxThreads (10,000 by default), and
	// clone(2) at a pids.max on the launcher's own cgroup chain or at kernel.threads-max, which on a small
	// host sit far below 10,000. An abort runs no teardown: the kernel releases every pending event as an
	// allow (§6 E15) while whatever of the run outlives the launcher keeps running (§6 E38). Ending the
	// listener here instead cancels the run and kills its cgroup (§7).
	//
	// This is a cap, not the ceiling a listener runs with: newFanotifyListener measures the nearest of those
	// limits (threadBudget) and sizes the ceiling so that it plus fanOverdueOvershoot fits in half of the
	// headroom (overdueCeilingFor), and refuses to start where even the smallest ceiling would not fit.
	fanotifyOverdueCeiling = 1024
	// fdCloserCap is the most answered events' descriptors the closer may hold before loop() stops reading and
	// waits for it (fdCloser.catchUp, §6 E35). A close that answers keeps about the loop's pace, a slow network
	// mount's included. Where a close is a request its filesystem waits on (FUSE's FLUSH, NFSv4's CLOSE), the
	// open that gave the loop the event's descriptor was one too (FUSE's OPEN unless the daemon declined opens,
	// NFSv4's OPEN unless a delegation is held, which spares the CLOSE as well), and the loop's own read paid
	// it, so the closer spends on a descriptor about what the loop spent getting it, with nothing else to do.
	// That holds only while the closer has a processor, and the loop, which blocks nowhere while events keep
	// coming, can keep the one it would run on: a backlog this deep can also mean the closer has not run. So
	// the loop waits there, which gives the closer a processor, and gives the group up only when the closer
	// does not close half of what it holds within one decision deadline: a close has stopped answering, or a
	// filesystem answers its closes far slower than its opens. It is a cap: loop() holds the closer to a
	// quarter of the soft RLIMIT_NOFILE when that is smaller (closeBacklogFor), so the backlog alone cannot take
	// the process to the limit at which a membership read fails (decideEvent).
	fdCloserCap = 1024
	// fanCloserJoinTimeout is how long a cancelled loop() waits for its closer to finish before it returns and
	// leaves the rest of the closes to it (§6 E35): long enough for a queue of closes that each answer, and
	// bounded, so a filesystem that never answers one cannot keep a run that has ended from writing run_end. It
	// matches the runtime's own bound on a kill (internal/runtime's killTimeout).
	fanCloserJoinTimeout = 10 * time.Second
	// DefaultFanotifyDeadline is the per-decision deadline of §6 E16. Approval waits are handled
	// separately; ask.timeout does not extend a fanotify membership or path decision.
	DefaultFanotifyDeadline = 500 * time.Millisecond
)

// Gap reasons this listener raises. They are the `why` of a gap event (§7).
const (
	// GapFanotifyTimeout means a decision exceeded the deadline and the open was allowed (§6 E16).
	GapFanotifyTimeout = "fanotify-timeout"
	// GapFanotifyOverflow means the kernel dropped notification events because the queue filled.
	GapFanotifyOverflow = "fanotify-overflow"
	// GapFanotifyUnresolved means the opened file's path could not be read back, so no rule could be
	// applied and the open was allowed.
	GapFanotifyUnresolved = "fanotify-path-unresolved"
	// GapFanotifyMembership means the path verdict refused an open or exec and the opener's cgroup could not
	// be read, so the refusal was kept as if the opener were the run's (decideEvent, §6 E35). It goes out
	// beside the refusal event, whose pid the listener could not place.
	GapFanotifyMembership = "fanotify-membership-unread"
	// GapFanotifyCloseBacklog means loop() gave the group up because the closer held as many answered
	// events' descriptors as it may and did not close half of them within one decision deadline of the loop's
	// wait (fdCloser.catchUp, §6 E35): a close was waiting on its filesystem, or closes fell far behind opens
	// (fdCloserCap). Like GapFanotifyOverdue it is the ledger's record of why the run ended, emitted before
	// ErrListenerDied.
	GapFanotifyCloseBacklog = "fanotify-close-backlog"
	// GapFanotifyOverdue means loop() gave the group up because more decisions answered at the deadline
	// were still running than the thread budget allows (§6 E34). It is the ledger's record of why the run
	// ended, emitted before the listener returns ErrListenerDied.
	GapFanotifyOverdue = "fanotify-overdue-ceiling"
	// GapFanotifyMalformed means a read returned bytes that are not a whole fanotify record.
	GapFanotifyMalformed = "fanotify-malformed-record"
	// GapFanotifyResponse means a response could not be written; the kernel releases the opener anyway when
	// the group is closed, so this reports a lost decision, never a blocked process. A refusal whose FAN_DENY
	// it reports gets no refusal event: the close let that open through (handle).
	GapFanotifyResponse = "fanotify-response-failed"
	// GapFanotifyAbandoned means loop() failed while its workers still held count permission events. Each is
	// answered within E16's deadline after loop() returned, and a line recorded for it then (a refusal, or a
	// gap) can reach the run's queue after internal/runtime's final drain, where nothing writes it; this line
	// goes out before loop() returns, so before that drain, and counts them (§6 E35). It is an upper bound:
	// a worker that finishes before the drain has its line written as well.
	GapFanotifyAbandoned = "fanotify-listener-abandoned"
	// GapEventsChannelFull means the event sink could not take an event (§7).
	GapEventsChannelFull = "events-channel-full"
)

// Emitter is where this backend's events go: internal/runtime's bounded queue satisfies it. It is an
// interface rather than a channel so the backend never blocks on a slow consumer, and an interface declared
// here rather than imported so this package does not depend on internal/runtime (which would be a cycle).
type Emitter interface {
	// Emit takes an event without blocking; a full sink drops it and counts the drop.
	Emit(*record.Event)
}

// fanEvent is one decoded fanotify record. It is the struct the kernel writes, with nothing derived.
type fanEvent struct {
	Len  uint32
	Vers uint8
	Mask uint64
	FD   int32
	PID  int32 // FAN_REPORT_TID: the opening thread ID, despite the kernel field name
}

// isPermission reports whether the record demands a response. Every one that does gets exactly one (§8 I8).
func (e fanEvent) isPermission() bool { return e.Mask&fanPermMask != 0 }

// isExec reports whether the open is an execve's.
func (e fanEvent) isExec() bool { return e.Mask&unix.FAN_OPEN_EXEC_PERM != 0 }

// parseFanotifyEvents decodes a read(2) buffer into records. It returns everything it could decode plus an
// error describing the first byte it could not, so a caller still answers the permission events it did get:
// dropping the whole batch because its tail was odd would leave real processes blocked forever.
//
// The bytes come from the kernel, but they are parsed defensively anyway (§8 I11): a length that does not
// advance, a length past the buffer, or a version this code cannot respond to all stop the walk instead of
// indexing out of range.
func parseFanotifyEvents(buf []byte) ([]fanEvent, error) {
	var out []fanEvent
	for off := 0; off < len(buf); {
		if len(buf)-off < fanMetadataLen {
			return out, fmt.Errorf("cgroup: fanotify record at %d is %d bytes, need %d", off, len(buf)-off, fanMetadataLen)
		}
		rec := buf[off:]
		length := binary.NativeEndian.Uint32(rec[0:4])
		if length < fanMetadataLen {
			return out, fmt.Errorf("cgroup: fanotify record at %d declares %d bytes, minimum is %d", off, length, fanMetadataLen)
		}
		if int(length) > len(buf)-off {
			return out, fmt.Errorf("cgroup: fanotify record at %d declares %d bytes, %d remain", off, length, len(buf)-off)
		}
		ev := fanEvent{
			Len:  length,
			Vers: rec[4],
			Mask: binary.NativeEndian.Uint64(rec[8:16]),
			FD:   int32(binary.NativeEndian.Uint32(rec[16:20])),
			PID:  int32(binary.NativeEndian.Uint32(rec[20:24])),
		}
		if ev.Vers != fanMetadataVersion {
			return out, fmt.Errorf("cgroup: fanotify record at %d has ABI version %d, this build speaks %d",
				off, ev.Vers, fanMetadataVersion)
		}
		out = append(out, ev)
		off += int(length)
	}
	return out, nil
}

// fanotifyListener owns one fanotify group: its descriptor, its marks, and the goroutine that answers
// permission events. Nothing else writes to the descriptor, and Close is the only thing that closes it.
type fanotifyListener struct {
	fd       int
	policy   *policy
	run      Run
	out      Emitter
	deadline time.Duration
	now      func() time.Time

	// decide resolves one permission event to a verdict, markMount adds a mount mark for the events in mask,
	// unmarkMounts removes every mount mark the group holds at once, naming no path. They are fields so the
	// decision logic, the response protocol and the teardown ordering are all exercised without a fanotify
	// group, which needs CAP_SYS_ADMIN.
	decide       func(ev fanEvent) (verdict, error)
	markMount    func(mount string, mask uint64) error
	unmarkMounts func() error
	// disarm releases this process's arm (internal/platform/proc.Arm), taken before the group's first mark
	// and held until no mark of it can exist: while it is held the process starts nothing (ADR 0021 (3)). Nil
	// when no mark was ever asked for, or once released. Guarded by mu.
	disarm func()
	// settle answers, on the read loop itself, an event whose path alone allows it, and reports false for
	// any other, which goes to a worker and decide (readOnce). An event it answered leaves its descriptor to
	// the caller, which hands it to the closer. Nil sends every event to the workers, which is what a listener
	// built without newFanotifyListener gets.
	settle func(ev fanEvent) bool
	// closeSettled is what the closer closes an answered event's descriptor with, the loop's and the workers'
	// alike; nil is close(2). It is a field so a test can hold a close as a FUSE daemon or an NFS server that
	// stopped answering would (fdCloser).
	closeSettled func(fd int) error
	// write is how a response reaches the group; nil is write(2). It is a field so a test can have the
	// kernel refuse a response as it does for an opener that is gone (§6 E10).
	write func(fd int, p []byte) (int, error)
	// closeBacklogCap is the most descriptors the closer may hold before loop() waits for it and, when it does
	// not catch up, gives the group up; zero means closeBacklogFor the soft RLIMIT_NOFILE loop() starts under.
	// It is a field so a test reaches the cap with a few held closes rather than a thousand.
	closeBacklogCap int
	// pollTimeoutMS is loop()'s poll timeout; zero means fanPollTimeoutMS. It is a field so a test can make it
	// long enough that only the wake can end a cancelled loop's poll in time.
	pollTimeoutMS int
	// closerJoin is how long a cancelled loop() waits for its closer; zero means fanCloserJoinTimeout. It is a
	// field so a test holds a close past it in milliseconds rather than seconds.
	closerJoin time.Duration
	// closer is the loop's fdCloser, which every event descriptor it or its workers answered is closed through;
	// nil until loop() runs, and then handle() closes the descriptor itself. loop() sets it before it starts a
	// worker, and stops it only once every worker has returned, so nothing is handed to a stopped closer.
	closer *fdCloser
	// cgroupOfPID answers which cgroup an opener is in, from /proc/<pid>/cgroup. It is a field for the same
	// reason decide is, and because what a test needs to observe about it is how often decideEvent does *not*
	// call it (§6 E34).
	cgroupOfPID func(pid int) (string, error)
	// members answers the same question by cgroup id first (inRun, §6 E34); nil leaves it to cgroupOfPID
	// alone, which is what a listener built without newFanotifyListener gets.
	members *runMembers
	// overdueCeiling is the ceiling this listener runs with, sized by newFanotifyListener to the thread
	// budget it measured; zero means fanotifyOverdueCeiling. It is a field for the same reason decide is: a
	// test drives the count past a small ceiling instead of stalling a thousand decisions.
	overdueCeiling int64

	mu sync.Mutex
	// marks is each marked mount and the events its mark asks for, which is what its removal names.
	marks map[string]uint64

	// execLine, once the supervisor exists (Handle.SetSupervisorExecLines), says whether a refused open is an
	// exec's open of its image whose line the supervisor writes (supervisor.Loop.ExecLine): the exec's one line
	// (supervisor R7a), which this listener then leaves unwritten. Nil asks nothing.
	execLine atomic.Pointer[func(tid int, dev, ino uint64) bool]
	// fileID is the device and inode an event's descriptor holds (fstat); a field so a test needs no group.
	fileID func(fd int) (dev, ino uint64, ok bool)
	// threadGroup resolves an event's thread ID for ledger process attribution.
	threadGroup func(tid int) int

	// goneESRCH and goneENOENT record that a response refused with that errno, its opener gone, was logged
	// (logGone, §6 E10).
	goneESRCH, goneENOENT atomic.Bool

	// groupMu orders the close of the group's descriptor after every response write that began before it: a
	// response names its event by the descriptor number the group was given, and once the group is closed the
	// kernel can hand that number to any file this process opens next, which a late write would then write into.
	// On a fatal path loop() returns before its workers finish (loop), so Detach's Close can come while one is
	// still answering. Writes take it shared, Close exclusively; a write to a fanotify group waits on nothing,
	// so Close waits for at most the writes already under way.
	groupMu sync.RWMutex
	closed  atomic.Bool
	// answered, refused, timeouts and dropped count what the listener did. Only the tests read them (stats): the
	// ledger has each timeout as a GapFanotifyTimeout gap and each refusal as its own event.
	answered atomic.Int64
	refused  atomic.Int64
	timeouts atomic.Int64
	dropped  atomic.Int64
	// overdue counts the decisions handle() answered at the deadline whose decide call has not returned
	// yet. It is not a running total of timeouts: a decision leaves it when it returns, so only stalls that
	// are still holding a thread add up to the ceiling (loop, §6 E34).
	overdue atomic.Int64
	// withWorkers counts the permission events readOnce has handed the workers that they have not finished
	// handling, queued or in hand. A loop that fails counts them in a gap before it returns
	// (GapFanotifyAbandoned), since what they record afterwards can miss the run's final drain.
	withWorkers atomic.Int64
	// workersDone is closed once every worker loop() started has returned; nil until loop() runs. waitWorkers
	// waits on it. It is written and read under mu.
	workersDone chan struct{}
}

// threadRoots are the procfs and cgroupfs mounts newFanotifyListener measures the thread budget under (§6
// E34). fanotifyInit is fanotify_init(2). Both are variables so this package's tests can put a listener on a
// host of a chosen size without CAP_SYS_ADMIN, which is the only way to check that the constructor itself sizes
// its ceiling and refuses a host too small for one; production never replaces either. fanotifyMark is
// fanotify_mark(2), which the constructor's mark, unmark and ignore functions call, and a variable for the same
// reason: a test holds a call that names a path, as a filesystem that stopped answering would, and so checks
// what the listener's own calls wait on (unmarkMounts).
var (
	threadRoots  = struct{ proc, cgroup string }{proc: "/proc", cgroup: "/sys/fs/cgroup"}
	fanotifyInit = unix.FanotifyInit
	fanotifyMark = unix.FanotifyMark
)

// newFanotifyListener creates the group. FAN_CLASS_CONTENT is a class that permits permission events, which
// FAN_CLASS_NOTIF does not. FAN_CLASS_PRE_CONTENT would permit them too, and it alone may send a custom
// refusal errno, but the only one on its list a policy refusal could honestly carry is EPERM, which the bare
// FAN_DENY already yields (respond, §6 E2).
// FAN_UNLIMITED_QUEUE removes the 16384-event cap so a burst of opens cannot overflow into silence; and
// FAN_NONBLOCK keeps the loop responsive to context cancellation without a second descriptor.
//
// It needs CAP_SYS_ADMIN, which tier 2 requires anyway. A failure reports ErrFanotify before an actor
// starts; it does not silently remove the selected tier's permission listener.
//
// The overdue ceiling is sized here, before the group exists, to the thread budget this process has now
// (§6 E34); a budget too small for any ceiling is ErrFanotify too, so no group is created that could only
// be kept safe by a ceiling it cannot have.
func newFanotifyListener(p *policy, run Run, out Emitter, deadline time.Duration) (*fanotifyListener, error) {
	if deadline <= 0 {
		deadline = DefaultFanotifyDeadline
	}
	ceiling, err := overdueCeilingFor(threadBudget(threadRoots.proc, threadRoots.cgroup))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFanotify, err)
	}
	fd, err := fanotifyInit(
		unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT|unix.FAN_UNLIMITED_QUEUE|unix.FAN_NONBLOCK|unix.FAN_REPORT_TID,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("%w: fanotify_init: %w (%s)", ErrFanotify, err, fanotifyInitHint(err))
	}
	l := &fanotifyListener{
		fd: fd, policy: p, run: run, out: out, deadline: deadline, overdueCeiling: ceiling,
		now: time.Now, marks: map[string]uint64{},
	}
	l.decide = l.decideEvent
	l.settle = l.settleByPath
	l.cgroupOfPID = cgroupPathOfPID
	l.members = newRunMembers(run)
	l.markMount = func(mount string, mask uint64) error {
		return fanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, mount)
	}
	// FAN_MARK_FLUSH with FAN_MARK_MOUNT removes every mount mark the group holds, which are all the marks it has
	// (it places no inode mark, ADR 0021 (4)). The kernel takes it before it resolves a path (do_fanotify_mark),
	// so it names none and waits on no filesystem. FAN_MARK_REMOVE names each mount's root, and the kernel walks that path and
	// checks read permission on it first (fanotify_find_path): on an NFS mount whose server stopped answering,
	// or a FUSE mount with default_permissions whose daemon did, that check is a GETATTR that waits for as long
	// as the server does, and so could hold a failed listener's return, and with it the run's kill (§6 E35).
	l.unmarkMounts = func() error {
		return fanotifyMark(fd, unix.FAN_MARK_FLUSH|unix.FAN_MARK_MOUNT, 0, unix.AT_FDCWD, "")
	}
	return l, nil
}

// fanotifyInitHint and fanotifyMarkHint say what a failure to create the group or place a mark means where it
// is not the missing privilege. Each group and each mark is charged to the user that makes it, root for this
// listener, against a quota that every other fanotify user of root on the host draws on as well:
// fs.fanotify.max_user_groups (128 by default) refuses a group with EMFILE, and fs.fanotify.max_user_marks (at
// least 8,192, more with memory) refuses a mark with ENOSPC. A run holds one group and one mark per marked
// mount, so enough concurrent runs, with whatever else of root watches files, use
// them up. The run is then refused before it starts (§7), never run without its marks, and the error names
// the setting to raise.
func fanotifyInitHint(err error) string {
	if errors.Is(err, unix.EMFILE) {
		return "root's fs.fanotify.max_user_groups is used up by the groups already open on this host, " +
			"or this process has no descriptor left"
	}
	return "tier 2 needs CAP_SYS_ADMIN"
}

func fanotifyMarkHint(err error) string {
	if errors.Is(err, unix.ENOSPC) {
		return " (root's fs.fanotify.max_user_marks is used up by the marks already placed on this host)"
	}
	return ""
}

// markFor adds a mount-scoped mark for the permission events in mask, the ones this listener can refuse on
// that mount (policy.masks, §5 R8). Marking is per mount and idempotent: a mount that holds several rules is
// marked once, and a mount that holds none is never marked, so an unruled filesystem pays nothing. A second
// call for a marked mount adds only the events its mark lacks, as FAN_MARK_ADD does in the kernel.
//
// The first mark arms this process first (internal/platform/proc.Arm): from before the mark exists until
// unmarkAll or Close has removed every mark, the process starts no process (ADR 0021 (3)), so no vfork of this
// process can wait on an open this group holds. Arm waits for a start already in flight to finish its exec.
func (f *fanotifyListener) markFor(mountRoot string, mask uint64) error {
	mask &= fanPermMask
	if mountRoot == "" || mask == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	have := f.marks[mountRoot]
	if have&mask == mask {
		return nil
	}
	if f.closed.Load() {
		return fmt.Errorf("%w: mark %s: the group is closed", ErrFanotify, mountRoot)
	}
	if f.disarm == nil {
		f.disarm = proc.Arm()
	}
	if err := f.markMount(mountRoot, have|mask); err != nil {
		if len(f.marks) == 0 {
			f.releaseArmLocked() // the kernel placed nothing: no mark of this group exists
		}
		return fmt.Errorf("%w: mark %s: %w%s", ErrFanotify, mountRoot, err, fanotifyMarkHint(err))
	}
	f.marks[mountRoot] = have | mask
	return nil
}

// loop answers permission events until the context ends or the group fails. It returns nil on cancellation
// and an error on anything else; the caller treats a non-nil return as fatal to the run, because the kernel
// fails *open* when a permission listener disappears — the opposite of seccomp — and a run must not keep
// running in that window (§6 E15).
//
// A fatal error is returned at once. Its marks are down by then, removed by one call that names no path and so
// waits on no marked filesystem (unmarkAll), so nothing asks about the run's opens any more, and only the return
// lets RunListener's caller cancel the run and kill its cgroup. What is left (the workers answering what they
// already hold, the group's close after them, and the closer's queue) finishes on a goroutine of its own: a
// loop that waited for the closer held one close waiting on its filesystem and returned nothing while the run
// went on unmarked (§6 E35), and even the workers, bounded by E16, would hold the kill up to a deadline per
// event they hold. That goroutine and the closer can outlive the run and Detach, the closer for as long as a
// close it holds is held; what the workers still record then can reach the run's queue after its last drain,
// so the loop counts the events they hold in a gap before it returns (GapFanotifyAbandoned), and waitWorkers
// waits for them (§6 E35, §9).
//
// A cancelled loop joins its workers and closes the group before it returns, since its run is already
// ending, and waits for the closer up to closerJoin. Past that it leaves the closer to finish on its own, so a
// close its filesystem never answers holds neither run_end nor the teardown after it.
func (f *fanotifyListener) loop(ctx context.Context) error {
	// The marks come down before the answering stops, on every way out. A FAN_OPEN_PERM event with no
	// listener reading the group is not failed open: the kernel blocks the opener in fanotify_get_response
	// until a response arrives or the group is closed, and a mark on a mount holds every opener there, on the
	// whole host (§6 E34). A cancelled loop used to stop reading first and remove the marks in Close, after
	// the workers had finished: every open on a marked mount in between waited on a group nobody read, and was
	// then released by the close with an allow nobody decided, a refusal the contract asked for included.
	// Now the cancelled loop removes the marks, so no new event can enter the group, reads and decides what
	// the group already holds (drain), and only then returns; the workers answer every event read on a
	// descriptor that still exists (§8 I8), and the group is closed after them. Close is idempotent and guarded
	// by a CompareAndSwap, so the Detach that follows stays a no-op (§8 I10).
	//
	// Deciding happens off this goroutine (fanotifyWorkers) for every event its path alone does not allow:
	// reading and a decision that can wait on a membership read are separate so a slow decision delays nothing
	// but itself (§6 E35). What the path allows is answered here (settle), which reads no procfs file of
	// another process, and every answered event's descriptor, this goroutine's and the workers', is closed by
	// the closer (closing), since a close can wait on the file's filesystem. Closing the group before the
	// workers finish would turn each answer in flight into a response never written (groupMu): the kernel
	// releases those openers anyway, but as a fail-open with the decision thrown away, one
	// GapFanotifyResponse each, rather than the decision that was made.
	queue := make(chan fanEvent, fanotifyWorkers)
	closing := newFDCloser(f.closeSettled, f.closeBacklogLimit())
	f.closer = closing
	go closing.run()
	workersDone := make(chan struct{})
	f.mu.Lock()
	f.workersDone = workersDone
	f.mu.Unlock()
	var answering sync.WaitGroup
	for range fanotifyWorkers {
		answering.Add(1)
		go func() {
			defer answering.Done()
			for ev := range queue {
				f.handle(ev)
				f.withWorkers.Add(-1)
			}
		}()
	}
	cancelled := false
	defer func() {
		// The error paths come here with the marks still in place; the cancelled one has removed them.
		_ = f.unmarkAll()
		close(queue)
		// The group is closed once every worker has answered, and before the closer is waited for: every
		// descriptor the closer holds was answered before it was queued, so no response waits on it.
		if !cancelled {
			// Nothing is handed to a worker after the close above, so this counts every event whose line
			// can still come after the loop returned.
			if n := f.withWorkers.Load(); n > 0 {
				f.emitGap(GapFanotifyAbandoned, int(n), fmt.Errorf("%d permission events were with the "+
					"listener's workers when it failed; each is answered within the %s deadline, and a line "+
					"recorded for one after the run's final drain is not written (§6 E35)", n, f.deadline))
			}
			go func() {
				answering.Wait()
				close(workersDone)
				_ = f.Close()
				closing.stop()
			}()
			return
		}
		// A worker waits on nothing but its decision's deadline (handle), and the group's close on no
		// filesystem, so only the closer's wait is bounded here. With no mark left, a close still held when
		// that bound passes holds no opener, and the closer ends once it returns.
		answering.Wait()
		close(workersDone)
		_ = f.Close()
		closing.stopWithin(f.closerJoinTimeout())
	}()
	buf := make([]byte, fanReadBuffer)
	// The context's end wakes the poll through a pipe, so a cancelled loop notices it at once rather than when
	// the poll times out: the run's teardown waits for this loop, and a run whose last open came just before its
	// end waited out the whole fanPollTimeoutMS, about 100 ms of every short tier-2 run (kill test 4,
	// test/vm/README.md). The timeout stays as the bound should a wake be lost. The read end is closed only on
	// return, so the number the poll names is the pipe's for as long as it polls; a wake that runs after the
	// write end's close meets os.ErrClosed, never another file behind the number.
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("%w: wake pipe: %w", ErrListenerDied, err)
	}
	defer func() { _ = wakeR.Close() }()
	stopWake := context.AfterFunc(ctx, func() { _, _ = wakeW.Write([]byte{0}) })
	defer func() {
		stopWake()
		_ = wakeW.Close()
	}()
	pfd := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}, {Fd: int32(wakeR.Fd()), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			// A mark that cannot be removed here goes with the close below, which destroys every mark the
			// group holds; the drain still answers whatever it lets in meanwhile.
			_ = f.unmarkAll()
			f.drain(pfd[:1], buf, queue, closing)
			cancelled = true
			return nil
		}
		// Between reads, never mid-batch: every record already read still reaches a worker and gets its
		// decided answer (§8 I8), and the poll timeout below brings the loop back here at least every
		// fanPollTimeoutMS while nothing arrives. The gap goes out first, because the error alone reaches
		// the ledger nowhere: the run is cancelled and its cgroup killed, and without this line the ledger
		// would show a run of fanotify-timeout gaps and then an agent killed for no stated reason.
		if n, ceiling := f.overdue.Load(), f.ceiling(); n > ceiling {
			cause := f.overdueCause(n, ceiling)
			f.emitGap(GapFanotifyOverdue, int(n), cause)
			return fmt.Errorf("%w: %w", ErrListenerDied, cause)
		}
		// The closer's backlog is checked at the same place, so one read's descriptors and the workers' in
		// flight are all it can pass its cap by, and the cap sits far enough below the descriptor limit to
		// hold them (closeBacklogFor). At the cap the loop reads nothing more until the closer has caught up,
		// and gives the group up only when it has not within one decision deadline (catchUp): the backlog also
		// reaches the cap when the closer never ran, because this goroutine kept the processor it needed.
		if n := closing.backlog(); n >= closing.limit && !closing.catchUp(ctx, f.deadline) {
			n = closing.backlog()
			cause := fmt.Errorf("%d answered events' descriptors are waiting to be closed, the most a listener may "+
				"hold is %d, and the closer did not close half of them within %s: a close is waiting on its "+
				"filesystem, or closes fall far behind opens (§6 E35)", n, closing.limit, f.deadline)
			f.emitGap(GapFanotifyCloseBacklog, n, cause)
			return fmt.Errorf("%w: %w", ErrListenerDied, cause)
		}
		timeout := f.pollTimeoutMS
		if timeout == 0 {
			timeout = fanPollTimeoutMS
		}
		n, err := unix.Poll(pfd, timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("%w: poll: %w", ErrListenerDied, err)
		}
		if n == 0 || pfd[0].Revents == 0 {
			continue // a timeout, or the wake alone: the loop's top sees the cancelled context
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("%w: fanotify group reported revents %#x", ErrListenerDied, pfd[0].Revents)
		}
		switch err := f.readOnce(buf, queue, closing); {
		case err == nil, errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
		default:
			return fmt.Errorf("%w: read: %w", ErrListenerDied, err)
		}
	}
}

// readOnce reads one batch of records, answers each permission event its path allows and hands every other to
// the workers. EAGAIN means the group held nothing to read: it was opened FAN_NONBLOCK.
func (f *fanotifyListener) readOnce(buf []byte, queue chan<- fanEvent, closing *fdCloser) error {
	got, err := unix.Read(f.fd, buf)
	if err != nil {
		return err
	}
	events, perr := parseFanotifyEvents(buf[:got])
	for _, ev := range events {
		// A record that demands no response costs a hand-off to the closer at most; answering it here keeps
		// the workers for the events that actually have a process blocked behind them. The hand-off itself is
		// bounded: every worker returns within the deadline, since none closes a descriptor or reads through
		// one itself (handle leaves both to the closer and the decision's goroutine), so a full
		// queue waits one deadline at worst and never the unbounded wait §6 E35 describes.
		if !ev.isPermission() {
			f.handle(ev)
			continue
		}
		// So is an event its path alone allows, which is nearly every event on a marked mount (§6 E34): a
		// readlink of this process's own descriptor and a lookup in the in-memory policy whose cost does not
		// grow with its entries (pathSet), with no membership read, the stall E35 is about. Handing it to a
		// worker cost the opener two more goroutine hand-offs and a timer, about a third of the round trip.
		// Its descriptor goes to the closer, answered already, so that a close waiting on the file's
		// filesystem holds no later event (fdCloser).
		if f.settle != nil && f.settle(ev) {
			closing.add(int(ev.FD))
			continue
		}
		f.withWorkers.Add(1)
		queue <- ev
	}
	if perr != nil {
		// The records that did decode were answered above; the rest cannot be, because a record this code
		// cannot decode carries no descriptor to answer on.
		f.emitGap(GapFanotifyMalformed, 1, perr)
	}
	return nil
}

// drain reads until the group holds nothing, once its marks are gone, so every event that entered the group
// before then gets the decision the contract gives it rather than the allow a close would give it. It ends:
// with no mark left, nothing adds to the group except an opener that passed a mark in the instant it was
// removed, and whatever such an opener adds after the last read is released by the close that follows. Each
// read follows a poll that does not wait, so an empty group ends the drain whether or not reading it would
// block.
func (f *fanotifyListener) drain(pfd []unix.PollFd, buf []byte, queue chan<- fanEvent, closing *fdCloser) {
	for {
		n, err := unix.Poll(pfd, 0)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil, n == 0, pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0:
			return
		}
		if err := f.readOnce(buf, queue, closing); err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
	}
}

// handle answers exactly one event. Every path out of it either writes a response or establishes that the
// record needs none, which is invariant I8.
func (f *fanotifyListener) handle(ev fanEvent) {
	if ev.Mask&unix.FAN_Q_OVERFLOW != 0 {
		// An overflow record carries no descriptor and needs no response; it says notifications were lost.
		//
		// This group cannot currently produce one — it asks for FAN_UNLIMITED_QUEUE, and fanotify.c's
		// fanotify_handle_event deliberately queues no overflow record for a permission event ("the access
		// is denied and so no event is in fact lost"), which is every event in fanPermMask. The branch
		// stays because the mask is the only thing keeping it unreachable: adding one notification-class
		// event to fanPermMask makes overflow records real again, and I11 asks this reader to survive any
		// record the kernel hands it rather than fall through to the descriptor path with FAN_NOFD. The
		// case that *does* occur on this group is the opposite one and is invisible here (§6 E37).
		f.emitGap(GapFanotifyOverflow, 1, nil)
		return
	}
	if ev.FD < 0 {
		if ev.isPermission() {
			f.emitGap(GapFanotifyUnresolved, 1, fmt.Errorf("permission event with no descriptor (mask %#x)", ev.Mask))
		}
		return
	}
	if !ev.isPermission() {
		f.closeEvent(int(ev.FD))
		return
	}

	type result struct {
		v   verdict
		err error
		// supervisors: the refusal is an exec's whose line the supervisor writes (execLineOwner).
		supervisors bool
		pid         int // read while the opener is blocked, before the response lets its TID be reused
	}
	// The image's identity (execLineOwner) is read through ev.FD, and that read can wait on the file's
	// filesystem (an NFS server or a FUSE daemon that stopped answering), so it runs in the decision's
	// goroutine, under the deadline, and never on this worker: a worker waiting on it without bound would take
	// the pool one worker smaller for good, counted nowhere, and a pool of such workers stalls the read loop
	// and every opener on every marked mount (§6 E35). The descriptor must still be open when it is read, since
	// a number the deadline branch closed may already name another event's file, whose supervisor entry the
	// read would consume; so whichever side comes second closes it (fdHandoff): the deadline branch once the
	// read is done, or the goroutine once the deadline has answered, and that goroutine then decides nothing.
	var hand fdHandoff
	done := make(chan result, 1)
	go func() {
		owned := f.execLineOwner(ev)
		if !hand.read() {
			f.closeLate(int(ev.FD))
			done <- result{v: allowed}
			return
		}
		v, err := f.decide(ev)
		r := result{v: v, err: err, supervisors: !v.allow && owned != nil && owned()}
		if !v.allow && !r.supervisors {
			group := f.threadGroup
			if group == nil {
				group = threadGroupOf
			}
			r.pid = group(int(ev.PID))
		}
		done <- r
	}()

	timer := time.NewTimer(f.deadline)
	defer timer.Stop()

	select {
	case r := <-done:
		// Respond first, close second. A fanotify response is matched to its pending event by the
		// descriptor *number* (fanotify(7)'s example writes the response and only then closes
		// metadata->fd), and the kernel hands the lowest free number to the next event it delivers.
		// Closing first frees the number while the response naming it is still unwritten, so a response
		// can be addressed to a number another pending event has already been given — which the worker
		// pool in loop() makes an ordinary interleaving rather than a theoretical one. The deadline
		// branch below closes in the same order.
		switch {
		case errors.Is(r.err, errMembershipUnread):
			// The path verdict refused and the opener could not be placed: the refusal stands, as it would for
			// the run's own opener (decideEvent), and the gap says whose membership went unread and why. Both
			// are recorded only once the FAN_DENY is written, as below.
			written := f.respond(ev, r.v)
			f.closeEvent(int(ev.FD))
			if written {
				if !r.supervisors {
					f.emitRefusal(ev, r.v, r.pid)
				}
				f.emitGap(GapFanotifyMembership, 1, r.err)
			}
			return
		case errors.Is(r.err, errPathUnresolved) && !r.v.allow:
			// The path could not be read back, the policy has an entry that could refuse this event, and the
			// opener is the run's: refused path-unresolved (SEMANTICS §2, R8), never guessed into an allow. The
			// gap names the readlink's error, since the refusal line carries no path.
			written := f.respond(ev, r.v)
			f.closeEvent(int(ev.FD))
			if written {
				if !r.supervisors {
					f.emitRefusal(ev, r.v, r.pid)
				}
				f.emitGap(GapFanotifyUnresolved, 1, r.err)
			}
			return
		case r.err != nil:
			// A decision that failed with nothing to refuse (no entry of the policy could refuse this event) is
			// allowed and reported as a gap; an unresolved path the run opens under such an entry is the case above.
			f.respond(ev, allowed)
			f.closeEvent(int(ev.FD))
			f.emitGap(GapFanotifyUnresolved, 1, r.err)
			return
		}
		// A refusal is recorded only once its FAN_DENY is written. One that was not is let through by the
		// group's close, and respond has emitted GapFanotifyResponse for it instead of a refusal that did not
		// happen; that gap is written when the write failed while the run was live. A worker a fatal loop left
		// behind meets a closed group only once Detach has closed it (loop's own close waits for its workers),
		// and Detach runs after internal/runtime's final drain, so the gap it emits then is never written; the
		// event is counted instead in the GapFanotifyAbandoned line loop wrote before it returned (§6 E35).
		written := f.respond(ev, r.v)
		f.closeEvent(int(ev.FD))
		if !r.v.allow && written && !r.supervisors {
			f.emitRefusal(ev, r.v, r.pid)
		}
	case <-timer.C:
		// §6 E16: the opener is never left blocked. Allow at the deadline, then close the event descriptor,
		// in the order the branch above gives the reason for. The decision itself is left to finish, since a
		// read blocked in the kernel cannot be interrupted, but it has no use for the descriptor: decideEvent
		// reads through it only in its first readlink, before any
		// read that can block, and whatever it decides now is discarded, so a late read of a number already
		// reissued yields a verdict nobody reads. What the decision does keep (its goroutine, the waiter below, its own procfs descriptor and, while blocked,
		// an OS thread) stays counted in overdue until it returns, and loop() stops once too many are (§6 E34).
		f.timeouts.Add(1)
		f.overdue.Add(1)
		f.respond(ev, allowed)
		if hand.abandon() {
			f.closeEvent(int(ev.FD))
		}
		f.emitGap(GapFanotifyTimeout, 1, fmt.Errorf("decision for pid %d exceeded %s", ev.PID, f.deadline))
		go func() {
			<-done
			f.overdue.Add(-1)
		}()
	}
}

// fdHandoff settles who closes an event's descriptor when its decision outlives the deadline: the decision's
// goroutine reads through it first (execLineOwner), and the deadline branch may not close it before that read
// is done. Whichever of the two comes second closes it.
type fdHandoff struct {
	mu                sync.Mutex
	idRead, abandoned bool
}

// read marks the identity read done and reports whether the event is still the goroutine's to decide; false
// means the deadline has answered it and the goroutine closes the descriptor.
func (h *fdHandoff) read() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.idRead = true
	return !h.abandoned
}

// abandon marks the event answered at the deadline and reports whether the caller closes the descriptor now:
// true once the identity read is done, false when the goroutine still reads through it and closes it after.
func (h *fdHandoff) abandon() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.abandoned = true
	return h.idRead
}

// closeLate closes a descriptor on a decision's goroutine that the deadline already answered. It does not go
// through the closer, which may have been stopped by then and takes nothing after; the goroutine is counted in
// overdue until it returns, so a close that waits here is bounded by the ceiling as the read before it is.
func (f *fanotifyListener) closeLate(fd int) {
	if f.closeSettled != nil {
		_ = f.closeSettled(fd)
		return
	}
	_ = unix.Close(fd)
}

// ceiling is the overdue ceiling this listener runs with (overdueCeiling, or the cap when none was sized).
func (f *fanotifyListener) ceiling() int64 {
	if f.overdueCeiling > 0 {
		return f.overdueCeiling
	}
	return fanotifyOverdueCeiling
}

// overdueCause says why loop() gave the group up: n decisions answered at the deadline are still running
// against a ceiling they passed. loop() records it as a gap and returns it wrapped in ErrListenerDied. The
// ceiling ends the listener rather than refusing anything, so no verdict changes before it trips, and only
// decisions already past their deadline count, so a lookup that returns in time never counts. What it
// prevents is the abort at the launcher's nearest thread limit, which runs no teardown (§6 E34, §7).
func (f *fanotifyListener) overdueCause(n, ceiling int64) error {
	return fmt.Errorf("%d decisions answered at the %s deadline are still running, more than the %d a listener "+
		"may leave behind (§6 E34)", n, f.deadline, ceiling)
}

// decideEvent resolves the opened file's path, applies the policy, and only then asks which cgroup the opener
// is in. A file opened by a process outside this run's cgroup subtree is always allowed: the marks are
// mount-scoped, so the group sees every opener on the mount, and the run is the only thing this backend may
// decide for. An opener whose cgroup cannot be read, for any reason but its having exited, is not known to be
// outside, so the path's refusal is returned with errMembershipUnread and handle() keeps it (fail-closed).
//
// The order is what the whole host pays. A FAN_MARK_MOUNT mark covers the entire mount (fanotify_mark(2)),
// which on an ordinary single-root box is "/", so every open and every execve by every process on that
// filesystem that its mark asks about comes here, or to the same path verdict on the read loop (settleByPath,
// which answers the allows before a worker sees them) — and nearly all of them are neither in the run's cgroup
// nor on a ruled path (§6 E34). Reading /proc/<pid>/cgroup first made each of those pay an open, a read and a
// parse of procfs before being allowed, and put a procfs read that can block in D state in front of every
// open on the machine. The cgroup lookup can only ever turn a refusal into an allow, never the reverse, so an event the
// policy already allows has the same verdict with or without it: deciding on the path first leaves procfs to
// the events that could actually be refused.
//
// That takes procfs off the host's opens of paths no deny_read entry covers, which is nearly all of them, and
// not off anything else (§6 E34 states both halves). An open under a deny_read path that no longer write or
// watch entry reopens (decideOpen allows those first) pays the membership read whoever makes it, the user's
// own ssh reading ~/.ssh included. With an explicit exec policy, decideExec refuses any binary the contract
// did not name (§5 R8), so an execve of such a binary never
// reaches an early allow here, and every such execve pays the membership read, whichever process ran it; only
// execs of named binaries skip it. An absent exec section leaves exec unrestricted through the shared
// ListenerExec decision. Nothing cheaper can decide a restricted exec: membership is the only thing separating
// the host's execs from the run's, and it is knowable only from the kernel's view of the opener: its cgroup id
// through a pidfd where the kernel has PIDFD_GET_INFO (inRun, runMembers), /proc/<pid>/cgroup where it has
// not. Checking membership first for execs would spare an unnamed exec the readlink and the policy lookup but
// never the membership read, and would add that read to every exec of a named binary, the run's own included;
// opens outnumber execs by orders of magnitude besides. So one order serves both halves of the mask.
//
// Under an explicit exec policy, no exec inside the run is admitted that no entry names. The child stage's
// own execve of the launcher binary,
// the run's first exec, happens before the group has any mark (Arm, ADR 0021 (2)), so it is never an event
// here; every exec the group sees in the run is the agent's, tego's binary included.
func (f *fanotifyListener) decideEvent(ev fanEvent) (verdict, error) {
	v, pathErr := f.pathVerdict(ev)
	if pathErr != nil {
		if !errors.Is(pathErr, errPathUnresolved) || !f.policy.canRefuse(ev.isExec()) {
			return allowed, pathErr
		}
		// The path could not be read back (a canonical path longer than PATH_MAX gives ENAMETOOLONG), so no
		// entry can be matched, and an entry the policy has could refuse this event. A path that cannot be
		// resolved is refused (SEMANTICS §2), for the run's own opener only: the membership read below still
		// allows an opener outside the run, as it does any refusal (R8).
		v = verdict{rule: agent.UnmatchedRule, reason: record.ReasonPathUnresolved}
	}
	// An allow is final: the cgroup lookup below can only turn a refusal into an allow, so skip it.
	if v.allow {
		return allowed, nil
	}

	in, err := f.inRun(int(ev.PID))
	if err != nil {
		if errors.Is(err, ErrProcGone) {
			// The opener exited while the decision was in flight; nothing to refuse (§6 E10).
			return allowed, nil
		}
		// Anything else leaves the opener unplaced, and the path verdict stands: an allow here would be the
		// run's own refusal given away whenever a membership read fails, and the read that fails most is the one
		// a process out of descriptors makes (EMFILE, §6 E35). The cost falls on a host process only while
		// reads fail, and only on a path the contract refuses.
		return v, fmt.Errorf("%w: %w", errMembershipUnread, err)
	}
	if !in {
		return allowed, nil
	}
	return v, pathErr
}

// errPathUnresolved is pathVerdict's error for an event whose file's path could not be read back through its
// descriptor. decideEvent refuses such an event for the run's own opener wherever the policy could refuse it
// (policy.canRefuse), and allows it otherwise; either way handle() reports GapFanotifyUnresolved.
var errPathUnresolved = errors.New("cgroup: resolve fanotify descriptor")

// errMembershipUnread is decideEvent's error for an opener whose cgroup could not be read, returned beside the
// path's refusal, which handle() keeps rather than allows (GapFanotifyMembership).
var errMembershipUnread = errors.New("cgroup: the opener's cgroup could not be read, so the refusal stands")

// pathVerdict is the policy's verdict on the path alone: the opened file's path read back through the event's
// descriptor, which the kernel gives in canonical form, and decideExec or decideOpen on it. It reads no procfs
// file of another process, and no file at all: the readlink is of this process's own descriptor, which the
// kernel answers from the path of the file it holds, and the policy is in memory.
func (f *fanotifyListener) pathVerdict(ev fanEvent) (verdict, error) {
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(ev.FD)))
	if err != nil {
		return allowed, fmt.Errorf("%w: %w", errPathUnresolved, err)
	}
	if ev.isExec() {
		return f.policy.decideExec(path), nil
	}
	return f.policy.decideOpen(path), nil
}

// settleByPath answers, on the read loop, a permission event whose path alone allows it, and reports whether
// it did. That verdict is final whatever the opener's cgroup, since the membership read can only turn a
// refusal into an allow (decideEvent), so the event needs neither a worker nor E16's deadline. Anything else,
// a path the policy refuses or one that cannot be read back, is left to a worker and decideEvent, which reads
// it again and answers it under the deadline (§6 E16, E35).
//
// It does not close the event's descriptor: the caller does, once this has answered, in handle's order
// (respond first), and readOnce does it off the loop (fdCloser). The verdict costs the loop a readlink and a
// lookup whose cost grows with the path's length and not with the policy's entries (pathSet).
func (f *fanotifyListener) settleByPath(ev fanEvent) bool {
	if ev.FD < 0 || ev.Mask&unix.FAN_Q_OVERFLOW != 0 || f.policy == nil {
		return false
	}
	v, err := f.pathVerdict(ev)
	if err != nil || !v.allow {
		return false
	}
	f.respond(ev, allowed)
	return true
}

// fdCloser closes, on a goroutine of its own, the descriptor of every event the running loop answered, on the
// read loop itself (settleByPath) or on a worker (handle), so that no close holds either (§6 E35). Closing an
// event's descriptor runs its filesystem's flush and, as the last reference goes, its release, and on some
// filesystems those are a request to something outside the kernel that is waited on: FUSE sends FLUSH to its
// daemon unless the daemon declined it, and NFSv4 sends CLOSE to its server unless it holds a delegation. A
// daemon or server that answered the open the listener's read(2) made and then stopped answering, a network
// partition right after the open, held the loop in that close when the loop closed there, and with it every
// opener on every marked mount, until it answered; a worker held there was one fewer deciding. Here it holds
// the closes queued behind it and no opener; the response went out before the descriptor was queued, so a
// number the kernel reissues once it is closed names no response still to be written. The hand-off, a wake-up
// of this goroutine per answered event, costs the allowed round trip 1–2 µs in the 6.17 guest (§9).
//
// The backlog is capped (limit, closeBacklogFor): each entry is an open descriptor, and a backlog left to grow
// behind one held close reached the process's descriptor limit, where the membership reads of the refusals
// fail (EMFILE) and the group's reads fail with it. loop() checks it between reads; once it is full, loop()
// reads nothing more until this goroutine has closed half of it (catchUp), and gives the group up when that
// has not happened within one decision deadline, recording why (GapFanotifyCloseBacklog), so the run is ended
// (§6 E15) long before that limit. The held close and the closes behind it are then the closer's to finish
// after loop() has returned, as they are when a cancelled loop's bounded wait for them passes (closerJoin), for
// as long as that close is held.
//
// The wait is not for the close alone. loop() answers most events on its own goroutine (settleByPath) and
// blocks nowhere while events keep coming: its poll, read and response write are system calls that return at
// once and keep its processor, and the runtime runs the goroutine a wake-up readied on that processor only
// once the running one blocks, or after 10 ms of running, when it is preempted. Where no other processor is
// free, with a GOMAXPROCS of 1, or of 2 while another goroutine keeps the second busy (GOMAXPROCS is the
// machine's CPU count or a container's CPU limit), this goroutine was not run, and the backlog reached its cap
// with no close held: as root in a 2-vCPU guest, where BenchmarkFanotifyRoundTrip's own goroutine opens, its
// allowed opens ended the listener at the cap in every run. Blocking in catchUp hands the processor over.
type fdCloser struct {
	closeFD func(fd int) error
	// limit is the backlog at which loop() waits for this closer to catch up, and gives the group up when it
	// does not.
	limit int
	wake  chan struct{}
	done  chan struct{}
	// held counts the descriptors added and not yet closed: those pending and the batch run is closing.
	held    atomic.Int64
	mu      sync.Mutex
	pending []int
	stopped bool
	// target is the backlog catchUp waits for, and -1 while nothing waits; run signals caughtUp once held
	// has fallen to it.
	target   atomic.Int64
	caughtUp chan struct{}
}

// newFDCloser returns a closer that closes with closeFD, or with close(2) when that is nil, and for whose backlog
// loop() waits at limit.
func newFDCloser(closeFD func(fd int) error, limit int) *fdCloser {
	if closeFD == nil {
		closeFD = unix.Close
	}
	c := &fdCloser{closeFD: closeFD, limit: max(limit, 1), wake: make(chan struct{}, 1), done: make(chan struct{}),
		caughtUp: make(chan struct{}, 1)}
	c.target.Store(-1)
	return c
}

// closeBacklogFor is the closer's cap under a soft RLIMIT_NOFILE of soft: fdCloserCap, or a quarter of the
// limit where that is smaller. The rest is for everything else this process holds (the run's ledger and
// sources, the membership reads in flight, the descriptors of the events one read delivers), and the backlog
// passes its cap by no more than what loop() lets through between two checks.
func closeBacklogFor(soft uint64) int {
	return int(min(soft/4, fdCloserCap))
}

// closeBacklogLimit is the cap this listener's closer runs with: closeBacklogCap when a test set one, and
// otherwise closeBacklogFor the soft limit now. A limit that cannot be read gives the smallest cap a read
// batch fits in, the side on which the listener gives up sooner.
func (f *fanotifyListener) closeBacklogLimit() int {
	if f.closeBacklogCap > 0 {
		return f.closeBacklogCap
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return fanReadBatch
	}
	return closeBacklogFor(lim.Cur)
}

// closeEvent closes an answered event's descriptor: through the loop's closer, or here when no loop has run
// (a test driving handle alone).
func (f *fanotifyListener) closeEvent(fd int) {
	if c := f.closer; c != nil {
		c.add(fd)
		return
	}
	_ = unix.Close(fd)
}

// add queues fd to be closed, and never waits for a close.
func (c *fdCloser) add(fd int) {
	c.held.Add(1)
	c.mu.Lock()
	c.pending = append(c.pending, fd)
	c.mu.Unlock()
	c.signal()
}

// backlog is how many descriptors have been added and not yet closed.
func (c *fdCloser) backlog() int { return int(c.held.Load()) }

// signal wakes run; a wake-up already pending covers this one too, since run takes everything queued.
func (c *fdCloser) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// run closes what is queued until stop, and everything queued before it.
func (c *fdCloser) run() {
	defer close(c.done)
	var batch []int
	for {
		c.mu.Lock()
		batch, c.pending = c.pending, batch[:0]
		stopped := c.stopped
		c.mu.Unlock()
		for _, fd := range batch {
			_ = c.closeFD(fd)
			// held is lowered before target is read, and catchUp sets target before it reads held, so one of
			// the two sees the other and the wake-up is not lost.
			if c.held.Add(-1) <= c.target.Load() {
				select {
				case c.caughtUp <- struct{}{}:
				default:
				}
			}
		}
		switch {
		case len(batch) > 0:
		case stopped:
			return
		default:
			<-c.wake
		}
	}
}

// catchUp is loop()'s wait at the cap: it returns true once the closer holds at most half its limit, or false
// when d passes first. A ctx that ends also ends the wait, with true, and loop() then takes its cancelled path.
// d is the decision deadline of §6 E16: while loop() waits here it reads nothing, and every opener on a marked
// mount waits with it, so the wait is bounded as a decision is. A closer that only lacked a processor gets one
// from this goroutine blocking, and closes what it holds in about a millisecond; one held in a close, or whose
// filesystem answers closes far slower than its opens, does not close half of it in d, and loop() then gives
// the group up (fdCloser).
func (c *fdCloser) catchUp(ctx context.Context, d time.Duration) bool {
	target := int64(c.limit / 2)
	c.target.Store(target)
	defer c.target.Store(-1)
	if c.held.Load() <= target {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-c.caughtUp:
			// A signal left from an earlier wait says nothing about this one.
			if c.held.Load() <= target {
				return true
			}
		case <-t.C:
			return c.held.Load() <= target
		case <-ctx.Done():
			return true
		}
	}
}

// stop has run close what is queued and end, and returns once it has. Nothing may be added after it.
func (c *fdCloser) stop() {
	c.stopWithin(-1)
}

// stopWithin is stop waiting at most d, or with no bound when d is negative. A run that has not ended by then
// goes on closing what it holds, and ends once it has.
func (c *fdCloser) stopWithin(d time.Duration) {
	c.mu.Lock()
	c.stopped = true
	c.mu.Unlock()
	c.signal()
	if d < 0 {
		<-c.done
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.done:
	case <-t.C:
	}
}

// waitWorkers returns once every worker loop() started has returned, and so has answered every event it held
// and handed on what it recorded for each, or with ctx's error if ctx ends first. A listener whose loop never
// ran has no worker, and it returns nil at once.
func (f *fanotifyListener) waitWorkers(ctx context.Context) error {
	f.mu.Lock()
	done := f.workersDone
	f.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closerJoinTimeout is how long a cancelled loop() waits for its closer: closerJoin when a test set one, and
// otherwise fanCloserJoinTimeout.
func (f *fanotifyListener) closerJoinTimeout() time.Duration {
	if f.closerJoin > 0 {
		return f.closerJoin
	}
	return fanCloserJoinTimeout
}

// inRun answers whether an opener is in the run's cgroup subtree: by cgroup id where the kernel gives one
// (runMembers, PIDFD_GET_INFO), and from /proc/<pid>/cgroup wherever that has no answer, which is also what
// tells an opener that has exited apart (ErrProcGone).
func (f *fanotifyListener) inRun(pid int) (bool, error) {
	if in, ok := f.members.lookup(pid); ok {
		return in, nil
	}
	lookup := f.cgroupOfPID
	if lookup == nil {
		lookup = cgroupPathOfPID
	}
	cg, err := lookup(pid)
	if err != nil {
		return false, err
	}
	return inSubtree(f.run.CgroupPath, cg), nil
}

// respond writes the one response a permission event gets. A refusal is the bare FAN_DENY, which the refused
// open or execve reports as EPERM on every kernel; the ledger event, not the errno, carries the rule and the
// reason (§6 E2). A response to a process that has already exited is not an error (§6 E10).
//
// A refusal carries no FAN_DENY_ERRNO bits, and nothing probes for them, because no kernel would take them
// from this group. The bits arrived in Linux 6.14, and process_access_response (fs/notify/fanotify/
// fanotify_user.c) accepts a custom errno only from a FAN_CLASS_PRE_CONTENT group and only one of EIO,
// EPERM, EBUSY, ETXTBSY, EAGAIN, ENOSPC or EDQUOT; anything else is EINVAL. This group is FAN_CLASS_CONTENT,
// and the code a policy refusal would want — EACCES, what Landlock reports for the same kind of refusal — is
// on no kernel's list. Sending it bought only a write the kernel rejected ahead of the bare FAN_DENY that had
// to follow, and the one listed code a refusal could honestly carry is EPERM, which FAN_DENY already yields.
//
// It reports whether the response was written, or found its opener gone (§6 E10); a response that was not has
// its GapFanotifyResponse already.
func (f *fanotifyListener) respond(ev fanEvent, v verdict) bool {
	f.answered.Add(1)
	response := uint32(unix.FAN_ALLOW)
	if !v.allow {
		f.refused.Add(1)
		response = unix.FAN_DENY
	}
	if err := f.writeResponse(ev.FD, response); err != nil {
		f.emitGap(GapFanotifyResponse, 1, err)
		return false
	}
	return true
}

// writeResponse writes the eight-byte fanotify response. ESRCH and ENOENT mean the opener is already gone,
// which the kernel resolves on its own; they are swallowed, not fatal, and logged at debug the first time each
// is seen, since a pids cap killing a busy cgroup can produce one per event in flight (§6 E10). A group already closed gets no
// write (groupMu): the close released the opener, and its descriptor number may name another file by now.
func (f *fanotifyListener) writeResponse(fd int32, response uint32) error {
	var raw [8]byte
	binary.NativeEndian.PutUint32(raw[0:4], uint32(fd))
	binary.NativeEndian.PutUint32(raw[4:8], response)
	f.groupMu.RLock()
	defer f.groupMu.RUnlock()
	if f.closed.Load() {
		return fmt.Errorf("cgroup: fanotify response for descriptor %d: the group is closed", fd)
	}
	for {
		write := f.write
		if write == nil {
			write = unix.Write
		}
		_, err := write(f.fd, raw[:])
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ESRCH), errors.Is(err, unix.ENOENT):
			f.logGone(fd, err)
			return nil
		default:
			return fmt.Errorf("cgroup: fanotify response for descriptor %d: %w", fd, err)
		}
	}
}

// logGone logs a response refused because its opener is gone, once per errno for the listener's life.
func (f *fanotifyListener) logGone(fd int32, err error) {
	class := &f.goneESRCH
	if errors.Is(err, unix.ENOENT) {
		class = &f.goneENOENT
	}
	if f.run.Log == nil || !class.CompareAndSwap(false, true) {
		return
	}
	f.run.Log.Debug("cgroup: fanotify response for an opener that is gone; later ones with this errno are not logged",
		"run", f.run.ID, "fd", fd, "err", err)
}

// execLineOwner returns the question whether a refused open is an exec's open of its image that the supervisor
// recorded as this listener's refusal and wrote the exec's line for (supervisor R7a): the exec's one line, so
// this listener writes none. An execve's open of its image is reported as FAN_OPEN_EXEC_PERM and then, allowed,
// as FAN_OPEN_PERM, and it is the latter a deny_read refuses; the supervisor matches it by the opener's thread
// and the image's identity, and answers each exec once. Nil means the answer is no whatever the verdict.
//
// The image's identity is read now, before the decision and while the descriptor cannot yet have been closed
// (handle's fdHandoff holds the deadline branch's close until this returns), and the question asks it later
// without the descriptor. handle asks after the decision, which can outlive the deadline: by then the deadline
// branch has answered and closed the descriptor, and its number may name another event's file, whose
// supervisor entry a fstat through it would have consumed (the supervisor's answer is a one-shot take). The
// read runs on the decision's goroutine, not the worker, since it can wait on the file's filesystem.
func (f *fanotifyListener) execLineOwner(ev fanEvent) func() bool {
	fn := f.execLine.Load()
	if fn == nil || ev.isExec() || ev.FD < 0 {
		return nil
	}
	id := f.fileID
	if id == nil {
		id = fstatID
	}
	dev, ino, ok := id(int(ev.FD))
	if !ok {
		return nil
	}
	pid := int(ev.PID)
	return func() bool { return (*fn)(pid, dev, ino) }
}

// fstatID is the device and inode fd holds, encoded as fstat's st_dev is (the supervisor compares with that).
// It asks statx for the inode alone with AT_STATX_DONT_SYNC, so a network filesystem answers from what it has
// cached rather than asking its server (NFS skips both the GETATTR and the writeback flush it does for a size
// or a time, and FUSE sends no FUSE_GETATTR); neither field can change while the descriptor is held.
func fstatID(fd int) (dev, ino uint64, ok bool) {
	var stx unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_INO, &stx) != nil ||
		stx.Mask&unix.STATX_INO == 0 {
		return 0, 0, false
	}
	return unix.Mkdev(stx.Dev_major, stx.Dev_minor), stx.Ino, true
}

// emitRefusal records a refused open or exec. The event carries the kernel as its source and fanotify as the
// mechanism, the rule that refused it and the reason code. FAN_REPORT_TID identifies the opening thread;
// the process ID is resolved separately and stays zero when the thread has already exited.
func (f *fanotifyListener) emitRefusal(ev fanEvent, v verdict, pid int) {
	kind, op := record.KindFS, record.FSOpen
	if ev.isExec() {
		kind = record.KindExec
	}
	e := &record.Event{
		V: record.Version, TS: f.now(), Run: f.run.ID, Agent: f.run.Agent,
		PID: pid, TID: int(ev.PID), Cgroup: f.run.CgroupID,
		Kind: kind, Source: record.SourceFanotify, Rule: v.rule,
		Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: v.reason,
	}
	var payload any
	if kind == record.KindExec {
		payload = record.ExecPayload{Path: v.path}
	} else {
		payload = record.FSPayload{Op: op, Path: v.path}
	}
	if err := e.SetPayload(payload); err != nil {
		return
	}
	f.emit(e)
}

// emitGap records something the listener could not do. A gap is never fatal and never blocks.
func (f *fanotifyListener) emitGap(why string, count int, cause error) {
	detail := why
	if cause != nil {
		detail = why + ": " + cause.Error()
	}
	e := &record.Event{
		V: record.Version, TS: f.now(), Run: f.run.ID, Agent: f.run.Agent, Cgroup: f.run.CgroupID,
		Kind: record.KindGap, Source: record.SourceFanotify,
	}
	if err := e.SetPayload(record.GapPayload{What: record.GapEnforce, Why: detail, Count: count}); err != nil {
		return
	}
	f.emit(e)
}

// emit hands an event to the sink without blocking; a sink that cannot take it counts a drop, which becomes
// its own gap when the next one succeeds (§7).
func (f *fanotifyListener) emit(e *record.Event) {
	if f.out == nil {
		f.dropped.Add(1)
		return
	}
	f.out.Emit(e)
}

// unmarkAll removes every mount mark this listener placed, so no new event enters the group; the events it
// already holds stay to be read. It is one call that names no path (unmarkMounts), so it waits on no marked
// filesystem, and a loop that fails returns without waiting on one (§6 E35). It is idempotent: the marks are
// forgotten once their removal was asked for, since closing the group removes whatever a failed removal left.
func (f *fanotifyListener) unmarkAll() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.marks) == 0 {
		return nil
	}
	err := f.unmarkMounts()
	clear(f.marks)
	if err != nil {
		return fmt.Errorf("cgroup: remove the mount marks: %w", err)
	}
	// Every mark is gone (the group has no other kind), so this process may start processes again; after a
	// failed removal the arm is held until Close has closed the group.
	f.releaseArmLocked()
	return nil
}

// releaseArmLocked releases the process arm the first mark took (markFor), once. f.mu is held.
func (f *fanotifyListener) releaseArmLocked() {
	if f.disarm != nil {
		f.disarm()
		f.disarm = nil
	}
}

// Close removes every mark and closes the group, and the cgroup2 mount descriptor membership reads under. It is
// idempotent and safe after a partial setup (§8 I10).
func (f *fanotifyListener) Close() error {
	if f == nil || !f.closed.CompareAndSwap(false, true) {
		return nil
	}
	var errs []error
	if err := f.unmarkAll(); err != nil {
		errs = append(errs, err)
	}
	f.groupMu.Lock()
	err := unix.Close(f.fd)
	f.groupMu.Unlock()
	if err != nil {
		errs = append(errs, fmt.Errorf("cgroup: close fanotify group: %w", err))
	}
	// The group, and with it any mark a failed removal left, is gone: the process may start processes again.
	f.mu.Lock()
	f.releaseArmLocked()
	f.mu.Unlock()
	f.members.close()
	return errors.Join(errs...)
}
