// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
)

// ackByte is the single byte the parent writes on pipe B after NOTIF_RECV is armed (R6, R7).
const ackByte = 0x01

// Sentinel errors, one per failure class (docs/p0/runtime-launch.md §9); each wraps the underlying errno.
var (
	// ErrClone is a failed clone3(CLONE_PIDFD|CLONE_INTO_CGROUP): EAGAIN, ENOSPC, EPERM, EINVAL, ENOSYS.
	// EPERM and ENOSYS additionally carry cloneFailure's hint, which says whether an outer seccomp profile
	// or the kernel's own age is the cause (case 20).
	ErrClone = errors.New("launch: clone3 failed")
	// ErrChildDied is a child that exited before completing the handshake (EOF on pipe A, case 3).
	ErrChildDied = errors.New("launch: child died before the fd handoff")
	// ErrChildSetup is a child-stage step that failed with an errno (reported over pipe A, case 4).
	ErrChildSetup = errors.New("launch: child stage step failed")
	// ErrChildLandlock is ErrChildSetup's Landlock-specific class: landlock_restrict_self failed.
	ErrChildLandlock = errors.New("launch: child landlock_restrict_self failed")
	// ErrChildSeccomp is ErrChildSetup's seccomp-specific class: the NEW_LISTENER install failed.
	ErrChildSeccomp = errors.New("launch: child seccomp install failed")
	// ErrNotifyFDUnavailable is pidfd_getfd refusing the child's listener (non-dumpable child, case 5).
	ErrNotifyFDUnavailable = errors.New("launch: notify fd unavailable")
	// ErrChildNotReaped is a startup abort whose SIGKILLed child had still not exited when the reap's bound
	// ran out (R13): a task in uninterruptible sleep takes a pending SIGKILL only when the sleep ends. It is
	// joined to the error that caused the abort, never in place of it.
	ErrChildNotReaped = errors.New("launch: child not reaped after SIGKILL")
)

// Launcher starts child stages. The zero value execs /proc/self/exe with ChildCommand.
type Launcher struct {
	// Exe is the binary to exec for the child stage; "" means /proc/self/exe (never argv[0]: a live
	// launcher keeps its inode across a binary upgrade, ARCHITECTURE.md §6).
	Exe string
	// Args are the child stage's arguments; nil means [ChildCommand].
	Args []string

	subreaperOnce sync.Once
	subreaperErr  error
}

// SetSubreaper sets PR_SET_CHILD_SUBREAPER once for the process (step 5 of runtime.Run, R1 of ADR 0006):
// daemonized descendants of the agent are re-parented to the launcher, not init. Later calls return the
// first result.
func (l *Launcher) SetSubreaper() error {
	l.subreaperOnce.Do(func() { l.subreaperErr = sys.SetChildSubreaper(true) })
	return l.subreaperErr
}

// Child is one started child stage and, after the ack, the agent's main process.
type Child struct {
	// PID is the child's pid.
	PID int
	// PidFD is the child's pidfd from clone3(CLONE_PIDFD), owned by Child and closed by Close (ADR 0023). It is
	// set once, at the start, and never reassigned: Kill, Wait and Signal borrow it, so a Close meanwhile is
	// deferred until they are done and none of them reaches a number that was closed and reused.
	PidFD *sys.FD
	// ControlR is the read end of pipe A: the child's control message, then its execve verdict.
	ControlR *os.File
	// StartBootNS is the child's start time in CLOCK_BOOTTIME nanoseconds, read right after clone3 (proc.Start's
	// Identity), before anything can reap the child, so it names this process and no later holder of its pid.
	StartBootNS uint64

	controlW *os.File // write end of pipe B: the ack byte
	release  chan struct{}
	once     sync.Once

	// cgroup is the /proc cgroup line the child started in, which ReapOrphans matches adopted zombies to.
	cgroup string
	// keep is the pid KeepUnreaped named, which ReapOrphans never reaps; 0 for none.
	keep atomic.Int64

	mu     sync.Mutex
	reaped bool
	result WaitResult
}

// Start creates the child stage (docs/p0/runtime-launch.md §4 Start): clone3 through proc.Start, the one
// process start of non-test code, which refuses while this process holds fanotify marks (ADR 0021 (3)), with
// SysProcAttr{UseCgroupFD, CgroupFD, PidFD} so the child is in the run cgroup from its first instruction
// (invariant 3), two anonymous pipes (R6) and the ruleset fd inherited via ExtraFiles, then the framed spec
// on pipe B. On return the child is blocked on its ack read, never past execve (R5). cgroup lends the run
// cgroup's directory, borrowed across the clone alone (sys.CloneIntoCgroup, ADR 0023 T2.3): one that lends
// nothing (closed) is sys.ErrClosed before any clone, and nil starts the child in the caller's cgroup (tests,
// observe tier without a manager). Any failure after clone3 SIGKILLs and reaps the child before returning
// (R13). No fs or cgroup writes happen here.
func (l *Launcher) Start(ctx context.Context, spec ChildSpec, cgroup sys.Lender) (*Child, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := newHandshake(spec)
	if err != nil {
		return nil, err
	}
	defer h.closeAll()
	// A handle that owns a loop the host waits on (tier 2's fanotify listener) must not be stopped by the
	// terminal: HoldJobControl ignores the job-control stops for this process, before the clone so the
	// stage is created with the disposition it will reset for the agent (E40).
	var resets []int
	if _, ok := spec.Handle.(api.Listener); ok {
		resets = HoldJobControl()
	}

	hasRuleset := h.ruleset != nil // read now: closeChildEnds below drops the parent's copy
	hasDeputy := h.deputy != nil
	cmd := l.command(spec, h)
	var child *Child
	start := func() error {
		var err error
		child, err = startOnKeptThread(cmd)
		return err
	}
	if cgroup != nil {
		err = sys.CloneIntoCgroup(cgroup, cmd.SysProcAttr, start)
	} else {
		err = start()
	}
	if err != nil {
		return nil, err
	}
	child.ControlR, child.controlW = h.reportR, h.controlW
	h.reportR, h.controlW = nil, nil // now owned by child
	// R6 ("a dead peer yields EOF, never a hang"): the parent's copies of the child-side ends go the moment
	// clone3 has duplicated them into the child, before a single byte is written. Keeping pipe B's read end
	// open here would hold the pipe readable against ourselves, so a spec larger than the pipe buffer
	// (64 KiB; a spec runs to maxSpecBytes, cases 18/27) could never raise EPIPE against a dead child and
	// the write would block with no reader, no EOF and no way back.
	h.closeChildEnds()

	if cgroup != nil {
		child.cgroup = procCgroup(child.PID)
	}
	w := spec.toWire(os.Getpid(), hasRuleset, hasDeputy)
	w.ResetSignals = resets
	if err := sendSpec(ctx, child, w); err != nil {
		return nil, child.abort(err)
	}
	return child, nil
}

// sendSpec writes the framed spec on pipe B. EPIPE is the dead child (R6, case 3). ctx bounds the write
// through a deadline the way readControl bounds its read: a child that is stopped rather than dead still
// holds the pipe's read end, so EPIPE alone cannot release a write that filled the pipe buffer.
func sendSpec(ctx context.Context, child *Child, w wireSpec) error {
	f := child.controlW
	stop := cutOnDone(ctx, func() { _ = f.SetWriteDeadline(time.Unix(1, 0)) })
	err := writeSpec(f, w)
	stop()
	switch {
	case err == nil:
		// ctx can fire between the finished write and stop(); clear the deadline so the later Ack write on
		// this same descriptor is not refused by a leftover one. stop has returned only once the callback
		// that sets it is done, so nothing sets it again after this.
		_ = f.SetWriteDeadline(time.Time{})
		return nil
	case ctx.Err() != nil && errors.Is(err, os.ErrDeadlineExceeded):
		return ctx.Err()
	case errors.Is(err, syscall.EPIPE):
		return fmt.Errorf("%w: %w", ErrChildDied, err)
	default:
		return err
	}
}

// handshake holds the pipe ends and the duplicated ruleset fd until Start hands them over or closes them.
type handshake struct {
	controlR, controlW *os.File // pipe B: parent writes, child reads
	reportR, reportW   *os.File // pipe A: child writes, parent reads
	ruleset            *os.File // O_CLOEXEC dup of the Handle's ruleset fd, or nil
	deputy             *os.File // O_CLOEXEC dup of the spec's deputy control end, or nil
}

func newHandshake(spec ChildSpec) (*handshake, error) {
	h := &handshake{}
	var err error
	if h.controlR, h.controlW, err = os.Pipe(); err != nil {
		return nil, fmt.Errorf("pipe(control): %w", err)
	}
	if h.reportR, h.reportW, err = os.Pipe(); err != nil {
		h.closeAll()
		return nil, fmt.Errorf("pipe(report): %w", err)
	}
	if fd, ok := spec.Handle.LandlockRuleset(); ok {
		// Dup so the *os.File wrapper owns its own descriptor and the Handle's fd is never closed here.
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			h.closeAll()
			return nil, fmt.Errorf("dup ruleset fd %d: %w", fd, err)
		}
		h.ruleset = os.NewFile(uintptr(dup), "landlock-ruleset")
	}
	if spec.Deputy != nil {
		dup, err := sys.DupFile(spec.Deputy, 0)
		if err == nil {
			h.deputy, err = dup.Release("deputy-control")
		}
		if err != nil {
			_ = dup.Close()
			h.closeAll()
			return nil, fmt.Errorf("dup deputy socket: %w", err)
		}
	}
	return h, nil
}

func (h *handshake) extraFiles() []*os.File {
	files := []*os.File{h.controlR, h.reportW}
	if h.ruleset != nil {
		files = append(files, h.ruleset)
	}
	if h.deputy != nil {
		files = append(files, h.deputy) // wireSpec.DeputyFD: the next number after the ruleset's, or in its place
	}
	return files
}

// closeChildEnds closes what only the child needs; after cmd.Start the child holds its own dups. Start calls
// it as soon as the child exists (R6), so it clears each field and stays safe under the deferred closeAll.
func (h *handshake) closeChildEnds() { closeAndClear(&h.controlR, &h.reportW, &h.ruleset, &h.deputy) }

// closeParentEnds closes the ends Start keeps, for the paths where ownership never reached the Child.
func (h *handshake) closeParentEnds() { closeAndClear(&h.controlW, &h.reportR) }

func (h *handshake) closeAll() {
	h.closeChildEnds()
	h.closeParentEnds()
}

func closeAndClear(files ...**os.File) {
	for _, f := range files {
		if *f != nil {
			_ = (*f).Close()
			*f = nil
		}
	}
}

func (l *Launcher) command(spec ChildSpec, h *handshake) *proc.Cmd {
	exe := l.Exe
	if exe == "" {
		exe = "/proc/self/exe"
	}
	args := l.Args
	if args == nil {
		args = []string{ChildCommand}
	}
	cmd := proc.Command(exe, args...)
	// Keep absent streams as nil interfaces so os/exec supplies /dev/null. A nil *os.File inside
	// an interface bypasses that default and closes the child's corresponding descriptor instead.
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	if spec.Stdout != nil {
		cmd.Stdout = spec.Stdout
	}
	if spec.Stderr != nil {
		cmd.Stderr = spec.Stderr
	}
	cmd.Env = []string{} // the stage needs nothing from the launcher's environment; the agent gets spec.Env
	cmd.ExtraFiles = h.extraFiles()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL, // covers the window before the stage re-arms it after its cred changes
	} // Start's sys.CloneIntoCgroup sets UseCgroupFD and CgroupFD for the clone alone
	return cmd
}

// startOnKeptThread runs proc.Start on a goroutine locked to an OS thread that stays alive until the
// Child is closed: PR_SET_PDEATHSIG fires when the *thread* that forked exits, so the forking thread must
// not be retired by the runtime while the agent runs. A start refused because this process is armed
// (proc.ErrArmed) is ErrClone's: no child exists.
func startOnKeptThread(cmd *proc.Cmd) (*Child, error) {
	release := make(chan struct{})
	type started struct {
		pidfd *sys.FD
		id    proc.Identity
		err   error
	}
	done := make(chan started, 1)
	go func() {
		runtime.LockOSThread()
		var id proc.Identity
		// sys.StartWithPidfd owns the pidfd clone3 stores, and closes it when proc.Start undid a start whose
		// identity it could not read.
		pidfd, err := sys.StartWithPidfd(cmd.SysProcAttr, func() error {
			var err error
			id, err = proc.Start(cmd)
			return err
		})
		done <- started{pidfd, id, err}
		if err != nil && !errors.Is(err, sys.ErrNoPidfd) {
			return // no child: the locked thread retires with this goroutine
		}
		<-release
	}()
	s := <-done
	switch {
	case errors.Is(s.err, sys.ErrNoPidfd):
		// Go asked clone3 for CLONE_PIDFD and got none: the kernel is below the 5.4 floor (case 20).
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		close(release)
		return nil, fmt.Errorf("%w: %w", ErrClone, s.err)
	case s.err != nil:
		if errors.Is(s.err, proc.ErrArmed) || errors.Is(s.err, proc.ErrIdentity) {
			return nil, fmt.Errorf("%w: %w", ErrClone, s.err)
		}
		return nil, cloneFailure(s.err, cmd.SysProcAttr.UseCgroupFD)
	}
	// os/exec keeps a dup of the pidfd for cmd.Process, closed only by its Wait, Release or a GC cleanup.
	// The Child reaps through its own pidfd, so cmd.Process is never used again: Release (no wait, no
	// signal) closes the dup now instead of leaving one fd per run open until the next GC.
	_ = cmd.Process.Release()
	return &Child{PID: s.id.PID, PidFD: s.pidfd, StartBootNS: s.id.StartBootNS, release: release}, nil
}

// seccompModeUnknown is "this process's seccomp mode could not be read": /proc/self/status was unreadable,
// or the kernel was built without CONFIG_SECCOMP, which omits the Seccomp line entirely (proc(5)).
const seccompModeUnknown = -1

// cloneFailure classes a failed clone3 as ErrClone and, for the two errnos an *outer* sandbox produces,
// names that sandbox rather than leaving the operator with a bare "operation not permitted".
//
// Case 20 used to frame EINVAL/ENOSYS as kernel age alone, but the failure that actually happens in the
// field is moby#42680 (berrange, 2021-07-27): a container runtime's default seccomp profile answered an
// unlisted clone3 with EPERM, which glibc 2.34+ treats as fatal instead of falling back to clone(2);
// runtimes then switched their default to ENOSYS. A systemd unit with SystemCallFilter= does the same,
// returning SystemCallErrorNumber= (EPERM by the documented convention, systemd.exec(5)). In both cases the
// kernel is modern, doctor's uname check passed, and a kernel-version message sends the operator to the
// wrong place.
//
// The discriminator is this process's own seccomp mode: an inherited profile shows as Seccomp: 2 in
// /proc/self/status. Measured on 6.17 with a hand-built filter: SECCOMP_RET_ERRNO(EPERM) on __NR_clone3
// reproduces EPERM with Seccomp: 2, ERRNO(ENOSYS) reproduces ENOSYS with Seccomp: 2, and an unprivileged
// clone3(CLONE_INTO_CGROUP) into a cgroup this task may not write fails EACCES -- so an EPERM here is never
// a cgroup-delegation refusal, which is what makes the "a filter said no" reading safe.
func cloneFailure(err error, intoCgroup bool) error {
	if hint := cloneHint(err, seccompMode(), intoCgroup); hint != "" {
		return fmt.Errorf("%w: %w (%s)", ErrClone, err, hint)
	}
	return fmt.Errorf("%w: %w", ErrClone, err)
}

// cloneHint is cloneFailure's explanation, split out from the /proc read so the errno/mode matrix is
// testable on a box whose clone3 works. "" means the errno says nothing about a filter (EAGAIN, ENOSPC,
// EINVAL, ENOENT ...) and the raw errno is the whole truth.
//
// intoCgroup is whether Start was given a cgroup, and it decides which syscall was actually made: os/exec reaches for
// clone3 only when UseCgroupFD is set (or CLONE_NEWTIME, which this package never uses) -- CLONE_PIDFD
// alone travels on legacy clone(2), which carries it in the ptid argument (syscall.forkAndExecInChild1).
// Naming clone3 on the path without a cgroup would send the operator after a profile that never ran.
func cloneHint(err error, mode int, intoCgroup bool) string {
	refused := errors.Is(err, syscall.EPERM)
	if !refused && !errors.Is(err, syscall.ENOSYS) {
		return ""
	}
	call := "clone(2)"
	if intoCgroup {
		call = "clone3"
	}
	switch {
	case mode > 0:
		return fmt.Sprintf("%s is being filtered, not missing: this process already runs under a seccomp "+
			"filter (/proc/self/status Seccomp: %d) -- a container runtime's default profile (moby#42680) or "+
			"SystemCallFilter= on the enclosing systemd unit; the kernel version is not the cause", call, mode)
	case mode == 0 && !refused && intoCgroup:
		return "no seccomp filter on this process (/proc/self/status Seccomp: 0), so the kernel itself has no " +
			"clone3 (5.3) or no CLONE_INTO_CGROUP (5.7)"
	case mode == 0 && !refused:
		return "no seccomp filter on this process (/proc/self/status Seccomp: 0), and with no cgroup fd the " +
			"syscall was clone(2), which every kernel above the floor has: kernel age does not explain this"
	case mode == 0:
		return fmt.Sprintf("no seccomp filter on this process (/proc/self/status Seccomp: 0), so %s was not "+
			"filtered; a cgroup delegation refusal would be EACCES, so look for an LSM denial instead", call)
	default:
		return fmt.Sprintf("%s was either filtered by an outer seccomp profile (moby#42680, or "+
			"SystemCallFilter=) or is absent from the kernel (clone3 5.3, CLONE_INTO_CGROUP 5.7); "+
			"/proc/self/status could not be read to tell the two apart", call)
	}
}

// seccompMode reports this process's seccomp mode: 0 disabled, 1 strict, 2 filter (proc(5), since 3.8), or
// seccompModeUnknown. Read from proc rather than prctl(PR_GET_SECCOMP), which sends SIGKILL when the caller
// is already in strict mode (PR_GET_SECCOMP(2const)) -- a diagnostic must never kill the launcher.
func seccompMode() int {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return seccompModeUnknown
	}
	return parseSeccompMode(string(b))
}

func parseSeccompMode(status string) int {
	for _, line := range strings.Split(status, "\n") {
		// The prefix carries the colon so the adjacent "Seccomp_filters:" line (5.9+, a count, not a mode)
		// can never be read as the mode.
		v, ok := strings.CutPrefix(line, "Seccomp:")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return seccompModeUnknown
		}
		return n
	}
	return seccompModeUnknown
}

// abortReapTimeout bounds abort's reap. It is runtime.killTimeout's value, the bound every other reap of
// the agent already has: SIGKILL is only delivered when a task leaves uninterruptible sleep, so an
// unbounded wait would turn a child stuck in D state into a launcher that never reports its startup
// failure. A variable so a test can shorten it.
var abortReapTimeout = 10 * time.Second

// abortKill is how abort ends the child; Kill outside tests. A test replaces it to stand in for a child
// that does not die on SIGKILL, which no unprivileged test can produce for real.
var abortKill = (*Child).Kill

// abort: SIGKILL, a reap bounded by abortReapTimeout, close, and return err annotated with the
// abort. A child still alive at the bound is reported as ErrChildNotReaped alongside err; its pidfd is
// closed regardless, since nothing this process does can make the kernel deliver the signal sooner. An
// ErrChildDied err also carries the reaped child's exit status or signal (case 3).
func (c *Child) abort(err error) error {
	ctx, cancel := context.WithTimeout(context.Background(), abortReapTimeout)
	defer cancel()
	switch kerr := abortKill(c, ctx); {
	case kerr == nil || errors.Is(kerr, syscall.ESRCH):
		if errors.Is(err, ErrChildDied) {
			err = c.withExitStatus(err)
		}
	case errors.Is(kerr, context.DeadlineExceeded):
		err = fmt.Errorf("%w (abort: %w: pid %d still running %s after SIGKILL)", err, ErrChildNotReaped,
			c.PID, abortReapTimeout)
	default:
		err = fmt.Errorf("%w (abort: %v)", err, kerr)
	}
	_ = c.Close()
	return err
}

// withExitStatus appends the reaped child's wait status to err. A stage that died before the handoff by a
// signal (an outer seccomp profile's SIGSYS, the OOM killer) prints nothing, so its status is the only record
// of the cause. An unreaped child adds nothing.
func (c *Child) withExitStatus(err error) error {
	c.mu.Lock()
	reaped, ws := c.reaped, c.result.Status
	c.mu.Unlock()
	switch {
	case !reaped:
		return err
	case ws.Signaled():
		return fmt.Errorf("%w (child killed by signal %d (%v))", err, int(ws.Signal()), ws.Signal())
	case ws.Exited():
		return fmt.Errorf("%w (child exit status %d)", err, ws.ExitStatus())
	default:
		return fmt.Errorf("%w (child wait status %#x)", err, uint32(ws))
	}
}

// WaitNotifyFD reads the child's control message from pipe A (bounded by ctx through a read deadline) and,
// for a listener, pidfd_getfd's it into this process (step 7 of runtime.Run) as a strict owner (ADR 0023 T1.4),
// which the caller moves into supervisor.New. It returns nil, nil when the tier installs no filter. Child
// keeps no copy: the listener is the caller's from the return on. Errors: io.EOF → ErrChildDied; a negative
// message → ErrChildLandlock,
// ErrChildSeccomp or ErrChildSetup naming the step and errno; EPERM from pidfd_getfd →
// ErrNotifyFDUnavailable; a child that died before pidfd_getfd → ErrChildDied. On any error the child is killed and reaped (R13).
func (c *Child) WaitNotifyFD(ctx context.Context) (*sys.FD, error) {
	msg, err := c.readControl(ctx)
	if err != nil {
		return nil, c.abort(err)
	}
	switch msg.Kind {
	case MessageNoListener:
		return nil, nil
	case MessageError:
		return nil, c.abort(stepFailure(msg))
	}
	var listener *sys.FD
	err = c.PidFD.Borrow(func(pidfd int) error {
		var err error
		listener, err = sys.Strict(sys.PidfdGetfdFD(pidfd, msg.FD))
		return err
	})
	if err != nil {
		return nil, c.abort(c.getfdFailure(err))
	}
	return listener, nil
}

// getfdFailure classes a pidfd_getfd error. EPERM is ErrNotifyFDUnavailable (case 5). A stage that died
// after writing its message and before the call (an OOM kill, a runtime crash under a low pids.max) is
// ErrChildDied like every other death before the handoff, so abort names its wait status: the kernel
// answers ESRCH once it is gone and EBADF while it is an unreaped zombie with no files table left. EBADF
// from a child that is still running is a bad fd number, not a death, and stays unclassed.
func (c *Child) getfdFailure(err error) error {
	switch {
	case errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w: %w", ErrNotifyFDUnavailable, err)
	case errors.Is(err, syscall.ESRCH), errors.Is(err, syscall.EBADF) && c.exited():
		return fmt.Errorf("%w: %w", ErrChildDied, err)
	}
	return err
}

// exited reports whether the child's pidfd says it has exited (readable), without waiting.
func (c *Child) exited() bool {
	var exited bool
	err := c.PidFD.Borrow(func(pidfd int) error {
		var err error
		exited, err = sys.PollPidfd(pidfd, 0)
		return err
	})
	return err == nil && exited
}

func stepFailure(m Message) error {
	class := ErrChildSetup
	switch m.Step {
	case StepLandlock:
		class = ErrChildLandlock
	case StepSeccomp:
		class = ErrChildSeccomp
	}
	return fmt.Errorf("%w: %s: %w", class, m.Step, m.Errno)
}

// cutOnDone runs cut once ctx ends, as context.AfterFunc does, and returns the stop to call when the
// bounded read or write is over. Unlike AfterFunc's own, this stop does not return while cut is running:
// once ctx has ended, AfterFunc has started cut on a goroutine of its own and its stop reports false and
// returns at once, so cut could still set its deadline after the caller had cleared it, on a later read
// or write of the same pipe (Ack's, execVerdict's), or while Close releases the file and clears the field.
// A started cut is waited for.
func cutOnDone(ctx context.Context, cut func()) (stop func()) {
	done := make(chan struct{})
	stopFunc := context.AfterFunc(ctx, func() {
		defer close(done)
		cut()
	})
	return func() {
		if !stopFunc() {
			<-done
		}
	}
}

// readControl reads one 4-byte control message with ctx bounding the blocking read via a deadline.
func (c *Child) readControl(ctx context.Context) (Message, error) {
	f := c.ControlR
	stop := cutOnDone(ctx, func() { _ = f.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	var b [controlSize]byte
	_, err := io.ReadFull(f, b[:])
	switch {
	case err == nil:
		return decodeControl(b[:])
	case ctx.Err() != nil && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)):
		return Message{}, ctx.Err()
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return Message{}, fmt.Errorf("%w: %w", ErrChildDied, err)
	default:
		return Message{}, fmt.Errorf("read control pipe: %w", err)
	}
}

// Ack writes the ack byte on pipe B and closes it (step 10): the child's blocked read returns and it
// execve's. The caller must have the supervisor's NOTIF_RECV in flight first (R7). EPIPE means the child
// already died: ErrChildDied.
func (c *Child) Ack() error {
	if c.controlW == nil {
		return errors.New("launch: Ack called twice")
	}
	_, err := c.controlW.Write([]byte{ackByte})
	cerr := c.controlW.Close()
	c.controlW = nil
	if err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return fmt.Errorf("%w: %w", ErrChildDied, err)
		}
		return fmt.Errorf("write ack: %w", err)
	}
	if cerr != nil {
		return fmt.Errorf("close control pipe: %w", cerr)
	}
	return nil
}

// Signal delivers sig through the pidfd (pidfd_send_signal), so a reused pid is never targeted.
func (c *Child) Signal(sig syscall.Signal) error {
	return c.PidFD.Borrow(func(pidfd int) error { return sys.PidfdSendSignal(pidfd, sig) })
}

// TakeStop reports a job-control stop of the agent's main process that it has not reported before, by the signal
// that stopped it (SIGTSTP, SIGTTIN, SIGTTOU or SIGSTOP), or 0 when there is none. It never reaps, so it does not
// race Wait, and it is not under c.mu, which a Wait holds while it polls. A stop that is over by the time it is
// taken (the process already continued, as the shell's SIGCONT to a whole job that Ctrl-Z stopped does) is 0. An
// agent that has exited is an error (ECHILD), as is a closed pidfd.
func (c *Child) TakeStop() (syscall.Signal, error) {
	var sig syscall.Signal
	err := c.PidFD.Borrow(func(pidfd int) error {
		var err error
		sig, err = sys.WaitPidfdStopped(pidfd)
		return err
	})
	if err == nil && sig != 0 && procStatState(c.PID) != 'T' {
		sig = 0
	}
	return sig, err
}

// Kill sends SIGKILL and reaps (R13). ESRCH from the signal means the child already exited; it is still
// reaped. Safe after Wait and after Close: a child that is already reaped, or whose pidfd is closed (abort
// kills, reaps and closes), has nothing left to signal, so that is a no-op and not EBADF.
func (c *Child) Kill(ctx context.Context) error {
	// Not under c.mu: a Wait in another goroutine holds it while it polls, and Kill is what ends that wait.
	switch err := c.Signal(syscall.SIGKILL); {
	case errors.Is(err, sys.ErrClosed):
		return nil // closed (abort kills, reaps and closes): nothing left to signal
	case err != nil && !errors.Is(err, syscall.ESRCH):
		return err
	}
	_, err := c.Wait(ctx)
	return err
}

// Wait blocks until the child exits (pidfd readable, polled in 100ms slices so ctx can cancel) and reaps it
// with waitid(P_PIDFD). It then reads pipe A once more: EOF means execve succeeded (the CLOEXEC end closed),
// a StepExec message carries the execve errno (case 8). The result is cached; later calls return it.
func (c *Child) Wait(ctx context.Context) (WaitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reaped {
		return c.result, nil
	}
	const slice = 100
	for {
		var exited bool
		err := c.PidFD.Borrow(func(pidfd int) error {
			var err error
			exited, err = sys.PollPidfd(pidfd, slice)
			return err
		})
		if err != nil {
			return WaitResult{}, err
		}
		if exited {
			break
		}
		if err := ctx.Err(); err != nil {
			return WaitResult{}, err
		}
	}
	var ws syscall.WaitStatus
	err := c.PidFD.Borrow(func(pidfd int) error {
		var err error
		ws, _, err = sys.WaitPidfd(pidfd, false)
		return err
	})
	if err != nil {
		return WaitResult{}, err
	}
	c.reaped = true
	c.result = WaitResult{Status: ws, ExecErr: c.execVerdict()}
	return c.result, nil
}

// execVerdict drains pipe A after exit: the writer is gone, so the read returns data or EOF immediately.
func (c *Child) execVerdict() syscall.Errno {
	if c.ControlR == nil {
		return 0
	}
	_ = c.ControlR.SetReadDeadline(time.Now().Add(time.Second))
	var b [controlSize]byte
	if _, err := io.ReadFull(c.ControlR, b[:]); err != nil {
		return 0
	}
	m, err := decodeControl(b[:])
	if err != nil || m.Kind != MessageError || m.Step != StepExec {
		return 0
	}
	return m.Errno
}

// Close releases the pipes, the pidfd and the kept forking thread. It does not reap: call Wait or Kill first.
// Safe to call twice. A pidfd a concurrent Kill or Wait is borrowing closes when that call returns it.
func (c *Child) Close() error {
	var first error
	c.once.Do(func() {
		close(c.release)
		if c.controlW != nil {
			first = c.controlW.Close()
			c.controlW = nil
		}
		if c.ControlR != nil {
			if err := c.ControlR.Close(); err != nil && first == nil {
				first = err
			}
			c.ControlR = nil
		}
		if err := c.PidFD.Close(); err != nil && first == nil {
			first = fmt.Errorf("close pidfd: %w", err)
		}
	})
	return first
}
