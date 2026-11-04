// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ChildMain is the `tego __child` stage (docs/p0/runtime-launch.md §4, ARCHITECTURE.md §5, ADR 0006). It
// runs on one locked OS thread, reads its ChildSpec from fd 3, applies in order: cwd, then (R4 unprivileged
// order) capability clear, PR_SET_DUMPABLE=1, PR_SET_PDEATHSIG=SIGKILL with the getppid
// re-check, PR_SET_NO_NEW_PRIVS, landlock_restrict_self, seccomp(SET_MODE_FILTER, NEW_LISTENER); writes
// the notify fd number to fd 4; blocks for the parent's ack byte on fd 3; and execve's the command with the
// spec's env. A privileged run (root launcher) applies Landlock and seccomp first, then drops uid/gid and
// capabilities. It sets no_new_privs by default; only an explicit spec.Setuid opt-out leaves it unset.
//
// args are the words after "__child"; the only one recognised is `--run <id>`, used to tag messages written
// before the spec arrives. The return value is the process exit code: 125 for a failed setup step (also
// reported to the parent as a negative control message), 126/127 when execve fails (EACCES/ENOEXEC vs
// ENOENT, one line on stderr), 2 for a usage error. It never returns on success.
func ChildMain(args []string) int {
	runtime.LockOSThread() // the Landlock domain, the filter and the execve all belong to this one thread
	tag, err := parseChildArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", ChildCommand, err)
		return identity.ExitUsage
	}
	// The handshake's pipes are this process's first owners (sys.Inherited's seal): a number at 3 or 4 that is not
	// the pipe the launcher passed is refused before anything is read from it or written to it.
	report, rerr := inheritFile(childReportFD, sys.KindFIFO, "report")
	control, cerr := inheritFile(childControlFD, sys.KindFIFO, "control")
	st := &stage{control: control, report: report, tag: tag}
	if err := errors.Join(rerr, cerr); err != nil {
		if report != nil {
			st.reportFailure(fail(StepSpec, err))
		}
		fmt.Fprintf(os.Stderr, "tego %s%s: %v [launcher]\n", ChildCommand, st.tagSuffix(), err)
		return identity.ExitLauncher
	}
	return st.run()
}

// inheritFile owns the number n this stage received at exec as kind (sys.Inherited) and hands it to an *os.File.
func inheritFile(n int, kind sys.Kind, name string) (*os.File, error) {
	fd, err := sys.Inherited(n, kind, name)
	if err != nil {
		return nil, err
	}
	return fd.Release(name)
}

func parseChildArgs(args []string) (string, error) {
	tag := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--run":
			if i+1 >= len(args) {
				return "", errors.New("--run needs a value [usage]")
			}
			tag = args[i+1]
			i++
		default:
			return "", fmt.Errorf("unknown argument %q [usage]", args[i])
		}
	}
	return tag, nil
}

// stepError is a failed child-stage step: the step name and the errno the parent decodes (case 4).
type stepError struct {
	step  ChildStep
	errno syscall.Errno
	err   error
}

// Error names the step and the underlying failure.
func (e *stepError) Error() string { return fmt.Sprintf("%s: %v", e.step, e.err) }

// Unwrap exposes the underlying error so errors.Is reaches the errno.
func (e *stepError) Unwrap() error { return e.err }

func fail(step ChildStep, err error) error {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = syscall.EIO
	}
	return &stepError{step: step, errno: errno, err: err}
}

// stage holds the child's side of the handshake.
type stage struct {
	control *os.File // fd 3, read: spec then ack
	report  *os.File // fd 4, write: one control message
	tag     string
	spec    wireSpec
	// deputy owns the inherited deputy control number the spec names, from right after the spec is read
	// (sys.Inherited's seal: before this stage makes any owner of its own); nil when it names none.
	deputy *sys.FD
	// notifyFD is the seccomp listener applySeccomp installed, or noListener. It stays a bare number: its one use
	// is its value, which reportSuccess writes to the parent for pidfd_getfd, and nothing here closes it (execve
	// does, close-on-exec), so no owner could guard anything; ADR 0023's lint admits no lent number written as
	// data, which is why launch keeps this producer site (FD-MID note).
	notifyFD int
	// devNull is /dev/null, opened before landlock_restrict_self for the open deputy's standard streams, when the
	// spec asks for a deputy (spawnDeputy).
	devNull *os.File
}

func (s *stage) run() int {
	if err := s.setup(); err != nil {
		s.reportFailure(err)
		fmt.Fprintf(os.Stderr, "tego %s%s: %v [launcher]\n", ChildCommand, s.tagSuffix(), err)
		return identity.ExitLauncher
	}
	if err := s.awaitAck(); err != nil {
		fmt.Fprintf(os.Stderr, "tego %s%s: %v [launcher]\n", ChildCommand, s.tagSuffix(), err)
		return identity.ExitLauncher
	}
	// execve only returns on failure. The filter is live, so this is the run's first notification (R7).
	err := syscall.Exec(s.spec.Command[0], s.spec.Command, s.spec.Env)
	return s.execFailed(err)
}

func (s *stage) tagSuffix() string {
	if s.tag == "" {
		return ""
	}
	return " run=" + s.tag
}

// setup performs every step before the fd handoff and writes the control message on success.
func (s *stage) setup() error {
	// FD_CLOEXEC on every descriptor from 3 up, so the agent's execve keeps 0, 1 and 2 and nothing else
	// (invariant 4a): the handshake's pipes and the ruleset, and whatever the launcher itself inherited without
	// the flag, which os/exec passes on to this stage as to any child. A GitHub Actions step starts with such
	// descriptors (fds 142 and 145 reached an agent in CI), and an inherited descriptor is access no Landlock rule
	// can take back, since Landlock checks at open. When neither close_range nor the /proc/self/fd walk can do it
	// the stage fails closed (exit 125).
	if err := sys.CloexecFrom(3); err != nil {
		return fail(StepSpec, err)
	}
	spec, err := readSpec(s.control)
	if err != nil {
		return fail(StepSpec, err)
	}
	s.spec = spec
	if spec.DeputyFD >= 3 { // absent, or a standard stream: no deputy
		if s.deputy, err = sys.Inherited(spec.DeputyFD, sys.KindSocket, "deputy control"); err != nil {
			return fail(StepSpec, err)
		}
	}
	if spec.RunID != "" {
		s.tag = spec.RunID
	}
	if err := resetSignals(spec.ResetSignals); err != nil {
		return fail(StepSpec, err)
	}
	if err := unix.Chdir(spec.Dir); err != nil {
		return fail(StepDir, fmt.Errorf("chdir(%q): %w", spec.Dir, err))
	}
	if s.deputy != nil {
		// Opened before the Landlock domain exists, so a domain that grants no /dev/null still starts the deputy. A
		// /dev/null that cannot be opened leaves spawnDeputy to report the deputy unavailable.
		if f, err := os.OpenFile("/dev/null", os.O_RDWR, 0); err == nil {
			s.devNull = f
		}
	}
	s.notifyFD = noListener
	if spec.Privileged {
		err = s.privilegedOrder()
	} else {
		err = s.unprivilegedOrder()
	}
	if err != nil {
		return err
	}
	return s.reportSuccess()
}

// unprivilegedOrder is ARCHITECTURE.md §5 steps 2–6 as written.
func (s *stage) unprivilegedOrder() error {
	if err := s.dropCapabilities(); err != nil {
		return err
	}
	if err := s.armDeathSignal(); err != nil {
		return err
	}
	// Step 4: no_new_privs is what lets an unprivileged thread call landlock_restrict_self and seccomp.
	// Observe mode (no ruleset, tier 1's record filter) keeps it too: the seccomp install needs it. The
	// ABI-11 LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS flag would fold it into step 5; the prctl is equivalent
	// on every ABI and needs no probe.
	if err := sys.SetNoNewPrivs(); err != nil {
		return fail(StepNoNewPrivs, err)
	}
	if err := s.applyLandlock(); err != nil {
		return err
	}
	s.spawnDeputy() // in the run's domain and cgroup, before the listener filter (ADR 0041 D2)
	return s.applySeccomp()
}

// privilegedOrder is the R4 swap: Landlock and seccomp while CAP_SYS_ADMIN is held, then the uid/gid drop,
// the capability drop, dumpable and PDEATHSIG (invariant 5), and then no_new_privs (ADR 0033). R4 skipped
// no_new_privs here as redundant for Landlock and seccomp, which CAP_SYS_ADMIN already allowed, and its one
// effect was that a setuid binary inside a root-tier run gained root: a root agent could open a pinned BPF map
// and delete its run's row, silencing the plane, the recorder and the cgroup programs for its run. Only a
// contract's `setuid: true` keeps the old behaviour. Under a net: section such a run gives up CAP_NET_ADMIN first
// (ChildSpec.DropNetAdmin, ADR 0128), while this thread still holds the CAP_SETPCAP the drop needs: the deputy and the
// agent start from a bounding set without it.
func (s *stage) privilegedOrder() error {
	if s.spec.DropNetAdmin {
		if err := sys.DropBoundingCapability(unix.CAP_NET_ADMIN); err != nil {
			return fail(StepCaps, err)
		}
	}
	if err := s.applyLandlock(); err != nil {
		return err
	}
	s.spawnDeputy() // exec'd with the agent's credentials, in the run's domain and cgroup, before the filter (ADR 0041 D2)
	if err := s.applySeccomp(); err != nil {
		return err
	}
	if err := s.dropCredentials(); err != nil {
		return err
	}
	if err := s.dropCapabilities(); err != nil {
		return err
	}
	if err := s.armDeathSignal(); err != nil {
		return err
	}
	if !s.spec.Setuid {
		if err := sys.SetNoNewPrivs(); err != nil {
			return fail(StepNoNewPrivs, err)
		}
	}
	return nil
}

// dropCredentials switches to the target uid/gid (privileged runs only). A setresuid from root clears the
// permitted, effective and ambient sets (commoncap.c), which is why the capability clear follows anyway.
func (s *stage) dropCredentials() error {
	// Per thread, not x/sys/unix's all-threads Setresuid: that path tgkills every other thread from this
	// one, which already carries the filter, and below Landlock ABI 6 the filter hands tgkill to a supervisor
	// that starts only once this stage reports, so the stage hung (docs/p0/enforce-landlock.md R7). This
	// thread is the
	// one that execs, and execve ends the others, so the agent gets exactly these credentials.
	if err := sys.DropThreadCreds(s.spec.UID, s.spec.GID); err != nil {
		return fail(StepCreds, err)
	}
	return nil
}

// dropCapabilities empties every capability set, then restores dumpable=1: capset resets it as a side
// effect and pidfd_getfd refuses non-dumpable targets (case 5).
func (s *stage) dropCapabilities() error {
	if err := sys.ClearCapabilities(); err != nil {
		return fail(StepCaps, err)
	}
	if err := sys.SetDumpable(true); err != nil {
		return fail(StepDumpable, err)
	}
	on, err := sys.Dumpable()
	if err != nil {
		return fail(StepDumpable, err)
	}
	if !on {
		return fail(StepDumpable, fmt.Errorf("PR_GET_DUMPABLE still 0 after PR_SET_DUMPABLE 1: %w", syscall.EPERM))
	}
	return nil
}

// armDeathSignal is step 3: after the last credential change (commit_creds clears a pending pdeath_signal,
// invariant 5), then the getppid re-check closes the window in which the launcher died before arming.
func (s *stage) armDeathSignal() error {
	if err := sys.SetPdeathsig(syscall.SIGKILL); err != nil {
		return fail(StepPdeathsig, err)
	}
	if ppid := os.Getppid(); ppid != s.spec.ParentPID {
		return fail(StepParent, fmt.Errorf("launcher pid %d gone, parent is now %d: %w", s.spec.ParentPID, ppid, syscall.ESRCH))
	}
	return nil
}

func (s *stage) applyLandlock() error {
	if s.spec.RulesetFD < 0 {
		return nil
	}
	if s.spec.BuiltinRefusals {
		rs, err := ttyRuleset()
		if err != nil {
			return fail(StepLandlock, err)
		}
		err = rs.RestrictLandlock(s.spec.LandlockFlags)
		if closeErr := rs.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fail(StepLandlock, err)
		}
	}
	// The ruleset stays a bare number until ADR 0023 C5 gives the launcher an owner to pass on: landlock_restrict_self
	// takes it through sys.RestrictSelf, whose ABI fallback the lint cannot follow a lent number into.
	if err := sys.RestrictSelf(s.spec.RulesetFD, s.spec.LandlockFlags); err != nil {
		return fail(StepLandlock, err)
	}
	if err := unix.Close(s.spec.RulesetFD); err != nil {
		return fail(StepLandlock, fmt.Errorf("close ruleset fd %d: %w", s.spec.RulesetFD, err))
	}
	return nil
}

// Landlock flags are shared with the syscall policy wrapper.
const (
	LandlockLogSameExecOff   = sys.LandlockLogSameExecOff
	LandlockLogNewExecOn     = sys.LandlockLogNewExecOn
	LandlockLogSubdomainsOff = sys.LandlockLogSubdomainsOff
	LandlockNoNewPrivs       = sys.LandlockNoNewPrivs
)

// LandlockFlags exposes the same flag split used by sys.RestrictSelf.
func LandlockFlags(requested uint32, abi int) (applied, dropped uint32) {
	return sys.LandlockRestrictFlags(requested, abi)
}

// applySeccomp installs the filter with NEW_LISTENER and keeps the listener's number in s.notifyFD, or leaves
// noListener there when the tier has no filter. The listener is O_CLOEXEC from the kernel; it is re-marked so
// the agent can never inherit its own notify channel (invariant 4).
func (s *stage) applySeccomp() error {
	if len(s.spec.Seccomp) == 0 {
		return nil
	}
	fd, err := sys.SeccompSetFilterNewListener(s.spec.Seccomp)
	if err != nil {
		return fail(StepSeccomp, err)
	}
	if err := markCloexec(fd); err != nil {
		return fail(StepSeccomp, err)
	}
	s.notifyFD = fd
	return nil
}

// reportSuccess is step 7: the notify fd number (or the no-listener marker) as one write(2) on pipe A. The
// listener stays open in this stage, where the parent's pidfd_getfd reads it, until execve closes it.
func (s *stage) reportSuccess() error {
	msg := encodeNoListener()
	if s.notifyFD >= 0 {
		msg = encodeFD(s.notifyFD)
	}
	if _, err := s.report.Write(msg); err != nil {
		return fail(StepAck, fmt.Errorf("write control message: %w", err))
	}
	return nil
}

func (s *stage) reportFailure(err error) {
	var se *stepError
	if !errors.As(err, &se) {
		se = &stepError{step: StepSpec, errno: syscall.EIO}
	}
	// Best effort: the parent may already be gone; its EOF on pipe A carries the same "child died" fact.
	_, _ = s.report.Write(encodeError(se.step, se.errno))
}

// awaitAck is step 8: block on pipe B for one byte. EOF means the launcher died; the child stops here
// rather than exec an unsupervised agent (R5).
func (s *stage) awaitAck() error {
	var b [1]byte
	n, err := io.ReadFull(s.control, b[:])
	if err != nil {
		return fail(StepAck, fmt.Errorf("launcher closed the control pipe before the ack (%d bytes): %w", n, err))
	}
	if b[0] != ackByte {
		return fail(StepAck, fmt.Errorf("unexpected ack byte %#x: %w", b[0], syscall.EPROTO))
	}
	return nil
}

// execFailed reports the execve errno on pipe A (still open: it is O_CLOEXEC and the exec did not happen),
// prints the shell-convention line and returns 126 or 127.
func (s *stage) execFailed(err error) int {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = syscall.EIO
	}
	_, _ = s.report.Write(encodeError(StepExec, errno))
	fmt.Fprintf(os.Stderr, "tego: %s: %v\n", s.spec.Command[0], errno)
	if errno == syscall.ENOENT {
		return identity.ExitNotFound
	}
	return identity.ExitNoExec
}

// resetSignals sets each signal to SIG_DFL with a raw rt_sigaction: the job-control stops a tier-2 launcher
// ignores for itself (HoldJobControl), which reach this stage ignored because an ignored disposition survives
// execve and would reach the agent the same way, leaving it unstoppable by Ctrl-Z. os/signal cannot do it:
// Reset restores the disposition the process started with, which for these is SIG_IGN. The Go runtime
// installs no handler for a job-control signal nothing asked to Notify, so this changes nothing it tracks.
// A zeroed kernel sigaction is SIG_DFL with no flags and an empty mask on both supported architectures.
func resetSignals(sigs []int) error {
	for _, sig := range sigs {
		var act [4]uint64 // sa_handler, sa_flags, sa_restorer, sa_mask: SIG_DFL
		if _, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig),
			uintptr(unsafe.Pointer(&act[0])), 0, 8, 0, 0); errno != 0 {
			return fmt.Errorf("rt_sigaction(%d, SIG_DFL): %w", sig, errno)
		}
	}
	return nil
}

// markCloexec sets FD_CLOEXEC on each fd, for a descriptor this stage creates after setup's sys.CloexecFrom(3).
func markCloexec(fds ...int) error {
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			return fmt.Errorf("fcntl(%d, F_SETFD, FD_CLOEXEC): %w", fd, err)
		}
	}
	return nil
}
