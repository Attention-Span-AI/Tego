// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
)

// deputyReadyTimeout bounds how long the stage waits for the deputy to report itself confined. A Go process starts in
// milliseconds; past this the deputy is taken as failed, killed, and the run continues without it (ADR 0041,
// Consequences: the launch probe and its degrade).
const deputyReadyTimeout = 10 * time.Second

// deputyEnv is the deputy's whole environment: no name of the agent's or the launcher's reaches it. Two Go runtime
// knobs keep its thread count low (it counts against the run's limits.pids) and its memory mappings unnamed (the
// runtime's PR_SET_VMA calls, which its filter answers EINVAL anyway).
var deputyEnv = []string{"GOMAXPROCS=2", "GODEBUG=decoratemappings=0"}

// spawnDeputy starts the run's open deputy when the spec asks for one (ADR 0041 D2): after landlock_restrict_self, so
// the deputy carries the run's own domain, inside the run cgroup the stage was cloned into, and before the listener
// filter, so its walks and opens are not notified. It is cloned with CLONE_PARENT, so its parent is the launcher, a
// subreaper, and never the agent this stage becomes: no wait(2) of the agent's meets it. On a privileged run it is
// exec'd with the credentials the agent drops to, so it has the agent's uid, gid and groups and no capability.
//
// A deputy that does not start fails nothing here: the stage reports it on the deputy's own control socket
// (deputy.ReportFailure), which the launcher reads in place of the hello, and the run goes on with its held-open
// cells best effort and disclosed (the degrade). Either way the stage closes its end of that socket before it
// returns, so the deputy holds the only copy.
func (s *stage) spawnDeputy() {
	if s.deputy == nil {
		return
	}
	owner := s.deputy
	s.deputy = nil
	control, err := owner.Release("deputy-control")
	if err == nil {
		err = s.startDeputy(control)
	}
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			errno = syscall.EIO
		}
		if control != nil {
			_ = sys.FileDo(control, func(n int) error { return deputy.ReportFailure(n, errno, err.Error()) })
		} else {
			_ = owner.Borrow(func(n int) error { return deputy.ReportFailure(n, errno, err.Error()) })
		}
	}
	_ = owner.Close() // a no-op once Release gave the number to control
	if control != nil {
		_ = control.Close()
	}
	if s.devNull != nil {
		_ = s.devNull.Close()
		s.devNull = nil
	}
}

// startDeputy execs `tego __open-deputy --parent <launcher>` and waits for its readiness message, which it sends
// once every confinement step is done (deputy.Main). The deputy's descriptors are /dev/null for its standard streams,
// opened before landlock_restrict_self (stage.devNull), the control socket at deputy.ControlFD and the readiness
// socket at deputy.ReadyFD; every other descriptor of this stage is close-on-exec (setup's sys.CloexecFrom(3)).
//
// This is a process start (ADR 0021 (3), (6)): it runs in the child stage, a process that holds no fanotify mark,
// before the stage reports on its control pipe, so before runner.arm places the run's first mark.
func (s *stage) startDeputy(control *os.File) error {
	if s.devNull == nil {
		return fmt.Errorf("deputy: no /dev/null for its standard streams: %w", syscall.ENOENT)
	}
	readyR, readyEnd, err := sys.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("deputy: readiness socketpair: %w", err)
	}
	defer readyR.Close() //nolint:errcheck // this stage's end of the readiness socket
	readyW, err := readyEnd.Release("deputy-ready")
	if err != nil {
		_ = readyEnd.Close()
		return fmt.Errorf("deputy: readiness socket: %w", err)
	}
	cmd := proc.Command("/proc/self/exe", deputy.Command, "--parent", strconv.Itoa(s.spec.ParentPID))
	cmd.Env = deputyEnv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.devNull, s.devNull, s.devNull
	cmd.ExtraFiles = []*os.File{control, readyW} // deputy.ControlFD, deputy.ReadyFD
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_PARENT}
	if s.spec.Privileged {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uint32(s.spec.UID), Gid: uint32(s.spec.GID), Groups: []uint32{uint32(s.spec.GID)},
		}
	}
	id, err := proc.Start(cmd)
	_ = readyW.Close()
	if err != nil {
		return fmt.Errorf("deputy: start: %w", err)
	}
	// The deputy is the launcher's child (CLONE_PARENT), never this stage's: nothing here waits for it. Release drops
	// the pidfd os/exec took without signalling or waiting.
	_ = cmd.Process.Release()
	if err := readyR.Borrow(func(n int) error { return awaitReady(n, deputyReadyTimeout) }); err != nil {
		_ = unix.Kill(id.PID, unix.SIGKILL)
		return err
	}
	return nil
}

// awaitReady reads the deputy's one readiness message within timeout: a 1 byte. A 0 byte followed by text is the
// reason the deputy gave for a start it could not complete (deputy.Main's fatal), and an end of stream with neither is
// a deputy that died before it could say (a signal, a runtime crash): each is ECHILD, the reason named in the error the
// stage reports (deputy.ReportFailure), so the run's warning says why its held opens are best effort.
func awaitReady(fd int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Errorf("deputy: not ready within %v: %w", timeout, syscall.ETIMEDOUT)
		}
		n, err := unix.Poll(fds, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("deputy: poll readiness: %w", err)
		}
		if n > 0 {
			break
		}
	}
	b := make([]byte, 1+deputyReasonMax)
	n, err := unix.Read(fd, b)
	switch {
	case err != nil:
		return fmt.Errorf("deputy: read readiness: %w", err)
	case n == 1 && b[0] == 1:
		return nil
	case n > 1 && b[0] == 0:
		return fmt.Errorf("deputy: %s: %w", b[1:n], syscall.ECHILD)
	}
	return fmt.Errorf("deputy: exited before it was confined, with no reason (killed or crashed): %w", syscall.ECHILD)
}

// deputyReasonMax bounds the reason a deputy sends for a start it could not complete (deputy.Main's maxLeaf).
const deputyReasonMax = 255
