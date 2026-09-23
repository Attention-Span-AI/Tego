// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// WaitResult is what Child.Wait learned from the kernel about the agent's main process.
type WaitResult struct {
	// Status is the wait4-encoded status (Exited/ExitStatus, Signaled/Signal).
	Status syscall.WaitStatus
	// ExecErr is the errno execve returned when the agent command could not be started, or 0 when the exec
	// succeeded: reported by the child stage over pipe A right before it exits 126/127 (case 8).
	ExecErr syscall.Errno
}

// Outcome is what the signal handler decided for the run; the zero value means no stop signal arrived.
type Outcome struct {
	// Signal is the first signal that started stop_grace (SIGINT, SIGTERM or SIGHUP), or 0.
	Signal syscall.Signal
	// Escalated is true when cgroup.kill was written: a second SIGINT within 2s or stop_grace expiry (R9).
	// A write that failed leaves it false -- run_end must not claim an escalation that did not happen; the
	// error travels out through SignalHandler.Run instead.
	Escalated bool
	// Stopped is true when the stop was a `tego stop` (stop.request marker present at handler time).
	Stopped bool
}

// Ended maps a wait result and the signal outcome to the run_end reason and the exit code of tego run
// (spec/identity/RUN-IDENTITY.md exit-code table). It decides only what this package observes: exec failure,
// stop, signal, or the agent's own exit. oom, pids and limit are decided by their owners and override this
// through identity.ExitCode directly.
func Ended(r WaitResult, o Outcome) (identity.EndReason, int) {
	switch {
	case r.ExecErr != 0:
		xf := identity.ExecFailureDenied
		if r.ExecErr == syscall.ENOENT {
			xf = identity.ExecFailureNotFound
		}
		return identity.ReasonExecFailed, identity.ExitCode(identity.ReasonExecFailed, r.Status, false, xf)
	case o.Stopped:
		return identity.ReasonStopped, identity.ExitCode(identity.ReasonStopped, r.Status, o.Escalated, identity.ExecFailureNone)
	case o.Signal != 0:
		return identity.ReasonSignal, identity.ExitCode(identity.ReasonSignal, r.Status, o.Escalated, identity.ExecFailureNone)
	default:
		return identity.ReasonExit, identity.ExitCode(identity.ReasonExit, r.Status, false, identity.ExecFailureNone)
	}
}
