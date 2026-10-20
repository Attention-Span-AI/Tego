// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// execPinHandle is a tier handle whose decision plane holds execs to their pins (cgroup.Handle; ADR 0048 (3) P2).
type execPinHandle interface {
	ExecPins() (execpin.Key, bool)
	PinExec(tid uint32, startTicks uint64, pin []byte) (uint32, error)
	SweepExecPins(live func(tid uint32, startTicks uint64) bool) error
}

// handlePinner adapts a pinning handle to the supervisor's seam (supervisor.ExecPinner).
type handlePinner struct{ h execPinHandle }

func (p handlePinner) Pin(tid uint32, startTicks uint64, pin []byte) (uint32, error) {
	seq, err := p.h.PinExec(tid, startTicks, pin)
	if errors.Is(err, cgroup.ErrPinsFull) {
		return 0, fmt.Errorf("%w: %w", supervisor.ErrExecPinsFull, err)
	}
	return seq, err
}

func (p handlePinner) Sweep(live func(tid uint32, startTicks uint64) bool) error {
	return p.h.SweepExecPins(live)
}

// execPinner is the supervisor's pin seam and the run's MAC key when the run's handle pinned its slot, and nil
// otherwise: the supervisor then writes no pin, and refuses no exec for the want of one.
func execPinner(handle any) (supervisor.ExecPinner, execpin.Key) {
	h, ok := handle.(execPinHandle)
	if !ok {
		return nil, execpin.Key{}
	}
	key, on := h.ExecPins()
	if !on {
		return nil, execpin.Key{}
	}
	return handlePinner{h}, key
}

// ExecPinRecorder is a kernel recorder that folds a pinned run's exec records with the plane's held and kill samples
// (observe.Recorder.SetExecPins; ADR 0048 (8)) and counts what the plane did for run_end's exec_rules.
type ExecPinRecorder interface {
	SetExecPins(on bool, kill func(pid int, startBootNS uint64) error)
	ExecPinCounts() (killed, killFailed, pinRefused int64)
}

// pinnedHandle reports whether the run's handle pinned its slot (ADR 0048 (3) P2).
func pinnedHandle(handle any) bool {
	h, ok := handle.(execPinHandle)
	if !ok {
		return false
	}
	_, on := h.ExecPins()
	return on
}

// ErrExecAssurance refuses an exec.assurance: kernel run whose execs the kernel does not hold to the decided facts,
// before the agent executes (ADR 0048 (3) P2).
var ErrExecAssurance = errors.New("runtime: kernel exec assurance unavailable")

// execPinClaim is the run's handle's ExecPinClaim, or false with the tier's reason where the tier has none.
func (r *runner) execPinClaim() (bool, string) {
	if c, ok := r.handle.(enforce.ExecPinClaimer); ok {
		return c.ExecPinClaim()
	}
	return false, fmt.Sprintf("tier %s has no decision plane that pins execs", r.deps.Enforce.Tier())
}

// execPinned reports whether the kernel holds this run's execs to the decided facts (execPinClaim), which takes
// exec.rules/argv and gate.exec out of run_start.best_effort (ADR 0048 (6)).
func (r *runner) execPinned() bool {
	ok, _ := r.execPinClaim()
	return ok
}

// requireExecAssurance refuses an exec.assurance: kernel run whose handle does not claim exec pins (ADR 0048 (3) P2:
// exit 125, before the child starts).
func (r *runner) requireExecAssurance() error {
	if r.rt.ExecutionAssurance() != agent.ExecAssuranceKernel {
		return nil
	}
	if ok, why := r.execPinClaim(); !ok {
		return fmt.Errorf("%w: exec.assurance: kernel needs the kernel to hold every exec to the facts that were "+
			"decided, and this run's does not: %s", ErrExecAssurance, why)
	}
	return nil
}

// superviseExecPins tells the run's kernel recorder that its execs are pinned, so each exec's line waits for the
// plane's held or kill sample, and hands it the pidfd backstop for a kill the kernel could not send. Called before
// any source starts.
func (r *runner) superviseExecPins() {
	if p, ok := r.kernelRecord.(ExecPinRecorder); ok && pinnedHandle(r.handle) {
		p.SetExecPins(true, killPinnedExec(proc.New()))
	}
}

// withExecPinCounts adds what the recorder counted of a pinned run (the plane's kills, the kills it could not send,
// and its pin refusals in bprm_check) to the supervisor's run_end exec_rules, which already counts the supervisor's
// own pin refusals (pin_unavailable).
func (r *runner) withExecPinCounts(s record.Supervisor) record.Supervisor {
	p, ok := r.kernelRecord.(ExecPinRecorder)
	if !ok || !pinnedHandle(r.handle) {
		return s
	}
	killed, killFailed, pinRefused := p.ExecPinCounts()
	rules := record.ExecRules{}
	if s.ExecRules != nil {
		rules = *s.ExecRules
	}
	rules.Killed, rules.KillFailed, rules.PinRefused = killed, killFailed, rules.PinRefused+pinRefused
	s.ExecRules = &rules
	return s
}

// killPinnedExec is the late backstop for a kill the plane could not send (ADR 0048 (3), R6d): SIGKILL through the
// process's pidfd, once /proc says the pid still names the process the kill sample did (the pidfd is opened first,
// so a pid reused after that check is not the one signalled).
func killPinnedExec(fs *proc.FS) func(pid int, startBootNS uint64) error {
	return func(pid int, startBootNS uint64) error {
		return sys.PidfdSignalVerified(pid, unix.SIGKILL, func() error {
			st, err := fs.Stat(pid)
			if err != nil {
				return err
			}
			if !proc.SameProcess(st.StartBootNS(), startBootNS) {
				return fmt.Errorf("pid %d names another process than the plane's kill sample", pid)
			}
			return nil
		})
	}
}
