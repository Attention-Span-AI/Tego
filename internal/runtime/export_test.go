// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"time"

	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// What this file exports, only this package's tests (and its external test package) call.

// ProbeLock is runlock.ProbeLock, whose doc is the contract.
func ProbeLock(runDir string) (held bool, info LockInfo, err error) { return runlock.ProbeLock(runDir) }

// RequestStop drops the stop marker in runDir, created through a temporary file and rename so a
// reader never sees a half-made marker (§3). An existing marker is ErrStopRequested: the run is
// already stopping and a second `tego stop` changes nothing about the reason it will end with, nor
// about the grace the first one asked for. The marker is empty, so the machine's stop_grace applies;
// RequestStopGrace writes one that asks for another.
func RequestStop(runDir string) error { return RequestStopGrace(runDir, 0) }

// WithSweepManager supplies the cgroup manager used to kill an orphan's surviving process tree.
// Without it Sweep detects the invoking user's delegated subtree itself; a machine with no
// delegation still writes run_end, it just cannot kill anything (recorded in SweepResult.Errs).
func WithSweepManager(m cgroup.Manager) SweepOption {
	return func(o *sweepOptions) { o.manager = m }
}

// WithSweepClock replaces time.Now for retention math; tests use it.
func WithSweepClock(now func() time.Time) SweepOption { return func(o *sweepOptions) { o.now = now } }

// OpenStopTarget is OpenStopTargetFor (whose doc is the contract) on a lock line's two values.
func OpenStopTarget(runDir string, pid int, wantStartBootNS uint64) (*StopTarget, error) {
	return OpenStopTargetFor(runDir, LockInfo{PID: pid, StartBootNS: wantStartBootNS})
}

// RequestStopGrace is RequestStopGraceThen with no after step.
func RequestStopGrace(runDir string, grace time.Duration) error {
	return RequestStopGraceThen(context.Background(), runDir, grace, nil)
}
