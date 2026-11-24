// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/internal/runlock"
)

// lockFree is runlock.LockFree, a variable only so a test can release the lock between the proof's failure and this look.
var lockFree = runlock.LockFree

// ErrNoBroker is a run whose lock no live launcher holds, so nothing serves its ask socket.
var ErrNoBroker = errors.New("run has no live approval broker")

// Launcher is the run's live launcher, the process that serves the run directory dir's ask socket, held by a pidfd
// verified against the run's lock (runlock.OpenStopTargetFor). The caller keeps it open through the exchange and
// passes its PID as expectedPID: matching the broker's SO_PEERCRED to it prevents a replacement pathname socket from
// posing as a live run's approval endpoint.
func Launcher(dir string) (*runlock.StopTarget, error) {
	held, info, err := runlock.ProbeLock(dir)
	if err != nil {
		return nil, err
	}
	if !held || info.PID <= 0 {
		return nil, ErrNoBroker
	}
	t, err := runlock.OpenStopTargetFor(dir, info)
	if errors.Is(err, runlock.ErrStale) {
		// The process the lock line names is gone (exited, reaped or not, even while this look at it was made), or is
		// another process now: no live launcher holds the run's lock, as `tego stop` and `tego status` read the same
		// refusal. The run is over; nothing here serves its ask socket (N109).
		return nil, fmt.Errorf("%w: %w", ErrNoBroker, err)
	}
	if errors.Is(err, runlock.ErrNotLockHolder) && lockFree(dir) {
		// The proof began on a held lock and the launcher released it meanwhile (the ledger's close does, before the process
		// exits): the run ended, and its launcher is not one that cannot be judged.
		return nil, fmt.Errorf("%w: %w", ErrNoBroker, err)
	}
	return t, err
}
