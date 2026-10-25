// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/runlock"
)

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
	return runlock.OpenStopTargetFor(dir, info)
}
