// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// activityGrain is the most often a run's forwarder reports relayed bytes to the stall check: one report per
// 100 ms across every relay and tunnel of the run. The check ticks once a second against a stall_after of
// seconds, so a coarser reading changes no verdict, and a stream of small chunks costs at most ten calls a
// second rather than one per chunk.
const activityGrain = 100 * time.Millisecond

// activityMeter reports the model traffic a relay carries as activity the ledger has no line for (limits R4,
// capture-derive.md R21): a response that streams for longer than stall_after is a run waiting on its model,
// not a stalled one, whatever the record mode, and its ssl_request and ssl_response lines are only its two
// ends. One meter serves a run's whole forwarder; a nil meter is a run with no stall budget and does nothing.
type activityMeter struct {
	fn    func(monoNS uint64)
	clock ledger.Clock
	// last is the reading of the last report, 0 before the first. It is read and swapped without a lock,
	// so relays on many connections coalesce through it without allocating or waiting on each other.
	last atomic.Uint64
}

// newActivityMeter is the meter for fn on clock, or nil when fn is nil.
func newActivityMeter(fn func(monoNS uint64), clock ledger.Clock) *activityMeter {
	if fn == nil {
		return nil
	}
	if clock == nil {
		clock = ledger.SystemClock{}
	}
	return &activityMeter{fn: fn, clock: clock}
}

// chunk reports one relayed chunk, unless another was reported less than activityGrain ago. Of two relays
// that race past the grain, the one whose swap lands reports and the other drops its chunk, which is within
// the grain of the one reported. A reading of 0 is unknown (E20) and is not reported.
func (a *activityMeter) chunk() {
	if a == nil {
		return
	}
	now := a.clock.Mono()
	last := a.last.Load()
	if now == 0 || (last != 0 && now < last+uint64(activityGrain)) {
		return
	}
	if a.last.CompareAndSwap(last, now) {
		a.fn(now)
	}
}
