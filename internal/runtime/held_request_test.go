// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// holderSource is a capture source that reports a request held inside Tego.
type holderSource struct{ holding atomic.Bool }

func (*holderSource) Name() string                                            { return "holder" }
func (*holderSource) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (*holderSource) Stop() error                                             { return nil }
func (*holderSource) Gaps() []source.Gap                                      { return nil }
func (h *holderSource) HoldingRequest() bool                                  { return h.holding.Load() }

// TestARequestTegoHoldsHoldsTheStallClock: the budget watcher's held hook is true while a capture source holds an
// agent's request inside Tego (the forwarder, while it connects to the model), and false once it does not, so a run
// is not ended as stalled for Tego's own latency (limits.WithHeld).
func TestARequestTegoHoldsHoldsTheStallClock(t *testing.T) {
	h := &holderSource{}
	r := &runner{deps: Deps{Capture: []source.Source{h}}}
	if r.held() {
		t.Fatal("the run is held with no request held")
	}
	h.holding.Store(true)
	if !r.held() {
		t.Fatal("a request Tego holds does not hold the stall clock")
	}
	h.holding.Store(false)
	if r.held() {
		t.Fatal("the run is still held after the request was sent on")
	}
}
