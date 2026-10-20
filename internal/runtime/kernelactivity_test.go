// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stampSource is a kernel recorder that reads the run's activity stamp (ActivityStamper), here one the test
// advances.
type stampSource struct {
	plainSource
	stamp atomic.Uint64
	reads atomic.Int64
}

func (s *stampSource) LastActivity() uint64 { s.reads.Add(1); return s.stamp.Load() }

// TestKernelActivityStampIsPulledUnderAStallBudget is limits R4's kernel half at the run: the stamp the BPF programs
// keep at the run's slot (trace_proc's allowed actions under record: off, the TLS probes' calls in every mode) is
// pulled by the watcher at each Tick whenever stall_after is bounded, in every record mode, and not at all when it
// is not. An agent whose stamp advances every 200 ms is never ended by a 1 s stall_after; once the stamp stops,
// the run stalls.
func TestKernelActivityStampIsPulledUnderAStallBudget(t *testing.T) {
	const s = uint64(time.Second)
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
		for _, bounded := range []bool{true, false} {
			name := string(mode) + "/unbounded"
			lim := agent.ResolvedLimits{}
			if bounded {
				name = string(mode) + "/stall_after=1s"
				lim = agent.ResolvedLimits{StallAfter: time.Second, Set: agent.BudgetStallAfter}
			}
			t.Run(name, func(t *testing.T) {
				src := &stampSource{plainSource: plainSource{name: "observe"}}
				clk := &stepClock{}
				r := newTestRunner(Deps{Clock: clk, ObserveFactory: func(string) (source.Source, error) { return src, nil }})
				r.rt, r.queue = &agent.RuleTable{Record: mode, Limits: lim}, NewQueue(4)
				r.startKernelRecord(tier2Handle{hash: "deadbeef"})
				t.Cleanup(r.closeHookQueues)
				r.newBudget()
				r.wireKernelActivity()
				clk.mono.Store(10 * s)
				r.budget.Observe(&record.Event{Kind: record.KindRunStart, MonoNS: 10 * s})
				for at := 10*s + s/5; at <= 14*s; at += s / 5 {
					src.stamp.Store(at)
					clk.mono.Store(at + s/10)
					if b, _ := r.budget.Tick(t.Context()); b != nil {
						t.Fatalf("stalled at %v with the kernel stamp advancing every 200ms under a 1s stall_after: %+v",
							time.Duration(at), *b)
					}
				}
				if !bounded {
					if n := src.reads.Load(); n != 0 {
						t.Fatalf("the stamp was read %d times for a run no stall check reads", n)
					}
					return
				}
				if got := r.budget.Snapshot().LastEventMonoNS; got != 14*s {
					t.Fatalf("LastEventMonoNS = %d, want the last pulled stamp %d", got, 14*s)
				}
				clk.mono.Store(14*s + 2*s)
				b, _ := r.budget.Tick(t.Context())
				if b == nil || b.Which != record.LimitStallAfter {
					t.Fatalf("2s after the stamp stopped, Tick = %v, want a stall", b)
				}
			})
		}
	}
}

// TestKernelActivityNeedsAStamper: a kernel recorder that keeps no stamp (or none at all, a tier with no ring) adds
// no source, and a run whose stall check cannot read the kernel's stamp behaves as before.
func TestKernelActivityNeedsAStamper(t *testing.T) {
	lim := agent.ResolvedLimits{StallAfter: time.Second, Set: agent.BudgetStallAfter}
	for _, tc := range []struct {
		name string
		src  source.Source
	}{{"no recorder", nil}, {"a recorder without a stamp", &plainSource{name: "observe"}}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Clock: &stepClock{}})
			r.rt, r.queue = &agent.RuleTable{Record: agent.RecordOff, Limits: lim}, NewQueue(4)
			r.kernelRecord = tc.src
			r.newBudget()
			r.wireKernelActivity() // nothing to wire, and no panic
		})
	}
}
