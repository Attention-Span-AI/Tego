// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// closedAtKillKiller reads the watcher's gate at the moment the kill is written.
type closedAtKillKiller struct {
	w                   *Watcher
	closedAtKill, kills int
}

func (k *closedAtKillKiller) Kill(cgroup.Cgroup) error {
	k.kills++
	if _, closed := k.w.Closed(); closed {
		k.closedAtKill++
	}
	return nil
}

// TestTheGateClosesAfterTheLimitLineAndBeforeTheKill: Closed is false while the run is under every ceiling, and true from the
// breach that ends it: after the limit event is emitted and the facade told (a request refused earlier could end the
// agent before the run's reason was the limit), and before the kill is written (the window it closes).
func TestTheGateClosesAfterTheLimitLineAndBeforeTheKill(t *testing.T) {
	for _, c := range []struct {
		name  string
		lim   agent.ResolvedLimits
		drive func(w *Watcher)
		which string
	}{
		{"repeats", agent.ResolvedLimits{Set: agent.BudgetRepeats, Repeats: 3}, func(w *Watcher) {
			for i := range 3 {
				w.Observe(decision(uint64(2_000+i), 1, "read_file", "h"))
			}
		}, record.LimitRepeats},
		{"tokens", agent.ResolvedLimits{Set: agent.BudgetTokens, Tokens: 100}, func(w *Watcher) {
			w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 60, 60, 0, 0))
		}, record.LimitTokens},
		{"cost_usd", agent.ResolvedLimits{Set: agent.BudgetCostUSD, CostUSD: 0.0001}, func(w *Watcher) {
			w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 600, 600, 0, 0))
		}, record.LimitCostUSD},
	} {
		t.Run(c.name, func(t *testing.T) {
			sink, clk := &fakeSink{}, &fakeClock{}
			killer := &closedAtKillKiller{}
			var openAtBreach, limitLines int
			w := NewWatcher(c.lim, testTable(), killer, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
				WithOnBreach(func(Breach) {
					limitLines = len(sink.kinds(record.KindLimit))
					if _, closed := killer.w.Closed(); !closed {
						openAtBreach++
					}
				}))
			killer.w = w
			w.Observe(runStart(1_000))
			if _, closed := w.Closed(); closed {
				t.Fatal("the gate is closed before any ceiling was crossed")
			}
			c.drive(w)
			b, closed := w.Closed()
			if !closed || b.Which != c.which {
				t.Fatalf("Closed() = %+v, %v after the %s breach", b, closed, c.which)
			}
			if limitLines != 1 {
				t.Fatalf("%d limit lines when the facade was told, want the one already emitted", limitLines)
			}
			if openAtBreach != 1 {
				t.Fatal("the gate was already closed when the facade was told: a refusal could end the agent before the run's reason is the limit")
			}
			if killer.kills != 1 || killer.closedAtKill != 1 {
				t.Fatalf("kills %d with the gate closed at %d of them, want one kill, written with the gate closed", killer.kills, killer.closedAtKill)
			}
		})
	}
}

// TestWallAndStallCloseTheGateAtTheTick: the two ceilings only the clock crosses close it too.
func TestWallAndStallCloseTheGateAtTheTick(t *testing.T) {
	for _, c := range []struct {
		name, which string
		lim         agent.ResolvedLimits
	}{
		{"wall", record.LimitWall, agent.ResolvedLimits{Set: agent.BudgetWall, Wall: 5_000_000_000}},
		{"stall_after", record.LimitStallAfter, agent.ResolvedLimits{Set: agent.BudgetStallAfter, StallAfter: 5_000_000_000}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, _, _, clk, _ := newTestWatcher(t, c.lim, nil)
			w.Observe(runStart(1_000))
			clk.set(1_000 + 4_000_000_000)
			if _, err := w.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, closed := w.Closed(); closed {
				t.Fatal("the gate closed under the ceiling")
			}
			clk.set(1_000 + 6_000_000_000)
			if _, err := w.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
			if b, closed := w.Closed(); !closed || b.Which != c.which {
				t.Fatalf("Closed() = %+v, %v after the %s breach", b, closed, c.which)
			}
		})
	}
}

// TestALedgerCeilingDoesNotCloseTheGate: ledger_bytes spends nothing and its limit line has no reason code, so a
// refusal line would carry none and only add to a ledger already at its ceiling; the run is ended as before.
func TestALedgerCeilingDoesNotCloseTheGate(t *testing.T) {
	sink, killer, clk := &fakeSink{}, &fakeKiller{}, &fakeClock{}
	w := NewWatcher(agent.ResolvedLimits{}, nil, killer, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithLedgerCeiling(100, func() int64 { return 500 }))
	w.Observe(runStart(1_000))
	w.Observe(decision(2_000, 1, "t", "h"))
	if _, tripped := w.Tripped(); !tripped || killer.kills.Load() != 1 {
		t.Fatalf("the ledger ceiling did not end the run: tripped %v, %d kills", tripped, killer.kills.Load())
	}
	if _, closed := w.Closed(); closed {
		t.Fatal("a ledger_bytes breach closed the admission gate")
	}
}

// TestAnUnboundedRunNeverClosesTheGate: no ceiling, no gate, however much the run does.
func TestAnUnboundedRunNeverClosesTheGate(t *testing.T) {
	w, _, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{}, testTable())
	w.Observe(runStart(1_000))
	for i := range 50 {
		w.Observe(decision(uint64(2_000+i), 1, "read_file", "h"))
		w.Observe(response(uint64(2_000+i), "claude-sonnet-4-5-20250929", 600, 600, 0, 0))
	}
	if _, closed := w.Closed(); closed {
		t.Fatal("a run with no budget closed the gate")
	}
}
