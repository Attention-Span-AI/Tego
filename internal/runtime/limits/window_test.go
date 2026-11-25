// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// wallClock is a run's clock whose wall and monotonic readings a test moves apart: the monotonic one drives a run's own
// spend through the window, the wall one is what a stepped clock changes.
type wallClock struct {
	wall atomic.Int64 // unix ns
	mono atomic.Uint64
}

func (c *wallClock) Now() time.Time { return time.Unix(0, c.wall.Load()).UTC() }
func (c *wallClock) MonoNS() uint64 { return c.mono.Load() }
func (c *wallClock) advance(d time.Duration) {
	c.wall.Add(int64(d))
	c.mono.Add(uint64(d))
}

const windowModel = "claude-sonnet-4-5-20250929"

var windowOrigin = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func newWindowWatcher(t *testing.T, ceiling agent.ResolvedLimits, span time.Duration, carry []CarryUse, prices *PriceTable) (*Watcher, *wallClock, *[]Breach) {
	t.Helper()
	clk := &wallClock{}
	clk.wall.Store(windowOrigin.UnixNano())
	clk.mono.Store(1_000_000_000)
	var breaches []Breach
	w := NewWatcher(ceiling, prices, &fakeKiller{}, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, &fakeSink{},
		WithWindow(Window{Span: span, Carry: carry}), WithOnBreach(func(b Breach) { breaches = append(breaches, b) }))
	return w, clk, &breaches
}

func spendTokens(w *Watcher, clk *wallClock, in, out int) {
	w.Observe(response(clk.MonoNS(), windowModel, in, out, 0, 0))
}

func carryOf(ago time.Duration, in, out uint64) CarryUse {
	return CarryUse{At: windowOrigin.Add(-ago), Usage: ledger.TokenUsage{Model: windowModel, In: in, Out: out}}
}

func tokenCeiling(n int64) agent.ResolvedLimits {
	return agent.ResolvedLimits{Tokens: n, Set: agent.BudgetTokens}
}

// TestWindowRestartMidBudget is AO-7's case: an earlier run spent 600 of 1000 tokens, and this one, a restart, is ended
// at the 1000th token of the two, not 1000 of its own.
func TestWindowRestartMidBudget(t *testing.T) {
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, []CarryUse{carryOf(time.Hour, 400, 200)}, nil)
	w.Observe(runStart(clk.MonoNS()))
	spendTokens(w, clk, 200, 100) // 600 + 300
	if len(*breaches) != 0 {
		t.Fatalf("breached at 900 of 1000: %+v", *breaches)
	}
	spendTokens(w, clk, 100, 100) // 1100
	if len(*breaches) != 1 {
		t.Fatalf("breaches = %+v, want one at 1100", *breaches)
	}
	if b := (*breaches)[0]; b.Which != "tokens" || b.Value != 1100 || b.Ceiling != 1000 {
		t.Fatalf("breach = %+v, want tokens 1100 over 1000", b)
	}
	if tok, _, ok := w.Windowed(); !ok || tok != 1100 {
		t.Fatalf("Windowed = %d, %v", tok, ok)
	}
	if got := w.state.Tokens(); got != 500 {
		t.Fatalf("the run's own count = %d, want 500 (the carry is not in it)", got)
	}
}

// TestWindowCarryAlreadyOverTrips: a restart into a window already over its ceiling ends at its first response.
func TestWindowCarryAlreadyOverTrips(t *testing.T) {
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, []CarryUse{carryOf(time.Hour, 900, 400)}, nil)
	spendTokens(w, clk, 1, 0)
	if len(*breaches) != 1 || (*breaches)[0].Value != 1301 {
		t.Fatalf("breaches = %+v, want one at 1301", *breaches)
	}
}

// TestWindowCarryLeavesTheWindow: spend older than the span no longer counts, to the minute.
func TestWindowCarryLeavesTheWindow(t *testing.T) {
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour,
		[]CarryUse{carryOf(23*time.Hour+59*time.Minute, 600, 0), carryOf(25*time.Hour, 5000, 0)}, nil)
	if tok, _, _ := w.Windowed(); tok != 600 {
		t.Fatalf("at start the window holds %d, want 600 (the 25 h old spend is out)", tok)
	}
	clk.advance(3 * time.Minute) // the 600 is now past 24 h, with its minute
	spendTokens(w, clk, 900, 0)
	if len(*breaches) != 0 {
		t.Fatalf("breached on spend the window no longer holds: %+v", *breaches)
	}
}

// TestWindowSlidesWithinOneRun: a run that never restarts is held to the same window by its own spend.
func TestWindowSlidesWithinOneRun(t *testing.T) {
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, nil, nil)
	spendTokens(w, clk, 600, 0)
	clk.advance(25 * time.Hour)
	spendTokens(w, clk, 600, 0)
	if len(*breaches) != 0 {
		t.Fatalf("a day-old spend counted: %+v", *breaches)
	}
	clk.advance(time.Minute)
	spendTokens(w, clk, 500, 0)
	if len(*breaches) != 1 || (*breaches)[0].Value != 1100 {
		t.Fatalf("breaches = %+v, want one at 1100", *breaches)
	}
}

// TestWindowClockSetBack: a line stamped after the run began (the wall clock was set back) counts, as spent now, and
// leaves a window after this run's start, not days later.
func TestWindowClockSetBack(t *testing.T) {
	future := CarryUse{At: windowOrigin.Add(10 * 24 * time.Hour), Usage: ledger.TokenUsage{Model: windowModel, In: 700}}
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, []CarryUse{future}, nil)
	if tok, _, _ := w.Windowed(); tok != 700 {
		t.Fatalf("a line from the future is not counted: window holds %d", tok)
	}
	spendTokens(w, clk, 400, 0)
	if len(*breaches) != 1 {
		t.Fatalf("breaches = %+v, want one at 1100", *breaches)
	}
	clk.advance(24*time.Hour + 2*time.Minute)
	if tok, _, _ := w.Windowed(); tok != 0 {
		t.Fatalf("after a window from the run's start the future line still counts: %d", tok)
	}
}

// TestWindowWallStepDuringARunMovesNothing: a run's own spend is placed by the monotonic clock, so stepping the wall
// clock forward mid-run does not age it out of the window (and stepping it back does not keep it in).
func TestWindowWallStepDuringARunMovesNothing(t *testing.T) {
	w, clk, breaches := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, nil, nil)
	spendTokens(w, clk, 600, 0)
	clk.wall.Add(int64(48 * time.Hour)) // an NTP or an administrator's step; the monotonic clock does not move
	spendTokens(w, clk, 600, 0)
	if len(*breaches) != 1 || (*breaches)[0].Value != 1200 {
		t.Fatalf("breaches = %+v, want one at 1200: the wall step aged the first spend out", *breaches)
	}
}

// TestWindowCostCarryIsPricedByThisRunsTable: cost is carried as usage and priced with the run's table, cache
// included, a model the table lacks at the table's highest prices.
func TestWindowCostCarryIsPricedByThisRunsTable(t *testing.T) {
	ceiling := agent.ResolvedLimits{CostUSD: 5, Set: agent.BudgetCostUSD}
	carry := []CarryUse{
		{At: windowOrigin.Add(-time.Hour), Usage: ledger.TokenUsage{Model: windowModel, In: 1_000_000}},       // $3
		{At: windowOrigin.Add(-time.Hour), Usage: ledger.TokenUsage{Model: "not-in-the-table", Out: 100_000}}, // at the highest: $1.50
	}
	w, clk, breaches := newWindowWatcher(t, ceiling, 24*time.Hour, carry, testTable())
	if _, cost, _ := w.Windowed(); cost < 4.49 || cost > 4.51 {
		t.Fatalf("carry costs %v, want 4.50", cost)
	}
	w.Observe(response(clk.MonoNS(), windowModel, 100_000, 0, 0, 0)) // $0.30 more: 4.80
	if len(*breaches) != 0 {
		t.Fatalf("breached under the ceiling: %+v", *breaches)
	}
	w.Observe(response(clk.MonoNS(), windowModel, 100_000, 0, 0, 0)) // 5.10
	if len(*breaches) != 1 || (*breaches)[0].Which != "cost_usd" {
		t.Fatalf("breaches = %+v, want one cost_usd", *breaches)
	}
}

// TestWindowCacheDoesNotCountAsTokens: R1's rule holds across runs.
func TestWindowCacheDoesNotCountAsTokens(t *testing.T) {
	carry := []CarryUse{{At: windowOrigin.Add(-time.Hour), Usage: ledger.TokenUsage{Model: windowModel, In: 100, CacheRead: 5_000_000, CacheWrite: 5_000_000}}}
	w, _, _ := newWindowWatcher(t, tokenCeiling(1000), 24*time.Hour, carry, nil)
	if tok, _, _ := w.Windowed(); tok != 100 {
		t.Fatalf("window holds %d tokens, want 100", tok)
	}
}

// TestNoWindowCountsPerRun: without WithWindow nothing changes, and Windowed says so.
func TestNoWindowCountsPerRun(t *testing.T) {
	w, _, _, _, _ := newTestWatcher(t, tokenCeiling(1000), nil)
	if _, _, ok := w.Windowed(); ok {
		t.Fatal("a watcher with no window reports one")
	}
}

// Windowed (a test reading) is the tokens and estimated cost the window holds now, and whether the watcher counts over a window.
func (w *Watcher) Windowed() (tokens uint64, costUSD float64, ok bool) {
	if w.win == nil {
		return 0, 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	t, c := w.win.totals(w.win.now(w))
	return t, c, true
}
