// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A table that names no server_tool_per_request fee at all charged 1000 web searches $0 toward a cost ceiling.
// MaxCost now declines to bound them, and under a cost budget the response is reported unmetered, which ends
// the run as an unreadable exchange does; with no cost budget nothing is reported (ADR 0037 amendment
// 2026-09-24).
func TestMaxCostServerToolWithNoFees(t *testing.T) {
	tab := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"m": {InputPerMTok: 1}}}
	u := ledger.TokenUsage{Model: "m", ServerTool: map[string]int{"web_search_requests": 1000}}
	if _, ok := tab.Cost(u); ok {
		t.Fatal("priced")
	}
	if c, ok := tab.MaxCost(u); ok {
		t.Errorf("1000 unpriced web searches charged %v toward a cost ceiling, want no bound", c)
	}
	if !tab.UnfeedServerTool(u) {
		t.Error("UnfeedServerTool is false for server-tool requests and a table with no fee")
	}
	// Without server-tool requests the table bounds the response as before.
	if _, ok := tab.MaxCost(ledger.TokenUsage{Model: "x", In: 10}); !ok {
		t.Error("a response with no server-tool requests lost its bound")
	}

	for _, tc := range []struct {
		name   string
		limits agent.ResolvedLimits
		want   int
	}{
		{"cost budget", agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, 1},
		{"tokens budget only", agent.ResolvedLimits{Tokens: 1 << 30, Set: agent.BudgetTokens}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reports int
			w := NewWatcher(tc.limits, tab, &fakeKiller{}, cgroup.Cgroup{}, &fakeClock{}, &fakeSink{},
				WithOnUnmetered(func(n int64, _ string) { reports += int(n) }))
			w.Observe(runStart(1_000))
			w.Observe(usageResponse(2_000, "m", record.Usage{Input: 1,
				ServerTool: map[string]int{"web_search_requests": 1000}}))
			if reports != tc.want {
				t.Errorf("%d unmetered reports, want %d", reports, tc.want)
			}
		})
	}
}

// A table that names models but prices none (every entry partial) bounds nothing: under a cost budget the
// response is unmetered rather than passing at $0 in silence.
func TestCostBudgetUnmeteredWhenTablePricesNoModel(t *testing.T) {
	tab := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"m": {partial: true, InputPerMTok: 1}}}
	var reports int
	w := NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, tab, &fakeKiller{},
		cgroup.Cgroup{}, &fakeClock{}, &fakeSink{}, WithOnUnmetered(func(n int64, _ string) { reports += int(n) }))
	w.Observe(runStart(1_000))
	w.Observe(usageResponse(2_000, "m", record.Usage{Input: 5}))
	if reports != 1 {
		t.Errorf("%d unmetered reports, want 1", reports)
	}
}

// A cost that overflowed to +Inf still leaves its limit event, with the value clamped.
func TestLimitEventSurvivesInfiniteCost(t *testing.T) {
	tab := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"m": {InputPerMTok: 1e305, OutputPerMTok: 1}}}
	sink := &fakeSink{}
	w := NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, tab, &fakeKiller{},
		cgroup.Cgroup{}, &fakeClock{}, sink)
	w.Observe(runStart(1_000))
	w.Observe(usageResponse(2_000, "m", record.Usage{Input: 10_000_000_000}))
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			return
		}
	}
	t.Error("no limit event for a non-finite cost")
}
