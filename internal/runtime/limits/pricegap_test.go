// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestWithPriceGapKeepsTheRunToOneTableGap is E15's "once" and R32 read together: the facade records
// why the run has no table right after run_start, and the watcher, told so, must not add a second
// no-price-table gap on the first response. For a version-mismatch run the second gap would also
// contradict the first, naming a different cause for the same missing table.
//
// The per-model gap is a different fact (one model missing from a table that did load) and is not
// suppressed; that case never reaches here with a nil table, so only the whole-table key is seeded.
func TestWithPriceGapKeepsTheRunToOneTableGap(t *testing.T) {
	for _, why := range []string{GapNoPriceTable, GapVersionMismatch} {
		t.Run(why, func(t *testing.T) {
			sink, clk := &fakeSink{}, &fakeClock{}
			w := NewWatcher(agent.ResolvedLimits{}, nil, &fakeKiller{}, cgroup.Cgroup{}, clk, sink,
				WithPriceGap(why))
			w.Observe(runStart(1_000))
			for i := range 3 {
				w.Observe(response(uint64(2_000+i), "claude-sonnet-4-5-20250929", 100, 10, 0, 0))
			}
			if gaps := sink.kinds(record.KindGap); len(gaps) != 0 {
				var p record.GapPayload
				_ = gaps[0].DecodePayload(&p)
				t.Fatalf("the watcher recorded %d gap(s), first %+v; the run already has its %s gap",
					len(gaps), p, why)
			}
			if s := w.Snapshot(); s.Tokens() != 330 || s.Unpriced != 3 {
				t.Fatalf("state %+v: an unpriced response must still count its tokens", s)
			}
		})
	}

	// An empty reason is a table that loaded: nothing is seeded, and a table with no rows still
	// gets the one gap the watcher owns.
	sink := &fakeSink{}
	w := NewWatcher(agent.ResolvedLimits{}, &PriceTable{Version: PriceVersion}, &fakeKiller{},
		cgroup.Cgroup{}, &fakeClock{}, sink, WithPriceGap(""))
	w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 1, 1, 0, 0))
	if gaps := sink.kinds(record.KindGap); len(gaps) != 1 {
		t.Fatalf("%d gaps for an empty table with no reason seeded, want the watcher's own one", len(gaps))
	}
}

// TestAnUnpricedModelIsChargedAtTheTablesTopPrice: under a cost budget, a response of a
// model the table does not name is charged toward the ceiling at the table's highest price per counter, so a
// model the table has not caught up with is not free spend. CostUSD, the estimate, stays the table's own.
func TestAnUnpricedModelIsChargedAtTheTablesTopPrice(t *testing.T) {
	table := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{
		"cheap": {InputPerMTok: 1, OutputPerMTok: 5},
		"dear":  {InputPerMTok: 15, OutputPerMTok: 75},
	}}
	sink, killer := &fakeSink{}, &fakeKiller{}
	w := NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, table, killer,
		cgroup.Cgroup{}, &fakeClock{}, sink)
	w.Observe(runStart(1_000))
	w.Observe(response(2_000, "claude-next", 50_000, 5_000, 0, 0)) // 0.75 + 0.375 at the dear prices
	b, tripped := w.Tripped()
	if !tripped || b.Which != record.LimitCostUSD {
		t.Fatalf("an unpriced response worth $1.125 at the table's top price did not trip a $1 budget (%+v)", w.Snapshot())
	}
	if s := w.Snapshot(); s.CostUSD != 0 || s.Unpriced != 1 {
		t.Errorf("state %+v: the estimate must stay the table's own", s)
	}
	// With no cost budget nothing is charged.
	w2 := NewWatcher(agent.ResolvedLimits{}, table, &fakeKiller{}, cgroup.Cgroup{}, &fakeClock{}, &fakeSink{})
	w2.Observe(response(2_000, "claude-next", 50_000, 5_000, 0, 0))
	if s := w2.Snapshot(); s.UnpricedMaxUSD != 0 {
		t.Errorf("an unbudgeted run charged %v", s.UnpricedMaxUSD)
	}
}

// usageResponse builds one ssl_response carrying u whole.
func usageResponse(mono uint64, model string, u record.Usage) *record.Event {
	ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, MonoNS: mono}
	must(ev.SetPayload(record.SSLResponsePayload{Model: model, Status: 200, ParserVersion: "1", Usage: &u}))
	return ev
}

// TestNewUsageCountersAreCharged: a cost budget counts 1-hour cache writes at their own
// rate and web search requests at their fee, where it charged the one as 5-minute writes and the other nothing.
func TestNewUsageCountersAreCharged(t *testing.T) {
	oneHour := 6.0
	table := &PriceTable{Version: PriceVersion,
		Models:               map[string]ModelPrice{"m": {CacheWritePerMTok: 3.75, CacheWrite1hPerMTok: &oneHour}},
		ServerToolPerRequest: map[string]float64{"web_search_requests": 0.01}}
	for _, tc := range []struct {
		name string
		u    record.Usage
	}{
		// $0.9375 as 5-minute writes, under the $1 budget; $1.50 at the 1-hour rate.
		{"1-hour cache writes", record.Usage{CacheWrite: 250_000, CacheWrite1h: 250_000}},
		// Nothing as tokens; $1.10 in fees.
		{"web search requests", record.Usage{Input: 1, ServerTool: map[string]int{"web_search_requests": 110}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, table, &fakeKiller{},
				cgroup.Cgroup{}, &fakeClock{}, &fakeSink{})
			w.Observe(runStart(1_000))
			w.Observe(usageResponse(2_000, "m", tc.u))
			if b, tripped := w.Tripped(); !tripped || b.Which != record.LimitCostUSD {
				t.Fatalf("a $1 budget did not trip (%+v)", w.Snapshot())
			}
			if s := w.Snapshot(); s.Unpriced != 0 {
				t.Errorf("state %+v: the response was priced", s)
			}
		})
	}
}

// TestAnUnpricedUsageCounterIsAnUnpricedModel pins the fail-closed rule: a response of a model the table
// prices, reporting a counter the table has no price for (1-hour writes with no 1-hour rate, a server tool
// with no fee), is handled as an unpriced model is: no estimate, the unpriced-model gap naming the model, and the
// response charged at the table's top prices toward a cost ceiling.
func TestAnUnpricedUsageCounterIsAnUnpricedModel(t *testing.T) {
	table := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"m": {InputPerMTok: 1, CacheWritePerMTok: 4}},
		ServerToolPerRequest: map[string]float64{"web_search_requests": 0.01}}
	for _, tc := range []struct {
		name string
		u    record.Usage
	}{
		{"1-hour writes with no 1-hour rate", record.Usage{CacheWrite: 300_000, CacheWrite1h: 300_000}},    // $1.20 at 4/MTok
		{"a server tool with no fee", record.Usage{ServerTool: map[string]int{"web_fetch_requests": 120}}}, // $1.20 at the top fee
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeSink{}
			w := NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, table, &fakeKiller{},
				cgroup.Cgroup{}, &fakeClock{}, sink)
			w.Observe(runStart(1_000))
			w.Observe(usageResponse(2_000, "m", tc.u))
			s := w.Snapshot()
			if s.Unpriced != 1 || s.CostUSD != 0 {
				t.Fatalf("state %+v, want one unpriced response and no estimate", s)
			}
			gaps := sink.kinds(record.KindGap)
			if len(gaps) != 1 {
				t.Fatalf("%d gaps, want the unpriced-model one", len(gaps))
			}
			var p record.GapPayload
			if err := gaps[0].DecodePayload(&p); err != nil || p.Why != GapUnpricedModel || p.Binary != "m" {
				t.Errorf("gap %+v %v, want why=%s binary=m", p, err, GapUnpricedModel)
			}
			if b, tripped := w.Tripped(); !tripped || b.Which != record.LimitCostUSD {
				t.Errorf("a $1 budget did not trip at the table's top prices (%+v)", s)
			}
		})
	}
}
