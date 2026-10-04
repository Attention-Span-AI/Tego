// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A response billed under a modifier the token counters do not show (fast speed, a priority tier, geo pinning,
// extra iterations) was priced at the base rate, so a cost ceiling fired late by the size of the premium. It is
// now unpriced, and a cost budget charges it at MaxCost, which carries the premium.
func TestModifiedResponseIsUnpricedAndChargedAtMaxCost(t *testing.T) {
	table := &PriceTable{Version: PriceVersion, Models: map[string]ModelPrice{"m": {InputPerMTok: 4, OutputPerMTok: 20}}}
	plain := ledger.TokenUsage{Model: "m", In: 1_000_000}
	fast := plain
	fast.Modified = true
	if c, ok := table.Cost(plain); !ok || !nearly(c, 4) {
		t.Fatalf("plain response: cost %v priced %v, want 4", c, ok)
	}
	if _, ok := table.Cost(fast); ok {
		t.Error("a modified response was priced at the base rate")
	}
	if c, ok := table.MaxCost(fast); !ok || !nearly(c, 8) {
		t.Errorf("MaxCost of a modified response = %v (%v), want 8: the base 4 at the fast-mode premium", c, ok)
	}

	// $8 at the premium is over a $5 ceiling; $4 at the base rate is under it.
	w := NewWatcher(agent.ResolvedLimits{CostUSD: 5, Set: agent.BudgetCostUSD}, table, &fakeKiller{},
		cgroup.Cgroup{}, &fakeClock{}, &fakeSink{})
	w.Observe(runStart(1_000))
	w.Observe(usageResponse(2_000, "m", record.Usage{Input: 1_000_000, Modified: true}))
	if b, tripped := w.Tripped(); !tripped || b.Which != record.LimitCostUSD {
		t.Errorf("a fast-mode response worth $8 did not trip a $5 budget (%+v)", w.Snapshot())
	}
}
