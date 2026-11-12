// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAdoptionRecordsAnUnmeteredBudget: an adoption captures no model traffic (run_start.capture is off), so a tokens,
// cost_usd or repeats budget in its table, which a machine ceiling imposes on every contract (agent-contract R11),
// never trips. A tego run records that as gap what=record why=budget-unmetered right after run_start
// (limits-check-doctor-cli.md R32); an adoption said nothing in its record. It now records the same gap, one per
// such budget, and none where its table has no budget.
func TestAdoptionRecordsAnUnmeteredBudget(t *testing.T) {
	unmetered := func(rt func(*agent.RuleTable)) []string {
		t.Helper()
		f := newAdoptFixture(t)
		rt(f.rt)
		s, done := f.adoptRunning(t, context.Background(), f.spec(t))
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
		var out []string
		for _, ev := range events(t, s.Dir) {
			if ev.Kind != record.KindGap {
				continue
			}
			var g record.GapPayload
			if err := ev.DecodePayload(&g); err != nil {
				t.Fatal(err)
			}
			if g.Why == GapBudgetUnmetered {
				if g.What != record.GapRecord {
					t.Errorf("gap %+v, want what=record", g)
				}
				out = append(out, g.Binary)
			}
		}
		return out
	}
	got := unmetered(func(rt *agent.RuleTable) {
		rt.Limits.Tokens = 1000
		rt.Limits.CostUSD = 5
		rt.Limits.Set |= agent.BudgetTokens | agent.BudgetCostUSD
	})
	if !slices.Equal(got, []string{"tokens", "cost_usd"}) {
		t.Errorf("an adoption under a tokens and a cost_usd budget recorded budget-unmetered gaps for %v, want [tokens cost_usd]", got)
	}
	if got := unmetered(func(*agent.RuleTable) {}); len(got) != 0 {
		t.Errorf("an adoption with no budget recorded budget-unmetered gaps for %v", got)
	}
}
