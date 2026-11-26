// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gateSource is a capture source that admits model requests itself and takes the run's gate (LimitGateSetter).
type gateSource struct {
	plainSource
	gate func() (string, record.Reason, bool)
}

func (s *gateSource) SetLimitGate(g func() (string, record.Reason, bool)) { s.gate = g }

// TestTheLimitGateIsWiredOnlyWhereABudgetCanCross: a source that admits requests gets the watcher's gate when the contract
// bounds tokens, cost_usd, repeats, wall or stall_after (a bound of 0 included, E16), and nothing otherwise, so the request
// path of a run with no such budget is the one it always was. A source that only reads the agent's TLS has no gate to take.
// The gate it gets says closed only once the budget has crossed, and names the budget's rule and reason.
func TestTheLimitGateIsWiredOnlyWhereABudgetCanCross(t *testing.T) {
	for _, c := range []struct {
		name  string
		lim   agent.ResolvedLimits
		wired bool
	}{
		{"none", agent.ResolvedLimits{}, false},
		{"memory only", agent.ResolvedLimits{Set: agent.BudgetMemory, MemoryB: 1 << 30}, false},
		{"tokens", agent.ResolvedLimits{Set: agent.BudgetTokens, Tokens: 100}, true},
		{"cost_usd", agent.ResolvedLimits{Set: agent.BudgetCostUSD, CostUSD: 1}, true},
		{"repeats zero", agent.ResolvedLimits{Set: agent.BudgetRepeats}, true},
		{"wall", agent.ResolvedLimits{Set: agent.BudgetWall, Wall: 1e9}, true},
		{"stall_after", agent.ResolvedLimits{Set: agent.BudgetStallAfter, StallAfter: 1e9}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := &gateSource{plainSource: plainSource{name: "forwarder"}}
			r := newTestRunner(Deps{Capture: []source.Source{src, &plainSource{name: "uprobe"}}})
			r.rt, r.queue = &agent.RuleTable{Limits: c.lim}, NewQueue(4)
			r.newBudget()
			r.wireLimitGate()
			if (src.gate != nil) != c.wired {
				t.Fatalf("gate wired %v for limits %+v, want %v", src.gate != nil, c.lim, c.wired)
			}
			if src.gate == nil {
				return
			}
			if _, _, closed := src.gate(); closed {
				t.Fatal("the gate is closed before any budget crossed")
			}
		})
	}
}

// TestTheLimitGateClosesWithTheWatcher: the run's gate reads the watcher itself, so it closes when the budget is crossed and
// reports rule limits.<which> and the budget's reason code, the pair a refused request is recorded under.
func TestTheLimitGateClosesWithTheWatcher(t *testing.T) {
	src := &gateSource{plainSource: plainSource{name: "forwarder"}}
	r := newTestRunner(Deps{Capture: []source.Source{src}})
	r.rt, r.queue = &agent.RuleTable{Limits: agent.ResolvedLimits{Set: agent.BudgetRepeats, Repeats: 2}}, NewQueue(4)
	r.newBudget()
	r.wireLimitGate()
	for i := range 2 {
		ev := &record.Event{Kind: record.KindDecision, Source: record.SourceForwarder, MonoNS: uint64(1_000 + i)}
		if err := ev.SetPayload(record.DecisionPayload{Step: 1, Tool: "read_file", InputHash: "h"}); err != nil {
			t.Fatal(err)
		}
		r.budget.Observe(ev)
	}
	rule, reason, closed := src.gate()
	if !closed || rule != "limits.repeats" || reason != record.ReasonLimitRepeats {
		t.Fatalf("gate = %q, %q, %v after the repeats ceiling, want limits.repeats, limit-repeats, true", rule, reason, closed)
	}
}
