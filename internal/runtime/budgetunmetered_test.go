// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnUnmeteredBudgetIsRecordedAsAGap: a tokens, cost_usd or repeats
// budget in a run that captures nothing (capture off, or the forwarder with no models: endpoint, which never
// starts) never trips, and the run exited 0 with only a capture gap that named no budget. The run now records
// gap what=record why=budget-unmetered for each such budget; a run whose capture runs, or one with no such
// budget, records none.
func TestAnUnmeteredBudgetIsRecordedAsAGap(t *testing.T) {
	budgeted := func(capture agent.CaptureMode) *agent.RuleTable {
		rt := &agent.RuleTable{Capture: capture}
		rt.Limits.Tokens = 1000
		rt.Limits.Repeats = 3
		rt.Limits.Wall = time.Minute
		rt.Limits.Set |= agent.BudgetTokens | agent.BudgetRepeats | agent.BudgetWall
		return rt
	}
	gaps := func(rt *agent.RuleTable, sources ...source.Source) []string {
		t.Helper()
		q := NewQueue(8)
		r := &runner{log: slog.New(slog.DiscardHandler), queue: q, rt: rt, deps: Deps{Capture: sources}}
		r.emitBudgetUnmeteredGaps()
		var out []string
		for {
			select {
			case ev := <-q.C():
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Kind != record.KindGap || p.What != record.GapRecord || p.Why != GapBudgetUnmetered {
					t.Fatalf("event %s payload %+v, want gap what=record why=%s", ev.Kind, p, GapBudgetUnmetered)
				}
				out = append(out, p.Binary)
			default:
				return out
			}
		}
	}
	for _, tc := range []struct {
		name    string
		rt      *agent.RuleTable
		sources []source.Source
		want    []string
	}{
		{"capture off", budgeted(agent.CaptureOff), nil, []string{"tokens", "repeats"}},
		{"forwarder that never started (no models:)", budgeted(agent.CaptureForwarder), nil, []string{"tokens", "repeats"}},
		{"forwarder running", budgeted(agent.CaptureForwarder), []source.Source{&plainSource{name: "forwarder"}}, nil},
		{"uprobe running", budgeted(agent.CaptureUprobe), []source.Source{&plainSource{name: "uprobe"}}, nil},
		{"no model budget", &agent.RuleTable{Capture: agent.CaptureOff}, nil, nil},
	} {
		if got := gaps(tc.rt, tc.sources...); !slices.Equal(got, tc.want) {
			t.Errorf("%s: gaps name %v, want %v", tc.name, got, tc.want)
		}
	}
}
