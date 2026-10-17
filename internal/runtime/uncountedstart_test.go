// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/capture"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestADeclaredBudgetNothingCountsIsRefused is limits-check-doctor-cli.md R32's refusal of a budget the contract
// declares and nothing counts (the custom-agent POC, item 1): a tokens, cost_usd or repeats budget under capture:
// off, a machine capture ceiling of off, a forwarder with no models: endpoint or record: off under uprobe capture,
// and a cost_usd budget with no price table, each ran with only a compile warning and a gap why=budget-unmetered,
// exiting as the agent did. Each is now refused with ErrBudgetUnmetered naming the budget, the cause and the fix. A
// budget a machine ceiling alone imposes keeps its gap, and a run whose capture runs, with a price table where it
// needs one, starts.
func TestADeclaredBudgetNothingCountsIsRefused(t *testing.T) {
	type budget struct{ tokens, cost, repeats bool }
	table := func(capture agent.CaptureMode, declared, imposed budget) *agent.RuleTable {
		rt := &agent.RuleTable{Capture: capture, Record: agent.RecordFull, Contract: &agent.Contract{}}
		rt.Limits.Wall = time.Minute
		rt.Limits.Set |= agent.BudgetWall
		if declared.tokens || imposed.tokens {
			rt.Limits.Tokens, rt.Limits.Set = 1000, rt.Limits.Set|agent.BudgetTokens
		}
		if declared.cost || imposed.cost {
			rt.Limits.CostUSD, rt.Limits.Set = 1, rt.Limits.Set|agent.BudgetCostUSD
		}
		if declared.repeats || imposed.repeats {
			rt.Limits.Repeats, rt.Limits.Set = 3, rt.Limits.Set|agent.BudgetRepeats
		}
		if declared.tokens {
			rt.Contract.Limits.Tokens = new(int64(1000))
		}
		if declared.cost {
			rt.Contract.Limits.CostUSD = new(1.0)
		}
		if declared.repeats {
			rt.Contract.Limits.Repeats = new(3)
		}
		return rt
	}
	tokens := budget{tokens: true}
	off := table(agent.CaptureOff, budget{tokens: true, repeats: true}, budget{})
	off.Contract.Capture = agent.CaptureOff
	recordOff := table(agent.CaptureUprobe, tokens, budget{})
	recordOff.Record = agent.RecordOff
	noModels := []source.Gap{{What: record.GapCapture, Why: capture.GapNoModels, Binary: "forwarder"}}
	// record: off where the run captures with the forwarder (every unprivileged run): the forwarder records under
	// record: off and no uprobe runs, so the cause is the missing models: endpoint. The refusal blamed record: off
	// and offered "set record: summary", which only led to a second refusal.
	fwdRecordOff := table(agent.CaptureForwarder, tokens, budget{})
	fwdRecordOff.Record = agent.RecordOff
	autoRecordOff := table(agent.CaptureAuto, tokens, budget{})
	autoRecordOff.Record = agent.RecordOff
	forwarder := []source.Source{&plainSource{name: "forwarder"}}
	// A table that loads and lists models, none with both an input and an output price: it prices no model, as one
	// that lists none does, and one complete entry prices the run.
	loadTable := func(body string) *limits.PriceTable {
		path := filepath.Join(t.TempDir(), "prices.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		pt, err := limits.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return pt
	}
	partial := loadTable("version: 1\nmodels:\n  claude-x: {}\n  m: {input_per_mtok: 1}\n")
	complete := loadTable("version: 1\nmodels:\n  m: {input_per_mtok: 1, output_per_mtok: 5}\n")
	for _, tc := range []struct {
		name     string
		rt       *agent.RuleTable
		sources  []source.Source
		gaps     []source.Gap
		priceGap string
		refused  []string // substrings the refusal names; nil when the run starts
		prices   *limits.PriceTable
	}{
		{"capture off by the contract", off, nil, nil, "",
			[]string{"the tokens, repeats budget cannot be counted", "the contract sets capture: off", "Fix: set capture: auto, or remove the budget"}, nil},
		{"capture off by the machine", table(agent.CaptureOff, tokens, budget{}), nil, nil, "",
			[]string{"the tokens budget", "the machine config's capture: ceiling", "Fix: raise the machine config's capture: ceiling"}, nil},
		{"a forwarder with no models:", table(agent.CaptureForwarder, tokens, budget{}), nil, noModels, "",
			[]string{"no models: endpoint is declared", "Fix: declare the model endpoint under models:"}, nil},
		{"record: off under uprobe capture", recordOff,
			[]source.Source{&causedInert{plainSource{name: "uprobe"}, "record: off keeps no model traffic, so no probe is placed"}}, nil, "",
			[]string{"record: off, under which the uprobe capture captures nothing", "Fix: set record: summary"}, nil},
		{"record: off with a forwarder and no models:", fwdRecordOff, nil, noModels, "",
			[]string{"no models: endpoint is declared", "Fix: declare the model endpoint under models:"}, nil},
		{"record: off with auto capture and no models:", autoRecordOff, nil, noModels, "",
			[]string{"no models: endpoint is declared", "Fix: declare the model endpoint under models:"}, nil},
		{"record: off with a forwarder and no gap", fwdRecordOff, nil, nil, "",
			[]string{"no capture source runs for this run"}, nil},
		{"cost_usd with no price table", table(agent.CaptureForwarder, budget{cost: true}, budget{}), forwarder, nil, "no-price-table",
			[]string{"the cost_usd budget cannot be counted", "no price table that lists a model loaded (no-price-table)", "bound the run with tokens instead"}, nil},
		{"a machine ceiling alone, capture off", table(agent.CaptureOff, budget{}, budget{tokens: true, cost: true}), nil, noModels, "no-price-table", nil, nil},
		{"tokens with no price table", table(agent.CaptureForwarder, tokens, budget{}), forwarder, nil, "no-price-table", nil, nil},
		{"the forwarder running", table(agent.CaptureForwarder, budget{tokens: true, cost: true}, budget{}), forwarder, nil, "", nil, nil},
		{"no model budget", table(agent.CaptureOff, budget{}, budget{}), nil, nil, "", nil, nil},
		{"cost_usd under a table that prices no model", table(agent.CaptureForwarder, budget{cost: true}, budget{}), forwarder, nil, "",
			[]string{"the cost_usd budget cannot be counted", "the price table " + partial.Path + " prices no model",
				"give a model entry both input_per_mtok and output_per_mtok"}, partial},
		// A ceiling alone is not refused: the watcher ends the run at its first response, which no price bounds.
		{"a machine ceiling alone under a table that prices no model", table(agent.CaptureForwarder, budget{}, budget{cost: true}), forwarder, nil, "", nil, partial},
		{"cost_usd under a table that prices a model", table(agent.CaptureForwarder, budget{cost: true}, budget{}), forwarder, nil, "", nil, complete},
	} {
		r := &runner{log: slog.New(slog.DiscardHandler), rt: tc.rt,
			deps: Deps{Capture: tc.sources, CaptureGaps: tc.gaps, PriceGap: tc.priceGap, Prices: tc.prices}}
		if err := r.refuseUnmeteredBudget(); err != nil {
			t.Errorf("%s: refused as a mechanism that failed: %v", tc.name, err)
		}
		err := r.refuseUncountedBudget()
		if tc.refused == nil {
			if err != nil {
				t.Errorf("%s: refused: %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrBudgetUnmetered) {
			t.Errorf("%s: err %v, want ErrBudgetUnmetered", tc.name, err)
			continue
		}
		for _, want := range tc.refused {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q does not name %q", tc.name, err, want)
			}
		}
	}
}
