// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// causedInert is a capture source that started and captures nothing: its own gap says its mechanism is not
// running, with the cause it can name.
type causedInert struct {
	plainSource
	cause string
}

func (s *causedInert) Gaps() []source.Gap {
	return []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: s.name}}
}
func (s *causedInert) UnavailableCause() string { return s.cause }

// TestABudgetWhoseCaptureCannotStartIsRefused is limits-check-doctor-cli.md R32's fail-closed half: a run with
// a tokens, cost_usd or repeats budget whose capture mechanism was given to it and could not start is refused
// before run_start with ErrCaptureUnavailable naming the budgets, the cause and the fix. A run without such a
// budget, one whose capture runs, one whose capture is off by the contract, a forwarder with no models:, and a
// record: off run are not this refusal's: refuseUncountedBudget refuses them when the contract declares the budget
// (TestADeclaredBudgetNothingCountsIsRefused), and a budget a machine ceiling alone imposes keeps its gap.
func TestABudgetWhoseCaptureCannotStartIsRefused(t *testing.T) {
	budgeted := func(capture agent.CaptureMode, set agent.BudgetSet) *agent.RuleTable {
		rt := &agent.RuleTable{Capture: capture, Record: agent.RecordFull}
		rt.Limits.Wall = time.Minute
		if set&agent.BudgetTokens != 0 {
			rt.Limits.Tokens = 1000
		}
		if set&agent.BudgetCostUSD != 0 {
			rt.Limits.CostUSD = 1
		}
		if set&agent.BudgetRepeats != 0 {
			rt.Limits.Repeats = 3
		}
		rt.Limits.Set |= set | agent.BudgetWall
		return rt
	}
	unavailable := []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: "uprobe"}}
	for _, tc := range []struct {
		name    string
		rt      *agent.RuleTable
		sources []source.Source
		gaps    []source.Gap
		refused []string // substrings the refusal names; nil when the run starts
	}{
		{"uprobe source inert under a tokens budget", budgeted(agent.CaptureUprobe, agent.BudgetTokens),
			[]source.Source{&causedInert{plainSource{name: "uprobe"}, "this run has no capture ring: the host's bpf.ring_budget had no room for it"}}, nil,
			[]string{"tokens budget cannot be metered, so the run is refused rather than run unmetered: the uprobe capture did not start (this run has no capture ring: the host's bpf.ring_budget had no room for it)", "Fix:"}},
		{"selection gap under cost and repeats budgets", budgeted(agent.CaptureUprobe, agent.BudgetCostUSD|agent.BudgetRepeats),
			nil, unavailable, []string{"cost_usd, repeats budget", "the uprobe capture is not available to this run"}},
		// The table's capture is uprobe, so it guards no models[] endpoint (agent.RuleTable.GuardedModels): with the
		// probes not running, a direct connection to the model is neither captured nor refused, and the forwarder
		// beside them meters only what the agent chooses to send it. The run started.
		{"uprobe inert, forwarder running", budgeted(agent.CaptureUprobe, agent.BudgetTokens),
			[]source.Source{&causedInert{plainSource{name: "uprobe"}, "x"}, &plainSource{name: "forwarder"}}, nil,
			[]string{"tokens budget cannot be metered on a direct connection to the model, which", "the uprobe capture did not start (x)", "capture: forwarder"}},
		{"uprobe selection gap, forwarder running", budgeted(agent.CaptureUprobe, agent.BudgetCostUSD),
			[]source.Source{&plainSource{name: "forwarder"}}, unavailable,
			[]string{"cost_usd budget", "a direct connection to the model", "the uprobe capture is not available to this run"}},
		{"uprobe never selected, forwarder running", budgeted(agent.CaptureUprobe, agent.BudgetTokens),
			[]source.Source{&plainSource{name: "forwarder"}}, nil, []string{"tokens budget", "the uprobe capture is not running for this run"}},
		{"forwarder capture, forwarder running", budgeted(agent.CaptureForwarder, agent.BudgetTokens),
			[]source.Source{&plainSource{name: "forwarder"}}, nil, nil},
		{"uprobe and forwarder running", budgeted(agent.CaptureUprobe, agent.BudgetTokens),
			[]source.Source{&plainSource{name: "uprobe"}, &plainSource{name: "forwarder"}}, nil, nil},
		{"uprobe inert, forwarder running, no model budget", budgeted(agent.CaptureUprobe, 0),
			[]source.Source{&causedInert{plainSource{name: "uprobe"}, "x"}, &plainSource{name: "forwarder"}}, nil, nil},
		{"uprobe inert, no model budget", budgeted(agent.CaptureUprobe, 0),
			[]source.Source{&causedInert{plainSource{name: "uprobe"}, "x"}}, nil, nil},
		{"capture off by the contract", budgeted(agent.CaptureOff, agent.BudgetTokens), nil, nil, nil},
		{"forwarder with no models:", budgeted(agent.CaptureForwarder, agent.BudgetTokens), nil,
			[]source.Gap{{What: record.GapCapture, Why: "no-models", Binary: "forwarder"}}, nil},
		{"uprobe running", budgeted(agent.CaptureUprobe, agent.BudgetTokens), []source.Source{&plainSource{name: "uprobe"}}, nil, nil},
	} {
		r := &runner{log: slog.New(slog.DiscardHandler), rt: tc.rt, deps: Deps{Capture: tc.sources, CaptureGaps: tc.gaps}}
		err := r.refuseUnmeteredBudget()
		if tc.refused == nil {
			if err != nil {
				t.Errorf("%s: refused: %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrCaptureUnavailable) {
			t.Errorf("%s: err %v, want ErrCaptureUnavailable", tc.name, err)
			continue
		}
		for _, want := range tc.refused {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q does not name %q", tc.name, err, want)
			}
		}
	}

	off := budgeted(agent.CaptureUprobe, agent.BudgetTokens)
	off.Record = agent.RecordOff
	r := &runner{log: slog.New(slog.DiscardHandler), rt: off,
		deps: Deps{Capture: []source.Source{&causedInert{plainSource{name: "uprobe"}, "record: off"}}}}
	if err := r.refuseUnmeteredBudget(); err != nil {
		t.Errorf("record: off: refused as a mechanism that failed: %v; it is refuseUncountedBudget's", err)
	}

	// An --observe run refuses nothing, a direct connection to the model included, so its forwarder running beside no
	// probe is no budget it can newly go around; at tier landlock the table's capture is the forwarder already (AtTier).
	for _, tier := range []backend.Tier{backend.TierObserve, backend.TierLandlock} {
		rt := budgeted(agent.CaptureUprobe, agent.BudgetTokens)
		rt.Tier = tier
		r := &runner{log: slog.New(slog.DiscardHandler), rt: rt, deps: Deps{Capture: []source.Source{&plainSource{name: "forwarder"}}}}
		if err := r.refuseUnmeteredBudget(); err != nil {
			t.Errorf("tier %s, forwarder running: refused: %v", tier, err)
		}
	}

	// Under record: off a forwarder the run was given and that could not start (its listen address held by another
	// process) is a mechanism that failed, refused [capture-unavailable] naming it, as under record: summary. It was
	// passed over for every record: off run and reached refuseUncountedBudget, whose [budget-unmetered] told a
	// contract that declares models: to declare them.
	for _, capture := range []agent.CaptureMode{agent.CaptureForwarder, agent.CaptureUprobe} {
		fwd := budgeted(capture, agent.BudgetTokens)
		fwd.Record = agent.RecordOff
		fwd.Contract = &agent.Contract{Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}}}
		fwd.Contract.Limits.Tokens = new(int64(1000))
		var sources []source.Source
		if capture == agent.CaptureUprobe {
			sources = []source.Source{&causedInert{plainSource{name: "uprobe"}, "record: off"}}
		}
		r := &runner{log: slog.New(slog.DiscardHandler), rt: fwd, deps: Deps{Capture: sources,
			CaptureGaps: []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: "forwarder"}}}}
		err := r.refuseUnmeteredBudget()
		if !errors.Is(err, ErrCaptureUnavailable) || !strings.Contains(err.Error(), "the forwarder capture is not available to this run") ||
			strings.Contains(err.Error(), "uprobe") {
			t.Errorf("record: off, capture %s, the forwarder failed: err %v, want ErrCaptureUnavailable naming the forwarder alone", capture, err)
		}
		requireForwarderFixAlone(t, "record: off, capture "+string(capture), err)
	}

	// A forwarder that could not start is the only cause at tier landlock under record: summary too. Its fix is the
	// forwarder's own: it led with ring-budget advice a run with no rings cannot use, and told a contract that
	// captures with the forwarder and declares models: to do so.
	fwd := budgeted(agent.CaptureForwarder, agent.BudgetTokens)
	fwd.Tier = backend.TierLandlock
	r = &runner{log: slog.New(slog.DiscardHandler), rt: fwd, deps: Deps{
		CaptureGaps: []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: "forwarder"}}}}
	requireForwarderFixAlone(t, "record: summary, tier landlock", r.refuseUnmeteredBudget())

	// Both mechanisms failed: each one's fix is given.
	both := budgeted(agent.CaptureUprobe, agent.BudgetTokens)
	r = &runner{log: slog.New(slog.DiscardHandler), rt: both, deps: Deps{
		Capture:     []source.Source{&causedInert{plainSource{name: "uprobe"}, "this run has no capture ring"}},
		CaptureGaps: []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: "forwarder"}}}}
	if err := r.refuseUnmeteredBudget(); !errors.Is(err, ErrCaptureUnavailable) ||
		!strings.Contains(err.Error(), "bpf.ring_budget") || !strings.Contains(err.Error(), "forwarder.listen") {
		t.Errorf("the uprobe and the forwarder failed: err %v, want ErrCaptureUnavailable with both fixes", err)
	}
}

// requireForwarderFixAlone fails the test unless err is the capture-unavailable refusal of a forwarder that could not
// start, whose fix names the forwarder's listen address and gives neither the ring-budget advice nor capture: forwarder.
func requireForwarderFixAlone(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, ErrCaptureUnavailable) {
		t.Errorf("%s: err %v, want ErrCaptureUnavailable", name, err)
		return
	}
	_, fix, _ := strings.Cut(err.Error(), "Fix: ")
	if !strings.Contains(fix, "forwarder.listen") || strings.Contains(fix, "ring_budget") || strings.Contains(fix, "capture: forwarder") {
		t.Errorf("%s: the fix %q, want the forwarder's own (its forwarder.listen address) and nothing else", name, fix)
	}
}
