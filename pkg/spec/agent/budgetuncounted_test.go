// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// uncountedWarnings is the budget-uncounted findings among ds.
func uncountedWarnings(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Code == CodeBudgetUncounted {
			out = append(out, d)
		}
	}
	return out
}

// A token or cost budget beside a models: entry whose provider declares an API style Tego does not count is a warning
// (not a refusal) at that entry's line: the run would end at the model's first answer. A counted provider, a contract
// with no such budget, one with only repeats or wall, and capture: off (which budget-unmetered answers) are not warned.
func TestABudgetBesideAnUncountedModelWarns(t *testing.T) {
	const base = "version: 0\nname: uncounted\ncommand: [\"/bin/sh\"]\n"
	const anthropicModel = "models:\n  - {provider: anthropic, host: api.anthropic.com, port: 443}\n"
	const other = "models:\n  - {provider: acme-llm, host: llm.example.com, port: 443}\n"
	for _, tc := range []struct {
		name, extra string
		want        int
		mentions    string
	}{
		{"tokens, an uncounted provider", other + "capture: forwarder\nlimits: {tokens: 1000}\n", 1, "limits.tokens"},
		{"cost, an uncounted provider", other + "capture: forwarder\nlimits: {cost_usd: 1}\n", 1, "limits.cost_usd"},
		{"both, said once for the entry", other + "capture: forwarder\nlimits: {tokens: 1000, cost_usd: 1}\n", 1, "limits.tokens and limits.cost_usd"},
		{"two uncounted entries", "models:\n  - {provider: acme-llm, host: llm.example.com, port: 443}\n  - {provider: other, host: o.example.com, port: 443}\ncapture: forwarder\nlimits: {tokens: 5}\n", 2, ""},
		{"openai is counted", "models:\n  - {provider: openai, host: api.openai.com, port: 443}\ncapture: forwarder\nlimits: {tokens: 1000}\n", 0, ""},
		{"a counted provider", anthropicModel + "capture: forwarder\nlimits: {tokens: 1000}\n", 0, ""},
		{"the provider's case", "models:\n  - {provider: Anthropic, host: api.anthropic.com, port: 443}\ncapture: forwarder\nlimits: {tokens: 1000}\n", 0, ""},
		{"no token or cost budget", other + "capture: forwarder\nlimits: {repeats: 3, wall: 1h}\n", 0, ""},
		{"capture off is budget-unmetered's", other + "capture: off\nlimits: {tokens: 1000}\n", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.load(base + tc.extra)
			_, ds := f.compile(c, WithTiers(backend.TierLandlock))
			got := uncountedWarnings(ds)
			if len(got) != tc.want {
				t.Fatalf("%d findings, want %d:\n%s", len(got), tc.want, render(ds))
			}
			for _, d := range got {
				if d.Severity != SeverityWarning {
					t.Errorf("severity %v, want a warning: %+v", d.Severity, d)
				}
				if !strings.Contains(d.Message, tc.mentions) || !strings.Contains(d.Message, CountedAPIWords()) {
					t.Errorf("the message %q does not name %q and the counted styles %q", d.Message, tc.mentions, CountedAPIWords())
				}
				if !strings.Contains(d.Fix, "remove "+tc.mentions) && tc.mentions != "" {
					t.Errorf("the fix %q does not offer to remove the budget", d.Fix)
				}
			}
		})
	}
}
