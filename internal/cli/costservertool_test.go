// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCompileReportsACostBudgetUnderATableListingNoModels: a price table that loads and lists no model prices
// nothing, as a missing one does. compile said nothing about a cost_usd budget under it, and the run went ahead
// with a limit that never tripped. A budget the contract declares is now reported
// [budget-unmetered], its run refused; one a machine ceiling alone imposes stays [unenforced].
func TestCompileReportsACostBudgetUnderATableListingNoModels(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"empty.yaml": "version: 1\n",
		"fees.yaml": "version: 1\nmodels: {}\nserver_tool_per_request:\n  web_search_requests: 0.01\n"} {
		table := filepath.Join(dir, name)
		if err := os.WriteFile(table, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		m := config.Builtin()
		m.Prices = config.Setting[string]{Value: table}
		declared := &agent.RuleTable{Contract: &agent.Contract{}}
		declared.Limits.CostUSD, declared.Limits.Set = 0.01, agent.BudgetCostUSD
		declared.Contract.Limits.CostUSD = new(0.01)
		imposed := &agent.RuleTable{}
		imposed.Limits.CostUSD, imposed.Limits.Set = 0.01, agent.BudgetCostUSD
		for _, tc := range []struct {
			rt   *agent.RuleTable
			code string
		}{{declared, "is refused"}, {imposed, "[unenforced]"}} {
			var stderr bytes.Buffer
			warnCostUnpriced(&stderr, "c.yaml", tc.rt, m)
			if out := stderr.String(); !strings.Contains(out, "lists no models") || !strings.Contains(out, tc.code) {
				t.Errorf("%s: want a warning that the table lists no models, %q:\n%s", name, tc.code, out)
			}
		}
		// run hands the runtime the price gap, on which it refuses the declared budget (runtime.refuseUncountedBudget).
		var stderr bytes.Buffer
		if table, why := runPrices(m, declared, &stderr); table != nil || why != "no-price-table" ||
			!strings.Contains(stderr.String(), "lists no models") {
			t.Errorf("%s: runPrices = %v, %q, want no table and the no-price-table gap:\n%s", name, table, why, stderr.String())
		}
	}
}

// compile warns [unenforced] when a cost_usd budget's price table names no server_tool_per_request fee: a run
// ends at the first response reporting server-tool requests, whose cost the table cannot bound (ADR 0037
// amendment 2026-09-24). A table with a fee, or a contract with no cost budget, draws no warning.
func TestCompileWarnsCostBudgetWithoutServerToolFees(t *testing.T) {
	dir := t.TempDir()
	// The price table follows the machine config's trust rule: no group-writable directory (umask 002).
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const models = "version: 1\nmodels:\n  m: {input_per_mtok: 1, output_per_mtok: 5}\n"
	bare, fees := filepath.Join(dir, "bare.yaml"), filepath.Join(dir, "fees.yaml")
	if err := os.WriteFile(bare, []byte(models), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fees, []byte(models+"server_tool_per_request:\n  web_search_requests: 0.01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(dir, "partial.yaml")
	if err := os.WriteFile(partial, []byte("version: 1\nmodels:\n  m: {input_per_mtok: 1}\nserver_tool_per_request:\n  web_search_requests: 0.01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	budgeted := &agent.RuleTable{}
	budgeted.Limits.CostUSD, budgeted.Limits.Set = 1, agent.BudgetCostUSD
	for _, tc := range []struct {
		name  string
		table string
		rt    *agent.RuleTable
		warn  bool
		text  string
	}{
		{"prices no model", partial, budgeted, false, "prices no model"},
		{"no fees", bare, budgeted, true, ""},
		{"fees", fees, budgeted, false, ""},
		{"no cost budget", bare, &agent.RuleTable{}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := config.Builtin()
			m.Prices = config.Setting[string]{Value: tc.table}
			var stderr bytes.Buffer
			warnCostUnpriced(&stderr, "c.yaml", tc.rt, m)
			got := strings.Contains(stderr.String(), "server_tool_per_request") && strings.Contains(stderr.String(), "[unenforced]")
			if tc.text != "" {
				if !strings.Contains(stderr.String(), tc.text) || !strings.Contains(stderr.String(), "[unenforced]") {
					t.Errorf("no %q warning:\n%s", tc.text, stderr.String())
				}
				return
			}
			if got != tc.warn {
				t.Errorf("warned %v, want %v:\n%s", got, tc.warn, stderr.String())
			}
		})
	}
}

// TestCompileReportsADeclaredCostBudgetUnderATableThatPricesNoModel: a table whose every entry
// lacks an input or an output price prices no model, as one that lists none does, so a cost_usd budget the
// contract declares under it is [budget-unmetered], its run refused at launch, where it was [unenforced] and ran
// to its first response; one a machine ceiling alone imposes stays [unenforced], the run ending at that response.
func TestCompileReportsADeclaredCostBudgetUnderATableThatPricesNoModel(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(dir, "partial.yaml")
	if err := os.WriteFile(table, []byte("version: 1\nmodels:\n  claude-x: {}\n  m: {input_per_mtok: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Prices = config.Setting[string]{Value: table}
	declared := &agent.RuleTable{Contract: &agent.Contract{}}
	declared.Limits.CostUSD, declared.Limits.Set = 1, agent.BudgetCostUSD
	declared.Contract.Limits.CostUSD = new(1.0)
	imposed := &agent.RuleTable{}
	imposed.Limits.CostUSD, imposed.Limits.Set = 1, agent.BudgetCostUSD
	for _, tc := range []struct {
		name string
		rt   *agent.RuleTable
		want []string
	}{
		{"declared", declared, []string{"prices no model", "every run of this contract on this machine is refused", "[budget-unmetered]"}},
		{"a ceiling alone", imposed, []string{"prices no model", "a run ends at its first response", "[unenforced]"}},
	} {
		var stderr bytes.Buffer
		warnCostUnpriced(&stderr, "c.yaml", tc.rt, m)
		for _, w := range tc.want {
			if !strings.Contains(stderr.String(), w) {
				t.Errorf("%s: the warning does not say %q:\n%s", tc.name, w, stderr.String())
			}
		}
	}
}
