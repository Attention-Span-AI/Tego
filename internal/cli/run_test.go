// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunPrices covers §7's price-table row for `run`: the check happens once here, before the run
// starts, and every way a table can be unusable is one warning line, no prices and a gap reason for
// the ledger — never a refused run, because a cost estimate is not what a run is for.
func TestRunPrices(t *testing.T) {
	dir := t.TempDir()
	// The price table follows the machine config's trust rule: no group-writable directory (umask 002).
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "prices.yaml")
	if err := os.WriteFile(good, []byte("version: 1\nmodels:\n  m:\n    input_per_mtok: 3.00\n    output_per_mtok: 15.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "prices-v99.yaml")
	if err := os.WriteFile(old, []byte("version: 99\nmodels: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		path     string
		wantGap  string
		wantWarn string
	}{
		{"a table this binary understands", good, "", ""},
		// A table nobody installed is the normal state of a fresh machine: the gap is recorded, the terminal stays
		// quiet (tego measure says it where a cost is asked for; a cost_usd budget says it, see
		// TestCostBudgetWithoutPrices).
		{"no table configured", "", limits.GapNoPriceTable, ""},
		{"a table that is not there", filepath.Join(dir, "absent.yaml"), limits.GapNoPriceTable, ""},
		{"a version this binary does not know", old, limits.GapVersionMismatch, "version 99"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := config.Builtin()
			m.Prices = config.Setting[string]{Value: tc.path}
			var stderr bytes.Buffer
			table, gap := runPrices(m, nil, &stderr)
			if gap != tc.wantGap {
				t.Fatalf("gap %q, want %q", gap, tc.wantGap)
			}
			if (table == nil) != (tc.wantGap != "") {
				t.Fatalf("table %v for gap %q", table, gap)
			}
			line := stderr.String()
			if tc.wantWarn == "" {
				if line != "" {
					t.Fatalf("a usable table printed %q", line)
				}
				return
			}
			if strings.Count(line, "\n") != 1 {
				t.Fatalf("want exactly one warning line, got %q", line)
			}
			if !strings.Contains(line, tc.wantWarn) || !strings.Contains(line, "["+codeNotFound+"]") {
				t.Fatalf("warning %q names neither %q nor its code", line, tc.wantWarn)
			}
		})
	}
}

// TestCostBudgetWithoutPrices: a cost_usd budget never trips where no price table loads, and neither compile
// nor run said so. compile warns [unenforced] at the budget's line, and run's no-price-table line names the
// budget; with no budget neither says anything about one.
func TestCostBudgetWithoutPrices(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("prices: "+filepath.Join(dir, "absent.yaml")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	body := "version: 0\nname: cost\ncommand: [\"true\"]\nnet: {}\n"
	budget, none := filepath.Join(dir, "budget.yaml"), filepath.Join(dir, "none.yaml")
	if err := os.WriteFile(budget, []byte(body+"limits:\n  cost_usd: 1.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(none, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "compile", budget, "--offline")
	if want := budget + ":6:13: limits.cost_usd budget never trips: no price table (no price table at " + filepath.Join(dir, "absent.yaml") +
		"; cost is not estimated), and every run of this contract on this machine is refused [budget-unmetered]"; code != identity.ExitOK ||
		!strings.Contains(errs, want) {
		t.Errorf("compile exit %d, stderr lacks %q:\n%s", code, want, errs)
	}
	if _, _, errs := run(t, "compile", none, "--offline"); strings.Contains(errs, "cost_usd") {
		t.Errorf("a contract with no cost budget warned about one:\n%s", errs)
	}

	m := config.Builtin()
	m.Prices = config.Setting[string]{Value: filepath.Join(dir, "absent.yaml")}
	rt := &agent.RuleTable{}
	rt.Limits.CostUSD = 1.5
	rt.Limits.Set |= agent.BudgetCostUSD
	var stderr bytes.Buffer
	runPrices(m, rt, &stderr)
	if want := "the cost_usd budget of 1.5 never trips"; !strings.Contains(stderr.String(), want) {
		t.Errorf("run's line %q does not name the budget (%q)", stderr.String(), want)
	}
}

// TestRunWarnsThatUsersIsIgnored covers the second half: spec/config/v0 says tego run ignores users: with a
// warning, and it ignored it with none, so an operator could take its max_runs to bind. Since ADR 0042 (4) users:
// is honoured from /etc/tego/config.yaml only: an $TEGO_CONFIG that sets it gets the "ignored here" warning
// and leaves the map empty, so run's own warning is /etc's (TestRunWarnsThatEtcUsersIsReadByTegodOnly).
func TestRunWarnsThatUsersIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  level: info\nusers:\n  \"1000\": {max_runs: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	// The contract is missing, so the run stops right after the machine config loads.
	_, _, errs := run(t, "run", filepath.Join(dir, "missing.yaml"), "--", "true")
	if want := cfg + ":4: users is honoured from /etc/tego/config.yaml only; ignored here [config-ignored]"; !strings.Contains(errs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, errs)
	}
	if strings.Contains(errs, "read by tegod only") {
		t.Errorf("an ignored users: still reached run as a map:\n%s", errs)
	}
	t.Setenv("TEGO_CONFIG", "")
	if _, _, errs := run(t, "run", filepath.Join(dir, "missing.yaml"), "--", "true"); strings.Contains(errs, "users:") {
		t.Errorf("a machine config with no users: warned about it:\n%s", errs)
	}
}

// TestRunWarnsThatEtcUsersIsReadByTegodOnly: a users: map from /etc/tego/config.yaml loads, and run says it
// binds nothing here, at the line that set it.
func TestRunWarnsThatEtcUsersIsReadByTegodOnly(t *testing.T) {
	m := &config.Machine{Users: config.Setting[map[string]config.UserPolicy]{
		Value:  map[string]config.UserPolicy{"1000": {MaxRuns: 1}},
		Source: config.Provenance{File: "/etc/tego/config.yaml", Line: 7, Layer: config.LayerEtc}}}
	var stderr bytes.Buffer
	warnUsersIgnored(&stderr, m)
	want := "/etc/tego/config.yaml:7: users: is read by tegod only; tego run ignores it"
	if !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "[config-ignored]") {
		t.Errorf("stderr %q lacks %q [config-ignored]", stderr.String(), want)
	}
}

// TestRunRefusesMissingEnvConfig: identity-config.md E13, a $TEGO_CONFIG that names no file is refused
// with 125 [config-untrusted] naming the path, and the line does not point at parse errors "above" that a
// missing file never printed.
func TestRunRefusesMissingEnvConfig(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.yaml")
	t.Setenv("TEGO_CONFIG", missing)
	code, _, errs := run(t, "run", filepath.Join(dir, "missing.yaml"), "--", "true")
	if code != identity.ExitConfig || !strings.Contains(errs, missing) || !strings.Contains(errs, "[config-untrusted]") {
		t.Errorf("exit %d, want %d naming %s [config-untrusted]:\n%s", code, identity.ExitConfig, missing, errs)
	}
	if strings.Contains(errs, "its errors are above") {
		t.Errorf("a missing file's refusal points at errors that were never printed:\n%s", errs)
	}
}

// TestRunFlagsCheckedFirst: a bad --record or --tier is a usage error, 2, before the contract is compiled (a
// missing contract was 125 and hid it), and --observe or --record off in effect is said on stderr.
func TestRunFlagsCheckedFirst(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	for _, args := range [][]string{
		{"run", "--record", "nope", missing, "--", "true"},
		{"run", "--tier", "nope", missing, "--", "true"},
		{"run", "--tier", "observe", missing, "--", "true"},
	} {
		if code, _, errs := run(t, args...); code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
			t.Errorf("%q: exit %d, want %d [usage]:\n%s", args, code, identity.ExitUsage, errs)
		}
	}
	for flagArg, want := range map[string]string{"--observe": "--observe is in effect", "--record=off": "--record off is in effect"} {
		_, _, errs := run(t, "run", flagArg, missing, "--", "true")
		if !strings.Contains(errs, "warning: tego run: "+want) || !strings.Contains(errs, "[unenforced]") {
			t.Errorf("%s: stderr lacks %q [unenforced]:\n%s", flagArg, want, errs)
		}
	}
	if _, _, errs := run(t, "run", missing, "--", "true"); strings.Contains(errs, "[unenforced]") {
		t.Errorf("a run with neither flag warned:\n%s", errs)
	}
}
