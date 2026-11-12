// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAdoptionRefusesAMachineCeilingItCannotApply: a machine limits.* ceiling is every tego run's limit (agent-contract
// R11). A boundary adoption refused the contract's limits but went on under a ceiling with no word, so an
// administrator's limit was skipped. A limit an adoption cannot hold (memory, memory_high, wall, stall_after) is now
// refused from either source alike, each ceiling at its file and line (a budget ceiling is
// TestBoundaryAdoptionGoesOnUnderABudgetCeiling's, cpu, cpu_weight and pids TestBoundaryAdoptionAppliesCPUAndPidsCeilings');
// a record-only adoption, which holds no rule (ADR 0055 (5)), goes on and says what it skips.
func TestAdoptionRefusesAMachineCeilingItCannotApply(t *testing.T) {
	contract := ceilingBoundary(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	compile := func(boundary string) (bool, int, string) {
		ok, code, errs, _ := compileCeilingAdoption(t, m, boundary)
		return ok, code, errs
	}
	if ok, code, errs := compile(contract); !ok {
		t.Fatalf("with no ceiling the boundary was refused: exit %d %q", code, errs)
	}

	etc := "/etc/tego/config.yaml"
	m.Limits.CPU = config.Ceiling[float64]{Value: 2, Bounded: true, Source: config.Provenance{File: etc, Line: 5, Layer: config.LayerEtc}}
	m.Limits.Wall = config.Ceiling[time.Duration]{Value: 8 * time.Hour, Bounded: true, Source: config.Provenance{File: etc, Line: 6, Layer: config.LayerEtc}}
	m.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 8 << 30, Bounded: true, Source: config.Provenance{File: etc, Line: 7, Layer: config.LayerEtc}}
	ok, code, errs := compile(contract)
	if ok || code != identity.ExitLauncher {
		t.Fatalf("a boundary adoption under ceilings it cannot apply was not refused: ok=%v exit %d %q", ok, code, errs)
	}
	for _, want := range []string{
		etc + ":7: tego adopt: the machine ceiling limits.memory=8GiB, which every tego run gets, cannot be held on a " +
			"running process: " + adoptNoMemory + " [adopt-refused]",
		etc + ":6: tego adopt: the machine ceiling limits.wall=8h",
		ceilingRemedy(2),
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("refusal lacks %q:\n%s", want, errs)
		}
	}

	ok, code, errs = compile("")
	if !ok {
		t.Fatalf("a record-only adoption was refused under ceilings: exit %d %q", code, errs)
	}
	want := etc + ":5: warning: tego adopt: the machine ceiling limits.cpu=2, which every tego run gets, is not applied: " +
		"a record-only adoption sets no limit and refuses nothing [unenforced]"
	if !strings.Contains(errs, want) || !strings.Contains(errs, "limits.wall=8h") {
		t.Errorf("a record-only adoption skipped a ceiling without saying so; want %q in:\n%s", want, errs)
	}
}

// ceilingBoundary writes a boundary contract that an adoption can hold, and points the agent owner's home at one that
// does not exist: nothing is made for the owner, so the tests need no passwd entry and no root.
func ceilingBoundary(t *testing.T) string {
	t.Helper()
	prevHome := adoptHomeOf
	t.Cleanup(func() { adoptHomeOf = prevHome })
	noHome := filepath.Join(t.TempDir(), "nonexistent")
	adoptHomeOf = func(int) (string, error) { return noHome, nil }
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(t.TempDir(), "boundary.yaml")
	y := "version: 0\nname: boundary\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\"" + ws + "\"]\nexec:\n  allow: [\"/bin/sh\"]\n"
	if err := os.WriteFile(contract, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return contract
}

// compileCeilingAdoption compiles an adoption's table under m, with the boundary contract (or record-only for ""),
// and returns whether it may go on, its exit, what it printed and the table.
func compileCeilingAdoption(t *testing.T, m *config.Machine, boundary string) (bool, int, string, *agent.RuleTable) {
	t.Helper()
	var errs bytes.Buffer
	a := &preparedAdoption{m: m, boundary: boundary != "", cleanup: func() {}, owner: 1000}
	t.Cleanup(func() { a.cleanup() })
	rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: boundary}, adopt.Process{PID: 4242, Exe: "/bin/sh", Comm: "sh"}, a, &errs)
	return rt != nil, code, errs.String(), rt
}

// ceilingRemedy is the last line of a boundary adoption refused for n machine ceilings.
func ceilingRemedy(n int) string {
	return fmt.Sprintf("tego adopt: the machine config sets %d limit ceiling(s) a boundary adoption cannot hold; adopt "+
		"with no --boundary to record the agent (record-only, which holds nothing), or start the agent with tego run, "+
		"which applies the ceilings; removing a ceiling lifts it for every run on the machine [adopt-refused]", n)
}

// etcAt is a ceiling's provenance in /etc/tego/config.yaml at line.
func etcAt(line int) config.Provenance {
	return config.Provenance{File: "/etc/tego/config.yaml", Line: line, Layer: config.LayerEtc}
}

// TestBoundaryAdoptionGoesOnUnderABudgetCeiling: a tokens, cost_usd or repeats budget that only a machine ceiling
// imposes is not refused at tego run where nothing meters it; the run records gap why=budget-unmetered
// (limits-check-doctor-cli.md R32). A boundary adoption refused every one of them, so a machine that copied the example
// config could use no boundary adoption at all. It now goes on, says at the ceiling's file and line that the budget is
// not metered, and keeps the budget in its table, where the adoption records the gap. A kernel limit beside it is
// still refused, and the budget is not counted among the refused ceilings.
func TestBoundaryAdoptionGoesOnUnderABudgetCeiling(t *testing.T) {
	contract := ceilingBoundary(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.Limits.Tokens = config.Ceiling[int64]{Value: 1000, Bounded: true, Source: etcAt(9)}
	m.Limits.CostUSD = config.Ceiling[float64]{Value: 5, Bounded: true, Source: etcAt(10)}
	m.Limits.Repeats = config.Ceiling[int]{Value: 3, Bounded: true, Source: etcAt(11)}
	ok, code, errs, rt := compileCeilingAdoption(t, m, contract)
	if !ok || code != identity.ExitOK {
		t.Fatalf("a boundary adoption under budget ceilings alone was refused: exit %d\n%s", code, errs)
	}
	for _, c := range []struct {
		line int
		kv   string
	}{{9, "limits.tokens=1000"}, {10, "limits.cost_usd=5"}, {11, "limits.repeats=3"}} {
		want := fmt.Sprintf("/etc/tego/config.yaml:%d: warning: tego adopt: the machine ceiling %s, which every tego run "+
			"gets, is not metered: an adoption captures no model traffic, so the budget never trips, and its run records "+
			"gap why=budget-unmetered [unenforced]", c.line, c.kv)
		if !strings.Contains(errs, want) {
			t.Errorf("no warning %q in:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "[adopt-refused]") {
		t.Errorf("a budget ceiling was printed as a refusal:\n%s", errs)
	}
	for _, b := range []agent.BudgetSet{agent.BudgetTokens, agent.BudgetCostUSD, agent.BudgetRepeats} {
		if !rt.Limits.Bounded(b) {
			t.Errorf("the adoption's table lost the ceiling's budget %v, so its run would record no gap for it", b)
		}
	}
	// A record-only adoption keeps the budget in its table too, so its run records the same gap.
	if ok, _, errs, rt := compileCeilingAdoption(t, m, ""); !ok || !rt.Limits.Bounded(agent.BudgetTokens) {
		t.Errorf("a record-only adoption under a tokens ceiling: ok=%v, table bounded=%v\n%s", ok, ok && rt.Limits.Bounded(agent.BudgetTokens), errs)
	}

	m.Limits.MemoryHigh = config.Ceiling[config.ByteSize]{Value: 4 << 30, Bounded: true, Source: etcAt(12)}
	ok, code, errs, _ = compileCeilingAdoption(t, m, contract)
	if ok || code != identity.ExitLauncher {
		t.Fatalf("a memory_high ceiling beside the budgets did not refuse the boundary: exit %d\n%s", code, errs)
	}
	if !strings.Contains(errs, "/etc/tego/config.yaml:12: tego adopt: the machine ceiling limits.memory_high=4GiB") ||
		!strings.Contains(errs, ceilingRemedy(1)) {
		t.Errorf("the refusal does not name the memory_high ceiling alone:\n%s", errs)
	}
	if strings.Contains(errs, "limits.tokens=1000, which every tego run gets, cannot be held") {
		t.Errorf("a budget ceiling was refused:\n%s", errs)
	}
}

// TestCeilingRefusalSaysWhatRemovingACeilingDoes: the refusal's remedy said "remove them where named above" first, and
// a ceiling removed is lifted for every tego run on the machine, not for this adoption alone. The remedy now offers
// the two ways that keep the ceiling first and says what removing one does.
func TestCeilingRefusalSaysWhatRemovingACeilingDoes(t *testing.T) {
	contract := ceilingBoundary(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 8 << 30, Bounded: true, Source: etcAt(5)}
	m.Limits.StallAfter = config.Ceiling[time.Duration]{Value: time.Hour, Bounded: true, Source: etcAt(6)}
	ok, code, errs, _ := compileCeilingAdoption(t, m, contract)
	if ok || code != identity.ExitLauncher {
		t.Fatalf("not refused: exit %d\n%s", code, errs)
	}
	if !strings.Contains(errs, ceilingRemedy(2)) {
		t.Errorf("remedy %q not in:\n%s", ceilingRemedy(2), errs)
	}
	if strings.Contains(errs, "remove them") {
		t.Errorf("the remedy still says to remove the ceilings without saying what that does:\n%s", errs)
	}
	if want := "/etc/tego/config.yaml:6: tego adopt: the machine ceiling limits.stall_after=1h, which every tego run " +
		"gets, cannot be held on a running process: it would end the agent, which an adoption never does [adopt-refused]"; !strings.Contains(errs, want) {
		t.Errorf("no line %q in:\n%s", want, errs)
	}
}

// TestRecordOnlyGuardWarnsOfEachCeilingOnceAtStart: the record-only guard (tego agents --follow --adopt --uid N, the
// shipped unit's command) prepared nothing at its start and each agent's adoption with its output discarded, so it
// never said that it applies none of the machine's ceilings, though GAPS C56 said it warns once when it starts. It
// now prints each ceiling's warning once at its start, however many uids it watches.
func TestRecordOnlyGuardWarnsOfEachCeilingOnceAtStart(t *testing.T) {
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.Limits.CPU = config.Ceiling[float64]{Value: 2, Bounded: true, Source: etcAt(5)}
	m.Limits.Tokens = config.Ceiling[int64]{Value: 1000, Bounded: true, Source: etcAt(6)}
	var errs bytes.Buffer
	if _, err := newGuard(t.Context(), m, []int{1000, 1001}, adoptOptions{}, func(watcher.Sighting) error { return nil }, &errs); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/etc/tego/config.yaml:5: warning: tego adopt: the machine ceiling limits.cpu=2, which every tego run gets, is " +
			"not applied: a record-only adoption sets no limit and refuses nothing [unenforced]",
		"/etc/tego/config.yaml:6: warning: tego adopt: the machine ceiling limits.tokens=1000, which every tego run " +
			"gets, is not metered: an adoption captures no model traffic, so the budget never trips, and its run records " +
			"gap why=budget-unmetered [unenforced]",
	} {
		if n := strings.Count(errs.String(), want); n != 1 {
			t.Errorf("%q printed %d times at the guard's start, want once:\n%s", want, n, errs.String())
		}
	}
	if n := strings.Count(errs.String(), "\n"); n != 2 {
		t.Errorf("the guard's start printed %d lines, want the two warnings:\n%s", n, errs.String())
	}
}
