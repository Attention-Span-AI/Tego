// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBoundaryAdoptionAppliesCPUAndPidsCeilings: on a machine whose config sets limits.cpu, limits.cpu_weight or
// limits.pids, every boundary `tego adopt` was refused (exit 125, [adopt-refused]), though unattended agents are often
// services and a machine-wide pids cap is common hardening: the main way to govern them was closed. Those three are
// now written into the adoption's cgroup before the move (ADR 0055, the 2026-11-11 limits amendment), so the boundary
// goes on with them in its table, and the notice says them. A memory ceiling beside them still refuses it, named.
func TestBoundaryAdoptionAppliesCPUAndPidsCeilings(t *testing.T) {
	contract := ceilingBoundary(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.Limits.CPU = config.Ceiling[float64]{Value: 2, Bounded: true, Source: etcAt(5)}
	m.Limits.CPUWeight = config.Ceiling[int]{Value: 50, Bounded: true, Source: etcAt(6)}
	m.Limits.Pids = config.Ceiling[int]{Value: 512, Bounded: true, Source: etcAt(7)}
	ok, code, errs, rt := compileCeilingAdoption(t, m, contract)
	if !ok || code != identity.ExitOK {
		t.Fatalf("a boundary adoption under cpu, cpu_weight and pids ceilings was refused: exit %d\n%s", code, errs)
	}
	if strings.Contains(errs, "[adopt-refused]") || len(ceilingWarnings(errs)) != 0 {
		t.Errorf("an applied ceiling was refused or warned of:\n%s", errs)
	}
	for _, b := range []agent.BudgetSet{agent.BudgetCPU, agent.BudgetCPUWeight, agent.BudgetPids} {
		if !rt.Limits.Bounded(b) {
			t.Errorf("the table lost the ceiling %v, so the runtime would write no limit for it", b)
		}
	}
	if got, want := adoptLimitsNotice(rt, true), "  limits: cpu 2, cpu_weight 50, pids 512, written to its cgroup before "+
		"the move"; !strings.HasPrefix(got, want) {
		t.Errorf("the notice's limits line = %q, want it to begin %q", got, want)
	}
	// The kernel ends no process for these limits, but a program that cannot start a thread may end itself (Go's
	// runtime aborts): the notice says no more than that.
	if got := adoptLimitsNotice(rt, true); !strings.Contains(got, "the kernel ends none") ||
		!strings.Contains(got, "may end itself") || strings.Contains(got, "none ends it") {
		t.Errorf("the notice's limits line says more than the kernel does: %q", got)
	}
	if got := adoptLimitsNotice(rt, false); got != "" {
		t.Errorf("a record-only adoption's notice names limits: %q", got)
	}

	// A record-only adoption still applies none and says so for each, in the lines ceilingWarnings finds.
	ok, _, errs, _ = compileCeilingAdoption(t, m, "")
	if !ok || strings.Count(errs, "is not applied: a record-only adoption sets no limit") != 3 || len(ceilingWarnings(errs)) != 3 {
		t.Errorf("a record-only adoption under three ceilings: ok=%v\n%s", ok, errs)
	}

	m.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 8 << 30, Bounded: true, Source: etcAt(8)}
	ok, code, errs, _ = compileCeilingAdoption(t, m, contract)
	if ok || code != identity.ExitLauncher || !strings.Contains(errs, "/etc/tego/config.yaml:8: tego adopt: the machine "+
		"ceiling limits.memory=8GiB") || !strings.Contains(errs, ceilingRemedy(1)) {
		t.Errorf("a memory ceiling beside them: ok=%v exit %d; want it alone refused:\n%s", ok, code, errs)
	}
}

// ceilingWarnings are the [unenforced] lines of errs that name a machine ceiling (limits.<key>). The other warnings
// of the adoption's compile are about its contract, not its ceilings: at a root tier a contract with no net: section
// always carries the host_sockets/root-tier one (ADR 0070), which a check of every [unenforced] line took for a ceiling
// warned of (acceptance 2C, 2026-11-11: the tegobpf build as root).
func ceilingWarnings(errs string) []string {
	var out []string
	for line := range strings.SplitSeq(errs, "\n") {
		if strings.Contains(line, "[unenforced]") && strings.Contains(line, "limits.") {
			out = append(out, line)
		}
	}
	return out
}

// TestEveryLimitsKeyIsAppliedOrRefusedByAnAdoption: every limits key of the machine config's schema is applied by a
// boundary adoption (cpu, cpu_weight, pids), warned of as an unmetered budget (tokens, cost_usd, repeats), or refused
// with its own reason (memory, memory_high, wall, stall_after). A key a later schema adds fails here until it is
// classified, and until then it is refused, never applied or skipped.
func TestEveryLimitsKeyIsAppliedOrRefusedByAnAdoption(t *testing.T) {
	const (
		applied = "applied"
		budget  = "budget"
		refused = "refused"
	)
	want := map[string]string{
		"limits.cpu": applied, "limits.cpu_weight": applied, "limits.pids": applied,
		"limits.tokens": budget, "limits.cost_usd": budget, "limits.repeats": budget,
		"limits.memory": refused, "limits.memory_high": refused, "limits.wall": refused, "limits.stall_after": refused,
	}
	// Every ceiling of the schema, set: each field of config.Limits is a Ceiling whose Bounded turns it on.
	m := config.Builtin()
	lv := reflect.ValueOf(&m.Limits).Elem()
	for i := range lv.NumField() {
		lv.Field(i).FieldByName("Bounded").SetBool(true)
	}
	ceilings := m.LimitCeilings()
	if len(ceilings) != lv.NumField() {
		t.Fatalf("%d limits ceilings for %d fields of config.Limits: a field the effective values do not list", len(ceilings), lv.NumField())
	}
	var keys []string
	for _, v := range ceilings {
		keys = append(keys, v.Key)
		w, ok := want[v.Key]
		if !ok {
			t.Errorf("%s is not classified for an adoption: say whether it is applied, a budget or refused (ADR 0055)", v.Key)
			continue
		}
		bare := strings.TrimPrefix(v.Key, "limits.")
		got := refused
		switch {
		case budgetCeiling(v.Key):
			got = budget
		case adoptLimitRefusal(v.Key) == "":
			got = applied
		}
		if got != w {
			t.Errorf("%s: an adoption has it %s, want %s", v.Key, got, w)
		}
		if got != applied && adoptRefusedLimits[bare] == "" {
			t.Errorf("%s has no reason of its own in adoptRefusedLimits", v.Key)
		}
		if tegoruntime.AdoptionApplies(bare) != (w == applied) {
			t.Errorf("tegoruntime.AdoptionApplies(%q) = %v, want %v", bare, !(w == applied), w == applied)
		}
	}
	for k := range want {
		if !slices.Contains(keys, k) {
			t.Errorf("%s is classified here but no longer in the schema", k)
		}
	}
	if why := adoptLimitRefusal("limits.later"); why == "" {
		t.Error("a key nobody classified is applied")
	}

	// The contract's own limits: each key of its schema compiled, the same split (its budgets are refused, as before).
	for key, value := range map[string]string{"cpu": "2", "cpu_weight": "50", "pids": "64", "memory": "1GiB",
		"memory_high": "1GiB", "wall": "1h", "stall_after": "10m", "tokens": "1000", "cost_usd": "5", "repeats": "3"} {
		lines := unenforceableForAdoption(compileAdoptTable(t, "limits:\n  "+key+": "+value+"\n"))
		refusedHere := slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "limits."+key+": ") })
		if refusedHere != (want["limits."+key] != applied) {
			t.Errorf("a boundary contract's limits.%s: refused %v (%q), want refused %v", key, refusedHere, lines,
				want["limits."+key] != applied)
		}
	}
	if n := reflect.TypeFor[agent.Limits]().NumField(); n != len(want) {
		t.Errorf("agent.Limits has %d fields and %d keys are classified: classify the new contract key", n, len(want))
	}
}
