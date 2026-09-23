// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCompileZeroCeilingIsEnforced covers E12: a machine ceiling of exactly zero is a real ceiling, not an
// absent one, so a contract asking for a positive value is clamped to zero with a limit-above-machine
// warning. The regression this guards is a ceiling carried as a bare value, where zero and "unbounded"
// collapse into the same number and the ceiling silently stops applying.
func TestCompileZeroCeilingIsEnforced(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	m.Limits.CostUSD = zeroCeil[float64]()
	m.Limits.Tokens = zeroCeil[int64]()
	m.Limits.Pids = zeroCeil[int]()
	m.Limits.Memory = zeroCeil[config.ByteSize]()

	c := f.load("version: 0\nname: a\ncommand: [python]\nlimits:\n  cost_usd: 5\n  tokens: 1000\n  pids: 64\n  memory: 1GiB\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if rt.Limits.CostUSD != 0 || rt.Limits.Tokens != 0 || rt.Limits.Pids != 0 || rt.Limits.MemoryB != 0 {
		t.Errorf("zero ceilings not enforced: cost=%v tokens=%v pids=%v memory=%v",
			rt.Limits.CostUSD, rt.Limits.Tokens, rt.Limits.Pids, rt.Limits.MemoryB)
	}
	if !hasCode(ds, CodeLimitAboveMachine) {
		t.Errorf("no limit-above-machine warning:\n%s", render(ds))
	}
	// The number alone cannot say a ceiling of 0 was asked for, and every consumer
	// downstream reads an unasked-for 0 as unbounded. The warning above promises the ceiling was
	// kept, so the presence has to survive compile or the promise is false.
	for _, k := range []BudgetSet{BudgetCostUSD, BudgetTokens, BudgetPids, BudgetMemory} {
		if !rt.Limits.Bounded(k) {
			t.Errorf("zero ceiling %d resolved to unbounded; the run would get no budget at all", k)
		}
	}
}

// TestCompileUnboundedCeilingKeepsContractValue is the other half of E12: an unbounded ceiling leaves the
// contract's value alone and warns about nothing.
func TestCompileUnboundedCeilingKeepsContractValue(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	m.Limits.CostUSD = config.Ceiling[float64]{}
	m.Limits.Tokens = config.Ceiling[int64]{}

	c := f.load("version: 0\nname: a\ncommand: [python]\nlimits:\n  cost_usd: 5\n  tokens: 1000\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if rt.Limits.CostUSD != 5 || rt.Limits.Tokens != 1000 {
		t.Errorf("unbounded ceiling changed the contract: cost=%v tokens=%v", rt.Limits.CostUSD, rt.Limits.Tokens)
	}
	if hasCode(ds, CodeLimitAboveMachine) {
		t.Errorf("unexpected ceiling warning:\n%s", render(ds))
	}
	// The other direction: cpu_weight and memory_high are named neither by this contract
	// nor by the fixture machine, and must stay unbounded — the presence bit cannot be won by
	// setting it everywhere.
	if rt.Limits.Bounded(BudgetCPUWeight) || rt.Limits.Bounded(BudgetMemoryHigh) {
		t.Errorf("a limit no one asked for came out bounded: %+v", rt.Limits)
	}
	if !rt.Limits.Bounded(BudgetTokens) || !rt.Limits.Bounded(BudgetCostUSD) {
		t.Errorf("the contract's own budgets are not bounded: %+v", rt.Limits)
	}
}

// TestAboveCeilingNamesTheLayer: R11's warning is `ceiling <key>=<value> kept from <file>:<line>`, and it said "kept
// from machine config", which does not say which of the three layers to edit. The tier's and capture's say where
// their ceiling came from too, and memory_high held to the run's memory names the cap it met.
func TestAboveCeilingNamesTheLayer(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	etc := config.Provenance{File: "/etc/tego/config.yaml", Line: 6, Layer: config.LayerEtc}
	user := config.Provenance{File: "/home/u/.tego/config.yaml", Line: 2, Layer: config.LayerUser}
	m.Limits.CPU = config.Ceiling[float64]{Value: 2, Bounded: true, Source: etc}
	m.Limits.Pids = config.Ceiling[int]{Value: 64, Bounded: true, Source: user}
	m.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 1 << 30, Bounded: true, Source: etc}
	m.Tier = config.Ceiling[config.TierSetting]{Value: config.TierSetting{Tier: "landlock"}, Bounded: true, Source: user}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\nlimits:\n  cpu: \"4\"\n  pids: 128\n  memory_high: 2GiB\n")
	_, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	got := render(ds)
	for _, want := range []string{
		"ceiling cpu=2 kept from /etc/tego/config.yaml:6; the contract asked for 4",
		"ceiling pids=64 kept from /home/u/.tego/config.yaml:2; the contract asked for 128",
		"ceiling tier=landlock kept from /home/u/.tego/config.yaml:2; the contract pinned cgroup",
		"limits.memory_high 2GiB is above the memory ceiling 1GiB from /etc/tego/config.yaml:6; kept at 1GiB",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "kept from machine config") {
		t.Errorf("a warning still names no layer:\n%s", got)
	}
}

// TestCompileCPUCeilingExactQuota covers R11 for cpu: the ceiling is compared as the cpu.max quota the run
// writes, round(cores*100000). Compared in hundredths of a core, "1.014" and a 1.01 ceiling were both 101,
// so the contract kept 1.014 and the run wrote a 101400 quota over the ceiling's 101000, with no warning.
func TestCompileCPUCeilingExactQuota(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	m.Limits.CPU = bounded(1.01)
	for _, tc := range []struct {
		cpu, want string
		warn      bool
	}{
		{"1.014", "1.01", true},
		{"1.01", "1.01", false},
		{"1.00999", "1.00999", false},
	} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nlimits:\n  cpu: \"" + tc.cpu + "\"\n")
		rt, ds, err := Compile(c, &m, f.opts()...)
		if err != nil {
			t.Fatalf("compile %s: %v\n%s", tc.cpu, err, render(ds))
		}
		if rt.Limits.CPU != tc.want || hasCode(ds, CodeLimitAboveMachine) != tc.warn {
			t.Errorf("cpu %s under a 1.01 ceiling: got %q warn=%v, want %q warn=%v\n%s",
				tc.cpu, rt.Limits.CPU, hasCode(ds, CodeLimitAboveMachine), tc.want, tc.warn, render(ds))
		}
	}
}

// TestMemoryHighWarningNamesWhoseValueItIs: a contract that wrote only limits.memory, under a machine memory_high
// ceiling above it, was told "limits.memory_high 4GiB is above the memory ceiling 1GiB from <the built-in>" and to
// raise a machine memory ceiling: it never wrote memory_high, the 1GiB is its own memory, and the ceiling to change
// is the memory_high one.
func TestMemoryHighWarningNamesWhoseValueItIs(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	etc := config.Provenance{File: "/etc/tego/config.yaml", Line: 9, Layer: config.LayerEtc}
	m.Limits.MemoryHigh = config.Ceiling[config.ByteSize]{Value: 4 << 30, Bounded: true, Source: etc}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\nlimits:\n  memory: 1GiB\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if rt.Limits.MemoryHigh != 1<<30 {
		t.Fatalf("memory_high = %d, want held to the 1GiB memory", rt.Limits.MemoryHigh)
	}
	got := render(ds)
	for _, want := range []string{
		"the machine's memory_high ceiling 4GiB from /etc/tego/config.yaml:9 is above this contract's limits.memory 1GiB",
		"set limits.memory_high to 1GiB or below, or lower the machine's memory_high ceiling",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "limits.memory_high 4GiB is above the memory ceiling") {
		t.Errorf("the contract is still blamed for a memory_high it never wrote:\n%s", got)
	}
}
