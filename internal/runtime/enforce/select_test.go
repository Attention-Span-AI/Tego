// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func machine(tier string) *config.Machine {
	m := config.Builtin()
	if tier != "" {
		m.Tier.Bounded = true
		m.Tier.Value = config.TierSetting{Tier: tier, Auto: tier == backend.Auto}
	}
	return m
}

func table(tier backend.Tier, pin string) *agent.RuleTable {
	return &agent.RuleTable{Tier: tier, ContractPath: "/c/agent.yaml", Contract: &agent.Contract{Tier: agent.TierPin(pin)}}
}

func hasSeverity(ds []Diagnostic, sev string) bool {
	for _, d := range ds {
		if d.Severity == sev {
			return true
		}
	}
	return false
}

// TestSelect is R17/R18 through the implementation filter: on this box as uid 1000 the probe offers
// landlock and Select returns the landlock backend.
func TestSelect(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	// The table's "built" rows describe a tegobpf build; TestSelectWithoutTheObjects is the other one.
	withObjects(t, true)
	user := backend.Probe{backend.TierLandlock: true}
	root := backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: true}
	cases := []struct {
		name     string
		m        *config.Machine
		rt       *agent.RuleTable
		probe    backend.Probe
		wantTier backend.Tier
		wantErr  bool
		wantWarn bool
	}{
		// An auto contract running below the tier Compile resolved it to is what auto means: no warning
		// (it printed one under [tier-unavailable] on every default run).
		{"uid 1000, auto contract compiled for bpflsm", machine(""), table(backend.TierBPFLSM, ""), user, backend.TierLandlock, false, false},
		{"uid 1000, contract compiled for landlock", machine(""), table(backend.TierLandlock, ""), user, backend.TierLandlock, false, false},
		{"machine ceiling landlock", machine("landlock"), table(backend.TierLandlock, ""), root, backend.TierLandlock, false, true},
		{"contract pins landlock under an unbounded machine", machine(""), table(backend.TierLandlock, "landlock"), root, backend.TierLandlock, false, true},
		{"contract pins cgroup: probed and built", machine(""), table(backend.TierCgroup, "cgroup"), root, backend.TierCgroup, false, true},
		{"machine names cgroup: probed and built", machine("cgroup"), table(backend.TierCgroup, ""), root, backend.TierCgroup, false, true},
		{"contract pins bpflsm: probed, but no LSM-mode plane handed over", machine(""), table(backend.TierBPFLSM, "bpflsm"), root, "", true, true},
		{"nothing probed", machine(""), table(backend.TierLandlock, ""), backend.Probe{}, "", true, false},
		{"nil probe", machine(""), table(backend.TierLandlock, ""), nil, "", true, false},
		{"nil machine and table", nil, nil, user, backend.TierLandlock, false, false},
		{"observe is never a candidate", machine(""), table(backend.TierLandlock, ""), backend.Probe{backend.TierObserve: true}, "", true, true},
		{"unknown pin refused", machine(""), table(backend.TierLandlock, "quantum"), user, "", true, false},
		{"auto machine tier is unbounded", machine("auto"), table(backend.TierLandlock, "auto"), user, backend.TierLandlock, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, ds := Select(tc.m, tc.rt, tc.probe)
			if tc.wantErr {
				if b != nil || !hasSeverity(ds, "error") {
					t.Fatalf("Select = %v, %v; want an error diagnostic", b, ds)
				}
				for _, d := range ds {
					if d.Code != backend.CodeTierUnavailable {
						t.Errorf("code %q", d.Code)
					}
					if tc.rt != nil && d.File != tc.rt.ContractPath {
						t.Errorf("file %q", d.File)
					}
				}
				return
			}
			if b == nil || hasSeverity(ds, "error") {
				t.Fatalf("Select = %v, %v", b, ds)
			}
			if b.Tier() != tc.wantTier {
				t.Errorf("tier %s, want %s", b.Tier(), tc.wantTier)
			}
			if hasSeverity(ds, "warning") != tc.wantWarn {
				t.Errorf("warnings = %v, want warning=%v", ds, tc.wantWarn)
			}
			if !b.Capabilities().Has(backend.CapFileWriteDeny) {
				t.Errorf("capabilities %v", b.Capabilities())
			}
			switch got := b.(type) {
			case landlockBackend:
				if got.Unwrap() == nil {
					t.Errorf("landlock backend without an implementation")
				}
			case cgroupBackend:
				if got.b == nil {
					t.Errorf("cgroup backend without an implementation")
				}
			default:
				t.Errorf("backend %T", b)
			}
		})
	}
}

func TestObserve(t *testing.T) {
	b := Observe()
	if b.Tier() != backend.TierObserve || len(b.Capabilities()) != 0 {
		t.Errorf("Observe = %s %v", b.Tier(), b.Capabilities())
	}
}

func TestCeilingAndPin(t *testing.T) {
	cases := []struct {
		name         string
		m            *config.Machine
		rt           *agent.RuleTable
		ceiling, pin backend.Tier
	}{
		{"nothing", nil, nil, "", ""},
		{"builtin machine is unbounded", machine(""), nil, "", ""},
		{"machine tier is ceiling and pin", machine("cgroup"), nil, backend.TierCgroup, backend.TierCgroup},
		{"contract pin overrides the machine pin", machine("cgroup"), table(backend.TierLandlock, "landlock"), backend.TierCgroup, backend.TierLandlock},
		{"contract auto keeps the machine pin", machine("cgroup"), table(backend.TierCgroup, "auto"), backend.TierCgroup, backend.TierCgroup},
		{"table without contract", machine(""), &agent.RuleTable{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := ceilingAndPin(tc.m, tc.rt)
			if c != tc.ceiling || p != tc.pin {
				t.Errorf("ceiling %q pin %q, want %q %q", c, p, tc.ceiling, tc.pin)
			}
		})
	}
}
