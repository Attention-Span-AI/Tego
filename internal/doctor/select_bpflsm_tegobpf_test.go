// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package doctor

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestReportSelectsTierBPFLSM is TIER3-PLAN T7's selection (enforce-plane R19, §6 case 12), in a build that carries
// the objects: where LSM mode passes, `--tier bpflsm` and an auto run are given tier bpflsm's backend, the plane in LSM
// mode; where bpf is not in the LSM list, `--tier bpflsm` is refused with doctor's own line, the GRUB fix included,
// and an auto run gets tier cgroup, never tier bpflsm in another mode.
func TestReportSelectsTierBPFLSM(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Name: "a"}}
	lsmBoot := state(nil).report(nil, "")
	for _, only := range []backend.Tier{backend.TierBPFLSM, ""} {
		b, ds := lsmBoot.Select(nil, rt, only)
		if b == nil || b.Tier() != backend.TierBPFLSM {
			t.Fatalf("lsm=bpf boot, --tier %q: Select = %v, %+v; want tier bpflsm", only, b, ds)
		}
		for _, d := range ds {
			if d.Severity == "error" {
				t.Errorf("--tier %q: %+v", only, d)
			}
		}
	}

	defaultBoot := state(func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "landlock"}, Source: LSMSourceSyscall}
		st.plane = defaultBootPlane()
	}).report(nil, "")
	b, ds := defaultBoot.Select(nil, rt, backend.TierBPFLSM)
	if b != nil {
		t.Fatalf("default boot, --tier bpflsm: Select = %s, want a refusal", b.Tier())
	}
	var refused bool
	for _, d := range ds {
		if d.Severity != "error" {
			continue
		}
		refused = true
		if d.Code != backend.CodeTierUnavailable || !strings.Contains(d.Message, "tier bpflsm pinned but not available") ||
			!strings.Contains(d.Fix, "bpf is not in the active LSM list") || !strings.Contains(d.Fix, "lsm=capability,landlock,bpf") {
			t.Errorf("refusal %+v: want [tier-unavailable] naming tier bpflsm with the GRUB line", d)
		}
	}
	if !refused {
		t.Errorf("no refusal: %+v", ds)
	}
	if b, ds := defaultBoot.Select(nil, rt, ""); b == nil || b.Tier() != backend.TierCgroup {
		t.Errorf("default boot, auto: Select = %v, %+v; want tier cgroup", b, ds)
	}
}
