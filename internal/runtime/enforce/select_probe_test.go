// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The probes below stand in for what internal/doctor's eight checks produce on each supported
// machine shape (docs/ARCHITECTURE.md §14's support matrix). The import direction is doctor ->
// enforce, so Select only ever sees a backend.Probe value; these are that value.
var (
	probeUser       = backend.Probe{backend.TierLandlock: true, backend.TierCgroup: false, backend.TierBPFLSM: false}
	probeRootNoBPF  = backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: false}
	probeRootBPFLSM = backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: true}
	probeNoLandlock = backend.Probe{backend.TierLandlock: false, backend.TierCgroup: false, backend.TierBPFLSM: false}
)

// TestSelectFromDoctorProbe walks the machine shapes doctor reports and the tier Select picks for
// each, in a build that embeds the BPF objects. Tier 3 is the plane in LSM mode (TIER3-PLAN T7): a machine that
// offers it, with doctor's LSM-mode plane handed over (LSMPlane), runs at tier 3; a probe offering it with no such
// plane is told so with a warning and runs at tier 2, never at tier 3 by another mode, and is never refused.
func TestSelectFromDoctorProbe(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true) // the shapes below are a tegobpf build's; see TestSelectWithoutTheObjects
	cases := []struct {
		name     string
		probe    backend.Probe
		wantTier backend.Tier
		wantErr  bool
		wantWarn string
		opts     []SelectOption
	}{
		{"uid 1000 on this box", probeUser, backend.TierLandlock, false, "", nil},
		// Tier 2 is the point of the middle tier: root with no boot change still gets kernel network
		// rules and path-aware open and exec deny, so a root probe selects cgroup, not landlock. The
		// contract leaves its tier to the machine, so a tier other than the one it compiled at is no
		// warning (every default run printed one under [tier-unavailable]).
		{"root without bpf in the LSM list", probeRootNoBPF, backend.TierCgroup, false, "", nil},
		{"root with bpf active and LSM mode", probeRootBPFLSM, backend.TierBPFLSM, false, "",
			[]SelectOption{LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)}},
		{"root with bpf active and no LSM mode handed over", probeRootBPFLSM, backend.TierCgroup, false,
			"tier bpflsm is available on this machine but the decision plane in LSM mode was not handed", nil},
		{"a kernel with no Landlock", probeNoLandlock, "", true, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, ds := Select(machine(""), table(backend.TierLandlock, ""), tc.probe, tc.opts...)
			if tc.wantErr {
				if b != nil || !hasSeverity(ds, "error") {
					t.Fatalf("Select = %v, %v; want an error diagnostic", b, ds)
				}
				return
			}
			if b == nil || hasSeverity(ds, "error") {
				t.Fatalf("Select = %v, %v", b, ds)
			}
			if b.Tier() != tc.wantTier {
				t.Errorf("tier %s, want %s", b.Tier(), tc.wantTier)
			}
			if tc.wantWarn == "" {
				if hasSeverity(ds, "warning") {
					t.Errorf("unexpected warnings: %v", ds)
				}
				return
			}
			if !containsMessage(ds, tc.wantWarn) {
				t.Errorf("diagnostics %v carry no warning about %q", ds, tc.wantWarn)
			}
		})
	}
}

// TestSelectAutoRunBelowItsCompiledTierIsQuiet: Compile resolves an auto contract
// to the highest tier the ceiling allows, bpflsm on an unbounded machine, so every default run on a machine
// without tier 3 printed "tier bpflsm is not available on this machine; running at landlock" with the code
// of the exit-125 refusal, on a run that went ahead.
func TestSelectAutoRunBelowItsCompiledTierIsQuiet(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	for _, pin := range []string{"", backend.Auto} {
		b, ds := Select(machine(""), table(backend.TierBPFLSM, pin), probeUser)
		if b == nil || b.Tier() != backend.TierLandlock {
			t.Fatalf("pin %q: Select = %v, %v", pin, b, ds)
		}
		if containsMessage(ds, "is not available on this machine") {
			t.Errorf("pin %q: an auto run warned about the tier it compiled at: %v", pin, ds)
		}
	}
}

// TestSelectRejectsANonTierProbeKey keeps a prober's mistake from reading as a machine capability.
func TestSelectRejectsANonTierProbeKey(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	probe := backend.Probe{backend.TierLandlock: true, backend.Tier("quantum"): true, backend.TierObserve: true}
	b, ds := Select(machine(""), table(backend.TierLandlock, ""), probe)
	if b == nil || b.Tier() != backend.TierLandlock {
		t.Fatalf("Select = %v, %v", b, ds)
	}
	for _, want := range []string{"quantum", string(backend.TierObserve)} {
		if !containsMessage(ds, want) {
			t.Errorf("diagnostics %v do not mention %q", ds, want)
		}
	}
	if !containsMessage(ds, "not a selectable tier") {
		t.Errorf("diagnostics %v do not say why the key was rejected", ds)
	}
}

// TestSelectDiagnosticsAreOrdered: the warning order must not depend on map iteration order, or a
// run's stderr would differ between two identical invocations.
func TestSelectDiagnosticsAreOrdered(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	var first []string
	for i := 0; i < 20; i++ {
		_, ds := Select(machine(""), table(backend.TierLandlock, ""), probeRootBPFLSM)
		got := make([]string, len(ds))
		for j, d := range ds {
			got[j] = d.Message
		}
		if i == 0 {
			first = got
			continue
		}
		if strings.Join(got, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d produced %v, run 0 produced %v", i, got, first)
		}
	}
}

// TestSortedTiers is the ordering itself: lowest rank first, so cgroup is warned about before
// bpflsm, and an unknown tier has a deterministic place.
func TestSortedTiers(t *testing.T) {
	got := sortedTiers(backend.Probe{
		backend.TierBPFLSM: true, backend.TierLandlock: true, backend.TierCgroup: true,
	})
	want := []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedTiers = %v, want %v", got, want)
		}
	}
	if len(sortedTiers(nil)) != 0 {
		t.Error("a nil probe has no keys")
	}
}

func containsMessage(ds []Diagnostic, sub string) bool {
	for _, d := range ds {
		if strings.Contains(d.Message, sub) {
			return true
		}
	}
	return false
}
