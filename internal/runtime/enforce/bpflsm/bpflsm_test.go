// SPDX-License-Identifier: Apache-2.0

package bpflsm

import (
	"errors"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestNewNeedsLSMMode is the constructor (TIER3-PLAN T7, enforce-plane R19): tier bpflsm is the tier-2 backend with
// the plane in LSM mode, reporting itself as tier bpflsm with tier 3's column; fmod_ret or no plane is refused.
func TestNewNeedsLSMMode(t *testing.T) {
	b, err := New(cgroupenforce.Options{Plane: cgroupenforce.PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}})
	if err != nil {
		t.Fatalf("New in LSM mode: %v", err)
	}
	if b.Tier() != backend.TierBPFLSM {
		t.Errorf("Tier() = %s", b.Tier())
	}
	if got, want := b.Capabilities(), backend.Matrix(backend.TierBPFLSM); len(got) != len(want) || got.Has(backend.CapChmodDeny) {
		t.Errorf("Capabilities() = %v, want tier bpflsm's static column %v", got, want)
	}
	for _, mode := range []ebpfbindings.PlaneMode{ebpfbindings.PlaneFmodRet, ""} {
		if b, err := New(cgroupenforce.Options{Plane: cgroupenforce.PlaneSetup{Mode: mode}}); b != nil || !errors.Is(err, cgroupenforce.ErrNeedsLSMMode) {
			t.Errorf("New in mode %q = %v, %v; want ErrNeedsLSMMode", mode, b, err)
		}
	}
}
