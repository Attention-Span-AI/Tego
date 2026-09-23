// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestAtTierStampsTheTierARunGot is R14's re-clamp on a real auto contract. Compile resolves tier: auto
// to the unbounded machine's top tier without probing anything, so the table says bpflsm; the run then
// gets whatever enforce.Select finds. Before AtTier the compiled tier reached the backend unchanged, and
// the tier-2 backend refuses any table that does not say cgroup, so every auto contract failed Prepare
// with exit 125 on exactly the machines tier 2 exists for.
func TestAtTierStampsTheTierARunGot(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	if rt.Tier != backend.TierBPFLSM || rt.Capture != CaptureUprobe {
		t.Fatalf("an auto contract compiled to tier %s capture %s; this test assumes bpflsm and uprobe", rt.Tier, rt.Capture)
	}
	before := *rt

	cg := rt.AtTier(backend.TierCgroup)
	if cg == rt {
		t.Fatal("AtTier(cgroup) returned the compiled table itself")
	}
	if cg.Tier != backend.TierCgroup || cg.Capture != CaptureUprobe {
		t.Errorf("at cgroup: tier %s capture %s, want cgroup and the compiled uprobe", cg.Tier, cg.Capture)
	}
	// Everything else is the compiled table's: the same rules, the same contract and its hash.
	cg.Tier = rt.Tier
	if !reflect.DeepEqual(*cg, before) {
		t.Error("AtTier changed more than the tier")
	}

	ll := rt.AtTier(backend.TierLandlock)
	if ll.Tier != backend.TierLandlock || ll.Capture != CaptureForwarder {
		t.Errorf("at landlock: tier %s capture %s, want landlock and forwarder (uprobe needs BPF)", ll.Tier, ll.Capture)
	}

	if !reflect.DeepEqual(*rt, before) {
		t.Error("AtTier modified the compiled table (I4)")
	}
	for _, same := range []backend.Tier{backend.TierBPFLSM, backend.TierObserve, backend.TierAuto, "", "quantum"} {
		if got := rt.AtTier(same); got != rt {
			t.Errorf("AtTier(%q) built a new table; the compiled one already describes that run", same)
		}
	}
	var none *RuleTable
	if none.AtTier(backend.TierCgroup) != nil {
		t.Error("AtTier on a nil table returned a table")
	}
}

// TestAtTierKeepsAForwarderOrOffCapture: only uprobe depends on the tier; a mode the contract or the
// machine already lowered stays as it was.
func TestAtTierKeepsAForwarderOrOffCapture(t *testing.T) {
	for _, mode := range []CaptureMode{CaptureForwarder, CaptureOff} {
		rt := &RuleTable{Tier: backend.TierCgroup, Capture: mode}
		if got := rt.AtTier(backend.TierLandlock).Capture; got != mode {
			t.Errorf("capture %s at landlock became %s", mode, got)
		}
	}
}
