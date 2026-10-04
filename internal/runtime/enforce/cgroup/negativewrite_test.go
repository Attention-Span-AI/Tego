// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// protectedWriteTable is a table with one built-in deny_write target.
func protectedWriteTable() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{}, DenyWrite: []agent.FSRule{
		{Kind: agent.FSDenyWrite, Path: "/work/.git/config"},
	}}
}

// TestProtectedWritesNeverFallBackToListener is choosePlane under fs.assurance: kernel (ADR 0041 D1 (a),
// enforce-landlock R5a): a table with built-in deny_write targets is refused (ErrPlaneCannotHold) when no plane
// mode is set or the plane cannot hold it, keeping no plane state, rather than taking the fanotify listener, where
// the supervisor refuses its targets only best effort. A table with no target still takes the listener.
func TestProtectedWritesNeverFallBackToListener(t *testing.T) {
	rt := protectedWriteTable()
	rt.FSAssurance = agent.FSAssuranceKernel
	lateFailure := errors.New("plane rows changed before prepare")
	for _, setup := range []PlaneSetup{{}, {Mode: ebpfbindings.PlaneLSM}} {
		h := &Handle{opts: Options{Plane: setup}, run: Run{PlaneErr: lateFailure}}
		if err := h.choosePlane(rt); !errors.Is(err, ErrPlaneCannotHold) {
			t.Fatalf("mode %q, fs.assurance: kernel: unsafe fallback = %v", setup.Mode, err)
		}
		if h.planeMode != "" || h.planeRows != nil {
			t.Fatalf("failed setup retained a plane: %q, %v", h.planeMode, h.planeRows)
		}
	}
	// The same late failure still permits the ordinary listener fallback when no negative-write exception needs a
	// stronger mechanism.
	rt.DenyWrite = nil
	h := &Handle{opts: Options{Plane: PlaneSetup{Mode: ebpfbindings.PlaneLSM}}, run: Run{PlaneErr: lateFailure}}
	if err := h.choosePlane(rt); err != nil || !errors.Is(h.planeWhy, lateFailure) {
		t.Fatalf("ordinary fallback = %v, reason %v", err, h.planeWhy)
	}
}

// TestProtectedWritesFallBackToListenerByDefault is choosePlane's default (fs.assurance best-effort, ADR 0041 D1
// (a)): the same table takes the fanotify listener like any other when no plane mode is set or the plane cannot
// hold it, the listener's supervisor refusing its targets best effort. From 82a723b3 to ADR 0041 D1 both were
// refused.
func TestProtectedWritesFallBackToListenerByDefault(t *testing.T) {
	rt := protectedWriteTable()
	lateFailure := errors.New("plane rows changed before prepare")
	for _, setup := range []PlaneSetup{{}, {Mode: ebpfbindings.PlaneLSM}} {
		h := &Handle{opts: Options{Plane: setup}, run: Run{PlaneErr: lateFailure}}
		if err := h.choosePlane(rt); err != nil || h.planeMode != "" || h.planeRows != nil {
			t.Fatalf("mode %q, best effort: = %v, plane %q %v; want the listener", setup.Mode, err, h.planeMode, h.planeRows)
		}
		if setup.Mode != "" && !errors.Is(h.planeWhy, lateFailure) {
			t.Errorf("mode %q, best effort: the fallback's reason %v, want the plane's failure", setup.Mode, h.planeWhy)
		}
	}
}
