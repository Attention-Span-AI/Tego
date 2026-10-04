// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"path/filepath"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// protectedWriteTable is a table whose write entry holds one built-in deny_write target.
func protectedWriteTable(t *testing.T) (*agent.RuleTable, string) {
	t.Helper()
	root := t.TempDir()
	rt := table(backend.TierCgroup, "")
	rt.FS = []agent.FSRule{{Path: root, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	target := filepath.Join(root, ".git/config")
	rt.DenyWrite = []agent.FSRule{{Path: target, Kind: agent.FSDenyWrite}}
	return rt, target
}

// TestSelectProtectedWritesRequiresActualPlane is enforce-landlock R5a under fs.assurance: kernel (ADR 0041 D1
// (a)): a table with built-in deny_write targets is refused at tier landlock and at tier cgroup with no plane
// mode, before launch, an error naming the target, the kernel requirement and a fix that names fs.assurance. A
// working plane mode selects it; a table with no target is unaffected.
func TestSelectProtectedWritesRequiresActualPlane(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	rt, target := protectedWriteTable(t)
	rt.FSAssurance = agent.FSAssuranceKernel
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		b, ds := Select(machine(""), rt, backend.Probe{tier: true}, Only(tier))
		if b != nil || !hasSeverity(ds, "error") || !containsMessage(ds, "fs.deny_write["+target+"]") ||
			!containsMessage(ds, "fs.assurance: kernel") || !strings.Contains(ds[len(ds)-1].Fix, "narrow fs.write") ||
			!strings.Contains(ds[len(ds)-1].Fix, "fs.assurance") {
			t.Fatalf("%s without a plane, fs.assurance: kernel: Select = %T, %v", tier, b, ds)
		}
	}
	b, ds := Select(machine(""), rt, backend.Probe{backend.TierCgroup: true},
		Only(backend.TierCgroup), Plane(PlaneSetup{Mode: ebpfbindings.PlaneFmodRet, Build: ebpfbindings.ObjectPlaneProbe}))
	if b == nil || hasSeverity(ds, "error") {
		t.Fatalf("working plane, fs.assurance: kernel = %T, %v", b, ds)
	}
	rt.DenyWrite = nil
	b, ds = Select(machine(""), rt, backend.Probe{backend.TierLandlock: true}, Only(backend.TierLandlock))
	if b == nil || hasSeverity(ds, "error") {
		t.Fatalf("ordinary landlock write under fs.assurance: kernel = %T, %v", b, ds)
	}
}

// TestSelectProtectedWritesBestEffortByDefault is R5a's default (fs.assurance best-effort, ADR 0041 D1 (a)): the
// same table is selected at tier landlock and at tier cgroup with no plane mode, where the supervisor refuses its
// targets best effort (supervisor R15c). From 82a723b3 to ADR 0041 D1 both selections were refused.
func TestSelectProtectedWritesBestEffortByDefault(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	rt, _ := protectedWriteTable(t)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		b, ds := Select(machine(""), rt, backend.Probe{tier: true}, Only(tier))
		if b == nil || b.Tier() != tier || hasSeverity(ds, "error") {
			t.Errorf("%s without a plane, best effort: Select = %v, %v; want the tier", tier, b, ds)
		}
	}
}
