// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneSelectionReachesTheTierTwoBackend is TIER3-PLAN T6's wiring: Select's Plane option (doctor's
// Report.PlaneFor for tier cgroup) becomes the tier-2 backend's Options.Plane, and a run of it compiles the table's
// plane rows once and hands them to tier 1's composition on the run (cgroup.Run.PlaneRows), so the Landlock plan
// holds the keyed paths the plane is filled from. Without the option neither happens.
func TestPlaneSelectionReachesTheTierTwoBackend(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	dir := t.TempDir()
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: filepath.Join(dir, "out"), Kind: agent.FSWrite, Access: agent.AccessWriteSet}}}
	for _, setup := range []PlaneSetup{{}, {Mode: ebpfbindings.PlaneFmodRet, Build: ebpfbindings.ObjectPlaneProbe}} {
		b, ds := Select(machine(""), table(backend.TierCgroup, "cgroup"), probeRootNoBPF, Plane(setup))
		cb, ok := b.(cgroupBackend)
		if !ok {
			t.Fatalf("Select = %T, %v", b, ds)
		}
		if cb.opts.Plane.Mode != setup.Mode || cb.opts.Plane.Build != setup.Build {
			t.Errorf("the backend's plane is %+v, want %+v", cb.opts.Plane, setup)
		}
		var composedWith *cgroupenforce.Run
		cb.opts.Inherit = func(_ context.Context, _ *agent.RuleTable, run cgroupenforce.Run) (cgroupenforce.Inherited, error) {
			composedWith = &run
			return fakeInherited{closed: new(int)}, nil
		}
		cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
			o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
			return cgroupenforce.New(o)
		}
		if h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a"}); err == nil {
			_ = h.Close()
		}
		if composedWith == nil {
			t.Fatal("tier 1 was not composed")
		}
		switch {
		case setup.Mode == "" && composedWith.PlaneRows != nil:
			t.Error("rows compiled for a run on the fanotify listener")
		case setup.Mode != "" && (composedWith.PlaneRows == nil || len(composedWith.PlaneRows.Keyed) == 0):
			t.Errorf("a plane-mode run's tier-1 composition got rows %+v, want the table's", composedWith.PlaneRows)
		}
	}
}

// TestLSMPlaneReachesTheTierThreeBackend is TIER3-PLAN T7's wiring (enforce-plane R19): Select's LSMPlane option
// (doctor's Report.PlaneFor for tier bpflsm) constructs tier bpflsm as the tier-2 backend with that plane and
// Options.Tier set, and a run of a table compiled for tier bpflsm composes tier 1 with the plane rows, as tier cgroup's
// plane-mode run does. Handed doctor's refusal instead, `--tier bpflsm` is refused with it as the fix, and an auto run
// is warned and runs at tier cgroup, never at tier bpflsm in another mode.
func TestLSMPlaneReachesTheTierThreeBackend(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	setup := PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}
	b, ds := Select(machine(""), table(backend.TierBPFLSM, ""), probeRootBPFLSM, Only(backend.TierBPFLSM), LSMPlane(setup, nil))
	cb, ok := b.(cgroupBackend)
	if !ok || b.Tier() != backend.TierBPFLSM {
		t.Fatalf("Select = %T, %v", b, ds)
	}
	if cb.opts.Tier != backend.TierBPFLSM || cb.opts.Plane.Mode != setup.Mode || cb.opts.Plane.Build != setup.Build {
		t.Errorf("the backend's options are tier %q, plane %+v", cb.opts.Tier, cb.opts.Plane)
	}
	var composedWith *cgroupenforce.Run
	cb.opts.Inherit = func(_ context.Context, _ *agent.RuleTable, run cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		composedWith = &run
		return fakeInherited{closed: new(int)}, nil
	}
	var tier backend.Tier
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		tier = o.RunTier()
		o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
		return cgroupenforce.New(o)
	}
	dir := t.TempDir()
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: filepath.Join(dir, "out"), Kind: agent.FSWrite, Access: agent.AccessWriteSet}}}
	if h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a"}); err == nil {
		_ = h.Close()
	}
	if tier != backend.TierBPFLSM {
		t.Errorf("the run's backend is tier %q", tier)
	}
	if composedWith == nil || composedWith.PlaneRows == nil || len(composedWith.PlaneRows.Keyed) == 0 {
		t.Errorf("tier 1 was composed with %+v, want the table's plane rows", composedWith)
	}

	why := errors.New("tier bpflsm needs the decision plane in LSM mode: bpf is not in the active LSM list; fix: add lsm=...,bpf")
	b, ds = Select(machine(""), table(backend.TierBPFLSM, ""), probeRootBPFLSM, Only(backend.TierBPFLSM), LSMPlane(PlaneSetup{}, why))
	if b != nil || !hasSeverity(ds, "error") {
		t.Fatalf("--tier bpflsm without LSM mode: Select = %v, %v", b, ds)
	}
	for _, d := range ds {
		if d.Severity == "error" && !strings.Contains(d.Fix, "lsm=...,bpf") {
			t.Errorf("refusal %+v does not carry doctor's fix", d)
		}
	}
	b, ds = Select(machine(""), table(backend.TierBPFLSM, ""), probeRootBPFLSM, LSMPlane(PlaneSetup{}, why))
	if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "bpf is not in the active LSM list") {
		t.Errorf("auto without LSM mode: Select = %v, %v; want tier cgroup, said so", b, ds)
	}
}

// TestInheritedRunDropsTheMemfdArmOnlyWithAPlane is enforce-plane R27's memfd half at the seam (TIER3-PLAN T14):
// tier 1's composition for a tier-2 or tier-3 run carries PlaneMaps exactly when the run carries plane rows, which
// cgroupBackend.Prepare compiles only for a mode doctor's probe selected, and the plane's hooks include step C's. A
// run on the fanotify listener keeps the refusing arm.
func TestInheritedRunDropsTheMemfdArmOnlyWithAPlane(t *testing.T) {
	if !ebpfbindings.PlaneDecidesMappings() {
		t.Fatal("the plane's hooks do not include step C's deciding mmap_file and file_mprotect")
	}
	rows := &decide.PlaneRows{}
	for _, tc := range []struct {
		name string
		run  cgroupenforce.Run
		want bool
	}{
		{"a plane mode's run", cgroupenforce.Run{ID: "r", PlaneRows: rows}, true},
		{"the fanotify listener's run", cgroupenforce.Run{ID: "r"}, false},
	} {
		got := inheritedRun(tc.run)
		if got.PlaneMaps != tc.want || got.Plane != tc.run.PlaneRows {
			t.Errorf("%s: tier 1 composes %+v, want PlaneMaps %v and the run's rows", tc.name, got, tc.want)
		}
	}
}

// TestSharedInodeTableKeepsTheTierOneArms is the fail-open a shared-inode table left at tier cgroup: the rows were
// handed to tier 1's composition before choosePlane found two fs rows naming one file and fell back to the listener,
// so the filter admitted io_uring and dropped the memfd arm on a run no plane decides. The rows are refused before
// tier 1 is composed, with the reason choosePlane gives.
func TestSharedInodeTableKeepsTheTierOneArms(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: a, Kind: agent.FSWrite, Access: agent.AccessWriteSet},
			{Path: b, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}}
	setup := PlaneSetup{Mode: ebpfbindings.PlaneFmodRet, Build: ebpfbindings.ObjectPlaneProbe}
	sel, ds := Select(machine(""), table(backend.TierCgroup, "cgroup"), probeRootNoBPF, Plane(setup))
	cb, ok := sel.(cgroupBackend)
	if !ok {
		t.Fatalf("Select = %T, %v", sel, ds)
	}
	var composedWith *cgroupenforce.Run
	cb.opts.Inherit = func(_ context.Context, _ *agent.RuleTable, run cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		composedWith = &run
		return fakeInherited{closed: new(int)}, nil
	}
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
		return cgroupenforce.New(o)
	}
	if h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a"}); err == nil {
		_ = h.Close()
	}
	if composedWith == nil {
		t.Fatal("tier 1 was not composed")
	}
	if composedWith.PlaneRows != nil || !errors.Is(composedWith.PlaneErr, cgroupenforce.ErrPlaneSharedInode) {
		t.Errorf("tier 1 composed with rows %+v, err %v; want no rows and ErrPlaneSharedInode",
			composedWith.PlaneRows, composedWith.PlaneErr)
	}
	if got := inheritedRun(*composedWith); got.IOUring || got.PlaneMaps {
		t.Errorf("tier 1 composes IOUring %v, PlaneMaps %v for a run on the listener; want both false", got.IOUring, got.PlaneMaps)
	}
}

// TestLateSharedInodeRecomposesTierOne is the race TestSharedInodeTableKeepsTheTierOneArms leaves: the rows pass
// holdablePlaneRows, tier 1 is composed from them (io_uring admitted, the memfd arm dropped), and a hard link made
// while it is composed makes choosePlane fail. Falling back to the listener there kept that filter on a run no plane
// decides; tier 1 is composed again without the rows, with the reason, and the first composition is closed.
func TestLateSharedInodeRecomposesTierOne(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: a, Kind: agent.FSWrite, Access: agent.AccessWriteSet},
			{Path: b, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}}
	setup := PlaneSetup{Mode: ebpfbindings.PlaneFmodRet, Build: ebpfbindings.ObjectPlaneProbe}
	sel, ds := Select(machine(""), table(backend.TierCgroup, "cgroup"), probeRootNoBPF, Plane(setup))
	cb, ok := sel.(cgroupBackend)
	if !ok {
		t.Fatalf("Select = %T, %v", sel, ds)
	}
	var composed []cgroupenforce.Run
	closed := new(int)
	cb.opts.Inherit = func(_ context.Context, _ *agent.RuleTable, run cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		composed = append(composed, run)
		if len(composed) == 1 {
			if err := os.Link(a, b); err != nil {
				t.Skipf("no hard links here: %v", err)
			}
		}
		return fakeInherited{closed: closed}, nil
	}
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
		return cgroupenforce.New(o)
	}
	h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a", CgroupID: 1})
	if err == nil {
		_ = h.Close()
	}
	if len(composed) == 0 || composed[0].PlaneRows == nil {
		t.Fatalf("tier 1 was first composed with %+v, want the rows that held then", composed)
	}
	if errors.Is(err, cgroupenforce.ErrPlaneRowsChanged) {
		t.Fatalf("Prepare = %v; the late failure reached the caller instead of a composition without the rows", err)
	}
	if len(composed) != 2 {
		t.Fatalf("tier 1 composed %d times (Prepare: %v); want again without the rows once they no longer held", len(composed), err)
	}
	last := composed[1]
	if last.PlaneRows != nil || !errors.Is(last.PlaneErr, cgroupenforce.ErrPlaneSharedInode) {
		t.Errorf("tier 1 composed again with rows %+v, err %v; want no rows and ErrPlaneSharedInode", last.PlaneRows, last.PlaneErr)
	}
	if got := inheritedRun(last); got.IOUring || got.PlaneMaps {
		t.Errorf("tier 1 composes IOUring %v, PlaneMaps %v for a run on the listener; want both false", got.IOUring, got.PlaneMaps)
	}
	if *closed < 1 {
		t.Error("the composition for the plane was not closed")
	}
}

// TestPlaneRowsRefuseAnUnreadableMountTable is enforce-plane R12 when the launcher's mount table cannot be read: a
// table with a deny_write target cannot have its mounted roots keyed, so its rows are refused with
// cgroupenforce.ErrMountTable (tier cgroup then runs it on the listener, tier bpflsm refuses it) rather than
// compiled with no mount row, which let an attribute change below the target pass. A table with no deny_write target
// keys no mount row, so it does not read the table.
func TestPlaneRowsRefuseAnUnreadableMountTable(t *testing.T) {
	prev := planeMounts
	read := 0
	planeMounts = func() ([]string, error) {
		read++
		return nil, cgroupenforce.ErrMountTable
	}
	t.Cleanup(func() { planeMounts = prev })

	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS:        []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Resolved: "/w", Access: agent.AccessWriteSet}},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/secret", Resolved: "/w/secret", BuiltIn: true}},
	}
	if rows, err := planeRows(rt); !errors.Is(err, cgroupenforce.ErrMountTable) || rows != nil {
		t.Errorf("planeRows over an unreadable mount table = %+v, %v; want ErrMountTable", rows, err)
	}
	rt.DenyWrite = nil
	if _, err := planeRows(rt); err != nil || read != 1 {
		t.Errorf("planeRows with no deny_write target = %v after %d reads; want rows, the table unread", err, read)
	}
}
