// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// withObjects describes a build that does, or does not, embed the BPF objects, for one test. The tests that
// use it do not run in parallel, because the seam is package state.
func withObjects(t *testing.T, present bool) {
	t.Helper()
	prev := objectsAvailable
	objectsAvailable = func() bool { return present }
	t.Cleanup(func() { objectsAvailable = prev })
}

// TestBuildable is the build's half of the one tier derivation: landlock is always built, cgroup and bpflsm (the
// plane in LSM mode over tier cgroup's backend, TIER3-PLAN T7) only with the objects, and anything else is not a tier
// at all.
func TestBuildable(t *testing.T) {
	if err := Buildable(backend.TierLandlock); err != nil {
		t.Errorf("landlock: %v", err)
	}
	withObjects(t, false)
	var nb *NotBuiltError
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		err := Buildable(tier)
		if !errors.As(err, &nb) || !errors.Is(err, ErrNotBuilt) {
			t.Fatalf("%s without objects: %v, want a NotBuiltError", tier, err)
		}
		if nb.Fix == "" || !strings.Contains(nb.Fix, "build-bpf") {
			t.Errorf("%s: fix %q does not name the build that carries the objects", tier, nb.Fix)
		}
		// One remedy for one condition: the backend's own refusal at Prepare names the same one.
		if nb.Fix != cgroupenforce.BuildFix {
			t.Errorf("%s: fix %q, but the tier-2 backend names %q for the same missing objects", tier, nb.Fix, cgroupenforce.BuildFix)
		}
	}
	withObjects(t, true)
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if err := Buildable(tier); err != nil {
			t.Errorf("%s with objects: %v", tier, err)
		}
	}
	for _, tier := range []backend.Tier{backend.TierObserve, backend.Tier("quantum")} {
		err := Buildable(tier)
		if !errors.As(err, &nb) {
			t.Errorf("%s: %v, want a NotBuiltError", tier, err)
			continue
		}
		if nb.Fix != "" {
			t.Errorf("%s: fix %q, but no build of this version carries it", tier, nb.Fix)
		}
	}
}

// TestBuildableReadsTheRealBuild ties the seam to the binary under test: an untagged test binary has no
// objects and refuses tier 2, and a tegobpf one builds it however it is linked. Since the tier arms after
// the child stage's execve (ADR 0021 (4)), a dynamically linked or PIE build, which `go test` makes wherever
// cgo is on, is offered the tier like a static one.
func TestBuildableReadsTheRealBuild(t *testing.T) {
	loader, rerr := agent.ReadInterp("/proc/self/exe")
	if rerr != nil {
		t.Fatalf("read this test binary's PT_INTERP: %v", rerr)
	}
	err := Buildable(backend.TierCgroup)
	if want := ebpfbindings.Available(); want != (err == nil) {
		t.Errorf("bpf.Available() = %v (PT_INTERP %q), but Buildable(cgroup) = %v", ebpfbindings.Available(), loader, err)
	}
}

// TestSelectWithoutTheObjects is the untagged release build on a root machine: doctor's probe would no
// longer offer tier 2 there, but a probe that does must still not produce a backend whose Prepare fails
// with ErrNotGenerated after the run's ledger and cgroup exist. An auto run falls to tier 1 and says why;
// a pinned tier 2 is exit 125 [tier-unavailable] before anything is created.
func TestSelectWithoutTheObjects(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, false)
	b, ds := Select(machine(""), table(backend.TierBPFLSM, ""), probeRootNoBPF)
	if b == nil || b.Tier() != backend.TierLandlock {
		t.Fatalf("Select = %v, %v; want landlock", b, ds)
	}
	if !containsMessage(ds, "tier cgroup is available on this machine but is not built into this binary") {
		t.Errorf("no warning names the missing objects: %v", ds)
	}
	var fixed bool
	for _, d := range ds {
		if strings.Contains(d.Fix, "build-bpf") {
			fixed = true
		}
	}
	if !fixed {
		t.Errorf("no diagnostic carries the build that has the objects: %v", ds)
	}

	b, ds = Select(machine(""), table(backend.TierCgroup, "cgroup"), probeRootNoBPF)
	if b != nil || !hasSeverity(ds, "error") {
		t.Fatalf("pinned cgroup without objects: Select = %v, %v; want exit 125", b, ds)
	}
}

// TestConstructRefusesWhatIsNotBuilt: the guard in construct holds even for a caller that skipped the
// filter, so no path hands the runtime a backend this binary cannot prepare.
func TestConstructRefusesWhatIsNotBuilt(t *testing.T) {
	withObjects(t, false)
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		b, err := construct(tier, machine(""), cgroupenforce.PlaneSetup{})
		if b != nil || !errors.Is(err, backend.ErrTierUnavailable) || !errors.Is(err, ErrNotBuilt) {
			t.Errorf("construct(%s) = %v, %v", tier, b, err)
		}
	}
}

// TestSelectWarnsWhenIOUringHasNoEffect: io_uring: true is refused at every tier this build runs but tier cgroup
// with a decision plane mode that holds the table and tier bpflsm (ADR 0018 (5), TIER3-PLAN T13), and a table
// compiled for a root tier got no compile warning about it (compile warns only for landlock), so Select says it for
// the tier the run actually got. A table compiled for landlock is not warned twice.
func TestSelectWarnsWhenIOUringHasNoEffect(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	ioTable := func(tier backend.Tier, pin string) *agent.RuleTable {
		rt := table(tier, pin)
		rt.Contract.IOUring = true
		return rt
	}
	plane := Plane(PlaneSetup{Mode: ebpfbindings.PlaneFmodRet, Build: ebpfbindings.ObjectPlaneRdonly})
	lsmPlane := LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)
	// A table the plane cannot hold (an exec entry that does not allow, decide.ErrPlaneExecVerdict) runs on the
	// fanotify listener at tier cgroup, where io_uring stays refused.
	unheld := ioTable(backend.TierCgroup, "cgroup")
	unheld.Exec = []agent.ExecRule{{Path: "/usr/bin/true", Verdict: agent.VerdictAsk}}
	// Two fs entries that are hard links of one file compile but fail Prepare's PlaneHoldable
	// (cgroupenforce.ErrPlaneSharedInode), so that run is on the listener too.
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	shared := ioTable(backend.TierCgroup, "cgroup")
	shared.FS = append(shared.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: a, Resolved: a},
		agent.FSRule{Kind: agent.FSDenyRead, Path: b, Resolved: b})
	overFDCap := ioTable(backend.TierCgroup, "cgroup")
	overFDCap.FS = []agent.FSRule{{Path: "/w", Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	decided := true
	defer func(was func() bool) { ioUringDecided = was }(ioUringDecided)
	ioUringDecided = func() bool { return decided }
	cases := []struct {
		name  string
		rt    *agent.RuleTable
		probe backend.Probe
		opts  []SelectOption
		warn  bool
	}{
		{"auto contract run at tier 1", ioTable(backend.TierBPFLSM, ""), probeUser, nil, true},
		{"auto contract run at tier 2", ioTable(backend.TierBPFLSM, ""), probeRootNoBPF, nil, true},
		{"contract pinned to cgroup", ioTable(backend.TierCgroup, "cgroup"), probeRootNoBPF, nil, true},
		{"contract pinned to cgroup, with a plane mode", ioTable(backend.TierCgroup, "cgroup"), probeRootNoBPF,
			[]SelectOption{plane}, false},
		{"auto contract run at tier 2, with a plane mode", ioTable(backend.TierBPFLSM, ""), probeRootNoBPF,
			[]SelectOption{plane}, false},
		{"auto contract run at tier 1, with a plane mode for tier 2", ioTable(backend.TierBPFLSM, ""), probeUser,
			[]SelectOption{plane}, true},
		// Tier 3's plane comes in LSMPlane, not Plane, and it decides the run as tier 2's does (ADR 0018 (5)).
		{"auto contract run at tier 3", ioTable(backend.TierBPFLSM, ""), probeRootBPFLSM,
			[]SelectOption{lsmPlane}, false},
		{"auto contract run at tier 3, with plane modes for tiers 2 and 3", ioTable(backend.TierBPFLSM, ""), probeRootBPFLSM,
			[]SelectOption{plane, lsmPlane}, false},
		{"contract pinned to cgroup, with a plane mode that cannot hold it", unheld, probeRootNoBPF,
			[]SelectOption{plane}, true},
		{"contract pinned to cgroup, two fs entries on one inode", shared, probeRootNoBPF,
			[]SelectOption{plane}, true},
		// Over the descriptor cap (planeFDCap 0 below, for this case alone): Prepare hands the plane no rows, so the
		// listener decides the run and io_uring stays refused, as over the maps.
		{"contract pinned to cgroup, with a plane mode, over the descriptor cap", overFDCap, probeRootNoBPF,
			[]SelectOption{plane}, true},
		{"compiled for landlock: compile already warned", ioTable(backend.TierLandlock, "landlock"), probeRootNoBPF, nil, false},
		{"io_uring not declared", table(backend.TierCgroup, "cgroup"), probeRootNoBPF, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rt == overFDCap {
				withPlaneFDCap(t, 0)
			}
			b, ds := Select(machine(""), tc.rt, tc.probe, tc.opts...)
			if b == nil {
				t.Fatalf("Select = nil, %v", ds)
			}
			var got bool
			for _, d := range ds {
				if d.Code == agent.CodeIOUring {
					got = true
					if d.Severity != "warning" || !strings.Contains(d.Message, "tier "+string(b.Tier())) {
						t.Errorf("diagnostic %+v", d)
					}
				}
			}
			if got != tc.warn {
				t.Errorf("io_uring warning = %v, want %v: %v", got, tc.warn, ds)
			}
		})
	}
	// A tier whose kernel could not decide every submission keeps io_uring refused, and says so.
	decided = false
	_, ds := Select(machine(""), ioTable(backend.TierCgroup, "cgroup"), probeRootNoBPF, plane)
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == agent.CodeIOUring }) {
		t.Errorf("a plane mode on a kernel that does not decide every submission: %v, want the io_uring warning", ds)
	}
	_, ds = Select(machine(""), ioTable(backend.TierBPFLSM, ""), probeRootBPFLSM, lsmPlane)
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == agent.CodeIOUring }) {
		t.Errorf("tier 3 on a kernel that does not decide every submission: %v, want the io_uring warning", ds)
	}
}
