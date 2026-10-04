// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// withPlaneFDCap gives selection and a run's Prepare a descriptor cap of n.
func withPlaneFDCap(t *testing.T, n int) {
	t.Helper()
	prev := planeFDCap
	planeFDCap = func() int { return n }
	t.Cleanup(func() { planeFDCap = prev })
}

// overCapTable is a table compiled for tier bpflsm (pin "" is auto) with more keyed exec directories than a slot's
// rows map holds (decide.ErrPlaneCap).
func overCapTable(pin string) *agent.RuleTable {
	rt := table(backend.TierBPFLSM, pin)
	rt.Reach = []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
	if pin != "" {
		rt.Reach = []backend.Tier{backend.TierBPFLSM}
	}
	for i := range decide.PlaneRowsMax + 1 {
		p := "/d/" + strconv.Itoa(i)
		rt.Exec = append(rt.Exec, agent.ExecRule{Path: p, Resolved: p, IsDir: true, Verdict: agent.VerdictAllow})
	}
	return rt
}

// TestSelectAutoFallsBelowAPlaneThatCannotHoldTheTable is enforce-plane §2.4 condition 7 and §2.10 condition 2: an
// auto run of a table the plane cannot hold (over a slot's rows, or over this launcher's descriptor cap) is given
// tier cgroup, not tier bpflsm, whose Prepare refuses it, and the run's warning says why, naming the cap. A run that
// pinned tier bpflsm (--tier bpflsm, or tier: bpflsm in the contract) keeps tier bpflsm and its refusal at Prepare
// (cgroup.ErrPlaneCannotHold, exit 125). A table that fits runs at tier bpflsm with no such warning.
func TestSelectAutoFallsBelowAPlaneThatCannotHoldTheTable(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	withPlaneFDCap(t, 1<<20)
	lsm := LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)

	b, ds := Select(machine(""), overCapTable(""), probeRootBPFLSM, lsm)
	if b == nil || b.Tier() != backend.TierCgroup {
		t.Fatalf("auto over the plane's rows: Select = %v, %v; want tier cgroup", b, ds)
	}
	if !containsMessage(ds, "tier bpflsm cannot hold this contract") || !containsMessage(ds, "running at tier cgroup") ||
		!containsMessage(ds, "at most 4096") || hasSeverity(ds, "error") {
		t.Errorf("auto over the plane's rows: diagnostics %v must warn why, naming the cap", ds)
	}

	for name, opts := range map[string][]SelectOption{
		"--tier bpflsm":   {lsm, Only(backend.TierBPFLSM)},
		"tier: bpflsm":    {lsm},
		"machine: bpflsm": {lsm},
	} {
		m, rt := machine(""), overCapTable("bpflsm")
		if name == "machine: bpflsm" {
			m, rt = machine("bpflsm"), overCapTable("")
			rt.Reach = []backend.Tier{backend.TierBPFLSM}
		}
		if name == "--tier bpflsm" {
			rt = overCapTable("")
		}
		b, ds := Select(m, rt, probeRootBPFLSM, opts...)
		if b == nil || b.Tier() != backend.TierBPFLSM || containsMessage(ds, "cannot hold this contract") {
			t.Errorf("%s over the plane's rows: Select = %v, %v; want tier bpflsm, refused at Prepare", name, b, ds)
			continue
		}
		cb := b.(cgroupBackend)
		cb.opts.Inherit = func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error) {
			return fakeInherited{closed: new(int)}, nil
		}
		cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
			o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
			return cgroupenforce.New(o)
		}
		h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a"})
		if err == nil {
			_ = h.Close()
		}
		if !errors.Is(err, cgroupenforce.ErrPlaneCannotHold) || !strings.Contains(err.Error(), "at most 4096") {
			t.Errorf("%s: Prepare = %v, want ErrPlaneCannotHold naming the cap", name, err)
		}
	}

	dir := t.TempDir()
	fits := table(backend.TierBPFLSM, "")
	fits.FS = []agent.FSRule{{Path: filepath.Join(dir, "out"), Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	if b, ds := Select(machine(""), fits, probeRootBPFLSM, lsm); b == nil || b.Tier() != backend.TierBPFLSM ||
		containsMessage(ds, "cannot hold this contract") {
		t.Errorf("auto, a table that fits: Select = %v, %v; want tier bpflsm", b, ds)
	}

	// The descriptor cap: the same small table over a launcher that can hold fewer descriptors than it keys.
	withPlaneFDCap(t, 0)
	b, ds = Select(machine(""), fits, probeRootBPFLSM, lsm)
	if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "descriptor cap is 0") {
		t.Errorf("auto over the descriptor cap: Select = %v, %v; want tier cgroup, naming the cap", b, ds)
	}
	b, _ = Select(machine(""), fits, probeRootBPFLSM, lsm, Only(backend.TierBPFLSM))
	if b == nil || b.Tier() != backend.TierBPFLSM {
		t.Fatalf("--tier bpflsm over the descriptor cap: Select = %v", b)
	}
	cb := b.(cgroupBackend)
	cb.opts.Inherit = func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		return fakeInherited{closed: new(int)}, nil
	}
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
		return cgroupenforce.New(o)
	}
	h, err := cb.Prepare(context.Background(), fits, RunRef{ID: "r", Agent: "a"})
	if err == nil {
		_ = h.Close()
	}
	if !errors.Is(err, cgroupenforce.ErrPlaneCannotHold) || !strings.Contains(err.Error(), "descriptor cap is 0") {
		t.Errorf("--tier bpflsm over the descriptor cap: Prepare = %v, want ErrPlaneCannotHold naming the cap", err)
	}
}

// TestPlaneFDCapBelowTheReserveIsZero is enforce-plane §2.4 condition 6: a budget whose descriptors in use and
// reserve exceed its limit (Cap < 0) is a cap of 0, which selection refuses a keyed table at, as Prepare's budget
// does; -1, which PlaneRows.FitFDs reads as unknown and refuses nothing at, is kept for a budget that cannot be read.
// PlaneFDCap returned the negative Cap unchanged, so an auto run was given tier bpflsm with no warning.
func TestPlaneFDCapBelowTheReserveIsZero(t *testing.T) {
	prev := readPlaneFDBudget
	t.Cleanup(func() { readPlaneFDBudget = prev })

	readPlaneFDBudget = func() (landlock.FDBudget, error) { return landlock.FDBudget{Limit: 100, InUse: 50, Reserve: 64}, nil }
	if got := PlaneFDCap(); got != 0 {
		t.Errorf("PlaneFDCap under a budget below its reserve = %d, want 0", got)
	}
	readPlaneFDBudget = func() (landlock.FDBudget, error) { return landlock.FDBudget{}, errors.New("no rlimit") }
	if got := PlaneFDCap(); got != -1 {
		t.Errorf("PlaneFDCap with no budget = %d, want -1", got)
	}
	readPlaneFDBudget = func() (landlock.FDBudget, error) {
		return landlock.FDBudget{Limit: 1024, InUse: 10, Reserve: 64}, nil
	}
	if got := PlaneFDCap(); got != 950 {
		t.Errorf("PlaneFDCap = %d, want 950", got)
	}

	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	readPlaneFDBudget = func() (landlock.FDBudget, error) { return landlock.FDBudget{Limit: 100, InUse: 50, Reserve: 64}, nil }
	prevCap := planeFDCap
	planeFDCap = PlaneFDCap
	t.Cleanup(func() { planeFDCap = prevCap })
	lsm := LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)
	fits := table(backend.TierBPFLSM, "")
	fits.FS = []agent.FSRule{{Path: filepath.Join(t.TempDir(), "out"), Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	b, ds := Select(machine(""), fits, probeRootBPFLSM, lsm)
	if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "descriptor cap is 0") {
		t.Errorf("auto under a budget below its reserve: Select = %v, %v; want tier cgroup, naming the cap", b, ds)
	}
}

// withPlaneMounts gives selection and a run's Prepare the mount table points.
func withPlaneMounts(t *testing.T, points []string) {
	t.Helper()
	prev := planeMounts
	planeMounts = func() ([]string, error) { return points, nil }
	t.Cleanup(func() { planeMounts = prev })
}

// TestSelectAutoFallsBelowWhatPrepareRefuses is enforce-plane §2.4 condition 7 and §2.10 condition 2 for the checks
// Prepare makes beyond CompilePlane: an auto run is given tier cgroup, with the warning, for a table whose fs entries
// are one file under two names (cgroup.ErrPlaneSharedInode), whose mounted-root rows below a deny_write target take it
// over a slot's rows, or whose mounted roots take its keys over the descriptor cap. Selection asked CompilePlane and
// FitFDs alone, so each of these was given tier bpflsm and refused at Prepare with exit 125. A pinned bpflsm keeps
// tier bpflsm (and Prepare's refusal).
func TestSelectAutoFallsBelowWhatPrepareRefuses(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	withPlaneFDCap(t, 1<<20)
	withPlaneMounts(t, nil)
	lsm := LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)
	auto := func() *agent.RuleTable {
		rt := table(backend.TierBPFLSM, "")
		rt.Reach = []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
		return rt
	}
	wantCgroup := func(name string, rt *agent.RuleTable, why string) {
		t.Helper()
		if len(rt.DenyWrite) != 0 {
			// Under fs.assurance: kernel the listener fallback, where the supervisor refuses a deny_write target
			// best effort, is no tier for the table: auto and pinned selection both refuse (ADR 0041 D1 (a)). By
			// default the table falls to the listener as any other does, below.
			strict := *rt
			strict.FSAssurance = agent.FSAssuranceKernel
			b, ds := Select(machine(""), &strict, probeRootBPFLSM, lsm)
			if b != nil || !hasSeverity(ds, "error") || !containsMessage(ds, why) || !containsMessage(ds, "fs.assurance: kernel") {
				t.Errorf("auto, %s, fs.assurance: kernel: Select = %v, %v; want protected-write refusal naming %q", name, b, ds, why)
			}
			b, ds = Select(machine(""), &strict, probeRootBPFLSM, lsm, Only(backend.TierBPFLSM))
			if b != nil || !hasSeverity(ds, "error") || !containsMessage(ds, why) {
				t.Errorf("pinned, %s, fs.assurance: kernel: Select = %v, %v; want protected-write refusal naming %q", name, b, ds, why)
			}
		}
		b, ds := Select(machine(""), rt, probeRootBPFLSM, lsm)
		if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "tier bpflsm cannot hold this contract") ||
			!containsMessage(ds, why) || hasSeverity(ds, "error") {
			t.Errorf("auto, %s: Select = %v, %v; want tier cgroup with a warning naming %q", name, b, ds, why)
		}
		b, ds = Select(machine(""), rt, probeRootBPFLSM, lsm, Only(backend.TierBPFLSM))
		if b == nil || b.Tier() != backend.TierBPFLSM || containsMessage(ds, "cannot hold this contract") {
			t.Errorf("--tier bpflsm, %s: Select = %v, %v; want tier bpflsm, refused at Prepare", name, b, ds)
		}
	}

	dir := t.TempDir()
	a, l := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, l); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	shared := auto()
	shared.FS = []agent.FSRule{{Path: a, Kind: agent.FSWrite, Access: agent.AccessWriteSet},
		{Path: l, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	wantCgroup("two fs entries one file", shared, "one file under two names")

	mounted := auto()
	w := filepath.Join(dir, "w")
	git := filepath.Join(w, ".git")
	mounted.FS = []agent.FSRule{{Path: w, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	mounted.DenyWrite = []agent.FSRule{{Kind: agent.FSDenyWrite, Path: git, Resolved: git, BuiltIn: true, Unenforced: true}}
	rows, err := decide.CompilePlane(mounted)
	if err != nil {
		t.Fatal(err)
	}
	var points []string
	for i := range decide.PlaneRowsMax - rows.FSMapEntries() + 1 {
		points = append(points, filepath.Join(git, "m"+strconv.Itoa(i)))
	}
	withPlaneMounts(t, points)
	if err := planeCannotHold(mounted); err == nil {
		t.Fatal("the mounted-root rows over a slot's rows: planeCannotHold = nil")
	}
	wantCgroup("mounted roots over a slot's rows", mounted, "at most 4096")

	withPlaneMounts(t, points[:2])
	withPlaneFDCap(t, rows.Held())
	wantCgroup("mounted roots over the descriptor cap", mounted, "descriptor cap is "+strconv.Itoa(rows.Held()))
}

// TestSelectAutoAsksWhatPrepareAsks is enforce-plane §2.4 condition 7 and §2.10 condition 2 for the checks Prepare
// makes after CompilePlane: an auto table naming one file under two names (a hard link), or one whose mounted-root
// rows below a deny_write target take the fs map past a slot's rows, is given tier cgroup with the warning, not tier
// bpflsm that Prepare then refuses with ErrPlaneCannotHold; under fs.assurance: kernel the deny_write table is
// refused instead, since the listener decides its targets only best effort (ADR 0041 D1 (a)).
func TestSelectAutoAsksWhatPrepareAsks(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	withPlaneFDCap(t, 1<<20)
	withPlaneMounts(t, nil)
	lsm := LSMPlane(PlaneSetup{Mode: ebpfbindings.PlaneLSM, Build: ebpfbindings.ObjectPlaneRdonly}, nil)
	auto := func() *agent.RuleTable {
		rt := table(backend.TierBPFLSM, "")
		rt.Reach = []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
		return rt
	}

	dir := t.TempDir()
	a, l := filepath.Join(dir, "a"), filepath.Join(dir, "l")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, l); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	linked := auto()
	linked.FS = []agent.FSRule{{Path: a, Kind: agent.FSWrite, Access: agent.AccessWriteSet},
		{Path: l, Kind: agent.FSWrite, Access: agent.AccessWriteSet}}
	b, ds := Select(machine(""), linked, probeRootBPFLSM, lsm)
	if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "tier bpflsm cannot hold this contract") ||
		!containsMessage(ds, "running at tier cgroup") || hasSeverity(ds, "error") {
		t.Errorf("auto, two entries one inode: Select = %v, %v; want tier cgroup with the warning", b, ds)
	}

	mounted := auto()
	mounted.FS = []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Access: agent.AccessWriteFile | agent.AccessMakeDir}}
	mounted.DenyWrite = []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/meta", Resolved: "/w/meta", BuiltIn: true, Unenforced: true}}
	many := make([]string, decide.PlaneRowsMax)
	for i := range many {
		many[i] = "/w/meta/m" + strconv.Itoa(i)
	}
	withPlaneMounts(t, many)
	b, ds = Select(machine(""), mounted, probeRootBPFLSM, lsm)
	if b == nil || b.Tier() != backend.TierCgroup || !containsMessage(ds, "tier bpflsm cannot hold this contract") ||
		hasSeverity(ds, "error") {
		t.Errorf("auto, mount rows over the cap: Select = %v, %v; want tier cgroup with the warning", b, ds)
	}
	strict := *mounted
	strict.FSAssurance = agent.FSAssuranceKernel
	b, ds = Select(machine(""), &strict, probeRootBPFLSM, lsm)
	if b != nil || !containsMessage(ds, "tier bpflsm cannot hold this contract") || !hasSeverity(ds, "error") {
		t.Errorf("auto, mount rows over the cap, fs.assurance: kernel: Select = %v, %v; want protected-write refusal", b, ds)
	}
	withPlaneMounts(t, nil)
	if b, ds = Select(machine(""), mounted, probeRootBPFLSM, lsm); b == nil || b.Tier() != backend.TierBPFLSM ||
		containsMessage(ds, "cannot hold this contract") {
		t.Errorf("auto, the same table with no mounts: Select = %v, %v; want tier bpflsm", b, ds)
	}
}
