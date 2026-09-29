// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakePlane records what a Handle asks of its plane into the fake kernel's call log, so the plane's steps are
// ordered against the kernel's.
type fakePlane struct {
	k     *fakeKernel
	fills []planeFillRequest
	// unix is whether the plane's step D hooks are loaded (a kernel below 6.7).
	unix bool
	// attached is the hook set the plane reports (hooks).
	attached map[string]bool
	// counters is what counts answers, countSlot the slot it was last asked, countErr its error.
	counters  ebpfbindings.PlaneCounts
	countSlot uint32
	countErr  error
	// pins is the plane's pin map for every slot; nil is a plane without pin maps.
	pins *fakePinMap
}

func (p *fakePlane) counts(slot uint32) (ebpfbindings.PlaneCounts, error) {
	p.countSlot = slot
	return p.counters, p.countErr
}

func (p *fakePlane) decidesUnix() bool { return p.unix }

func (p *fakePlane) hooks() map[string]bool { return p.attached }

func (p *fakePlane) pinsReady() bool { return p.pins != nil }

func (p *fakePlane) slotPins(slot uint32) (slotPinMap, error) {
	if p.pins == nil {
		return nil, errors.New("fake plane: no pin maps")
	}
	return p.pins, nil
}

func (p *fakePlane) prepareSlot(slot uint32) error { return p.k.note("plane.prepareSlot") }

func (p *fakePlane) clearSlot(slot uint32) error { return p.k.note("plane.clearSlot") }

func (p *fakePlane) fill(req planeFillRequest) (planeFillReport, error) {
	if err := p.k.note("plane.fill"); err != nil {
		return planeFillReport{}, err
	}
	p.fills = append(p.fills, req)
	keyed := make([]PlaneKeyed, 0, len(req.Rows.FS))
	for i, r := range req.Rows.FS {
		keyed = append(keyed, PlaneKeyed{Path: r.Path, Dev: 7, Ino: uint64(i + 1)})
	}
	return planeFillReport{Rows: len(req.Rows.FS), ExecRows: len(req.Rows.Exec), Keyed: keyed}, nil
}

// planeFixture is newFixture with a plane mode selected and a fake plane loaded with the build.
func planeFixture(t *testing.T, mode ebpfbindings.PlaneMode, opts ...func(*Options)) (*fixture, *fakePlane) {
	t.Helper()
	all := append([]func(*Options){func(o *Options) {
		o.Plane = PlaneSetup{Mode: mode, Build: ebpfbindings.ObjectPlaneProbe}
		o.planeHeld = func(string) (int, bool) { return -1, false }
		o.newListener = func(*Handle) (*fanotifyListener, error) {
			t.Error("a plane-mode run made a fanotify group")
			return nil, errors.New("no listener in plane mode")
		}
	}}, opts...)
	f := newFixture(t, all...)
	p := &fakePlane{k: f.kernel}
	f.kernel.plane = p
	return f, p
}

// callsFrom is the kernel's call log from the first call named first.
func callsFrom(calls []string, first string) []string {
	i := slices.Index(calls, first)
	if i < 0 {
		return nil
	}
	return calls[i:]
}

// TestPlaneRunPrepareArmDetach is a plane-mode run's whole life (enforce-plane R15, R16, R18, R22; TIER3-PLAN T6):
// no fanotify group; the slot's plane maps made and cleared beside the slot's purge, the rows filled last in Prepare
// with the run's gen; the run-set row, inserted by Arm, names the mode; the capability line keeps read and exec
// denial; Detach clears the slot's plane rows once the run-set row is gone.
func TestPlaneRunPrepareArmDetach(t *testing.T) {
	t.Parallel()
	for _, mode := range ebpfbindings.PlaneModes {
		t.Run(string(mode), func(t *testing.T) {
			f, plane := planeFixture(t, mode)
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if h.fan != nil {
				t.Fatal("a plane-mode run has a fanotify listener")
			}
			got := callsFrom(f.kernel.calls, "purgeSlot")
			if len(got) < 3 || got[1] != "plane.prepareSlot" || got[2] != "plane.clearSlot" {
				t.Errorf("after the slot's purge: %v, want the plane's slot made and cleared", got)
			}
			if last := f.kernel.calls[len(f.kernel.calls)-1]; last != "plane.fill" {
				t.Errorf("Prepare's last kernel step is %s, want the plane's fill: %v", last, f.kernel.calls)
			}
			if len(plane.fills) != 1 {
				t.Fatalf("%d fills", len(plane.fills))
			}
			req := plane.fills[0]
			if req.Slot != h.Slot() || req.Gen != h.gen || req.Gen == 0 || req.Rows == nil || req.Held == nil {
				t.Errorf("fill request %+v, want slot %d gen %d with rows and held descriptors", req, h.Slot(), h.gen)
			}
			if !req.Exec.Decides {
				t.Error("a compiled explicit exec section does not decide exec in the plane")
			}
			if dp, why := h.PlaneChoice(); dp != string(mode) || why != nil {
				t.Errorf("DecisionPlane = %s, %v", dp, why)
			}
			// The files the fill wrote the fs rows at, which an adoption reads (Handle.PlaneKeyed, ADR 0055).
			if keyed, ok := h.PlaneKeyed(); !ok || len(keyed) != len(req.Rows.FS) || len(keyed) == 0 || keyed[0].Path != req.Rows.FS[0].Path {
				t.Errorf("PlaneKeyed = %+v %v after the fill, want the fill's %d fs rows", keyed, ok, len(req.Rows.FS))
			}
			caps := h.Capabilities()
			if !caps.Has(backend.CapReadDeny) || !caps.Has(backend.CapExecDeny) {
				t.Errorf("capabilities %v: a plane decides read and exec denial", caps)
			}
			if !caps.Has(backend.CapProtectedWriteTargets) {
				t.Errorf("capabilities %v: a plane mode decides the built-in deny_write targets by inode (ADR 0041 D7)", caps)
			}
			if _, ok := f.kernel.runs[f.run.CgroupID]; ok {
				t.Fatal("Prepare inserted the run-set row")
			}
			if err := h.Arm(); err != nil {
				t.Fatalf("Arm: %v", err)
			}
			if row := f.kernel.runs[f.run.CgroupID]; row.Plane != ebpfbindings.RunPlaneOf(mode) || row.Plane == 0 {
				t.Errorf("run-set row %+v, want plane %d", row, ebpfbindings.RunPlaneOf(mode))
			}
			f.kernel.calls = nil
			if err := h.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			rm, cl := slices.Index(f.kernel.calls, "removeRun"), slices.Index(f.kernel.calls, "plane.clearSlot")
			if rm < 0 || cl < rm {
				t.Errorf("Detach: %v, want the plane's clear after the run-set row's removal", f.kernel.calls)
			}
		})
	}
}

// TestPlaneFillCarriesTheUnixPolicy is enforce-plane R14's Prepare half (TIER3-PLAN T15): the fill writes the slot's
// unix policy with the run's gen on every plane run, since a step D hook that finds none refuses; it decides only
// where the plane's unix hooks are loaded (below 6.7) and the contract has a net: section, and it names this
// launcher's cgroup as the relay's, as Attach does for connect_unix. A launcher inside the run's own cgroup fails
// Prepare, as it fails Attach: the relay could not be told from the agent.
func TestPlaneFillCarriesTheUnixPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		unix, noNet bool
		want        bool
		self        string
		wantPrepErr bool
	}{
		{name: "6.7+: connect_unix decides", unix: false},
		{name: "below 6.7 with a net: section", unix: true, want: true},
		{name: "below 6.7 with no net: section", unix: true, noNet: true},
		{name: "a launcher inside the run's cgroup", unix: true, self: "/tego.slice/run-1.scope", wantPrepErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, plane := planeFixture(t, ebpfbindings.PlaneLSM, func(o *Options) {
				if tc.self != "" {
					o.selfCgroup = func() (string, error) { return tc.self, nil }
				}
			})
			plane.unix = tc.unix
			if tc.noNet {
				f.table.Net = nil
				f.table.Contract = &agent.Contract{}
			}
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if tc.wantPrepErr {
				if err == nil {
					_ = h.Close()
					t.Fatal("Prepare went ahead with the launcher inside the run's cgroup")
				}
				return
			}
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			defer h.Close()
			if len(plane.fills) != 1 {
				t.Fatalf("%d fills", len(plane.fills))
			}
			got := plane.fills[0].Unix
			if got.Decides != tc.want {
				t.Errorf("unix policy %+v, want Decides %v", got, tc.want)
			}
			relay, err := cgroupIDOfPath(f.run.CgroupMount, "/")
			if err != nil {
				t.Fatal(err)
			}
			if tc.want && got.Relay != relay {
				t.Errorf("relay cgroup %d, want this launcher's, %d", got.Relay, relay)
			}
			if !tc.want && got.Relay != 0 {
				t.Errorf("relay cgroup %d on a policy that decides nothing", got.Relay)
			}
		})
	}
}

// TestPlaneFallsBackToTheListenerForATableItCannotHold is choosePlane: a table whose rows the plane cannot express
// (here an exec entry that does not allow, decide.ErrPlaneExecVerdict) runs on the fanotify listener, whole, and
// says why; the run-set row names no plane, so no plane program decides the run.
func TestPlaneFallsBackToTheListenerForATableItCannotHold(t *testing.T) {
	t.Parallel()
	f, plane := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) {
		o.newListener = nil // the listener is the run's this time
	})
	f.backend.opts.newListener = newFixture(t).backend.opts.newListener
	f.table.Exec = []agent.ExecRule{{Path: "/usr/bin/true", Verdict: agent.VerdictAsk}}
	h := f.prepareArmed(t)
	defer h.Close()
	if h.fan == nil {
		t.Error("the fallback run has no listener")
	}
	dp, why := h.PlaneChoice()
	var verdict *decide.ErrPlaneExecVerdict
	if dp != PlaneFanotify || !errors.As(why, &verdict) {
		t.Errorf("DecisionPlane = %s, %v; want fanotify because of the exec entry", dp, why)
	}
	if len(plane.fills) != 0 || slices.Contains(f.kernel.calls, "plane.prepareSlot") {
		t.Errorf("the fallback run touched the plane: %v", f.kernel.calls)
	}
	if row := f.kernel.runs[f.run.CgroupID]; row.Plane != ebpfbindings.RunPlaneNone {
		t.Errorf("run-set row %+v names a plane", row)
	}
}

// TestPlaneHoldsADenyWriteTargetDeclaredThroughALink: a deny_write target declared through a symlink (.git/hooks ->
// ../real-hooks) keys the link at its own inode (PlaneRows.NoFollow, enforce-plane R11), so the link's row and its
// target's are two files, not one under two names: the shared-inode check stats a NoFollow row without following, as
// the fill opens it. Two hard links named beside it are still one file under two names.
func TestPlaneHoldsADenyWriteTargetDeclaredThroughALink(t *testing.T) {
	t.Parallel()
	h := t.TempDir()
	target, git := filepath.Join(h, "real-hooks"), filepath.Join(h, ".git")
	for _, d := range []string{target, git} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(git, "hooks")
	if err := os.Symlink("../real-hooks", link); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS:        []agent.FSRule{{Kind: agent.FSWrite, Path: h, Raw: h, Resolved: h, Access: agent.AccessWriteSet}},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: link, Resolved: target, BuiltIn: true, Unenforced: true}},
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rows.NoFollow, link) {
		t.Fatalf("NoFollow = %v, want the link %s; the test's premise is gone", rows.NoFollow, link)
	}
	if err := PlaneHoldable(rows); err != nil {
		t.Errorf("PlaneHoldable over a target declared through a link = %v, want held", err)
	}
	if err := tier3Plane(PlaneSetup{Mode: ebpfbindings.PlaneLSM}, rt, &Run{}); err != nil {
		t.Errorf("tier3Plane over a target declared through a link = %v, want held", err)
	}

	f, g := filepath.Join(h, "f"), filepath.Join(h, "g")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(f, g); err != nil {
		t.Fatal(err)
	}
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: f, Resolved: f}, agent.FSRule{Kind: agent.FSDenyRead, Path: g, Resolved: g})
	if rows, err = decide.CompilePlane(rt); err != nil {
		t.Fatal(err)
	}
	if err := PlaneHoldable(rows); !errors.Is(err, ErrPlaneSharedInode) {
		t.Errorf("PlaneHoldable over two hard links beside the link = %v, want ErrPlaneSharedInode", err)
	}
}

// TestPlaneSharedInodeFallsBackOrRefuses: two fs entries that are one file under two names (hard links) are found
// before anything is loaded, where the fill's refusal of the second row failed every run with exit 125: tier cgroup
// runs the table on the listener, saying why, and tier bpflsm's precondition refuses it with ErrPlaneCannotHold
// naming both paths. Two exec entries on one inode are no clash: each listed link has its own row (§6 E15).
func TestPlaneSharedInodeFallsBackOrRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "dirname"), filepath.Join(dir, "mkdir")
	if err := os.WriteFile(a, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	fs := []agent.FSRule{{Path: a, Resolved: a, Kind: agent.FSDenyRead}, {Path: b, Resolved: b, Kind: agent.FSDenyRead}}

	f, plane := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) { o.newListener = nil })
	f.backend.opts.newListener = newFixture(t).backend.opts.newListener
	f.table.FS = append(f.table.FS, fs...)
	h := f.prepareArmed(t)
	defer h.Close()
	dp, why := h.PlaneChoice()
	if dp != PlaneFanotify || !errors.Is(why, ErrPlaneSharedInode) || !strings.Contains(why.Error(), b) {
		t.Errorf("PlaneChoice = %s, %v; want fanotify because %s and %s are one inode", dp, why, a, b)
	}
	if len(plane.fills) != 0 {
		t.Errorf("the fallback run filled the plane: %v", plane.fills)
	}

	rt := &agent.RuleTable{FS: fs}
	err := tier3Plane(PlaneSetup{Mode: ebpfbindings.PlaneLSM}, rt, &Run{})
	if !errors.Is(err, ErrPlaneCannotHold) || !errors.Is(err, ErrPlaneSharedInode) {
		t.Errorf("tier3Plane = %v; want ErrPlaneCannotHold for the shared inode", err)
	}

	// Two exec entries naming the two links are held as two rows.
	rt = &agent.RuleTable{Exec: []agent.ExecRule{{Path: a, Verdict: agent.VerdictAllow}, {Path: b, Verdict: agent.VerdictAllow}}}
	if err := tier3Plane(PlaneSetup{Mode: ebpfbindings.PlaneLSM}, rt, &Run{}); err != nil {
		t.Errorf("tier3Plane over two exec links of one file = %v", err)
	}
}

// TestPlaneFillFailureFailsPrepare: a fill that does not come out as planned fails Prepare, which unwinds with the
// slot's plane rows cleared and the slot released (R16, §7 "The fill disagreeing with fdinfo fails Prepare").
func TestPlaneFillFailureFailsPrepare(t *testing.T) {
	t.Parallel()
	f, _ := planeFixture(t, ebpfbindings.PlaneLSM)
	f.kernel.failAt = "plane.fill"
	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded over a failed fill")
	}
	after := callsFrom(f.kernel.calls, "plane.fill")
	if !slices.Contains(after, "plane.clearSlot") || !slices.Contains(after, "removeRules") {
		t.Errorf("after the failed fill: %v, want the plane's clear among the unwinding", after)
	}
	st, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if held, _ := st.heldBy(0); held {
		t.Error("slot 0 stays held after the failed Prepare")
	}
}

// TestPlaneNeedsTheInheritedPlansDescriptors: the rows are keyed by the inherited Landlock plan's O_PATH
// descriptors, so a plane-mode run with no inherited state that holds them is refused at Prepare.
func TestPlaneNeedsTheInheritedPlansDescriptors(t *testing.T) {
	t.Parallel()
	f, plane := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) { o.planeHeld = nil })
	_, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if !errors.Is(err, ErrNotPrepared) || !strings.Contains(err.Error(), "descriptors") {
		t.Fatalf("Prepare = %v, want ErrNotPrepared naming the descriptors", err)
	}
	if len(plane.fills) != 0 {
		t.Error("filled without descriptors")
	}
}

// TestExecKeyRows: the rows keyed by no inode. No exec: section writes none (bprm_check then decides nothing); one
// writes a row per bare-name entry at its name key and nothing at key 0 (the exec: section and exec.anonymous are the
// slot header's flags).
func TestExecKeyRows(t *testing.T) {
	t.Parallel()
	rows := &decide.PlaneRows{Names: []decide.PlaneExecName{{Name: "git", Rule: 3}}}
	if keys, _, err := execKeyRows(planeFillRequest{Gen: 9, Rows: rows}); err != nil || len(keys) != 0 {
		t.Errorf("no exec section: %v, %v", keys, err)
	}
	keys, vals, err := execKeyRows(planeFillRequest{Gen: 9, Rows: rows, Exec: planeExecPolicy{Decides: true, Anonymous: true}})
	if err != nil || len(keys) != 1 {
		t.Fatalf("%v, %v: want the name row alone (no policy row: the header says what it said)", keys, err)
	}
	want, _ := ebpfbindings.PlaneNameKey("git")
	if keys[0] != want || vals[0].Gen != 9 || vals[0].RuleIdx != 3 || vals[0].NameLen != 3 || string(vals[0].Name[:3]) != "git" ||
		vals[0].Flags != 0 {
		t.Errorf("name row %d %+v", keys[0], vals[0])
	}
	if keys, _, _ := execKeyRows(planeFillRequest{Gen: 9, Rows: &decide.PlaneRows{}, Exec: planeExecPolicy{Decides: true}}); len(keys) != 0 {
		t.Errorf("rows %v for a contract with no bare names", keys)
	}
	if _, _, err := execKeyRows(planeFillRequest{Gen: 1, Rows: &decide.PlaneRows{Names: []decide.PlaneExecName{{Name: "", Rule: 1}}},
		Exec: planeExecPolicy{Decides: true}}); err == nil {
		t.Error("an empty name became a row")
	}
}

// TestSlotHeaderSaysWhatTheRunDecides is enforce-plane R6's header: the run's gen, the rows written, and a flag per
// thing the contract decides beyond its fs rows; a section the contract lacks is a flag left clear, and step D's
// unix flag needs both the contract's net: section and this plane's unix hooks.
func TestSlotHeaderSaysWhatTheRunDecides(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		req  planeFillRequest
		unix bool
		want uint32
	}{
		{"nothing", planeFillRequest{}, true, 0},
		{"exec", planeFillRequest{Exec: planeExecPolicy{Decides: true}}, false, ebpfbindings.PlaneSlotExecDecides},
		{"exec.anonymous", planeFillRequest{Exec: planeExecPolicy{Decides: true, Anonymous: true}}, false,
			ebpfbindings.PlaneSlotExecDecides | ebpfbindings.PlaneSlotExecAnon},
		{"anonymous without exec", planeFillRequest{Exec: planeExecPolicy{Anonymous: true}}, false, 0},
		{"unix, hooks loaded", planeFillRequest{Unix: planeUnixPolicy{Decides: true}}, true, ebpfbindings.PlaneSlotUnixDecides},
		{"unix, hooks absent", planeFillRequest{Unix: planeUnixPolicy{Decides: true}}, false, 0},
		{"empty explicit listeners", planeFillRequest{Rows: &decide.PlaneRows{ListenPolicy: true}}, false, ebpfbindings.PlaneSlotListenDecides},
		{"legacy listeners", planeFillRequest{Rows: &decide.PlaneRows{}}, false, 0},
		{"keyring opt in", planeFillRequest{KeyringAllowed: true}, false, ebpfbindings.PlaneSlotKeyringAllowed},
	} {
		tc.req.Gen = 7
		h := slotHeader(tc.req, tc.unix, 3, 4)
		if h.Gen != 7 || h.Flags != tc.want || h.FSRows != 3 || h.ExecRows != 4 {
			t.Errorf("%s: header %+v, want gen 7 flags %#x rows 3, 4", tc.name, h, tc.want)
		}
	}
}

// TestSlotHeaderSaysTheRunHasNameEntries is ADR 0043 D9's header half: a table with name rows gets the name flag and
// the prefilter's leads and prefix lengths (written last, after putNameEntries), and a table without (one that can
// land only at tier landlock) leaves the flag clear and the leads zero, so no hook asks a name.
func TestSlotHeaderSaysTheRunHasNameEntries(t *testing.T) {
	t.Parallel()
	rows := &decide.PlaneRows{
		NameRows:   []decide.PlaneNameRow{{Name: ".env"}, {Name: ".env.", Prefix: true}},
		Leads:      []string{".env"},
		PrefixLens: []uint8{5},
	}
	h := slotHeader(planeFillRequest{Gen: 7, Rows: rows}, false, 1, 0)
	if h.Flags != ebpfbindings.PlaneSlotNameDecides || h.NLeads != 1 || h.LeadLen[0] != 4 || h.MinLen != 4 ||
		h.NPrefixes != 1 || h.PrefixLen[0] != 5 {
		t.Errorf("header %+v, want the name flag, one lead of 4 bytes and one prefix length of 5", h)
	}
	if h := slotHeader(planeFillRequest{Gen: 7, Rows: &decide.PlaneRows{Leads: []string{".env"}}}, false, 1, 0); h.Flags != 0 ||
		h.NLeads != 0 || h.Lead != [ebpfbindings.PlaneNameLeads]uint64{} {
		t.Errorf("a table without name rows has header %+v, want no name flag and no leads", h)
	}
	// A lead set the header cannot carry leaves the flag clear (fill then refuses Prepare): nine leads.
	many := *rows
	many.Leads = []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"}
	if h := slotHeader(planeFillRequest{Gen: 7, Rows: &many}, false, 1, 0); h.Flags&ebpfbindings.PlaneSlotNameDecides != 0 {
		t.Errorf("nine leads gave header %+v the name flag", h)
	}
}

// TestAdoptedPlaneIsReadyForPins: a plane adopted from a compact load keeps its maps' inner definitions unloaded until a
// slot map is made (loadInner), so it is ready for pins once the pin maps are open, and the pin map's inner definition
// is loaded when the first pinned slot is made. A second run on a plane another launcher loaded (tier bpflsm after a
// tier cgroup run in the same boot) ran unpinned, "the plane object has no exec pin maps", before this.
func TestAdoptedPlaneIsReadyForPins(t *testing.T) {
	t.Parallel()
	inner := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 1}
	full := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}
	for _, name := range []string{ebpfbindings.MapPlaneRows, ebpfbindings.MapPlaneExecRows,
		ebpfbindings.MapPlaneListenRows, ebpfbindings.MapPlaneNameRows, ebpfbindings.MapPlaneExecPins} {
		full.Maps[name] = &ebpf.MapSpec{Name: name, Type: ebpf.HashOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1,
			InnerMap: inner}
	}
	p := &bpfPlane{execPins: new(ebpf.Map), pinKeys: new(ebpf.Map)}
	loads := 0
	p.loadInner = func() error { loads++; return p.setInnerSpecs(full, "planepr") }
	if !p.pinsReady() {
		t.Fatal("an adopted plane with its pin maps open and its inner definitions not yet loaded is not ready for pins")
	}
	if got, err := p.innerSpec(ebpfbindings.MapPlaneExecPins); err != nil || got != inner || loads != 1 {
		t.Fatalf("the pin map's inner definition: %v, %v after %d loads", got, err, loads)
	}
	if !p.pinsReady() {
		t.Fatal("a plane whose inner definitions are loaded is not ready for pins")
	}
	if (&bpfPlane{execPins: new(ebpf.Map), pinKeys: new(ebpf.Map)}).pinsReady() {
		t.Error("a plane with no pin map definition and no way to load one is ready for pins")
	}
	if (&bpfPlane{pinKeys: new(ebpf.Map), loadInner: p.loadInner}).pinsReady() {
		t.Error("a plane with no pin map is ready for pins")
	}
}

// TestPlaneObjectWithoutTheNameMapIsRefused: a plane object whose specification declares no name map, or one without
// its inner map, is refused at load and at adoption alike (ADR 0043 D9): its programs could not decide a run whose
// slot header says they should.
func TestPlaneObjectWithoutTheNameMapIsRefused(t *testing.T) {
	t.Parallel()
	spec := func() *ebpf.CollectionSpec {
		maps := map[string]*ebpf.MapSpec{}
		for _, name := range []string{ebpfbindings.MapPlaneRows, ebpfbindings.MapPlaneExecRows,
			ebpfbindings.MapPlaneListenRows, ebpfbindings.MapPlaneNameRows, ebpfbindings.MapPlaneExecPins} {
			maps[name] = &ebpf.MapSpec{Name: name, Type: ebpf.HashOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1,
				InnerMap: &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 1}}
		}
		return &ebpf.CollectionSpec{Maps: maps}
	}
	var p bpfPlane
	if err := p.setInnerSpecs(spec(), "planepr"); err != nil || p.nameInner == nil || p.pinsInner == nil {
		t.Fatalf("a full plane specification: %v (name inner map %v, pin inner map %v)", err, p.nameInner, p.pinsInner)
	}
	// The same holds for the exec pin map (ADR 0048 (3) P2), whose inner map a pinned slot is made from.
	cases := map[string]*ebpf.CollectionSpec{}
	for _, name := range []string{ebpfbindings.MapPlaneNameRows, ebpfbindings.MapPlaneExecPins} {
		none := spec()
		delete(none.Maps, name)
		noInner := spec()
		noInner.Maps[name].InnerMap = nil
		cases["no "+name] = none
		cases[name+" without its inner map"] = noInner
	}
	for what, s := range cases {
		if err := new(bpfPlane).setInnerSpecs(s, "planepr"); !errors.Is(err, ErrProgramLoad) {
			t.Errorf("%s: %v, want ErrProgramLoad", what, err)
		}
	}
}

// TestExecPolicyOf reads the contract's exec: section.
func TestExecPolicyOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		c    *agent.Contract
		want planeExecPolicy
	}{
		{nil, planeExecPolicy{Decides: true}},
		{&agent.Contract{}, planeExecPolicy{}},
		{&agent.Contract{Exec: &agent.ExecSection{}}, planeExecPolicy{Decides: true}},
		{&agent.Contract{Exec: &agent.ExecSection{Anonymous: true}}, planeExecPolicy{Decides: true, Anonymous: true}},
		// ADR 0048 (1): a deny-list restricts no image; allow: [] beside a deny list restricts every one.
		{&agent.Contract{Exec: &agent.ExecSection{Deny: []string{"git push"}}}, planeExecPolicy{}},
		{&agent.Contract{Exec: &agent.ExecSection{Ask: []string{}}}, planeExecPolicy{}},
		{&agent.Contract{Exec: &agent.ExecSection{Allow: []string{}, Deny: []string{"git push"}}}, planeExecPolicy{Decides: true}},
	}
	for _, tc := range cases {
		if got := execPolicyOf(&agent.RuleTable{Contract: tc.c}); got != tc.want {
			t.Errorf("%+v: %+v, want %+v", tc.c, got, tc.want)
		}
	}
}

// TestPlaneDirOf names a build's plane directories and nothing else.
func TestPlaneDirOf(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{"abc-lsm": "abc", "abc-fmod_ret": "abc"} {
		if h, _, ok := planeDirOf(name); !ok || h != want {
			t.Errorf("planeDirOf(%s) = %s, %v", name, h, ok)
		}
	}
	for _, name := range []string{"abc", "-lsm", "abc-lsmx", "abc-fanotify"} {
		if _, _, ok := planeDirOf(name); ok {
			t.Errorf("planeDirOf(%s) names a plane", name)
		}
	}
}

// TestSweepTakesABuildsPlanesWithIt is R20's lifetime on the pin tree: a build's removal removes its <hash>-<mode>
// directories; a sweep never takes a plane directory for a build of its own, removes one whose build is gone, and
// ListBuilds lists a build's planes with it.
func TestSweepTakesABuildsPlanesWithIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, pinRoot)
	mk := func(p ...string) {
		if err := os.MkdirAll(filepath.Join(append([]string{base}, p...)...), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mk("live", pinMaps)
	mk("live-lsm", pinMaps)
	mk("live-lsm", pinProgs, "tego_lsm_file_open")
	mk("gone-fmod_ret", pinLinks)
	infos, err := ListBuilds(SweepOptions{BPFFS: dir, StateDir: dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Hash != "live" || !slices.Equal(infos[0].Planes, []string{"lsm"}) || infos[0].PlanePrograms != 1 {
		t.Fatalf("ListBuilds = %+v, want the build with its lsm plane", infos)
	}
	states, err := SweepBuilds(SweepOptions{BPFFS: dir, StateDir: dir, Force: true, Now: func() time.Time { return time.Now() }})
	if err != nil {
		t.Fatalf("SweepBuilds: %v", err)
	}
	for _, s := range states {
		if _, _, ok := planeDirOf(s.Hash); ok {
			t.Errorf("the sweep took a plane directory for a build: %+v", s)
		}
	}
	for _, name := range []string{"live", "live-lsm", "gone-fmod_ret"} {
		if _, err := os.Stat(filepath.Join(base, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there after the sweep: %v", name, err)
		}
	}
}

// TestPlanPlaneFillSkipsAKeyedPathThatDoesNotExist: a keyed path nothing holds because it does not exist keys no
// row, as the Landlock plan skips it (enforce-landlock E9); one that exists and nothing holds still fails.
func TestPlanPlaneFillSkipsAKeyedPathThatDoesNotExist(t *testing.T) {
	t.Parallel()
	rows, held, id := fillFixture()
	delete(held, "/w/secret")
	id.missing = map[string]bool{"/w/secret": true}
	plan, err := planPlaneFill(rows, 3, 7, func(p string) (int, bool) { fd, ok := held[p]; return fd, ok }, id)
	if err != nil {
		t.Fatalf("planPlaneFill: %v", err)
	}
	if !slices.Equal(plan.Absent, []string{"/w/secret"}) || len(plan.Entries) != len(rows.FS)+len(rows.Exec)-1 {
		t.Errorf("plan %+v, want /w/secret absent and every other row", plan)
	}
}

// TestRecordedMaskIsTheAttachedFexits is the backend's half of the record fallback (enforce-plane §7, R23;
// TIER3-PLAN T9b): the plane's recorder mask names exactly the recorder fexit programs among the build's shared
// tracing links, by their pins, so a hook whose fexit the build holds no link of is sampled by the plane, and one it
// holds is not. With every trace program linked, as newBPFKernel leaves a build, every fexit hook is set.
func TestRecordedMaskIsTheAttachedFexits(t *testing.T) {
	t.Parallel()
	links := func(names ...string) []sharedLink {
		var out []sharedLink
		for _, n := range names {
			out = append(out, sharedLink{pin: filepath.Join("/sys/fs/bpf/tego/h/links", n)})
		}
		return out
	}
	if got := recordedMask(nil); got != 0 {
		t.Errorf("no links: mask %#x, want 0", got)
	}
	all := ebpfbindings.PlaneRecordedMask(func(string) bool { return true })
	if got := recordedMask(links(append(slices.Clone(ebpfbindings.TrackPrograms), ebpfbindings.TracePrograms...)...)); got != all {
		t.Errorf("every trace program linked: mask %#x, want %#x", got, all)
	}
	got := recordedMask(links(ebpfbindings.ProgSchedExec, ebpfbindings.ProgFileOpen, ebpfbindings.ProgPathMkdir))
	want := uint32(1)<<ebpfbindings.PlaneHookNumber("file_open") | uint32(1)<<ebpfbindings.PlaneHookNumber("path_mkdir")
	if got != want {
		t.Errorf("file_open and path_mkdir linked: mask %#x, want %#x", got, want)
	}
}

// TestPlaneDetachKeepsACarriedSlotsRows is enforce-plane R6's Detach half: a run-set row Detach could not remove
// still carries the slot and decides for its tasks, so the slot's plane rows and header stay with it. Cleared, the
// row's tasks would be refused everything; kept, they are decided by their own run's rows until the reaper or the
// slot's next Prepare removes both.
func TestPlaneDetachKeepsACarriedSlotsRows(t *testing.T) {
	t.Parallel()
	f, _ := planeFixture(t, ebpfbindings.PlaneLSM)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.kernel.calls = nil
	f.kernel.failAt = "removeRun"
	if err := h.Detach(); err == nil {
		t.Fatal("Detach reported no error for a run-set row it could not remove")
	}
	if slices.Contains(f.kernel.calls, "plane.clearSlot") {
		t.Errorf("Detach cleared the plane rows of a slot a run-set row still carries: %v", f.kernel.calls)
	}
	if !h.rowsLeft {
		t.Error("rowsLeft not set after a failed removeRun")
	}
}

// TestPlaneFillCarriesTheSlotEpoch: the gen a plane run's rows, header and run-set row carry is its slot's epoch
// (slotTable.acquireGen), never the cgroup id's low half, which repeats once kernfs's idr wraps (ADR 0025 (1)).
func TestPlaneFillCarriesTheSlotEpoch(t *testing.T) {
	t.Parallel()
	f, plane := planeFixture(t, ebpfbindings.PlaneLSM)
	f.run.CgroupID = 1 << 32 // low half 0: a cgroup-id gen would be 0, which a cleared header holds
	var gens []uint32
	for i := 0; i < 2; i++ {
		h, err := f.backend.Prepare(context.Background(), f.table, f.run)
		if err != nil {
			t.Fatalf("Prepare %d: %v", i, err)
		}
		if err := h.Arm(); err != nil {
			t.Fatalf("Arm %d: %v", i, err)
		}
		req := plane.fills[len(plane.fills)-1]
		if row := f.kernel.runs[f.run.CgroupID]; row.Gen != req.Gen {
			t.Errorf("run %d: run-set gen %d, fill gen %d", i, row.Gen, req.Gen)
		}
		gens = append(gens, req.Gen)
		if err := h.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
	if gens[0] == 0 || gens[1] == 0 || gens[0] == gens[1] {
		t.Errorf("gens of two runs of one slot and one cgroup id: %v, want two distinct non-zero epochs", gens)
	}
}

// TestPlaneCountersAreTheSlotsNamedCounts is enforce-plane §2.8's counters half at the backend: PlaneCounters reads
// the run's own slot, before Detach clears anything, and names every counter by its gap why (the runtime writes one
// gap what=enforce line per non-zero one); a read that fails is an error, never zeros; a run with no plane reads
// nothing.
func TestPlaneCountersAreTheSlotsNamedCounts(t *testing.T) {
	t.Parallel()
	f, plane := planeFixture(t, ebpfbindings.PlaneLSM)
	plane.counters = ebpfbindings.PlaneCounts{Mismatch: 1, Unresolved: 0, Bound: 5, NoRows: 2}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	got, err := h.PlaneCounters()
	if err != nil {
		t.Fatal(err)
	}
	want := []PlaneCount{{Why: record.GapPlaneMismatch, Count: 1}, {Why: record.GapPlaneUnresolved},
		{Why: record.GapPlaneBound, Count: 5}, {Why: record.GapPlaneNoRows, Count: 2}}
	if !slices.Equal(got, want) {
		t.Errorf("counters %+v, want %+v", got, want)
	}
	if plane.countSlot != h.Slot() {
		t.Errorf("read slot %d, the run's is %d", plane.countSlot, h.Slot())
	}
	plane.countErr = errors.New("gone")
	if _, err := h.PlaneCounters(); err == nil {
		t.Error("a failed read answered counters")
	}

	fb := newFixture(t)
	hb, err := fb.backend.Prepare(context.Background(), fb.table, fb.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = hb.Close() }()
	if got, err := hb.PlaneCounters(); got != nil || err != nil {
		t.Errorf("a run with no plane read %+v, %v", got, err)
	}
}
