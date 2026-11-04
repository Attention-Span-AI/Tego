// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// requirePlaneRoot skips unless this process may load the plane and this build carries it.
func requirePlaneRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the plane probe loads and attaches programs as root: run under `make vm-root-test`")
	}
	if len(bpfobj.PlaneObjects()) == 0 {
		t.Skip("untagged: the plane probe loads decide.bpf.c's builds; the tegobpf suite runs this")
	}
}

// planeTemps lists the probe's fixture directories left in the temporary directory or fixtureRoot.
func planeTemps(t *testing.T) []string {
	t.Helper()
	var m []string
	for _, dir := range []string{os.TempDir(), fixtureRoot} {
		got, err := filepath.Glob(filepath.Join(dir, planeScratchPrefix+"*"))
		if err != nil {
			t.Fatal(err)
		}
		m = append(m, got...)
	}
	slices.Sort(m)
	return m
}

// leftovers is every trace the plane probe could leave: bpffs entries, BPF descriptors, scratch cgroups, fixture
// directories.
func leftovers(t *testing.T) [][]string {
	t.Helper()
	return [][]string{bpffsEntries(t), kernelFDs(t), scratchCgroups(t), planeTemps(t)}
}

// sameLeftovers compares two leftovers readings.
func sameLeftovers(a, b [][]string) bool {
	return slices.EqualFunc(a, b, func(x, y []string) bool { return slices.Equal(x, y) })
}

// TestIntegrationPlaneProbeOnThisKernel is R21 on a real kernel, as root in the KVM guest on both boots: the chosen
// build loads every hook in each mode the boot offers, each program runs for its probe syscall, the syscalls pass
// in the scratch cgroup (T2's stubs decide nothing; a body that decides must be refused there, which
// bpf.PlaneHook.Decides turns on) and outside it, and tier cgroup's selection is LSM mode where bpf is an active
// LSM and fmod_ret mode where it is not. The plane's answer is held to the boot's golden file, and the probe
// leaves no pin, descriptor, cgroup or fixture behind.
func TestIntegrationPlaneProbeOnThisKernel(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	uid, _ := config.InvokingUID()
	r, release, _ := probeKernelVersion()
	if !r.OK {
		t.Fatalf("kernel: %s", r.Detail)
	}
	lsm, err := ReadLSMState()
	if err != nil {
		t.Fatal(err)
	}
	st, rows := probePlane(true, uid, release, config.PlaneAuto, true)
	env, _ := json.Marshal(st.Env)
	t.Logf("env %s; build %s (%s)", env, st.Build, st.BuildWhy)
	for _, m := range st.Modes {
		t.Logf("mode %s: ok=%v tested=%v %s; the known answers took %v: %s", m.Mode, m.OK, m.Tested, m.Detail,
			m.KnownTook, strings.Join(m.KnownPhases, ", "))
		logKnown(t, m)
		// Every mode that passed answered every known-answer cell exactly (R21).
		if m.OK && len(m.Known) != len(planeKnownCells()) {
			t.Errorf("mode %s passed with %d of %d known answers", m.Mode, len(m.Known), len(planeKnownCells()))
		}
	}
	for _, r := range rows {
		t.Logf("%s: %s arity=%d btf=%v loaded=%v attached=%v ran=%v inside=%q outside=%q %s", r.Hook, r.Function,
			r.Arity, r.BTF, r.Loaded, r.Attached, r.Ran, r.Inside, r.Outside, r.Detail)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("the plane probe left state behind: before %v, after %v", before, after)
	}
	if st.Build == "" {
		t.Fatalf("no build of decide.bpf.c chosen on this kernel: %s", st.BuildWhy)
	}
	fmodRet := fmodRetOffered(t, st)
	want := map[bpfobj.PlaneMode]bool{bpfobj.PlaneFmodRet: fmodRet, bpfobj.PlaneLSM: lsm.BPFActive}
	for _, m := range st.Modes {
		if m.OK != want[m.Mode] {
			t.Errorf("mode %s: ok=%v, want %v (bpf active: %v, preemption %q): %s", m.Mode, m.OK, want[m.Mode],
				lsm.BPFActive, st.Env.Preempt, m.Detail)
		}
	}
	wantSel, boot := "fmod_ret", "default"
	if !fmodRet {
		wantSel = PlaneFanotify
	}
	if lsm.BPFActive {
		wantSel, boot = "lsm", "lsm"
	}
	if st.Selected != wantSel {
		t.Errorf("selected %q, want %q", st.Selected, wantSel)
	}
	// The golden files are the KVM guest's kernel (test/vm, 6.17) on its two boots; another kernel's arities or
	// build may differ, so there the answer is logged and the assertions above hold it.
	if got := planeGuestGolden(st, rows); strings.HasPrefix(release, planeGuestKernel) {
		checkGolden(t, "plane-guest-"+boot+".golden", got)
	} else {
		t.Logf("%s is not the guest's %s: golden not compared; answer:\n%s", release, planeGuestKernel, got)
	}

	// What the known answers add to the probe, warm: a second probe of this boot, with the binary, BTF and fixtures'
	// filesystems in cache and the first probe's matched answers kept (planeknowncache.go), logged per mode and held
	// under planeKnownBudget on the guest's kernel.
	warm, _ := probePlane(true, uid, release, config.PlaneAuto, true)
	var total time.Duration
	for _, m := range warm.Modes {
		total += m.KnownTook
		t.Logf("mode %s: the known answers took %v warm: %s", m.Mode, m.KnownTook, strings.Join(m.KnownPhases, ", "))
	}
	t.Logf("the known answers added %v to a warm probe", total)
	if strings.HasPrefix(release, planeGuestKernel) && total >= planeKnownBudget {
		t.Errorf("the known answers added %v to a warm probe, over %v", total, planeKnownBudget)
	}
}

// planeKnownBudget is what the known answers may add to a warm probe on the guest's kernel.
const planeKnownBudget = 200 * time.Millisecond

// logKnown logs each known-answer cell of a mode.
func logKnown(t *testing.T, m PlaneModeResult) {
	t.Helper()
	for _, a := range m.Known {
		t.Logf("mode %s known %s: %s counters %s, want %s counters %s (ok=%v)", m.Mode, a.Cell, a.Got, a.GotCounts,
			a.Want, a.WantCounts, a.OK())
	}
}

// TestIntegrationPlaneProbeCopiesTheBinaryOnce: the exec image depends on this binary alone, so a probe copies it
// into a memfd once, however many modes reach their syscalls (on the lsm= boot both do), and closes it after the
// last mode.
func TestIntegrationPlaneProbeCopiesTheBinaryOnce(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	made := 0
	makePlaneImage = func() (int, error) {
		made++
		return planeExecImage()
	}
	defer func() { makePlaneImage = planeExecImage }()
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	_, rows := probePlane(true, uid, release, config.PlaneAuto, false)
	// A mode reaches its syscalls once every row it has is attached (runPlaneProbe).
	all := map[bpfobj.PlaneMode]bool{}
	for _, r := range rows {
		if _, seen := all[r.Plane]; !seen {
			all[r.Plane] = true
		}
		if !r.Absent && !r.Attached {
			all[r.Plane] = false
		}
	}
	reached := map[bpfobj.PlaneMode]bool{}
	for m, ok := range all {
		if ok {
			reached[m] = true
		}
	}
	t.Logf("modes that reached their syscalls: %v; images made: %d", reached, made)
	if want := min(len(reached), 1); made != want {
		t.Errorf("%d modes reached their syscalls and the probe made %d exec images, want %d", len(reached), made, want)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("state left behind: before %v, after %v", before, after)
	}
}

// TestIntegrationPlaneProbeRejectsAFlippedKnownAnswer is the known answers' own failing path on a real kernel: with
// one cell's expected verdict flipped by the test-only switch, a kernel that answers it correctly fails every mode
// that reached the known answers, doctor's line says which cell and why, tier cgroup falls back to fanotify, and
// nothing is left behind.
func TestIntegrationPlaneProbeRejectsAFlippedKnownAnswer(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	planeKnownFlip = "stale-row"
	defer func() { planeKnownFlip = "" }()
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	st, _ := probePlane(true, uid, release, config.PlaneAuto, true)
	reached := 0
	for _, m := range st.Modes {
		t.Logf("mode %s: ok=%v tested=%v %s", m.Mode, m.OK, m.Tested, m.Detail)
		logKnown(t, m)
		if m.OK {
			t.Errorf("mode %s passed with stale-row's verdict flipped", m.Mode)
		}
		if len(m.Known) > 0 {
			reached++
			if !strings.Contains(m.Detail, "known answer stale-row: passed, want refused") {
				t.Errorf("mode %s does not say why it was rejected: %s", m.Mode, m.Detail)
			}
		}
	}
	if reached == 0 {
		if lsm, err := ReadLSMState(); err == nil && !lsm.BPFActive && !fmodRetOffered(t, st) {
			t.Skipf("no plane mode is offered here (bpf is no active LSM, and fmod_ret mode is ruled out: preemption %q "+
				"from %s), so no mode reaches the known answers; TEGO_TEST_PLANE_PREEMPT=waive probes fmod_ret mode",
				st.Env.Preempt, st.Env.PreemptSource)
		}
		t.Fatal("no mode reached the known answers")
	}
	line := planeSummary(st, false) // fanotify is selected: the bpf bit does not reach the clause
	t.Log(line)
	if st.Selected != PlaneFanotify || !strings.Contains(line, "known answer stale-row") {
		t.Errorf("selected %q; doctor's line: %s", st.Selected, line)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("state left behind: before %v, after %v", before, after)
	}
}

// TestIntegrationPlaneProbeAnswersTheNameCells is ADR 0043 C9's known answers on a real kernel:
// each mode the boot offers fills the built-in .env pair into its slot with the rest of its
// table, and answers every name cell exactly (a .env and a .ENV made after the fill refused, .env.example, a .env
// outside the scope and one beneath node_modules allowed, a directory renamed within its scope allowed and one moved
// out refused), or it is not selected; and the probe leaves nothing behind.
func TestIntegrationPlaneProbeAnswersTheNameCells(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	lsm, err := ReadLSMState()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	st, _ := probePlane(true, uid, release, config.PlaneAuto, true)
	want := map[bpfobj.PlaneMode]bool{bpfobj.PlaneFmodRet: fmodRetOffered(t, st), bpfobj.PlaneLSM: lsm.BPFActive}
	for _, m := range st.Modes {
		t.Logf("mode %s: ok=%v tested=%v %s; the known answers took %v: %s", m.Mode, m.OK, m.Tested, m.Detail,
			m.KnownTook, strings.Join(m.KnownPhases, ", "))
		logKnown(t, m)
		if m.OK != want[m.Mode] {
			t.Errorf("mode %s: ok=%v, want %v (bpf active: %v): %s", m.Mode, m.OK, want[m.Mode], lsm.BPFActive, m.Detail)
		}
		if !m.OK {
			continue
		}
		names := 0
		for _, a := range m.Known {
			if strings.HasPrefix(a.Cell, "name-") {
				names++
			}
		}
		if names != len(planeKnownNameCells) || len(m.Known) != len(planeKnownCells()) {
			t.Errorf("mode %s passed with %d of %d name cells and %d of %d cells", m.Mode, names, len(planeKnownNameCells),
				len(m.Known), len(planeKnownCells()))
		}
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("the plane probe left state behind: before %v, after %v", before, after)
	}
}

// TestIntegrationPlaneProbeRejectsAFlippedNameAnswer is the name cells' failing path: with name-created-later's
// expected verdict flipped, a kernel whose name check refuses the .env made after the fill fails every mode that
// reached the known answers, doctor names the cell, and tier cgroup falls back to fanotify.
func TestIntegrationPlaneProbeRejectsAFlippedNameAnswer(t *testing.T) {
	requirePlaneRoot(t)
	planeKnownFlip = "name-created-later"
	t.Cleanup(func() { planeKnownFlip = "" })
	before := leftovers(t)
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	st, _ := probePlane(true, uid, release, config.PlaneAuto, true)
	reached := 0
	for _, m := range st.Modes {
		t.Logf("mode %s: ok=%v tested=%v %s", m.Mode, m.OK, m.Tested, m.Detail)
		logKnown(t, m)
		if m.OK {
			t.Errorf("mode %s passed with name-created-later's verdict flipped", m.Mode)
		}
		if len(m.Known) > 0 {
			reached++
			if !strings.Contains(m.Detail, "known answer name-created-later: refused, want passed") {
				t.Errorf("mode %s does not say why it was rejected: %s", m.Mode, m.Detail)
			}
		}
	}
	if reached == 0 {
		if lsm, err := ReadLSMState(); err == nil && !lsm.BPFActive && !fmodRetOffered(t, st) {
			t.Skipf("no plane mode is offered here (bpf is no active LSM, and fmod_ret mode is ruled out: preemption %q "+
				"from %s), so no mode reaches the known answers; TEGO_TEST_PLANE_PREEMPT=waive probes fmod_ret mode",
				st.Env.Preempt, st.Env.PreemptSource)
		}
		t.Fatal("no mode reached the known answers")
	}
	if st.Selected != PlaneFanotify {
		t.Errorf("selected %q, want the fanotify fallback", st.Selected)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("state left behind: before %v, after %v", before, after)
	}
}

// insideCount is the scope evidence's count of meetings in the scratch cgroup, which is not held.
var insideCount = regexp.MustCompile(`met [1-9][0-9]* times in the scratch cgroup`)

// planeGuestKernel is the release prefix of the KVM guest's kernel, whose answers the plane-guest golden files hold.
const planeGuestKernel = "6.17."

// planeGuestGolden is the part of a real probe's answer that is the same on every run of one kernel and boot:
// the modes, the selection and each row's outcome. The environment's paths and the kernel release are logged, not
// held.
func planeGuestGolden(st *PlaneState, rows []HookResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "build %s: %s\n", st.Build, st.BuildWhy)
	fmt.Fprintf(&b, "bpf_loop=%v rdonly_cast=%v lto=%s\n", st.Env.BPFLoop, st.Env.RdonlyCast, st.Env.LTO)
	for _, m := range st.Modes {
		// How often file_open's walk met the probe row depends on how many files the exec'd noop opens; that it
		// met it in the cgroup and never outside is what is held.
		scope := insideCount.ReplaceAllString(m.Scope, "met N times in the scratch cgroup")
		fmt.Fprintf(&b, "mode %s ok=%v tested=%v: %s [%s]\n", m.Mode, m.OK, m.Tested, m.Detail, scope)
		for _, a := range m.Known {
			fmt.Fprintf(&b, "  known %s: %s counters %s, want %s counters %s\n", a.Cell, a.Got, a.GotCounts, a.Want,
				a.WantCounts)
		}
	}
	fmt.Fprintf(&b, "selected %s\n", strings.TrimSpace(st.Selected+" "+st.SelectedWhy))
	for _, r := range rows {
		fmt.Fprintf(&b, "%s %s arity=%d decides=%v btf=%v loaded=%v attached=%v ran=%v inside=%s outside=%s\n",
			r.Hook, r.Function, r.Arity, r.Decides, r.BTF, r.Loaded, r.Attached, r.Ran, r.Inside, r.Outside)
	}
	return b.String()
}

// TestIntegrationPlaneProbeCleansUpWhenTheChildFails is the probe's failing path: a child that never says ready
// (here, one started with a role it refuses) fails every mode it was started for, and still leaves no pin,
// descriptor, cgroup or fixture behind; the probe row was never armed.
func TestIntegrationPlaneProbeCleansUpWhenTheChildFails(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	planeChildRole = "noop"
	defer func() { planeChildRole = "child" }()
	uid, _ := config.InvokingUID()
	_, release, _ := probeKernelVersion()
	st, _ := probePlane(true, uid, release, config.PlaneAuto, true)
	for _, m := range st.Modes {
		if m.OK {
			t.Errorf("mode %s passed with a child that never ran its syscalls", m.Mode)
		}
		t.Logf("mode %s: %s", m.Mode, m.Detail)
	}
	if st.Selected != PlaneFanotify {
		t.Errorf("selected %q with no mode passing", st.Selected)
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("a failed plane probe left state behind: before %v, after %v", before, after)
	}
}

// TestIntegrationDoctorCancelledDuringThePlaneLeavesNothing extends the D7/D8 cancel test to the plane probe:
// cancelled as the plane probe starts, doctor still ends with nothing of its own left.
func TestIntegrationDoctorCancelledDuringThePlaneLeavesNothing(t *testing.T) {
	requirePlaneRoot(t)
	before := leftovers(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := machineChecks
	inner := c.plane
	c.plane = func(root bool, uid int, release, pin string, keep bool) (*PlaneState, []HookResult) {
		cancel()
		return inner(root, uid, release, pin, keep)
	}
	uid, _ := config.InvokingUID()
	st := scope{uid: uid, root: true, checks: c, planePin: config.PlaneAuto}.run(ctx)
	if ctx.Err() == nil || st.plane == nil {
		t.Fatal("the plane probe did not run under a cancelled context")
	}
	if after := leftovers(t); !sameLeftovers(after, before) {
		t.Errorf("state left behind: before %v, after %v", before, after)
	}
}

// TestIntegrationPlanePinRoundTrip is the pin-directory half of R21's cache (the backend's seam, T6): an answer
// pinned in a build's directory is read back by an adopting run as that mode, and nothing is left once the
// directory is removed.
func TestIntegrationPlanePinRoundTrip(t *testing.T) {
	requirePlaneRoot(t)
	dir, err := os.MkdirTemp("/sys/fs/bpf", "tego-doctor-test-")
	if err != nil {
		t.Skipf("no writable bpffs: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	want := PlaneChoice{Mode: bpfobj.PlaneFmodRet, Build: bpfobj.ObjectPlaneRdonly}
	if err := PinPlaneAnswer(dir, want); err != nil {
		t.Fatal(err)
	}
	if got, ok := readPlanePin(dir); !ok || got != want {
		t.Errorf("read back %+v %v, want %+v", got, ok, want)
	}
	if err := PinPlaneAnswer(dir, want); err == nil {
		t.Error("a second pin over the first succeeded")
	}
	if _, ok := readPlanePin(filepath.Join(dir, "none")); ok {
		t.Error("a directory without an answer answered")
	}
}
