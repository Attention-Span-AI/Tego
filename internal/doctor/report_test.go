// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// state builds a probeState with every probe passing, then applies the caller's edits. The tier
// derivation is a pure function of this struct, so every tier case can be expressed here without a
// kernel. It describes a build that constructs every tier, so these cases exercise the machine's half
// of the derivation alone; derive_test.go sets built to cover the build's half.
func state(edit func(*probeState)) probeState {
	st := probeState{
		built:       func(backend.Tier) error { return nil },
		byID:        map[CheckID]Result{},
		root:        true,
		release:     "6.17.0-generic",
		kernel:      Version{6, 17, 0},
		landlockABI: 7,
		lsm:         LSMState{Modules: []string{"capability", "bpf"}, Source: LSMSourceSyscall, BPFActive: true, Functional: "confirmed by a counting program on file_open"},
		fanotify:    FanotifyState{ReportFID: true, PermissionMarks: true, DenyErrno: true},
	}
	for _, id := range []CheckID{CheckKernel, CheckBTF, CheckCgroupV2, CheckLandlock, CheckSeccomp, CheckLSM, CheckPrograms, CheckFanotify} {
		r := Result{ID: id, OK: true, Detail: "ok"}
		st.results = append(st.results, r)
		st.byID[id] = r
	}
	for _, h := range hooks {
		st.hooks = append(st.hooks, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true, Attached: true})
	}
	st.plane = passingPlane("")
	if edit != nil {
		edit(&st)
	}
	return st
}

// fail marks one probe failed in a state.
func fail(st *probeState, id CheckID, detail, fix string) {
	r := Result{ID: id, Detail: detail, Fix: fix}
	st.byID[id] = r
	for i := range st.results {
		if st.results[i].ID == id {
			st.results[i] = r
		}
	}
}

// failRoundTrip marks D5's round trip failed with err, building D5's Result from the state's own
// PtraceState exactly as runProbes does, so the two halves the derivation reads cannot disagree.
func failRoundTrip(st *probeState, err error) {
	st.seccompErr = err
	r := seccompVerdict(-1, err, st.ptrace)
	st.byID[CheckSeccomp] = r
	for i := range st.results {
		if st.results[i].ID == CheckSeccomp {
			st.results[i] = r
		}
	}
}

func TestTierDerivation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*probeState)
		want backend.Tier
	}{
		{"everything passes", nil, backend.TierBPFLSM},
		{"not root", func(st *probeState) { st.root = false }, backend.TierLandlock},
		{"bpf not an active lsm", func(st *probeState) {
			st.lsm = LSMState{Modules: []string{"capability", "apparmor"}, Source: LSMSourceSyscall}
		}, backend.TierCgroup},
		{"bpf listed but silently inactive", func(st *probeState) {
			st.lsm.Functional = "attached but never ran"
		}, backend.TierCgroup},
		{"no fanotify", func(st *probeState) { fail(st, CheckFanotify, "no permission events", "rebuild the kernel") },
			backend.TierLandlock},
		{"no BTF", func(st *probeState) { fail(st, CheckBTF, "ENOENT", "CONFIG_DEBUG_INFO_BTF=y") },
			backend.TierLandlock},
		{"one tier-2 hook will not attach", func(st *probeState) {
			for i := range st.hooks {
				if st.hooks[i].Hook == "tp_btf/cgroup_mkdir" {
					st.hooks[i].Attached, st.hooks[i].Detail = false, "attach: no such BTF id"
				}
			}
		}, backend.TierLandlock},
		{"one tier-3 hook will not load", func(st *probeState) {
			st.plane.Modes[0] = PlaneModeResult{Mode: "lsm", Tested: true, Detail: "5 of 6 hooks load, attach and run; failed: lsm/path_rename"}
		}, backend.TierCgroup},
		{"no landlock at all", func(st *probeState) {
			st.root = false
			st.landlockABI = 0
			fail(st, CheckLandlock, "ENOSYS", "boot a newer kernel")
		}, ""},
		{"landlock ABI 1 is unsupported", func(st *probeState) {
			st.root = false
			st.landlockABI = 1
		}, ""},
		// Every tier installs the tier-1 NEW_LISTENER filter, so one this process may not install
		// leaves no tier at all, root and a working BPF LSM notwithstanding.
		{"the seccomp round trip fails", func(st *probeState) {
			failRoundTrip(st, fmt.Errorf("%w: %w", ErrSeccompSelfTest, unix.EBUSY))
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := state(tc.edit)
			tier, err := backend.Select("", "", st.probe())
			got := backend.Tier("")
			if err == nil {
				got = tier
			}
			if got != tc.want {
				t.Errorf("tier %q, want %q (missing: %v)", got, tc.want, st.missing(got))
			}
		})
	}
}

func TestTierRespectsTheMachineCeiling(t *testing.T) {
	m := config.Builtin()
	m.Tier.Bounded = true
	m.Tier.Value = config.TierSetting{Tier: string(backend.TierCgroup)}
	if got := ceiling(m); got != backend.TierCgroup {
		t.Fatalf("ceiling %q", got)
	}
	if got := ceiling(nil); got != "" {
		t.Errorf("a nil machine bounds nothing, got %q", got)
	}
	auto := config.Builtin()
	auto.Tier.Bounded = true
	auto.Tier.Value = config.TierSetting{Tier: backend.Auto, Auto: true}
	if got := ceiling(auto); got != "" {
		t.Errorf("auto bounds nothing, got %q", got)
	}
	st := state(nil)
	tier, err := backend.Select(backend.TierCgroup, "", st.probe())
	if err != nil || tier != backend.TierCgroup {
		t.Errorf("ceiling cgroup with everything available gave %q, %v", tier, err)
	}
}

func TestMissingAndFix(t *testing.T) {
	st := state(func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "landlock", "apparmor"}, Source: LSMSourceSyscall}
	})
	missing := st.missing(backend.TierCgroup)
	if _, ok := missing[backend.TierCgroup]; ok {
		t.Errorf("the reached tier must not be listed as missing: %v", missing)
	}
	reasons, ok := missing[backend.TierBPFLSM]
	if !ok || len(reasons) == 0 {
		t.Fatalf("missing %v", missing)
	}
	if !strings.Contains(reasons[0], "bpf is not in the active LSM list") {
		t.Errorf("reason %q", reasons[0])
	}
	fix := st.fix(backend.TierCgroup)
	if !strings.Contains(fix, "lsm=capability,landlock,apparmor,bpf") {
		t.Errorf("fix %q must be built from the machine's own LSM list", fix)
	}
	if got := state(nil).fix(backend.TierBPFLSM); got != "" {
		t.Errorf("the top tier needs no fix, got %q", got)
	}
	if got := state(nil).missing(backend.TierBPFLSM); got != nil {
		t.Errorf("nothing is missing at the top tier, got %v", got)
	}
}

func TestNextTier(t *testing.T) {
	cases := []struct{ from, want backend.Tier }{
		{"", backend.TierLandlock},
		{backend.TierLandlock, backend.TierCgroup},
		{backend.TierCgroup, backend.TierBPFLSM},
		{backend.TierBPFLSM, ""},
	}
	for _, tc := range cases {
		if got := nextTier(tc.from); got != tc.want {
			t.Errorf("nextTier(%q) = %q, want %q", tc.from, got, tc.want)
		}
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name    string
		tier    backend.Tier
		require backend.Tier
		want    int
	}{
		{"no require", backend.TierLandlock, "", identity.ExitOK},
		{"require met exactly", backend.TierCgroup, backend.TierCgroup, identity.ExitOK},
		{"require below the reached tier", backend.TierBPFLSM, backend.TierLandlock, identity.ExitOK},
		{"require above the reached tier", backend.TierLandlock, backend.TierCgroup, identity.ExitRequire},
		{"require with no tier at all", "", backend.TierLandlock, identity.ExitRequire},
		{"no tier and no require is a finding", "", "", identity.ExitFinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Tier: tc.tier, Require: tc.require}
			if got := r.ExitCode(); got != tc.want {
				t.Errorf("ExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReportProbe is the value enforce.Select consumes. It is Tiers copied tier by tier, never
// inferred from the reached tier or from rank, so a map with a hole below a true tier is passed on as
// it is and Select, not Probe, decides what that means.
func TestReportProbe(t *testing.T) {
	cases := []struct {
		name  string
		tiers backend.Probe
		want  backend.Probe
	}{
		{"landlock only", backend.Probe{backend.TierLandlock: true},
			backend.Probe{backend.TierLandlock: true, backend.TierCgroup: false, backend.TierBPFLSM: false}},
		{"every tier", backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: true},
			backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: true}},
		{"a true tier above a false one is copied, not inferred", backend.Probe{backend.TierCgroup: true},
			backend.Probe{backend.TierLandlock: false, backend.TierCgroup: true, backend.TierBPFLSM: false}},
		{"nothing", backend.Probe{},
			backend.Probe{backend.TierLandlock: false, backend.TierCgroup: false, backend.TierBPFLSM: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (&Report{Tiers: tc.tiers}).Probe()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Probe = %v, want %v", got, tc.want)
			}
			if _, ok := got[backend.TierObserve]; ok {
				t.Error("observe is a run mode, never a probed tier")
			}
		})
	}
}

// TestNoRootTierWithoutLandlock: a kernel with BPF LSM but no Landlock (the shape a custom build can
// have) reaches no tier at all. This test used to demand bpflsm there, and `tego run` could never have
// given it: tier 2 installs tier 1's Landlock ruleset for delete, rename and mkdir (ADR 0011, "Landlock
// inside the run"; enforce.construct refuses tier cgroup without a Landlock ABI), and tier 3 is tier 2
// plus bpf in the LSM list (docs/ARCHITECTURE.md §2). Reporting the tier would have promised a run that
// either failed at construction or ran without the rename and delete rules the tier claims.
func TestNoRootTierWithoutLandlock(t *testing.T) {
	st := state(func(st *probeState) {
		st.landlockABI = 0
		fail(st, CheckLandlock, "ENOSYS", "boot a kernel with CONFIG_SECURITY_LANDLOCK=y")
	})
	probe := st.probe()
	if probe[backend.TierLandlock] || probe[backend.TierCgroup] || probe[backend.TierBPFLSM] {
		t.Fatalf("a machine without Landlock offers %v", probe)
	}
	if tier, err := backend.Select("", "", probe); err == nil {
		t.Fatalf("tier %q selected on a machine without Landlock", tier)
	}
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if reasons := strings.Join(st.missingFor(tier), "; "); !strings.Contains(reasons, "landlock: ENOSYS") {
			t.Errorf("missingFor(%s) = %q, does not name the missing Landlock", tier, reasons)
		}
	}
	if f := st.fix(""); !strings.Contains(f, "CONFIG_SECURITY_LANDLOCK=y") {
		t.Errorf("fix = %q, want D4's remedy", f)
	}
}

func TestWriteTextAndJSON(t *testing.T) {
	rep, err := Run(context.Background(), nil, backend.TierBPFLSM)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 9 {
		t.Fatalf("%d results", len(rep.Results))
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, want := range []string{"ok   kernel:", "capability matrix", "tier:", "deny file write outside contract"} {
		if !strings.Contains(out, want) {
			t.Errorf("the text report has no %q:\n%s", want, out)
		}
	}
	if rep.ExitCode() == identity.ExitRequire && !strings.Contains(out, "required tier bpflsm is not available") {
		t.Errorf("an unmet --require is not reported in the text:\n%s", out)
	}
	var js bytes.Buffer
	if err := writeJSONForTest(&js, rep); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatalf("--json is not valid JSON: %v", err)
	}
	if len(back.Results) != len(rep.Results) || back.Tier != rep.Tier || back.Require != rep.Require {
		t.Errorf("round trip lost fields: %+v", back)
	}
	if back.Kernel == "" {
		t.Error("--json carries no kernel release")
	}
	if !reflect.DeepEqual(back.Probe(), rep.Probe()) {
		t.Errorf("the probe did not survive --json: %v vs %v", back.Probe(), rep.Probe())
	}
}

// outsideSubtree reports whether this process runs outside the delegated subtree Detect finds for its uid,
// where no run can be placed (runtime-launch.md case 41): a login over ssh, or a service such as a CI
// runner's step. doctor then offers no tier, and says why in D3.
func outsideSubtree() bool {
	fs, err := cgroup.Detect(os.Getuid())
	return err == nil && errors.Is(fs.CanPlace(), cgroup.ErrOutsideSubtree)
}

// TestRunOnThisMachine is the ticket's acceptance for an unprivileged run: tier landlock, exit 0,
// and a printed GRUB line whenever bpf is not an active LSM. From outside the delegated subtree it is the
// other answer case 41 gives: no tier, exit 1, and D3 failing with the remedy that starts tego inside.
func TestRunOnThisMachine(t *testing.T) {
	rep, err := Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tier=%q exit=%d root=%v abi=%d lsm=%v", rep.Tier, rep.ExitCode(), rep.Root, rep.LandlockABI, rep.LSM.Modules)
	if rep.Root {
		t.Skip("this test describes the unprivileged answer")
	}
	if outsideSubtree() {
		if rep.Tier != "" || rep.ExitCode() != identity.ExitFinding {
			t.Fatalf("tier %q exit %d outside the delegated subtree, want no tier and exit %d",
				rep.Tier, rep.ExitCode(), identity.ExitFinding)
		}
		for _, r := range rep.Results {
			if r.ID == CheckCgroupV2 && (r.OK || !strings.Contains(r.Fix, "systemd-run --user --scope")) {
				t.Fatalf("D3 outside the delegated subtree: %+v, want a failure whose fix is systemd-run --user --scope", r)
			}
		}
		return
	}
	if rep.Tier != backend.TierLandlock {
		t.Fatalf("tier %q, want landlock as an ordinary user on a Landlock kernel", rep.Tier)
	}
	if rep.ExitCode() != identity.ExitOK {
		t.Errorf("exit %d", rep.ExitCode())
	}
	if _, ok := rep.Missing[backend.TierCgroup]; !ok {
		t.Errorf("tier cgroup should be listed as missing: %v", rep.Missing)
	}
	if !rep.Matrix.Has(backend.CapFileWriteDeny) {
		t.Errorf("the landlock column must deny writes: %v", rep.Matrix)
	}
	var buf bytes.Buffer
	if err := rep.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !rep.LSM.BPFActive && !strings.Contains(buf.String(), "lsm=") {
		t.Errorf("no lsm= fix line for tier 3:\n%s", buf.String())
	}
	if got := (&Report{Tier: rep.Tier, Require: backend.TierBPFLSM}).ExitCode(); got != identity.ExitRequire {
		t.Errorf("--require bpflsm here should exit %d, got %d", identity.ExitRequire, got)
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, nil, ""); err == nil {
		t.Fatal("a cancelled Run returned no error")
	}
}

// TestFixNamesTheActionableStep walks the fix line for every machine shape: privilege first, then
// the boot change, then the kernel build, and the Landlock answer when even tier 1 is out of reach.
func TestFixNamesTheActionableStep(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*probeState)
		reached backend.Tier
		want    string
	}{
		{"unprivileged", func(st *probeState) { st.root = false }, backend.TierLandlock, sudoDoctor()},
		{"root without bpf", func(st *probeState) {
			st.lsm = LSMState{Modules: []string{"capability", "apparmor"}, Source: LSMSourceSyscall}
		}, backend.TierCgroup, "lsm=capability,apparmor,bpf"},
		{"root without BTF", func(st *probeState) {
			fail(st, CheckBTF, "ENOENT", "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y")
		}, backend.TierLandlock, "CONFIG_DEBUG_INFO_BTF=y"},
		{"no landlock at all", func(st *probeState) {
			st.root = false
			st.landlockABI = 0
			fail(st, CheckLandlock, "ENOSYS", "boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y")
		}, "", "CONFIG_SECURITY_LANDLOCK=y"},
		{"already at the top", nil, backend.TierBPFLSM, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := state(tc.edit).fix(tc.reached)
			if tc.want == "" {
				if got != "" {
					t.Errorf("fix = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("fix = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// TestPinnedMachineTierIsReportedAsARun would get it: a machine config naming a concrete tier is a
// pin as well as a ceiling (R17), so a machine pinned to a tier it cannot reach reports no tier —
// the same answer `tego run` would give with exit 125 [tier-unavailable].
func TestPinnedMachineTierIsReportedAsARunWouldGetIt(t *testing.T) {
	m := config.Builtin()
	m.Tier.Bounded = true
	m.Tier.Value = config.TierSetting{Tier: string(backend.TierBPFLSM)}
	rep, err := Run(context.Background(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ceiling != backend.TierBPFLSM {
		t.Fatalf("ceiling %q", rep.Ceiling)
	}
	if rep.Tiers[backend.TierBPFLSM] {
		// A machine that reaches tier 3 (root with the objects where bpf is an active LSM: the guest's lsm=...,bpf
		// boot since TIER3-PLAN T7) gets the pinned tier itself, the answer a run would get there too.
		if rep.Tier != backend.TierBPFLSM {
			t.Errorf("tier %q on a machine that reaches the pinned tier bpflsm", rep.Tier)
		}
		return
	}
	if rep.Tier != "" {
		t.Errorf("tier %q; a pinned tier the machine cannot reach must not silently fall back", rep.Tier)
	}
	if rep.ExitCode() != identity.ExitFinding {
		t.Errorf("exit %d, want %d", rep.ExitCode(), identity.ExitFinding)
	}
}

// TestUnavailablePinNamesItsLine: a machine config pinning tier cgroup on a machine
// that provides only landlock left doctor at "tier: none (this machine can only record)", naming
// neither the pin nor its file, and pointing at no fix. The report names the line, the tiers the
// machine does provide, and a fix that edits the pin.
func TestUnavailablePinNamesItsLine(t *testing.T) {
	m := config.Builtin()
	m.Tier.Bounded = true
	m.Tier.Value = config.TierSetting{Tier: string(backend.TierCgroup)}
	m.Tier.Source = config.Provenance{File: "/etc/tego/config.yaml", Line: 2, Layer: config.LayerEtc}
	st := state(func(st *probeState) { st.root = false })
	rep := st.report(m, "")
	if rep.Tier != "" || !rep.Tiers[backend.TierLandlock] || rep.Tiers[backend.TierCgroup] {
		t.Fatalf("tier %q tiers %v; the described machine provides landlock only", rep.Tier, rep.Tiers)
	}
	if rep.CeilingSource != "/etc/tego/config.yaml:2" {
		t.Errorf("ceiling_source %q", rep.CeilingSource)
	}
	if !strings.Contains(rep.Fix, "set tier: auto, or a tier this machine provides, at /etc/tego/config.yaml:2") {
		t.Errorf("fix %q does not edit the pin", rep.Fix)
	}
	var buf bytes.Buffer
	if err := rep.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	want := "tier: none: the machine config pins tier cgroup at /etc/tego/config.yaml:2, which this machine " +
		"cannot provide (available here: landlock)"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("text lacks %q:\n%s", want, buf.String())
	}
	if rep.ExitCode() != identity.ExitFinding {
		t.Errorf("exit %d, want %d", rep.ExitCode(), identity.ExitFinding)
	}
	// Unpinned, the same machine is tier landlock, and the fix line is the next tier's, not the pin's.
	if rep := st.report(config.Builtin(), ""); rep.Tier != backend.TierLandlock || strings.Contains(rep.Fix, "set tier") {
		t.Errorf("unpinned: tier %q fix %q", rep.Tier, rep.Fix)
	}
}

// TestSummaryComesBeforeTheMatrix: doctor's answer, the tier line, came after the capability matrix's rows, so a
// reader met the probes, then the matrix, and learned which tier the machine gets only at the end
// (limits-check-doctor-cli.md R27 Output, amended 2026-11-02).
// One summary line now follows the probes, before the matrix: the tier, or why there is none, a machine config that
// caps it, and what each tier above it needs, by the names its missing line gives. The tier line after the matrix is
// unchanged and is still the one line that starts with "tier: " (test/vm/run-matrix-row.sh reads the first,
// doctor-refusal.sh the last, goldenReport splits there), and --json carries no summary.
func TestSummaryComesBeforeTheMatrix(t *testing.T) {
	user := func(st *probeState) {
		st.root = false
		for i := range st.results {
			if st.results[i].ID == CheckFanotify {
				st.results[i] = Result{ID: CheckFanotify, Detail: "requires root to test (fanotify_init needs CAP_SYS_ADMIN)",
					Fix: "re-run as root: sudo tego doctor", Skipped: true}
				st.byID[CheckFanotify] = st.results[i]
			}
		}
	}
	noLSM := func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"lockdown", "capability", "landlock", "yama", "apparmor"}, Source: LSMSourceSyscall}
		fail(st, CheckLSM, "bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected",
			st.lsm.GRUBFixFor(bootDebian))
	}
	stockUser := func(st *probeState) { user(st); noLSM(st) }
	machine := func(tier backend.Tier, line int) *config.Machine {
		m := config.Builtin()
		m.Tier.Bounded = true
		m.Tier.Value = config.TierSetting{Tier: string(tier)}
		m.Tier.Source = config.Provenance{File: "/etc/tego/config.yaml", Line: line, Layer: config.LayerEtc}
		return m
	}
	const pin = "none: the machine config pins tier cgroup at /etc/tego/config.yaml:2, which this machine cannot provide " +
		"(available here: landlock)"
	for _, tc := range []struct {
		name          string
		edit          func(*probeState)
		m             *config.Machine
		summary, tier string
	}{
		{"a user on a stock Ubuntu", stockUser, nil, "tier landlock; cgroup needs root; bpflsm needs root, lsm", "landlock"},
		{"root on a stock Ubuntu", noLSM, nil, "tier cgroup; bpflsm needs lsm", "cgroup"},
		{"every tier", nil, nil, "tier bpflsm", "bpflsm"},
		{"a machine config's ceiling", nil, machine(backend.TierLandlock, 3),
			"tier landlock, capped by the machine config (/etc/tego/config.yaml:3)", "landlock"},
		{"a pin this machine cannot provide", stockUser, machine(backend.TierCgroup, 2),
			"tier " + pin + "; cgroup needs root; bpflsm needs root, lsm", pin},
		{"Landlock ABI 1", func(st *probeState) {
			user(st)
			st.landlockABI = 1
			fail(st, CheckLandlock, "ABI 1 is below the supported minimum 2 (rename and link confined to one directory)",
				"boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)")
		}, nil, "tier none (this machine can only record); landlock needs landlock; cgroup needs landlock, root; " +
			"bpflsm needs landlock, root", "none (this machine can only record)"},
		// The one reason of the derivation that names no check of its own is named by its first word.
		{"Landlock ABI 1 behind a passing D4", func(st *probeState) { st.landlockABI = 1 }, nil,
			"tier none (this machine can only record); landlock needs landlock; cgroup needs landlock; bpflsm needs landlock",
			"none (this machine can only record)"},
		// A D7 row is named by its hook; the summary names D7 itself, whose line is just above it.
		{"a tier-2 hook that will not attach", func(st *probeState) {
			for i := range st.hooks {
				if st.hooks[i].Hook == "tp_btf/cgroup_mkdir" {
					st.hooks[i].Attached, st.hooks[i].Detail = false, "attach: no such BTF id"
				}
			}
		}, nil, "tier landlock; cgroup needs programs; bpflsm needs programs", "landlock"},
		{"a build without the BPF objects", func(st *probeState) {
			st.built = func(tier backend.Tier) error {
				if tier == backend.TierLandlock {
					return nil
				}
				return &enforce.NotBuiltError{Tier: tier, Why: "test build", Fix: "make build"}
			}
		}, nil, "tier landlock; cgroup needs build; bpflsm needs build", "landlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.m
			if m == nil {
				m = config.Builtin()
			}
			rep := state(tc.edit).report(m, "")
			var buf bytes.Buffer
			if err := rep.WriteText(&buf); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(buf.String(), "\n")
			probes := len(rep.Results)
			if len(lines) < probes+4 || lines[probes] != "" || lines[probes+1] != "summary: "+tc.summary ||
				lines[probes+2] != "" || !strings.HasPrefix(lines[probes+3], "capability matrix for tier ") {
				t.Fatalf("want the probes, then \"summary: %s\", then the matrix:\n%s", tc.summary, buf.String())
			}
			var summaries, tiers []int
			for i, l := range lines {
				if strings.HasPrefix(l, "summary:") {
					summaries = append(summaries, i)
				}
				if strings.HasPrefix(l, "tier: ") {
					tiers = append(tiers, i)
				}
			}
			if len(summaries) != 1 || len(tiers) != 1 || lines[tiers[0]] != "tier: "+tc.tier || tiers[0] < probes+3 {
				t.Errorf("summary lines %v, tier lines %v; want one of each and \"tier: %s\" after the matrix:\n%s",
					summaries, tiers, tc.tier, buf.String())
			}
			var js bytes.Buffer
			if err := writeJSONForTest(&js, rep); err != nil {
				t.Fatal(err)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(js.Bytes(), &obj); err != nil {
				t.Fatal(err)
			}
			if _, ok := obj["summary"]; ok {
				t.Errorf("--json carries the summary, a line of the text report only: %s", obj["summary"])
			}
		})
	}
}

// TestSkippedFanotifyIsNull: an unprivileged doctor never runs D8, and --json reported its fields as
// false, which reads as a kernel that refuses them. They are null until measured.
func TestSkippedFanotifyIsNull(t *testing.T) {
	skipped := state(func(st *probeState) {
		st.root = false
		fail(st, CheckFanotify, "requires root to test", "re-run as root")
		for i := range st.results {
			if st.results[i].ID == CheckFanotify {
				st.results[i].Skipped = true
				st.byID[CheckFanotify] = st.results[i]
			}
		}
	}).report(config.Builtin(), "")
	var buf bytes.Buffer
	if err := writeJSONForTest(&buf, skipped); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"fanotify": null`) {
		t.Errorf("a skipped D8 is not null in --json:\n%s", buf.String())
	}
	measured := state(func(st *probeState) { st.fanotify = FanotifyState{PermissionMarks: true, Refuses: true} }).report(config.Builtin(), "")
	if measured.Fanotify == nil || !measured.Fanotify.Refuses {
		t.Errorf("a D8 that ran lost its answer: %+v", measured.Fanotify)
	}
}

// TestSeccompSelfTestDoesNotHang is the listener timeout: a probe that never gets a notification
// must report rather than block doctor forever.
func TestSeccompSelfTestDoesNotHang(t *testing.T) {
	// A pipe read end never becomes readable, standing in for a kernel that accepted the filter and
	// then delivered nothing.
	var fds [2]int
	if err := syscallPipe(&fds); err != nil {
		t.Skipf("pipe: %v", err)
	}
	defer func() {
		_ = closeFD(fds[0])
		_ = closeFD(fds[1])
	}()
	start := time.Now()
	err := waitReadable(fds[0], 50*time.Millisecond)
	if err == nil {
		t.Fatal("waitReadable returned success on a quiet fd")
	}
	if !errors.Is(err, ErrSeccompSelfTest) {
		t.Errorf("error %v does not wrap ErrSeccompSelfTest", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waitReadable blocked for %s past its 50ms timeout", elapsed)
	}
}

// syscallPipe and closeFD keep the unix import in one place for the timeout test above.
func syscallPipe(fds *[2]int) error { return unix.Pipe(fds[:]) }

func closeFD(fd int) error { return unix.Close(fd) }

// TestCeilingIsExplainedInTheText: a machine capped by its own config must say so, or the missing
// higher tier looks like a kernel gap.
func TestCeilingIsExplainedInTheText(t *testing.T) {
	m := config.Builtin()
	m.Tier.Bounded = true
	m.Tier.Value = config.TierSetting{Tier: string(backend.TierLandlock)}
	rep, err := Run(context.Background(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier != backend.TierLandlock {
		t.Skipf("this machine cannot reach the ceiling: tier %q", rep.Tier)
	}
	var buf bytes.Buffer
	if err := rep.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ceiling: the machine config caps every run at landlock (built-in)") {
		t.Errorf("the ceiling is not explained:\n%s", buf.String())
	}
}

// TestTestHookWithoutBTF: a hook that needs a BTF name must refuse to be probed without a spec,
// never dereference a nil one.
func TestTestHookWithoutBTF(t *testing.T) {
	for _, h := range hooks {
		got := testHook(h, nil, nil, nil, Version{7, 0, 0})
		if got.BTF || got.Loaded || got.Attached {
			if h.btfName != "" {
				t.Errorf("%s was probed without BTF: %+v", h.Name, got)
			}
		}
		if h.btfName != "" && got.Detail == "" {
			t.Errorf("%s says nothing about why it was not probed", h.Name)
		}
	}
}

// TestSeccompRoundTripFailureStopsEveryEnforcementTier is D5's other half. A NEW_LISTENER filter this
// process may not install is one the launcher may not install either — EACCES from an outer filter,
// EBUSY under another supervisor's listener — and tier 2 installs the same filter, so the one
// derivation `tego doctor` reports and `tego run` selects from (derive.go) refuses every tier on it.
// Before, doctor's own derivation read only D5's Yama half, so on such a machine it reported tier
// landlock (and tier 3 as root) for runs that could never start: exactly the promise R27 D5 says
// doctor must not make.
func TestSeccompRoundTripFailureStopsEveryEnforcementTier(t *testing.T) {
	busy := fmt.Errorf("%w: %w", ErrSeccompSelfTest, unix.EBUSY)
	st := state(func(st *probeState) { failRoundTrip(st, busy) })
	if p := st.probe(); p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
		t.Fatalf("a machine whose seccomp listener cannot be installed still offers %+v", p)
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		reasons := strings.Join(st.missingFor(tier), "; ")
		if n := strings.Count(reasons, string(CheckSeccomp)+": "); n != 1 {
			t.Errorf("missingFor(%s) names the round trip %d times, want once: %q", tier, n, reasons)
		}
	}
	if f := st.fix(""); !strings.Contains(f, "seccomp user-notification supervisor") {
		t.Errorf("fix = %q, want D5's own remedy for EBUSY", f)
	}

	// Both halves failing: each is listed once, and Yama's sentence is not repeated inside D5's line.
	detail, blocked, remedy := yamaConsequence(yamaAdminOnly, false)
	both := state(func(st *probeState) {
		st.ptrace = PtraceState{Scope: yamaAdminOnly, Detail: detail, Blocked: blocked, Fix: remedy}
		failRoundTrip(st, fmt.Errorf("%w: %w", ErrSeccompSelfTest, unix.EACCES))
	})
	reasons := strings.Join(both.missingFor(backend.TierLandlock), "; ")
	if n := strings.Count(reasons, blocked); n != 1 {
		t.Errorf("Yama's reason appears %d times, want once: %q", n, reasons)
	}
	if !strings.Contains(reasons, "a filter needs no_new_privs or CAP_SYS_ADMIN") {
		t.Errorf("the round trip's own failure is hidden behind Yama's: %q", reasons)
	}
	if f := both.fix(""); !strings.Contains(f, "kernel.yama.ptrace_scope") || !strings.Contains(f, "CAP_SYS_ADMIN") {
		t.Errorf("fix = %q, want both D5 remedies on the one line", f)
	}
}

// writeJSONForTest encodes a report the way the CLI's --json does for the fields the Report owns
// (cli.doctorReport embeds it); the package has no encoder of its own.
func writeJSONForTest(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
