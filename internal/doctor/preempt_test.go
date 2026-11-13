// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// stubPreempt makes readPreempt answer model from source for the rest of t, as a kernel in that mode would.
func stubPreempt(t *testing.T, model, source string) {
	t.Helper()
	old := readPreempt
	readPreempt = func(string) (string, string) { return model, source }
	t.Cleanup(func() { readPreempt = old })
}

// noPreemptWaiver turns a waiver the environment set (preempt_waiver_test.go) off for the rest of t.
func noPreemptWaiver(t *testing.T) {
	t.Helper()
	old := planePreemptWaived
	planePreemptWaived = false
	t.Cleanup(func() { planePreemptWaived = old })
}

// TestPreemptModel holds the reading of the kernel's preemption model to ADR 0024 (16)'s admission rule: fmod_ret mode
// needs a model shown never to preempt kernel code, a PREEMPT_DYNAMIC build's shown by debugfs's live mode file
// alone, a fixed build's by its config with uname -v agreeing, and any doubt refuses it. The cases include the ones a
// 2026-11-03 review found admitted by the first reading, which also took the build's default, the kernel log and the
// boot line: a dynamic build booted `preempt=full preempt=bogus` (Linux keeps full, the old parser read the default)
// with debugfs and the log unavailable, and a dynamic build whose debugfs is not mounted.
func TestPreemptModel(t *testing.T) {
	const (
		ubuntu617 = "#41-Ubuntu SMP PREEMPT_DYNAMIC Sat Jun 20 18:01:40 UTC 2026"
		fedora70  = "#1 SMP PREEMPT_DYNAMIC Wed Jul  1 13:34:38 UTC 2026"
		azureArm  = "#17~24.04.1-Ubuntu SMP PREEMPT Thu Sep 24 19:06:39 UTC 2026"
		static    = "#1 SMP Mon Jan  5 10:00:00 UTC 2026"
	)
	voluntaryDyn := map[string]bool{"CONFIG_PREEMPT_DYNAMIC": true, "CONFIG_PREEMPT_VOLUNTARY": true}
	lazyDyn := map[string]bool{"CONFIG_PREEMPT_DYNAMIC": true, "CONFIG_PREEMPT_LAZY": true}
	voluntary := map[string]bool{"CONFIG_PREEMPT_VOLUNTARY": true}
	const noDebugfs = "open /sys/kernel/debug/sched/preempt: no such file or directory"
	for _, c := range []struct {
		name       string
		f          preemptFacts
		want       string
		wantSource string
		admits     bool
	}{
		{"6.17's default boot: debugfs says voluntary", preemptFacts{Version: ubuntu617, Config: voluntaryDyn,
			ConfigSource: "/boot/config-6.17", Debugfs: "none (voluntary) full lazy\n"}, preemptVoluntary, debugfsPreemptPath, true},
		{"6.17 booted preempt=none", preemptFacts{Version: ubuntu617, Config: voluntaryDyn,
			Debugfs: "(none) voluntary full lazy\n"}, preemptNone, debugfsPreemptPath, true},
		{"6.17 booted preempt=full", preemptFacts{Version: ubuntu617, Config: voluntaryDyn,
			Debugfs: "none voluntary (full) lazy\n"}, preemptFull, debugfsPreemptPath, false},
		{"Fedora's 7.0: debugfs says lazy", preemptFacts{Version: fedora70, Config: lazyDyn, Debugfs: "full (lazy)\n"},
			preemptLazy, debugfsPreemptPath, false},
		{"a dynamic build whose debugfs is not mounted, with a voluntary default: the default is no proof",
			preemptFacts{Version: ubuntu617, Config: voluntaryDyn, ConfigSource: "/boot/config-6.17", DebugfsErr: noDebugfs},
			"", "cannot be read (" + noDebugfs, false},
		{"preempt=full preempt=bogus on a voluntary-default dynamic build, debugfs and the log unavailable",
			preemptFacts{Version: ubuntu617, Config: voluntaryDyn, ConfigSource: "/boot/config-6.17",
				DebugfsErr: "open /sys/kernel/debug/sched/preempt: operation not permitted"}, "", "cannot be read", false},
		{"a dynamic build only uname -v says is one, debugfs refused by lockdown", preemptFacts{Version: fedora70,
			DebugfsErr: "operation not permitted"}, "", "PREEMPT_DYNAMIC", false},
		{"a dynamic build's debugfs file naming no mode", preemptFacts{Version: ubuntu617, Config: voluntaryDyn,
			Debugfs: "none voluntary full lazy\n"}, "", "names no mode", false},
		{"a dynamic build's debugfs file naming two", preemptFacts{Version: ubuntu617, Debugfs: "(none) (voluntary)"},
			"", "names no mode", false},
		{"a dynamic build by config alone, uname -v saying nothing", preemptFacts{Version: static, Config: voluntaryDyn,
			ConfigSource: "/proc/config.gz", DebugfsErr: noDebugfs}, "", "cannot be read", false},
		{"a static voluntary build", preemptFacts{Version: static, Config: voluntary, ConfigSource: "/proc/config.gz"},
			preemptVoluntary, "/proc/config.gz", true},
		{"a static none build", preemptFacts{Version: static, Config: map[string]bool{"CONFIG_PREEMPT_NONE": true},
			ConfigSource: "/boot/config-6.1"}, preemptNone, "/boot/config-6.1", true},
		{"a static build with no config: uname -v alone proves nothing", preemptFacts{Version: static}, "",
			"no build config", false},
		{"a voluntary config uname -v disagrees with", preemptFacts{Version: azureArm, Config: voluntary,
			ConfigSource: "/boot/config-7.0"}, preemptFullOrLazy, "uname", false},
		{"a config with no model at all", preemptFacts{Version: static, Config: map[string]bool{},
			ConfigSource: "/boot/config-x"}, "", "sets none", false},
		{"GitHub's arm64 runner: SMP PREEMPT, no config", preemptFacts{Version: azureArm}, preemptFullOrLazy, "uname", false},
		{"a static full config", preemptFacts{Version: azureArm, Config: map[string]bool{"CONFIG_PREEMPT": true},
			ConfigSource: "/boot/config-6.8"}, preemptFull, "/boot/config-6.8", false},
		{"a static lazy config", preemptFacts{Version: azureArm, Config: map[string]bool{"CONFIG_PREEMPT_LAZY": true},
			ConfigSource: "/boot/config-7.0"}, preemptLazy, "/boot/config-7.0", false},
		{"PREEMPT_RT by uname", preemptFacts{Version: "#1 SMP PREEMPT_RT Mon Jan  5", Config: voluntary},
			preemptRT, "uname", false},
		{"PREEMPT_RT by config", preemptFacts{Version: static, Config: map[string]bool{"CONFIG_PREEMPT_RT": true,
			"CONFIG_PREEMPT_VOLUNTARY": true}, ConfigSource: "/boot/config-rt"}, preemptRT, "/boot/config-rt", false},
		{"nothing at all", preemptFacts{}, "", "no build config", false},
	} {
		got, src := preemptModel(c.f)
		if got != c.want || !strings.Contains(src, c.wantSource) || preemptsKernelCode(got) == c.admits {
			t.Errorf("%s: %q from %q (admits fmod_ret: %v); want %q from ...%q... (%v)", c.name, got, src,
				!preemptsKernelCode(got), c.want, c.wantSource, c.admits)
		}
	}
}

func TestDebugfsPreemptMode(t *testing.T) {
	for in, want := range map[string]string{"full (lazy)\n": preemptLazy, "none (voluntary) full lazy": preemptVoluntary,
		"(none) voluntary full": preemptNone, "full lazy": "", "(bogus)": "", "": "", "(none) (full)": "",
		") none (": "", "( voluntary)": ""} {
		if got := debugfsPreemptMode(in); got != want {
			t.Errorf("debugfs %q: %q, want %q", in, got, want)
		}
	}
}

func TestScanConfigPreempt(t *testing.T) {
	cfg := "# CONFIG_PREEMPT_NONE is not set\nCONFIG_PREEMPT_VOLUNTARY=y\n# CONFIG_PREEMPT is not set\n" +
		"CONFIG_PREEMPT_COUNT=y\nCONFIG_PREEMPT_DYNAMIC=y\nCONFIG_PREEMPT_RCU=y\n"
	got, ok := scanConfigPreempt(strings.NewReader(cfg))
	if !ok || len(got) != 2 || !got["CONFIG_PREEMPT_VOLUNTARY"] || !got["CONFIG_PREEMPT_DYNAMIC"] {
		t.Errorf("config read as %v (%v)", got, ok)
	}
	if _, ok := scanConfigPreempt(strings.NewReader("")); ok {
		t.Error("an empty config is an answer")
	}
}

// TestFmodRetNeedsAKernelThatDoesNotPreempt is ADR 0024 (16)'s precondition: fmod_ret mode is ruled out before any
// load on a kernel not shown never to preempt kernel code, with the fix that would change it; a test build's waiver
// lets it be probed; LSM mode is not ruled out by it on a kernel whose trampoline exempts LSM programs (ADR 0148), and
// only there is it offered as the fix.
func TestFmodRetNeedsAKernelThatDoesNotPreempt(t *testing.T) {
	inactive := LSMState{Modules: []string{"capability", "landlock"}, Source: LSMSourceSyscall}
	active := LSMState{Modules: []string{"capability", "landlock", "bpf"}, BPFActive: true, Source: LSMSourceSyscall}
	for _, m := range []string{preemptFull, preemptLazy, preemptRT, preemptFullOrLazy, ""} {
		env := PlaneEnv{Preempt: m, PreemptSource: debugfsPreemptPath, LSMRecursionExempt: true}
		if m == "" {
			env.PreemptSource = "a PREEMPT_DYNAMIC build, whose live mode only " + debugfsPreemptPath + " says, and it cannot be read"
		}
		d, fix := modePrecondition(bpfobj.PlaneFmodRet, env, inactive)
		if !strings.Contains(d, "the BPF trampoline skips an fmod_ret program") || !strings.Contains(fix, "lsm=") ||
			!strings.Contains(fix, "preempt=voluntary") {
			t.Errorf("fmod_ret under %q: %q, fix %q", m, d, fix)
		}
		if m != "" && !strings.Contains(d, "preemption "+m+", from "+debugfsPreemptPath) {
			t.Errorf("fmod_ret under %q does not say what it read: %q", m, d)
		}
		if m == "" && (!strings.Contains(d, "is not proven") || !strings.Contains(d, "cannot be read") ||
			!strings.Contains(fix, "mount debugfs")) {
			t.Errorf("an unproven model: %q, fix %q", d, fix)
		}
		if _, fix := modePrecondition(bpfobj.PlaneFmodRet, env, active); !strings.HasPrefix(fix, "use LSM mode") {
			t.Errorf("fmod_ret under %q where bpf is active: fix %q", m, fix)
		}
		if d, _ := modePrecondition(bpfobj.PlaneLSM, env, active); d != "" {
			t.Errorf("LSM mode under %q ruled out: %q", m, d)
		}
		env.PreemptWaived = true
		if d, _ := modePrecondition(bpfobj.PlaneFmodRet, env, inactive); d != "" {
			t.Errorf("a waived precondition under %q: %q", m, d)
		}
	}
	for _, m := range []string{preemptNone, preemptVoluntary} {
		if d, _ := modePrecondition(bpfobj.PlaneFmodRet, PlaneEnv{Preempt: m}, inactive); d != "" {
			t.Errorf("fmod_ret under %q ruled out: %q", m, d)
		}
	}
}

// TestAdoptionRechecksPreemption: a pinned build's fmod_ret answer is not adopted on a kernel that does not prove it
// (the build may have been pinned by a test build that waived it, or before root changed the mode in debugfs), so the
// run probes and the probe says why; an LSM answer on a kernel that exempts LSM programs, or fmod_ret's under voluntary
// preemption, is adopted and carries the reading; an LSM answer on one that does not is held to fmod_ret's rule.
func TestAdoptionRechecksPreemption(t *testing.T) {
	adopted := func(m bpfobj.PlaneMode) *PlaneState {
		return &PlaneState{Source: planeSourcePin, Modes: []PlaneModeResult{{Mode: m, OK: true, Tested: true}}}
	}
	lsm := LSMState{Source: LSMSourceSyscall}
	lazy := PlaneEnv{Preempt: preemptLazy, PreemptSource: debugfsPreemptPath}
	if adoptStillAdmitted(adopted(bpfobj.PlaneFmodRet), lazy, lsm) {
		t.Error("an fmod_ret answer adopted under lazy preemption")
	}
	unproven := PlaneEnv{PreemptSource: "a PREEMPT_DYNAMIC build ... cannot be read"}
	if adoptStillAdmitted(adopted(bpfobj.PlaneFmodRet), unproven, lsm) {
		t.Error("an fmod_ret answer adopted where debugfs cannot be read")
	}
	exempt := lazy
	exempt.LSMRecursionExempt = true
	if st := adopted(bpfobj.PlaneLSM); !adoptStillAdmitted(st, exempt, lsm) || st.Env.Preempt != preemptLazy ||
		!st.Env.LSMRecursionExempt {
		t.Errorf("an LSM answer under lazy preemption on a kernel that exempts LSM programs: %+v", st.Env)
	}
	if adoptStillAdmitted(adopted(bpfobj.PlaneLSM), lazy, lsm) {
		t.Error("an LSM answer adopted under lazy preemption on a kernel whose trampoline checks LSM programs")
	}
	if st := adopted(bpfobj.PlaneLSM); !adoptStillAdmitted(st, PlaneEnv{Preempt: preemptVoluntary}, lsm) {
		t.Error("an LSM answer refused under voluntary preemption on a kernel whose trampoline checks LSM programs")
	}
	vol := PlaneEnv{Preempt: preemptVoluntary, PreemptSource: debugfsPreemptPath}
	if st := adopted(bpfobj.PlaneFmodRet); !adoptStillAdmitted(st, vol, lsm) || st.Env.PreemptSource != vol.PreemptSource {
		t.Errorf("an fmod_ret answer under voluntary preemption: %+v", st.Env)
	}
	waived := lazy
	waived.PreemptWaived = true
	if !adoptStillAdmitted(adopted(bpfobj.PlaneFmodRet), waived, lsm) {
		t.Error("a test build's waiver does not adopt")
	}
}

// TestACachedPlaneAnswerIsHeldToTheKernelsModeNow: the run-probe cache never answers the preemption precondition (a
// 2026-11-03 review: a cache hit copied the kept plane and selected cached fmod_ret on a kernel a fresh probe would
// refuse it on). An answer kept under voluntary preemption is not taken once the kernel's mode is lazy, or once
// debugfs can no longer be read: the run probes, and the probe rules fmod_ret mode out. Back under the reading it was
// kept under, an answer is taken again.
func TestACachedPlaneAnswerIsHeldToTheKernelsModeNow(t *testing.T) {
	var n int
	c := passingChecks(&calls{})
	inactive := LSMState{Modules: []string{"capability", "landlock"}, Source: LSMSourceSyscall}
	// The plane probe as plane.go's: the environment read now, and fmod_ret mode ruled out before any load where it
	// does not admit the mode; bpf is no active LSM, so LSM mode is ruled out too.
	c.plane = func(_ bool, _ int, _, pin string, _ bool) (*PlaneState, []HookResult) {
		n++
		st := passingPlane(pin)
		st.Env.Preempt, st.Env.PreemptSource = readPreempt("")
		for i := range st.Modes {
			var why, fix string
			if st.Modes[i].Mode == bpfobj.PlaneLSM {
				why, fix = modePrecondition(bpfobj.PlaneLSM, st.Env, inactive)
			} else {
				why, fix = fmodRetPreemptRefusal(st.Env, inactive)
			}
			if why != "" {
				st.Modes[i] = PlaneModeResult{Mode: st.Modes[i].Mode, Detail: why, Fix: fix}
			}
		}
		selectPlane(st)
		return st, passingPlaneRows()
	}
	noPreemptWaiver(t)
	cache, _ := testCache(t)
	run := func() probeState {
		return scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneFmodRet}.run(context.Background())
	}
	stubPreempt(t, preemptVoluntary, debugfsPreemptPath)
	if first := run(); n != 1 || first.plane == nil || first.plane.Selected != "fmod_ret" {
		t.Fatalf("the first run under voluntary preemption: %d probes, plane %+v", n, first.plane)
	}
	if hit := run(); n != 1 || hit.plane.Source != planeSourceRunCache || hit.plane.Selected != "fmod_ret" {
		t.Fatalf("the same mode again: %d probes, plane from %s selects %s; want the cache's fmod_ret", n,
			hit.plane.Source, hit.plane.Selected)
	}
	stubPreempt(t, preemptLazy, debugfsPreemptPath)
	lazy := run()
	if n != 2 || lazy.plane.Source == planeSourceRunCache || lazy.plane.Selected == "fmod_ret" {
		t.Errorf("after the mode changed to lazy: %d probes, plane from %s selects %s; want a probe that rules fmod_ret out",
			n, lazy.plane.Source, lazy.plane.Selected)
	}
	stubPreempt(t, preemptVoluntary, debugfsPreemptPath)
	if back := run(); n != 3 || back.plane.Selected != "fmod_ret" {
		t.Errorf("back under voluntary preemption: %d probes, plane %s; want a probe that admits fmod_ret", n, back.plane.Selected)
	}
	stubPreempt(t, "", "a PREEMPT_DYNAMIC build, whose live mode only "+debugfsPreemptPath+" says, and it cannot be read")
	if gone := run(); n != 4 || gone.plane.Selected == "fmod_ret" {
		t.Errorf("with debugfs unmounted after a voluntary answer was kept: %d probes, plane %s", n, gone.plane.Selected)
	}
}

// TestFmodRetAdmittedNowReadsAfresh: the check a reused answer is held to reads the kernel each time, and a test build's
// waiver admits a preemptive kernel only where it is set.
func TestFmodRetAdmittedNowReadsAfresh(t *testing.T) {
	noPreemptWaiver(t)
	lsm := LSMState{Source: LSMSourceSyscall}
	stubPreempt(t, preemptVoluntary, debugfsPreemptPath)
	if env, why := fmodRetAdmittedNow("", lsm); why != "" || env.Preempt != preemptVoluntary {
		t.Errorf("voluntary: %+v, %q", env, why)
	}
	stubPreempt(t, preemptFull, debugfsPreemptPath)
	if _, why := fmodRetAdmittedNow("", lsm); !strings.Contains(why, "preemption full") {
		t.Errorf("full: %q", why)
	}
	old := planePreemptWaived
	planePreemptWaived = true
	t.Cleanup(func() { planePreemptWaived = old })
	if env, why := fmodRetAdmittedNow("", lsm); why != "" || !env.PreemptWaived {
		t.Errorf("full under the waiver: %+v, %q", env, why)
	}
	if why := FmodRetRefusedNow(); why != "" {
		t.Errorf("FmodRetRefusedNow under the waiver: %q", why)
	}
	planePreemptWaived = false
	if why := FmodRetRefusedNow(); !strings.Contains(why, "preemption full") {
		t.Errorf("FmodRetRefusedNow: %q", why)
	}
}

// TestReadPreemptLiveNeedsUname: the live reading takes a fixed build's config only with uname -v beside it, which
// must carry no PREEMPT flag; a uname that fails proves nothing, so a voluntary config alone does not admit fmod_ret
// mode (a 2026-11-03 review: the error left the version empty, which passed the cross-check).
func TestReadPreemptLiveNeedsUname(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(cfg, []byte("CONFIG_PREEMPT_VOLUNTARY=y\n# CONFIG_PREEMPT is not set\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPaths, oldUname := preemptConfigPaths, unameVersion
	t.Cleanup(func() { preemptConfigPaths, unameVersion = oldPaths, oldUname })
	preemptConfigPaths = func(string) []string { return []string{cfg} }
	unameVersion = func() (string, error) { return "#1 SMP Mon Jan  5 10:00:00 UTC 2026", nil }
	if m, src := readPreemptLive("r"); m != preemptVoluntary || src != cfg {
		t.Errorf("a voluntary config with uname agreeing: %q from %q, want voluntary", m, src)
	}
	unameVersion = func() (string, error) { return "#1 SMP PREEMPT Mon Jan  5 10:00:00 UTC 2026", nil }
	if m, _ := readPreemptLive("r"); !preemptsKernelCode(m) {
		t.Errorf("a voluntary config uname -v contradicts: %q admits fmod_ret", m)
	}
	unameVersion = func() (string, error) { return "", errors.New("uname: operation not permitted") }
	if m, src := readPreemptLive("r"); m != "" || !strings.Contains(src, "uname -v could not be read") {
		t.Errorf("a voluntary config with uname failing: %q from %q, want no model", m, src)
	}
}
