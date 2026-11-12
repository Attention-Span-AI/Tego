// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// calls counts which of R27's checks a scope ran, and what D7 was handed.
type calls struct {
	n                map[CheckID]int
	tierRows, capRow int
	plane            int
	keep             []bool // keep flag of each plane probe call (the known-answers cache on)
	funcs            int    // kernelFuncs calls: the BTF parse a fresh answer keeps
}

// passingChecks describes a root machine on which every check passes, and counts the calls into calls.
func passingChecks(c *calls) checks {
	c.n = map[CheckID]int{}
	ok := func(id CheckID) Result { c.n[id]++; return Result{ID: id, OK: true, Detail: "ok"} }
	return checks{
		kernel: func() (Result, string, Version, kernelProbe) {
			return ok(CheckKernel), "6.17.0-test", Version{6, 17, 0}, kernelProbe{}
		},
		btf:      func() Result { return ok(CheckBTF) },
		cgroup:   func(int, []config.Value) Result { return ok(CheckCgroupV2) },
		landlock: func() (Result, int) { return ok(CheckLandlock), 7 },
		seccomp:  func() (Result, PtraceState, error) { return ok(CheckSeccomp), PtraceState{}, nil },
		lsm: func(bool) (Result, LSMState) {
			return ok(CheckLSM), LSMState{Modules: []string{"landlock", "bpf"}, BPFActive: true,
				Functional: "confirmed by a counting program on file_open"}
		},
		programs: func(_ bool, _ int, _ Version, tier, capture []hook) (Result, []HookResult) {
			c.tierRows, c.capRow = len(tier), len(capture)
			var rows []HookResult
			for _, h := range tier {
				rows = append(rows, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true, Attached: true})
			}
			for _, h := range capture {
				rows = append(rows, HookResult{Hook: h.Name, Capture: true, Loaded: true, Attached: true})
			}
			return ok(CheckPrograms), rows
		},
		fanotify: func(bool, Version) (Result, FanotifyState) {
			return ok(CheckFanotify), FanotifyState{ReportFID: true, PermissionMarks: true, Refuses: true}
		},
		swap: func() Result { return ok(CheckSwap) },
		plane: func(_ bool, _ int, _, pin string, keep bool) (*PlaneState, []HookResult) {
			c.plane++
			c.keep = append(c.keep, keep)
			return passingPlane(pin), passingPlaneRows()
		},
		kernelFuncs: func() map[string]bool {
			c.funcs++
			return map[string]bool{"bpf_loop": true, "bpf_rdonly_cast": true, "security_file_truncate": false}
		},
	}
}

// allBuilt describes a build that constructs every tier, so the scope's reach is the only thing left out.
func allBuilt(st *probeState) { st.built = func(backend.Tier) error { return nil } }

// TestRunAtReachLandlockLoadsNoProgram is ACC-F2-probe-per-run's test: a run whose selection can reach no tier
// above landlock — `--tier landlock`, a contract or a machine config pinned there, or an auto run of a process
// that is not root — runs D1, D3, D4 and D5 and nothing else. D6's functional half, D7 and D8 are what loaded
// 228 BPF programs and maps and took about 3 s of every root run on Ubuntu 24.04's 6.8, and none of them is
// read by tier landlock. At reach cgroup it runs tier 2's D7 rows alone, and D2 and D8, never D6 or tier 3's
// or capture's rows; doctor's own scope runs everything.
func TestRunAtReachLandlockLoadsNoProgram(t *testing.T) {
	cases := []struct {
		reach       backend.Tier
		want        map[CheckID]int
		tier, cap   int
		notProbed   []CheckID
		offered     backend.Probe
		unprobedFor []backend.Tier
	}{
		{reach: backend.TierLandlock,
			want:        map[CheckID]int{CheckKernel: 1, CheckCgroupV2: 1, CheckLandlock: 1, CheckSeccomp: 1, CheckSwap: 1},
			notProbed:   []CheckID{CheckBTF, CheckLSM, CheckPrograms, CheckFanotify},
			offered:     backend.Probe{backend.TierLandlock: true, backend.TierCgroup: false, backend.TierBPFLSM: false},
			unprobedFor: []backend.Tier{backend.TierCgroup, backend.TierBPFLSM}},
		{reach: backend.TierCgroup,
			want: map[CheckID]int{CheckKernel: 1, CheckBTF: 1, CheckCgroupV2: 1, CheckLandlock: 1, CheckSeccomp: 1,
				CheckPrograms: 1, CheckFanotify: 1, CheckSwap: 1},
			tier: len(tierHooks(backend.TierCgroup)), notProbed: []CheckID{CheckLSM},
			offered:     backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: false},
			unprobedFor: []backend.Tier{backend.TierBPFLSM}},
		{reach: "",
			want: map[CheckID]int{CheckKernel: 1, CheckBTF: 1, CheckCgroupV2: 1, CheckLandlock: 1, CheckSeccomp: 1,
				CheckLSM: 1, CheckPrograms: 1, CheckFanotify: 1, CheckSwap: 1},
			tier: len(hooks), cap: len(captureHooks),
			offered: backend.Probe{backend.TierLandlock: true, backend.TierCgroup: true, backend.TierBPFLSM: true}},
	}
	for _, c := range cases {
		var n calls
		st := scope{reach: c.reach, root: true, checks: passingChecks(&n)}.run(context.Background())
		if !reflect.DeepEqual(n.n, c.want) {
			t.Errorf("reach %q ran %v, want %v", c.reach, n.n, c.want)
		}
		if n.tierRows != c.tier || n.capRow != c.cap {
			t.Errorf("reach %q handed D7 %d tier rows and %d capture rows, want %d and %d", c.reach, n.tierRows, n.capRow, c.tier, c.cap)
		}
		// R27's nine results stay in order, a check the scope skipped marked as such and never as passed.
		var ids []CheckID
		for _, r := range st.results {
			ids = append(ids, r.ID)
		}
		if want := []CheckID{CheckKernel, CheckBTF, CheckCgroupV2, CheckLandlock, CheckSeccomp, CheckLSM, CheckPrograms, CheckFanotify, CheckSwap}; !reflect.DeepEqual(ids, want) {
			t.Errorf("reach %q results %v, want R27's order %v", c.reach, ids, want)
		}
		for _, id := range c.notProbed {
			if r := st.byID[id]; r.OK || !r.Skipped || !strings.HasPrefix(r.Detail, "not probed by tego run") {
				t.Errorf("reach %q: %s = %+v, want a skipped, not-probed result", c.reach, id, r)
			}
		}
		allBuilt(&st)
		if got := st.probe(); !reflect.DeepEqual(got, c.offered) {
			t.Errorf("reach %q offers %v, want %v", c.reach, got, c.offered)
		}
		rep := st.report(nil, "")
		for _, tier := range c.unprobedFor {
			if why := rep.WhyNot(tier); !strings.Contains(why, "not probed") {
				t.Errorf("reach %q: tier %s is explained as %q, not as unprobed", c.reach, tier, why)
			}
		}
	}
}

// TestRunReportIsDoctorsAtAndBelowItsReach: on any machine, the tiers at or below a run's reach are offered and
// explained exactly as doctor's own report offers and explains them, so skipping the checks above the reach
// never changes what a run selects or what its refusal says (R27 Output: `run` never gives another account of
// a tier than `doctor` does).
func TestRunReportIsDoctorsAtAndBelowItsReach(t *testing.T) {
	machines := map[string]func(*checks){
		"every check passes": func(*checks) {},
		"fanotify refuses nothing": func(c *checks) {
			c.fanotify = func(bool, Version) (Result, FanotifyState) {
				return Result{ID: CheckFanotify, Detail: "the open a FAN_DENY answered returned <nil>", Fix: fanotifyNotRefusedFix},
					FanotifyState{PermissionMarks: true}
			}
		},
		"no landlock": func(c *checks) {
			c.landlock = func() (Result, int) {
				return Result{ID: CheckLandlock, Detail: "landlock_create_ruleset: ENOSYS", Fix: "boot a kernel >= 5.13"}, 0
			}
		},
		"a verifier refusal": func(c *checks) {
			inner := c.programs
			c.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
				_, rows := inner(root, uid, v, tier, capture)
				rows[0].Attached, rows[0].Loaded, rows[0].Detail = false, false, "load: permission denied"
				return programsVerdict(rows), rows
			}
		},
		// Tier landlock's own list is missing a line whose check has no fix (missingFor's ABI floor under a D4
		// that passed), so tier cgroup's fix line falls through to the checks above tier 1. D6's GRUB line is
		// not among them: bpf in lsm= gives tier cgroup nothing, and a run at reach cgroup never runs D6.
		"landlock ABI 1 and no bpf in lsm=": func(c *checks) {
			c.landlock = func() (Result, int) { return Result{ID: CheckLandlock, OK: true, Detail: "ABI 1"}, 1 }
			c.lsm = func(bool) (Result, LSMState) {
				s := LSMState{Modules: []string{"lockdown", "capability", "landlock"}, Source: "securityfs"}
				return Result{ID: CheckLSM, Detail: "lockdown,capability,landlock via securityfs; bpf is not active " +
					"(tier bpflsm unavailable)", Fix: s.GRUBFix()}, s
			}
		},
		// D7's own fix is worded for the worst of all its rows: a tier-3 hook the kernel lacks makes it "boot a
		// kernel with the listed hooks", which is not what tier cgroup's verifier refusal needs, and a run at
		// reach cgroup never sees the tier-3 row.
		"a tier-2 verifier refusal and a tier-3 hook the kernel lacks": func(c *checks) {
			inner := c.programs
			c.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
				_, rows := inner(root, uid, v, tier, capture)
				rows[0].Loaded, rows[0].Attached, rows[0].Object = false, false, "trace_proc.o"
				rows[0].Detail = "load: the verifier refused it: invalid mem access"
				for i := range rows {
					if rows[i].Tier == backend.TierBPFLSM {
						rows[i].BTF, rows[i].Loaded, rows[i].Attached = false, false, false
						rows[i].Detail = "no BTF for " + rows[i].Hook
						break
					}
				}
				return programsVerdict(rows), rows
			}
		},
	}
	cgroupFix := map[string]string{
		"landlock ABI 1 and no bpf in lsm=": "(rename and link would be confined to one directory)",
		"a tier-2 verifier refusal and a tier-3 hook the kernel lacks": "; fix: this kernel's verifier refuses the " +
			"listed programs of this build: boot a kernel that accepts them or report the verifier's lines as a " +
			"tego bug, or pin a lower tier in the machine config",
	}
	for name, edit := range machines {
		full := passingChecks(&calls{})
		edit(&full)
		doctorState := scope{root: true, checks: full}.run(context.Background())
		allBuilt(&doctorState)
		doctorRep := doctorState.report(nil, "")
		// Agreeing is not enough: the line both give for tier cgroup is the one tier cgroup's own checks call for.
		if fix, ok := cgroupFix[name]; ok && !strings.HasSuffix(doctorRep.WhyNot(backend.TierCgroup), fix) {
			t.Errorf("%s: doctor explains tier cgroup as %q, want it to end %q", name, doctorRep.WhyNot(backend.TierCgroup), fix)
		}
		for _, reach := range backend.Tiers() {
			c := passingChecks(&calls{})
			edit(&c)
			st := scope{reach: reach, root: true, checks: c}.run(context.Background())
			allBuilt(&st)
			rep := st.report(nil, "")
			for _, tier := range backend.Tiers() {
				if !tier.AtOrBelow(reach) {
					continue
				}
				if rep.Probe()[tier] != doctorRep.Probe()[tier] || rep.WhyNot(tier) != doctorRep.WhyNot(tier) {
					t.Errorf("%s, reach %s: tier %s offered=%v %q; doctor %v %q", name, reach, tier,
						rep.Probe()[tier], rep.WhyNot(tier), doctorRep.Probe()[tier], doctorRep.WhyNot(tier))
				}
			}
		}
	}
}

// TestReach: the tiers a run must probe are the ones its selection can pick or has to explain.
func TestReach(t *testing.T) {
	pinned := func(tier string) *agent.RuleTable {
		return &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Name: "a", Tier: agent.TierPin(tier)}}
	}
	capped := func(tier string) *config.Machine {
		m := config.Builtin()
		m.Tier.Bounded = true
		m.Tier.Value.Auto = false
		m.Tier.Value.Tier = tier
		return m
	}
	built := func(ts ...backend.Tier) func(backend.Tier) error {
		return func(t backend.Tier) error {
			for _, b := range ts {
				if b == t {
					return nil
				}
			}
			return errors.New("not built")
		}
	}
	tagged := built(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	cases := []struct {
		name  string
		m     *config.Machine
		rt    *agent.RuleTable
		only  backend.Tier
		root  bool
		built func(backend.Tier) error
		want  backend.Tier
	}{
		{"--tier landlock as root", nil, pinned(""), backend.TierLandlock, true, tagged, backend.TierLandlock},
		{"contract tier: landlock as root", nil, pinned("landlock"), "", true, tagged, backend.TierLandlock},
		{"machine tier: landlock as root", capped("landlock"), pinned(""), "", true, tagged, backend.TierLandlock},
		{"auto as the user", nil, pinned("auto"), "", false, tagged, backend.TierLandlock},
		{"auto as root, untagged build", nil, pinned(""), "", true, built(backend.TierLandlock), backend.TierLandlock},
		{"auto as root, tagged build", nil, pinned(""), "", true, tagged, backend.TierBPFLSM},
		{"auto as root, a build of tier cgroup alone", nil, pinned(""), "", true, built(backend.TierLandlock, backend.TierCgroup), backend.TierCgroup},
		{"auto as root, a build of every tier", nil, pinned(""), "", true, built(backend.Tiers()...), backend.TierBPFLSM},
		{"auto as root under a cgroup cap, a build of every tier", capped("cgroup"), pinned(""), "", true,
			built(backend.Tiers()...), backend.TierCgroup},
		// A named tier is explained by name when refused, so its checks are probed whoever is asking.
		{"--tier cgroup as the user", nil, pinned(""), backend.TierCgroup, false, tagged, backend.TierCgroup},
		{"--tier bpflsm", nil, pinned(""), backend.TierBPFLSM, true, tagged, backend.TierBPFLSM},
		{"contract tier: bpflsm", nil, pinned("bpflsm"), "", true, tagged, backend.TierBPFLSM},
		// --tier landlock against a contract pinned at cgroup is refused as a conflict that also explains
		// the pin when it is missing, so the pin's checks are probed too.
		{"--tier landlock, contract cgroup", nil, pinned("cgroup"), backend.TierLandlock, true, tagged, backend.TierCgroup},
		{"--tier landlock, machine cgroup", capped("cgroup"), pinned(""), backend.TierLandlock, true, tagged, backend.TierCgroup},
		{"no contract at all", nil, nil, "", false, tagged, backend.TierLandlock},
		{"--tier observe", nil, pinned(""), backend.TierObserve, true, tagged, backend.TierLandlock},
	}
	for _, c := range cases {
		if got := reach(c.m, c.rt, c.only, c.root, c.built); got != c.want {
			t.Errorf("%s: reach %s, want %s", c.name, got, c.want)
		}
	}
}

// TestRunAtReachBPFLSMProbesAsReachCgroupAndTheLSMList: tier bpflsm is the plane in LSM mode over tier cgroup
// (enforce-plane R19, TIER3-PLAN T7), so a run that can reach it reads tier cgroup's checks, the LSM list and LSM
// mode's answer, and nothing else: D7's tier-2 rows alone, never tier 3's legacy rows or capture's; D6 without its
// counting program, whose proof LSM mode's probe (or the pinned or cached answer of one this boot) already is; and the
// run-probe cache and a pinned build's answer as at reach cgroup, so an auto run as root, which now reaches bpflsm,
// probes no plane and loads no program once the boot has an answer.
func TestRunAtReachBPFLSMProbesAsReachCgroupAndTheLSMList(t *testing.T) {
	var n calls
	c := passingChecks(&n)
	lsm := c.lsm
	var lsmRoot []bool
	c.lsm = func(root bool) (Result, LSMState) { lsmRoot = append(lsmRoot, root); return lsm(root) }
	cache, _ := testCache(t)
	run := func() probeState {
		return scope{reach: backend.TierBPFLSM, root: true, checks: c, cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	}
	st := run()
	if n.tierRows != len(tierHooks(backend.TierCgroup)) || n.capRow != 0 || n.plane != 1 {
		t.Errorf("D7 was handed %d tier rows and %d capture rows and the plane probed %d times; want tier 2's %d, none, once",
			n.tierRows, n.capRow, n.plane, len(tierHooks(backend.TierCgroup)))
	}
	if !slices.Equal(lsmRoot, []bool{false}) {
		t.Errorf("D6 ran as %v, want once without its counting program", lsmRoot)
	}
	allBuilt(&st)
	if p := st.probe(); !p[backend.TierBPFLSM] || !p[backend.TierCgroup] {
		t.Fatalf("offered %v: %v", p, st.missingFor(backend.TierBPFLSM))
	}
	rep := st.report(nil, "")
	if ch, err := rep.PlaneFor(backend.TierBPFLSM); err != nil || ch.Mode != bpfobj.PlaneLSM {
		t.Errorf("PlaneFor(bpflsm) = %+v, %v", ch, err)
	}

	// The second run is answered by the cache: no program, no plane.
	n.n, n.plane, n.tierRows = map[CheckID]int{}, 0, 0
	second := run()
	if n.n[CheckPrograms] != 0 || n.n[CheckFanotify] != 0 || n.plane != 0 || second.cached == nil {
		t.Errorf("the second run probed %v and the plane %d times, cached %v", n.n, n.plane, second.cached)
	}
	allBuilt(&second)
	if !second.probe()[backend.TierBPFLSM] {
		t.Errorf("the cached answer does not offer tier bpflsm: %v", second.missingFor(backend.TierBPFLSM))
	}

	// A pinned build's answer in LSM mode is adopted, as at reach cgroup.
	n.plane = 0
	adopted := scope{reach: backend.TierBPFLSM, root: true, checks: c, planePin: config.PlaneAuto,
		adopt: func(pin string) (*PlaneState, bool) {
			st, err := adoptPlaneFrom(pin, LSMState{BPFActive: true}, "h", func(string) (PlaneChoice, bool) {
				return PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly}, true
			})
			return st, err == nil
		}}.run(context.Background())
	allBuilt(&adopted)
	if n.plane != 0 || !adopted.probe()[backend.TierBPFLSM] {
		t.Errorf("over a pinned build: %d plane probes, offered %v", n.plane, adopted.probe())
	}
}

// TestPlaneKnownAnswersCacheIsForRunsOnly is limits-check-doctor-cli R27: doctor's own scope exercises the plane's
// known answers afresh, so its plane probe gets the known-answers cache off; a run's scope (the run-probe cache on)
// gets it on.
func TestPlaneKnownAnswersCacheIsForRunsOnly(t *testing.T) {
	cache, _ := testCache(t)
	var doc, run calls
	scope{reach: "", root: true, checks: passingChecks(&doc), cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&run), cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	if !reflect.DeepEqual(doc.keep, []bool{false}) {
		t.Errorf("doctor's scope probed the plane with keep %v, want [false]", doc.keep)
	}
	if !reflect.DeepEqual(run.keep, []bool{true}) {
		t.Errorf("a run's scope probed the plane with keep %v, want [true]", run.keep)
	}
	if c := newPlaneKnownCache("6.8.0", 0, false); c.cache != nil || c.ok {
		t.Errorf("keep false still built a known-answers cache: %+v", c)
	}
}

// TestAutoTiers: tier auto resolves among the tiers this build constructs and this process could be given here, so a
// tegobpf build run by a normal user, or by root on a kernel without bpf in lsm=, never compiles at a tier its run
// cannot get (the demo's ask_read refusal at tier bpflsm). The built tiers it leaves out come back by the precondition
// they lack, which compile --test's header names: it said every tier this tego builds while the set was landlock alone.
func TestAutoTiers(t *testing.T) {
	all := func(backend.Tier) error { return nil }
	landlockOnly := func(tier backend.Tier) error {
		if tier == backend.TierLandlock {
			return nil
		}
		return errors.New("not built")
	}
	L, C, B := backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM
	for _, c := range []struct {
		name   string
		root   bool
		bpfLSM bool
		built  func(backend.Tier) error
		want   AutoSet
	}{
		{"tegobpf build, normal user, bpf in lsm=", false, true, all, AutoSet{Tiers: []backend.Tier{L}, NeedRoot: []backend.Tier{C, B}}},
		{"tegobpf build, normal user, no bpf in lsm=", false, false, all, AutoSet{Tiers: []backend.Tier{L}, NeedRoot: []backend.Tier{C, B}}},
		{"tegobpf build, root, no bpf in lsm=", true, false, all, AutoSet{Tiers: []backend.Tier{L, C}, NeedBPFLSM: []backend.Tier{B}}},
		{"tegobpf build, root, bpf in lsm=", true, true, all, AutoSet{Tiers: []backend.Tier{L, C, B}}},
		{"untagged build, root, bpf in lsm=", true, true, landlockOnly, AutoSet{Tiers: []backend.Tier{L}}},
		{"untagged build, normal user, no bpf in lsm=", false, false, landlockOnly, AutoSet{Tiers: []backend.Tier{L}}},
	} {
		got := autoTiers(c.root, func() bool { return c.bpfLSM }, c.built)
		if !slices.Equal(got.Tiers, c.want.Tiers) || !slices.Equal(got.NeedRoot, c.want.NeedRoot) ||
			!slices.Equal(got.NeedBPFLSM, c.want.NeedBPFLSM) {
			t.Errorf("%s: autoTiers = %+v, want %+v", c.name, got, c.want)
		}
	}
	// A normal user's set never reads the LSM list: no precondition it holds can give that user tier bpflsm.
	autoTiers(false, func() bool { t.Error("the LSM list was read for a process that is not root"); return true }, all)
}
