// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// builtExcept describes a build that constructs every tier but the ones named, answering for those with
// enforce's own refusal so the text doctor prints is the text a real build prints.
func builtExcept(missing ...backend.Tier) func(backend.Tier) error {
	return func(t backend.Tier) error {
		for _, m := range missing {
			if t == m {
				return &enforce.NotBuiltError{Tier: t, Why: "test build", Fix: fixFor(t)}
			}
		}
		return nil
	}
}

// fixFor is what enforce.Buildable says for each tier: tier 2 has a build that carries it, tier 3 none.
func fixFor(t backend.Tier) string {
	if t == backend.TierCgroup {
		return "use a tego built with the BPF objects"
	}
	return ""
}

// TestTierOneNeedsD1D3D4D5 is the gate `tego run` used to keep for itself (internal/cli tiersFrom), now
// part of the one derivation both commands read. Each of D1, D3, D4 and either half of D5 takes tier 1
// away on its own, and with it every tier, because each tier is the one below plus more. Before, doctor
// read only D4 and D5 for tier 1, so a machine without a delegated cgroup got tier landlock from
// `tego doctor` and exit 125 [tier-unavailable] from `tego run` (the open question R27 and §11 carried).
// The probes that need root answer "requires root to test" for an ordinary user, and tier 1 needs none
// of them.
// supervisor.md E27: a kernel below the floor (D1) blocks tier 1 before the supervisor runs. The floor in code is 5.14.0, not the 6.1 the rule states.
func TestTierOneNeedsD1D3D4D5(t *testing.T) {
	user := func(edit func(*probeState)) probeState {
		return state(func(st *probeState) {
			st.root = false
			if edit != nil {
				edit(st)
			}
		})
	}
	if p := user(nil).probe(); !p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
		t.Fatalf("every probe OK as an ordinary user: %v, want landlock alone", p)
	}

	detail, blocked, remedy := yamaConsequence(yamaAdminOnly, false)
	blockers := []struct {
		name string
		edit func(*probeState)
		// named is what missingFor(landlock) must say, fix what the fix line must carry.
		named, fix string
	}{
		{"D1 kernel below the floor", func(st *probeState) {
			fail(st, CheckKernel, "5.10.0 is below 5.14.0 (cgroup.kill, SECCOMP_ADDFD_FLAG_SEND)", "boot a kernel >= 5.14.0")
		}, "kernel: 5.10.0 is below 5.14.0", "boot a kernel >= 5.14.0"},
		{"D3 no delegated cgroup", func(st *probeState) {
			fail(st, CheckCgroupV2, "no delegated cgroup v2 subtree", delegateFix)
		}, "cgroupv2: no delegated cgroup v2 subtree", "Delegate=cpu memory pids"},
		{"D4 no Landlock", func(st *probeState) {
			st.landlockABI = 0
			fail(st, CheckLandlock, "landlock_create_ruleset: function not implemented", "boot a kernel with CONFIG_SECURITY_LANDLOCK=y")
		}, "landlock: landlock_create_ruleset", "CONFIG_SECURITY_LANDLOCK=y"},
		{"D5 Yama refuses the supervisor", func(st *probeState) {
			st.ptrace = PtraceState{Scope: yamaAdminOnly, Detail: detail, Blocked: blocked, Fix: remedy}
		}, "ptrace_scope=2", "kernel.yama.ptrace_scope"},
		{"D5 the round trip fails on its own", func(st *probeState) {
			failRoundTrip(st, fmt.Errorf("%w: %w", ErrSeccompSelfTest, unix.EBUSY))
		}, "seccomp: ", "seccomp user-notification supervisor"},
	}
	for _, b := range blockers {
		t.Run(b.name, func(t *testing.T) {
			for _, root := range []bool{false, true} {
				st := state(b.edit)
				st.root = root
				if p := st.probe(); p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
					t.Errorf("root=%v: %s and still offered %v", root, b.name, p)
				}
				for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
					reasons := strings.Join(st.missingFor(tier), "; ")
					if n := strings.Count(reasons, b.named); n != 1 {
						t.Errorf("root=%v: missingFor(%s) names %q %d times, want once: %q", root, tier, b.named, n, reasons)
					}
				}
				if f := st.fix(""); !strings.Contains(f, b.fix) {
					t.Errorf("root=%v: fix = %q, want %q", root, f, b.fix)
				}
			}
		})
	}

	// Two tier-1 blockers at once: both remedies on the one line, in missingFor's order.
	both := state(func(st *probeState) {
		fail(st, CheckCgroupV2, "no delegated cgroup v2 subtree", delegateFix)
		st.landlockABI = 0
		fail(st, CheckLandlock, "ENOSYS", "boot a kernel with CONFIG_SECURITY_LANDLOCK=y")
	})
	f := both.fix("")
	if i, j := strings.Index(f, "Delegate="), strings.Index(f, "CONFIG_SECURITY_LANDLOCK"); i < 0 || j < 0 || i > j {
		t.Errorf("fix = %q, want D3's remedy then D4's on one line", f)
	}

	for _, id := range []CheckID{CheckBTF, CheckLSM, CheckPrograms, CheckFanotify} {
		st := user(func(st *probeState) { fail(st, id, "requires root to test", "re-run as root: sudo tego doctor") })
		if !st.probe()[backend.TierLandlock] {
			t.Errorf("%s failing took tier landlock away: %v", id, st.missingFor(backend.TierLandlock))
		}
	}
}

// TestTheBuildIsHalfTheDerivation: a root machine on which every probe passes reaches only the tiers the
// binary can construct, and the report says which build is missing. Before, doctor loaded its own minimal
// programs and never asked the build, so `sudo tego doctor` from a release binary (no objects) reported
// tier cgroup, and tier bpflsm on a machine with bpf in lsm=, while no run of that binary could prepare
// either.
func TestTheBuildIsHalfTheDerivation(t *testing.T) {
	cases := []struct {
		name    string
		built   func(backend.Tier) error
		want    backend.Tier
		missing backend.Tier
		fix     string
	}{
		{"a build without the objects", builtExcept(backend.TierCgroup, backend.TierBPFLSM), backend.TierLandlock,
			backend.TierCgroup, "use a tego built with the BPF objects"},
		{"a build with the objects", builtExcept(backend.TierBPFLSM), backend.TierCgroup, backend.TierBPFLSM, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := state(func(st *probeState) { st.built = tc.built })
			tier, err := backend.Select("", "", st.probe())
			if err != nil || tier != tc.want {
				t.Fatalf("tier %q, %v; want %s", tier, err, tc.want)
			}
			reasons := strings.Join(st.missing(tier)[tc.missing], "; ")
			if !strings.Contains(reasons, "build: tier "+string(tc.missing)+" is not built into this binary") {
				t.Errorf("missing for %s = %q, does not name the build", tc.missing, reasons)
			}
			// No machine change makes a tier this build lacks available, so the fix line names the build,
			// or nothing when no build carries the tier; never the GRUB line for tier 3.
			if f := st.fix(tier); f != tc.fix {
				t.Errorf("fix = %q, want %q", f, tc.fix)
			}
		})
	}
}

// TestTheDerivationReadsThisBuild ties the seam to the binary: with built left nil, doctor asks
// enforce.Buildable, so an untagged test binary reports neither tier cgroup nor tier bpflsm, and a binary with the
// objects reports both where the machine gives them (bpflsm is the plane in LSM mode over tier cgroup, TIER3-PLAN T7).
func TestTheDerivationReadsThisBuild(t *testing.T) {
	st := state(func(st *probeState) { st.built = nil })
	p := st.probe()
	if want := enforce.Buildable(backend.TierCgroup) == nil; p[backend.TierCgroup] != want {
		t.Errorf("tier cgroup offered = %v, but this binary builds it: %v", p[backend.TierCgroup], want)
	}
	if want := enforce.Buildable(backend.TierBPFLSM) == nil; p[backend.TierBPFLSM] != want {
		t.Errorf("tier bpflsm offered = %v, but this binary builds it: %v", p[backend.TierBPFLSM], want)
	}
	if !p[backend.TierLandlock] {
		t.Errorf("tier landlock withheld: %v", st.missingFor(backend.TierLandlock))
	}
}

// TestDoctorAndRunSelectTheSameTier: for every machine shape, the tier
// `tego doctor` reports is the tier Report.Select, which `tego run` calls (enforce.Select over Report.Probe with
// the planes doctor chose), constructs for an auto contract, and Select finds nothing in doctor's probe to filter
// out: not the build, and not tier bpflsm's plane in LSM mode. It uses this binary's own build answer, the one both
// commands really read.
func TestDoctorAndRunSelectTheSameTier(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel, so Select cannot construct tier 1 here: %v", err)
	}
	shapes := map[string]func(*probeState){
		"ordinary user":        func(st *probeState) { st.root = false },
		"root, no bpf in lsm=": func(st *probeState) { st.lsm = LSMState{Modules: []string{"capability", "landlock"}} },
		"root, everything":     nil,
		"root, no fanotify":    func(st *probeState) { fail(st, CheckFanotify, "no permission events", "rebuild") },
		"no delegated cgroup":  func(st *probeState) { fail(st, CheckCgroupV2, "not delegated", delegateFix) },
		"Yama at scope 2": func(st *probeState) {
			st.ptrace = PtraceState{Scope: yamaAdminOnly, Blocked: "yama: ptrace_scope=2 admits only CAP_SYS_PTRACE"}
		},
	}
	for name, edit := range shapes {
		t.Run(name, func(t *testing.T) {
			st := state(edit)
			st.built = nil
			probe := st.probe()
			reported, rerr := backend.Select("", "", probe)
			b, ds := st.report(nil, "").Select(nil, nil, "")
			for _, d := range ds {
				if strings.Contains(d.Message, "not built into this binary") || strings.Contains(d.Message, "LSM mode") {
					t.Errorf("Select filtered a tier doctor reported: %s", d.Message)
				}
			}
			switch {
			case rerr != nil && b != nil:
				t.Errorf("doctor reports no tier (%v) and run selected %s", rerr, b.Tier())
			case rerr == nil && b == nil:
				t.Errorf("doctor reports %s and run refused: %v", reported, ds)
			case rerr == nil && b.Tier() != reported:
				t.Errorf("doctor reports %s and run selected %s", reported, b.Tier())
			}
		})
	}
}

// TestRunOffersOnlyWhatThisBinaryBuilds is the same property on this machine as it is: every tier the
// real report offers is one this binary can construct.
func TestRunOffersOnlyWhatThisBinaryBuilds(t *testing.T) {
	rep, err := Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for tier, ok := range rep.Probe() {
		err := enforce.Buildable(tier)
		if ok && err != nil {
			t.Errorf("doctor offers %s, which this binary cannot construct: %v", tier, err)
		}
		reasons, listed := rep.Missing[tier]
		if listed && errors.Is(err, enforce.ErrNotBuilt) && !strings.Contains(strings.Join(reasons, "; "), "not built into this binary") {
			t.Errorf("missing for %s does not say the build lacks it: %v", tier, reasons)
		}
	}
}

// TestProgramsFailingBeforeAnyHookTakesTierTwo: as root, D7 can fail before it tests one hook — a BTF that
// cilium/ebpf cannot parse fails btf.LoadKernelSpec, and the derivation must not rely on D2 failing with it.
// No per-hook row then fails, so a derivation that read D7 through its rows alone offered tier cgroup, and
// every run of it failed loading programs after its ledger and cgroup existed.
func TestProgramsFailingBeforeAnyHookTakesTierTwo(t *testing.T) {
	st := state(func(st *probeState) {
		st.hooks = nil
		fail(st, CheckPrograms, "doctor: program load test unavailable: parse vmlinux: bad magic",
			"boot a kernel built with CONFIG_DEBUG_INFO_BTF=y")
	})
	p := st.probe()
	if !p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
		t.Fatalf("D7 failed before testing any hook and the derivation offers %v, want landlock alone", p)
	}
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		reasons := strings.Join(st.missingFor(tier), "; ")
		if n := strings.Count(reasons, "programs: doctor: program load test unavailable"); n != 1 {
			t.Errorf("missingFor(%s) names D7's failure %d times, want once: %q", tier, n, reasons)
		}
	}
	if f := st.fix(backend.TierLandlock); f != "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y" {
		t.Errorf("fix = %q, want D7's own remedy", f)
	}

	// With its rows present, D7's failure is theirs to report, and a D7 that only an ordinary user skipped
	// is the root line's.
	rows := state(func(st *probeState) {
		st.hooks[0].Attached = false
		st.hooks[0].Detail = "attach: EINVAL"
		fail(st, CheckPrograms, "15 of 16 hooks load and attach; missing: "+st.hooks[0].Hook, "boot a kernel with the listed hooks")
	})
	if n := strings.Count(strings.Join(rows.missingFor(backend.TierCgroup), "; "), "programs: "); n != 0 {
		t.Errorf("D7's summary repeated beside its own failing row: %v", rows.missingFor(backend.TierCgroup))
	}
	user := state(func(st *probeState) {
		st.root, st.hooks = false, nil
		fail(st, CheckPrograms, "requires root to test", "re-run as root: sudo tego doctor")
	})
	if n := strings.Count(strings.Join(user.missingFor(backend.TierCgroup), "; "), "programs: "); n != 0 {
		t.Errorf("an ordinary user's skipped D7 listed beside the root line: %v", user.missingFor(backend.TierCgroup))
	}
}

// TestRunIsRefusedInDoctorsWords: `tego run --tier cgroup` selects through Report.Select on the report the
// derivation produced, so on a machine whose derivation withholds tier cgroup the refusal names that tier
// and carries doctor's own "missing for cgroup" line and fix. It used to narrow the probe to an empty set
// and answer "no enforcement tier available on this machine", on a machine doctor gave tier landlock,
// naming neither the build nor root. The reports are the derivation's, for a build without the objects,
// never a probe the derivation could not produce.
func TestRunIsRefusedInDoctorsWords(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel, so Select cannot construct tier 1 here: %v", err)
	}
	auto := &agent.RuleTable{Tier: backend.TierBPFLSM, ContractPath: "/p/agent.yaml", Contract: &agent.Contract{Name: "a"}}
	cases := []struct {
		name  string
		root  bool
		named []string
	}{
		{"root, a build without the objects", true, []string{"build: tier cgroup is not built into this binary"}},
		{"an ordinary user, a build without the objects", false,
			[]string{"root: tier cgroup needs", "build: tier cgroup is not built into this binary"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := state(func(st *probeState) {
				st.root = tc.root
				st.built = builtExcept(backend.TierCgroup, backend.TierBPFLSM)
			}).report(nil, "")
			if rep.Tier != backend.TierLandlock || rep.Tiers[backend.TierCgroup] {
				t.Fatalf("the derivation reports %s with tiers %v, want landlock alone", rep.Tier, rep.Tiers)
			}

			b, ds := rep.Select(nil, auto, backend.TierCgroup)
			if b != nil {
				t.Fatalf("--tier cgroup selected %s on a machine doctor withholds it from", b.Tier())
			}
			var text strings.Builder
			for _, d := range ds {
				text.WriteString(d.String() + "\n")
			}
			out := text.String()
			if !strings.Contains(out, "tier cgroup pinned but not available [tier-unavailable]") {
				t.Errorf("refusal does not name tier cgroup:\n%s", out)
			}
			if strings.Contains(out, "no enforcement tier") {
				t.Errorf("refusal says no tier is available on a machine doctor gives landlock:\n%s", out)
			}
			for _, want := range append(tc.named, "missing for cgroup: "+strings.Join(rep.Missing[backend.TierCgroup], "; "),
				"fix: use a tego built with the BPF objects") {
				if !strings.Contains(out, want) {
					t.Errorf("refusal lacks %q:\n%s", want, out)
				}
			}

			// The same report, asked for an auto contract, gives the tier doctor reports.
			if b, ds := rep.Select(nil, auto, ""); b == nil || b.Tier() != rep.Tier {
				t.Errorf("auto selected %v, doctor reports %s: %v", b, rep.Tier, ds)
			}
		})
	}
}

// TestWhyNotIsDoctorsLineForEveryTier: a run can ask for any tier by name, not only the next one up, so
// WhyNot answers for each missing tier with that tier's own fix line — tier bpflsm, which no build of this
// version carries, with no fix line at all — and says nothing about a tier the machine offers.
func TestWhyNotIsDoctorsLineForEveryTier(t *testing.T) {
	rep := state(func(st *probeState) {
		st.root = false
		st.built = builtExcept(backend.TierBPFLSM)
	}).report(nil, "")
	if got := rep.WhyNot(backend.TierLandlock); got != "" {
		t.Errorf("WhyNot(landlock) = %q on a machine that offers it", got)
	}
	cg := rep.WhyNot(backend.TierCgroup)
	if !strings.HasPrefix(cg, "missing for cgroup: root: ") || !strings.HasSuffix(cg, "; fix: "+rep.Fix) {
		t.Errorf("WhyNot(cgroup) = %q, want doctor's missing line and its fix line %q", cg, rep.Fix)
	}
	lsm := rep.WhyNot(backend.TierBPFLSM)
	if !strings.HasPrefix(lsm, "missing for bpflsm: root: ") || strings.Contains(lsm, "fix:") ||
		!strings.Contains(lsm, "build: tier bpflsm is not built into this binary") {
		t.Errorf("WhyNot(bpflsm) = %q, want its missing line and no fix line", lsm)
	}
}

// A list no mechanism could read is unknown, not empty: a bare lsm=bpf would switch off every other LSM,
// Landlock included, so neither the fix nor the missing line may build it.
func TestUnreadLSMListNeverGetsABareGRUBFix(t *testing.T) {
	st := state(func(st *probeState) { st.lsm = LSMState{Source: LSMSourceNone} })
	if fix := st.fixFor(backend.TierBPFLSM); strings.Contains(fix, "lsm=bpf") || !strings.Contains(fix, "securityfs") {
		t.Errorf("fix for an unread LSM list = %q", fix)
	}
	for _, line := range st.missingFor(backend.TierBPFLSM) {
		if strings.Contains(line, "not in the active LSM list") {
			t.Errorf("an unread list is said to lack bpf: %q", line)
		}
	}
}
