// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestYamaConsequence is the whole rule of the ptrace_scope check, scope by scope. The supervisor's
// process_vm_readv(2) and pidfd_getfd(2) are both PTRACE_MODE_ATTACH_REALCREDS operations, and Yama
// gates exactly that mode: scope 1 exempts a descendant (the agent is the supervisor's own child),
// scope 2 admits only CAP_SYS_PTRACE, scope 3 admits nobody at all (ptrace(2),
// /proc/sys/kernel/yama/ptrace_scope; security/yama/yama_lsm.c yama_ptrace_access_check, where only
// YAMA_SCOPE_RELATIONAL carries task_is_descendant()).
func TestYamaConsequence(t *testing.T) {
	cases := []struct {
		name       string
		scope      int
		capPtrace  bool
		wantBlock  bool
		wantDetail string
	}{
		{"classic", yamaClassic, false, false, "unrestricted"},
		{"relational is the descendant case the supervisor is", yamaRelational, false, false, "parent"},
		{"relational, capability irrelevant", yamaRelational, true, false, "parent"},
		{"admin-only without the capability blocks", yamaAdminOnly, false, true, "ptrace_scope=2"},
		{"admin-only with CAP_SYS_PTRACE passes but warns", yamaAdminOnly, true, false, "unprivileged tego run"},
		{"no-attach blocks even with CAP_SYS_PTRACE", yamaNoAttach, true, true, "ptrace_scope=3"},
		{"no-attach without it blocks too", yamaNoAttach, false, true, "ptrace_scope=3"},
		{"an unknown scope is treated as restricting", yamaNoAttach + 1, true, true, "does not know"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail, blocked, fix := yamaConsequence(tc.scope, tc.capPtrace)
			if (blocked != "") != tc.wantBlock {
				t.Fatalf("scope %d cap=%v: blocked=%q, want blocked=%v", tc.scope, tc.capPtrace, blocked, tc.wantBlock)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail %q does not mention %q", detail, tc.wantDetail)
			}
			if tc.wantBlock && fix == "" {
				t.Error("a blocking scope with no fix line")
			}
			if !tc.wantBlock && fix != "" {
				t.Errorf("a scope that is fine carries a fix: %q", fix)
			}
			if tc.wantBlock && !strings.Contains(blocked, "args-unreadable") &&
				!strings.Contains(blocked, "not known") {
				t.Errorf("blocked=%q names no consequence for the run", blocked)
			}
		})
	}
}

// TestProbePtraceReadsTheSysctl covers the file half: a value, a missing file (no Yama built in),
// and a file that holds something else. An unreadable sysctl blocks, because guessing wrong there
// means reporting a working sandbox for a run that will refuse every connect.
func TestProbePtraceReadsTheSysctl(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if st := probePtrace(write("one", "1\n")); st.Scope != yamaRelational || st.Blocked != "" {
		t.Errorf("scope 1: %+v", st)
	}
	if st := probePtrace(write("three", "3\n")); st.Scope != yamaNoAttach || st.Blocked == "" || st.Fix == "" {
		t.Errorf("scope 3: %+v", st)
	}
	// No Yama in the kernel is not a restriction: it is the same answer as scope 0.
	if st := probePtrace(filepath.Join(dir, "absent")); st.Scope != yamaAbsent || st.Blocked != "" {
		t.Errorf("absent sysctl: %+v", st)
	}
	if st := probePtrace(write("junk", "sometimes\n")); st.Blocked == "" || st.Fix == "" {
		t.Errorf("unparsable sysctl must fail closed: %+v", st)
	}
}

// TestPtraceBlockedStopsEveryEnforcementTier is why the probe exists. Under ptrace_scope >= 2 the
// launcher's pidfd_getfd of the child's seccomp listener returns EPERM (pidfd_getfd(2): "EPERM: the
// calling process did not have PTRACE_MODE_ATTACH_REALCREDS permissions") and the run aborts, so a
// doctor that still reported tier landlock would be promising a sandbox no run can get. Tier 2
// installs the same filter and inherits the same supervisor, and tier 3 is tier 2 plus BPF LSM, so
// all three have to go.
func TestPtraceBlockedStopsEveryEnforcementTier(t *testing.T) {
	blocked := PtraceState{Scope: yamaAdminOnly, Blocked: "yama: ptrace_scope=2 admits only CAP_SYS_PTRACE"}
	st := probeState{
		byID:        map[CheckID]Result{CheckLandlock: {ID: CheckLandlock, OK: true}},
		landlockABI: 6,
		root:        true,
		ptrace:      blocked,
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		reasons := strings.Join(st.missingFor(tier), "; ")
		if !strings.Contains(reasons, "ptrace_scope=2") {
			t.Errorf("missingFor(%s) = %q, does not name the Yama scope", tier, reasons)
		}
	}
	if p := st.probe(); p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
		t.Errorf("a machine whose supervisor cannot read the agent still offers %+v", p)
	}
	// Tier 3 reaches the reason through its own tier-2 call; it must not therefore print it twice.
	if n := strings.Count(strings.Join(st.missingFor(backend.TierBPFLSM), "; "), "ptrace_scope=2"); n != 1 {
		t.Errorf("tier 3 names the Yama scope %d times, want once", n)
	}

	// The same machine with Yama at its distribution default keeps every tier it had.
	st.ptrace = PtraceState{Scope: yamaRelational}
	if reasons := st.missingFor(backend.TierLandlock); len(reasons) != 0 {
		t.Errorf("scope 1 blocks tier landlock: %q", reasons)
	}
}

// TestFixNamesTheYamaSysctlWhenItIsTheOnlyThingWrong is the other half of the report R27 asks for.
// missingFor now says a blocking ptrace_scope stands in the way of every tier, but `fix:` is the
// single line R27 requires alongside it — "one fix: <command> line" — and it is what `--json`
// consumers read out of Report.Fix. On a machine where every other probe passes, the Landlock branch
// of fix() answers for D4 alone, so the whole report came out with three "missing for" lines naming
// Yama and no action to take; the sysctl setting is the action.
func TestFixNamesTheYamaSysctlWhenItIsTheOnlyThingWrong(t *testing.T) {
	detail, blocked, remedy := yamaConsequence(yamaAdminOnly, false)
	st := state(func(st *probeState) {
		st.ptrace = PtraceState{Scope: yamaAdminOnly, Detail: detail, Blocked: blocked, Fix: remedy}
	})
	// The precondition: Yama alone, every other probe green, so no tier at all is reachable.
	if p := st.probe(); p[backend.TierLandlock] || p[backend.TierCgroup] || p[backend.TierBPFLSM] {
		t.Fatalf("this case is meant to have Yama as the only blocker, got %+v", p)
	}
	got := st.fix("")
	if got == "" {
		t.Fatal("no tier is reachable and doctor offers no fix line at all")
	}
	if !strings.Contains(got, "kernel.yama.ptrace_scope") {
		t.Errorf("fix = %q, want the sysctl that unblocks every tier", got)
	}
	// Every tier above it reports the same blocker, so the same action answers each of them.
	for _, reached := range []backend.Tier{"", backend.TierLandlock, backend.TierCgroup} {
		if f := st.fix(reached); !strings.Contains(f, "kernel.yama.ptrace_scope") {
			t.Errorf("fix(%q) = %q, want the Yama sysctl", reached, f)
		}
	}
	// And it never displaces the answers it sits in front of: with Yama at the distribution default
	// the fix line is whatever the failing probe said, exactly as before.
	st.ptrace = PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	fail(&st, CheckBTF, "ENOENT", "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y")
	if f := st.fix(backend.TierLandlock); !strings.Contains(f, "CONFIG_DEBUG_INFO_BTF=y") {
		t.Errorf("fix = %q, want D2's own answer when Yama is not the problem", f)
	}
}

// TestFixNamesEveryTierOneBlockerOnOneLine: doctor's tier-1 derivation (missingFor(TierLandlock))
// lists Yama and the round trip (D5), the kernel floor (D1), cgroup delegation (D3) and Landlock (D4),
// and the fix line is "the one line that makes the next tier up available" (R27); this test takes the
// D5 and D4 pair. When fix() answered with Yama's remedy
// alone, a machine at ptrace_scope=3 whose Landlock is not in lsm= was told to reboot with the Yama
// setting, and only on the next doctor run learned that the lsm= line needed a reboot as well. Both
// remedies belong on the line. (D1 and D3 are tier-1 blockers too, and TestTierOneNeedsD1D3D4D5 puts
// their remedies on the same line.)
//
// Joining them has a cost of its own, which the scope-2 row pins: the line asks for a reboot, so the
// Yama remedy in front of it has to survive one. At scope 2 it used to be `sysctl -w
// kernel.yama.ptrace_scope=1`, a /proc/sys write the lsm= reboot then undid, and the next doctor run
// reported Yama again — the very round trip joining the remedies was meant to save.
func TestFixNamesEveryTierOneBlockerOnOneLine(t *testing.T) {
	lsmFix := "add landlock to the kernel's lsm= line (or CONFIG_LSM) and reboot"
	cases := []struct {
		name  string
		scope int
		// yama is what names Yama's remedy on the line; it has to be one a reboot keeps.
		yama string
	}{
		{"ptrace_scope=3, a boot setting beside a boot setting", yamaNoAttach, "boot with kernel.yama.ptrace_scope=1"},
		{"ptrace_scope=2, a sysctl beside a reboot", yamaAdminOnly, "kernel.yama.ptrace_scope=1 in /etc/sysctl.d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail, blocked, remedy := yamaConsequence(tc.scope, false)
			st := state(func(st *probeState) {
				st.root = false
				st.ptrace = PtraceState{Scope: tc.scope, Detail: detail, Blocked: blocked, Fix: remedy}
				st.landlockABI = 0
				fail(st, CheckLandlock, "landlock_create_ruleset: operation not supported", lsmFix)
			})
			got := st.fix("")
			if !strings.Contains(got, tc.yama) {
				t.Errorf("fix = %q, want Yama's remedy %q", got, tc.yama)
			}
			if !strings.Contains(got, "lsm= line") {
				t.Errorf("fix = %q, want D4's lsm= change on the same line", got)
			}
			if strings.Contains(got, "\n") {
				t.Errorf("fix = %q spans lines; R27 asks for one", got)
			}
			// Yama first: it blocks every tier, so it leads whatever else tier 1 needs.
			if strings.Index(got, "ptrace_scope") > strings.Index(got, "lsm=") {
				t.Errorf("fix = %q, want Yama's remedy before D4's", got)
			}
			// A /proc/sys write taken before the reboot this line asks for is gone after it.
			if strings.Contains(got, "sysctl -w") {
				t.Errorf("fix = %q asks for a sysctl -w that the lsm= reboot on the same line undoes", got)
			}
		})
	}
}

// TestEveryYamaRemedySurvivesTheRebootBesideIt: R27's fix line joins Yama's remedy with D4's lsm=
// reboot, so every remedy Yama can put there has to be one the reboot keeps — not only scope 2's and
// scope 3's, which TestFixNamesEveryTierOneBlockerOnOneLine pins. The unreadable sysctl used to answer
// "set it to 1 and re-run" (a /proc/sys write) and an out-of-range value "set
// kernel.yama.ptrace_scope=1"; both are undone by the reboot the same line asks for.
func TestEveryYamaRemedySurvivesTheRebootBesideIt(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("sometimes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outOfRange := yamaNoAttach + 1
	detail, blocked, remedy := yamaConsequence(outOfRange, false)
	for name, pt := range map[string]PtraceState{
		// A directory reads as EISDIR: the sysctl is there and cannot be read, as under an LSM or a
		// masked /proc/sys.
		"unreadable":   probePtrace(dir),
		"unparsable":   probePtrace(junk),
		"out of range": {Scope: outOfRange, Detail: detail, Blocked: blocked, Fix: remedy},
	} {
		t.Run(name, func(t *testing.T) {
			if pt.Blocked == "" || pt.Fix == "" {
				t.Fatalf("this case must block with a remedy: %+v", pt)
			}
			if !strings.Contains(pt.Fix, "/etc/sysctl.d") || !strings.Contains(pt.Fix, "sysctl --system") {
				t.Errorf("remedy %q is not the persistent setting", pt.Fix)
			}
			if name != "out of range" && !strings.Contains(pt.Fix, "boot with kernel.yama.ptrace_scope=1") {
				t.Errorf("remedy %q does not cover a sysctl that turns out to hold 3", pt.Fix)
			}
			st := state(func(st *probeState) {
				st.root = false
				st.ptrace = pt
				st.landlockABI = 0
				fail(st, CheckLandlock, "landlock_create_ruleset: operation not supported",
					"add landlock to the kernel's lsm= line (or CONFIG_LSM) and reboot")
			})
			got := st.fix("")
			if !strings.Contains(got, pt.Fix) || !strings.Contains(got, "lsm= line") {
				t.Errorf("fix = %q, want Yama's remedy and D4's reboot on one line", got)
			}
			if strings.Contains(got, "sysctl -w") || strings.Contains(got, "set it to 1 and re-run") {
				t.Errorf("fix = %q carries a runtime write the reboot beside it undoes", got)
			}
		})
	}
}
