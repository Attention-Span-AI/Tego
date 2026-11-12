// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// planeVerifiedBudget is the most instructions the verifier may walk for one plane program. ADR 0024's T0 note
// measured the walk's form d at 391-896 per program on 5.14, 6.1 and 6.17, rename's two calls included, against
// 16k-573k for the loop forms it rejected; a body that pushes a program past this has left form d. It holds on every
// kernel that charges the plane what 5.14 to 6.19.3 and 7.0 do; planeBudgetFor scales it on the one family that
// charges the same bytes more.
const planeVerifiedBudget = 20000

// planeListenVerifiedBudget is socket_listen's own budget. That hook walks no path, so form d's figures say
// nothing about it: its body is decide_listen.h's bound-address and autobind checks, which the verifier walked
// 16,945 to 18,295 times on 6.17 and 43,850 to 44,096 times on 7.0 (GitHub's runners, 7.0.0-1017-azure,
// 2026-11-02), the program unchanged. A loop form would still show as a jump far past this; the kernel's own
// limit is a million. Linux 6.19.4 did not move it (16,768 on 6.19.3 and on 6.19.4 to 6.19.14), so it does not scale.
const planeListenVerifiedBudget = 64000

// planeCharge is how much more one kernel family's verifier charges the plane's unchanged object, per reader: the
// largest plane program's count there over its count on the last kernel before the family, the same bytes loaded by
// the same test binary in both.
type planeCharge struct {
	family   string
	matches  func(major, minor, patch int) bool
	there    map[Object]uint32
	baseline map[Object]uint32
}

// planeCharges lists the kernel families whose verifier counts the plane's bytes differently enough to break
// planeVerifiedBudget, with the counts that set each one's scale.
//
// Linux 6.19.4 to 6.19.y. Mainline 6.19.3 verifies the plane's largest programs in 14,562 (rd) and 11,582 (pr), and
// 6.19.4 in 63,939 and 28,681, measured again on 6.19.10, 6.19.14 and Fedora 44's 6.19.10-300.fc44 (guests,
// 2026-11-10). 6.19.4 took the stable backport de2f14d97bda of f597664454bd ("bpf: bpf_scc_visit instance and
// backedges accumulation for bpf_loop()"), the one bpf_loop-specific verifier change between them, after which every
// bpf_loop callback is verified as a loop: T0's spike moved in its bpf_loop forms only (d-rd 1,032 to 3,789) and
// not in its plain-loop forms (a-rd 248,374 on both). 7.0 carries f597664454bd too and verifies the plane in at most
// 19,834 (Fedora's 7.0.14), so it is not in the family. The scale keeps the budget's headroom over the plane as
// 6.19.3 has it, and T0's plain-loop walks alone still cost more than the scaled budgets on 6.19.4 (a-rd 248,374,
// b-rd 289,281, b-pr 67,514), so a walk that leaves form d for those forms still fails. Form a-pr (16,338 there) is
// cheaper than the plane's larger pr programs on this family, so no budget there can tell it from form d; it fails
// on the other kernels, as before.
//
// A family is a release range because the change came by stable backport, which no BTF type or kfunc marks. A
// distribution kernel outside it that took the same backport without 7.0's offset fails this budget with its
// counts in the log, which is the sign to measure it and add its family here; it does not pass silently.
var planeCharges = []planeCharge{{
	family:   "Linux 6.19.4 to 6.19.y (f597664454bd backported, de2f14d97bda)",
	matches:  func(major, minor, patch int) bool { return major == 6 && minor == 19 && patch >= 4 },
	there:    map[Object]uint32{ObjectPlaneRdonly: 63939, ObjectPlaneProbe: 28681},
	baseline: map[Object]uint32{ObjectPlaneRdonly: 14562, ObjectPlaneProbe: 11582},
}}

// planeRelease parses a kernel release such as 6.19.10-300.fc44.x86_64 into its version, ok false when it has not
// three numbers.
func planeRelease(release string) (major, minor, patch int, ok bool) {
	head, _, _ := strings.Cut(release, "-")
	f := strings.SplitN(head, ".", 3)
	if len(f) != 3 {
		return 0, 0, 0, false
	}
	var n [3]int
	for i, s := range f {
		end := 0
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}
		v, err := strconv.Atoi(s[:end])
		if err != nil {
			return 0, 0, 0, false
		}
		n[i] = v
	}
	return n[0], n[1], n[2], true
}

// planeChargeFor is the family release belongs to, nil for none.
func planeChargeFor(release string) *planeCharge {
	major, minor, patch, ok := planeRelease(release)
	if !ok {
		return nil
	}
	for i := range planeCharges {
		if planeCharges[i].matches(major, minor, patch) {
			return &planeCharges[i]
		}
	}
	return nil
}

// planeBudgetFor is the verified-instruction budget of o's plane program serving hook ("" for the exec-pin
// program) on a kernel of release: planeVerifiedBudget, scaled up by the family's charge where release is in one,
// rounded up; socket_listen's own budget everywhere.
func planeBudgetFor(hook string, o Object, release string) uint32 {
	if hook == "socket_listen" {
		return planeListenVerifiedBudget
	}
	c := planeChargeFor(release)
	if c == nil || c.baseline[o] == 0 || c.there[o] <= c.baseline[o] {
		return planeVerifiedBudget
	}
	return uint32((uint64(planeVerifiedBudget)*uint64(c.there[o]) + uint64(c.baseline[o]) - 1) / uint64(c.baseline[o]))
}

// planeBudgetLogged is the set of builds whose budget this test binary has logged.
var planeBudgetLogged sync.Map

// planeBudget is planeBudgetFor on the running kernel. The first call for each build logs the budget and, where
// the kernel is in a family, why.
func planeBudget(t *testing.T, o Object, hook string) uint32 {
	t.Helper()
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	release := unix.ByteSliceToString(uts.Release[:])
	b := planeBudgetFor(hook, o, release)
	if _, seen := planeBudgetLogged.LoadOrStore(o, true); !seen {
		if c := planeChargeFor(release); c != nil {
			t.Logf("%s on %s (%s): the verifier charges the plane's largest program %d where 6.19.3 charges %d, so a "+
				"plane program's budget is %d", o, release, c.family, c.there[o], c.baseline[o], planeBudgetFor("", o, release))
		} else {
			t.Logf("%s on %s: a plane program's budget is %d", o, release, planeBudgetFor("", o, release))
		}
	}
	return b
}

// TestPlaneBudgetFollowsTheKernelsChargeForTheSameBytes holds the plane's verified-instruction budget per kernel
// family to the counts the guests measured (2026-11-10; one test binary, the same object bytes on
// every kernel). It needs no root: it runs wherever the integration and tegobpf tags build.
func TestPlaneBudgetFollowsTheKernelsChargeForTheSameBytes(t *testing.T) {
	for _, c := range []struct {
		release     string
		hook        string
		o           Object
		want        uint32
		mustHoldMax uint32 // the largest plane program that kernel verified, which the budget must admit
	}{
		// Kernels that charge the plane what the budget was set against: 20,000, unchanged.
		{"5.14.0-687.61.1.el9_8.x86_64", "path_mknod", ObjectPlaneRdonly, 20000, 13819},
		{"6.12.115+deb13.1-cloud-amd64", "path_mknod", ObjectPlaneRdonly, 20000, 13819},
		{"6.17.0-061700-generic", "path_mknod", ObjectPlaneRdonly, 20000, 13804},
		{"6.18.0-061800-generic", "path_mknod", ObjectPlaneRdonly, 20000, 14562},
		{"6.19.0-061900-generic", "path_mknod", ObjectPlaneRdonly, 20000, 14562},
		{"6.19.3-061903-generic", "path_mknod", ObjectPlaneRdonly, 20000, 14562},
		{"6.19.3-061903-generic", "path_mknod", ObjectPlaneProbe, 20000, 11582},
		{"7.0.14-201.fc44.x86_64", "path_mknod", ObjectPlaneRdonly, 20000, 19834},
		{"7.2.9-300.fc45.x86_64", "path_mknod", ObjectPlaneRdonly, 20000, 18137},
		// Linux 6.19.4 and later 6.19.y: the same bytes cost 63,939 / 14,562 (rd) and 28,681 / 11,582 (pr) of 6.19.3's.
		{"6.19.4-061904-generic", "path_mknod", ObjectPlaneRdonly, 87817, 63939},
		{"6.19.4-061904-generic", "path_mknod", ObjectPlaneProbe, 49527, 28681},
		{"6.19.10-300.fc44.x86_64", "file_open", ObjectPlaneRdonly, 87817, 63939},
		{"6.19.10-300.fc44.x86_64", "", ObjectPlaneProbe, 49527, 28681},
		// socket_listen walks no path and has its own budget, which 6.19.4 did not move (16,768 on both).
		{"6.19.10-300.fc44.x86_64", "socket_listen", ObjectPlaneRdonly, planeListenVerifiedBudget, 16768},
		{"7.0.14-201.fc44.x86_64", "socket_listen", ObjectPlaneProbe, planeListenVerifiedBudget, 43978},
		// A release this test cannot read is held to the unscaled budget.
		{"", "file_open", ObjectPlaneRdonly, 20000, 0},
		{"6.19", "file_open", ObjectPlaneRdonly, 20000, 0},
	} {
		got := planeBudgetFor(c.hook, c.o, c.release)
		if got != c.want {
			t.Errorf("%s %s %q: budget %d, want %d", c.release, c.o, c.hook, got, c.want)
		}
		if got < c.mustHoldMax {
			t.Errorf("%s %s %q: budget %d is under the %d that kernel verified for the plane as it is", c.release, c.o,
				c.hook, got, c.mustHoldMax)
		}
	}
	// What the budget is for (form d, ADR 0024's T0 note): on 6.19.4 and later 6.19.y, T0's walk written as a plain
	// loop costs, alone, a-rd 248,374, b-rd 289,281 and b-pr 67,514 (unchanged from 6.19.3), over the scaled budgets.
	if b := planeBudgetFor("file_open", ObjectPlaneRdonly, "6.19.10-300.fc44.x86_64"); b >= 248374 {
		t.Errorf("the 6.19.4+ rd budget %d admits form a's bare walk (248,374)", b)
	}
	if b := planeBudgetFor("file_open", ObjectPlaneProbe, "6.19.10-300.fc44.x86_64"); b >= 67514 {
		t.Errorf("the 6.19.4+ pr budget %d admits form b's bare walk (67,514)", b)
	}
}
