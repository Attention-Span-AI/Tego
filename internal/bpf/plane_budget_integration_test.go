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

// planeBlockWalkBudget is what a plane program may spend on top for its second walk, the live blocks' (ADR 0124,
// amendment 2026-11-21: tego_block_decide, form d too, a global function verified once per program, which walks to
// the namespace root). Measured on one test binary at 858f6def7, the largest walking program went from 13,804 to 16,864
// on 6.17 (rd path_mknod) and from 19,834 to 24,167 on Fedora's 7.0.14 (rd path_rename), a walk of about 3,100 and
// 4,400; 5.14 (RHEL 9.8) and 6.12 (Debian 13) verified the same objects (6392c64b3) in at most 19,171. It is not
// added to a charged family's figure (planeCharges): on Linux 6.19.4 to 6.19.y, which charges bpf_loop callbacks as
// loops without 7.0's offset, the block walk was measured at about 36,500 (rd) and 30,700 (pr) on Fedora's 6.19.10
// (2026-11-24), not this allowance, so that family's budget is its measured count plus a headroom rule instead.
// A loop-form walk still costs more than this allowance alone on every measured kernel (T0's a-rd 35,855 on 5.14 the
// least of them).
const planeBlockWalkBudget = 8000

// planeListenVerifiedBudget is socket_listen's own budget. That hook walks no path, so form d's figures say
// nothing about it: its body is decide_listen.h's bound-address and autobind checks, which the verifier walked
// 16,945 to 18,295 times on 6.17 and 43,850 to 44,096 times on 7.0 (GitHub's runners, 7.0.0-1017-azure),
// the program unchanged. A loop form would still show as a jump far past this; the kernel's own
// limit is a million. Linux 6.19.4 did not move it (16,768 on 6.19.3 and on 6.19.4 to 6.19.14), so it does not scale.
const planeListenVerifiedBudget = 64000

// planeMeasuredHeadroomPercent is the headroom a charged family's budget leaves over the count measured there: the
// largest plane program's verified instructions, plus this many percent, rounded up. Verifier counts of one object on
// one kernel build do not vary, so this is room for the same family's other releases, not for noise, and a program
// that grows by more than this (an added walk, a body that leaves form d) fails with its counts logged. It cannot be
// much larger on 6.19.4 to 6.19.y: form b's bare walk costs 67,514 there, 13.7 % over the pr program as measured, and
// the pr budget has to stay under it (the test below holds that). The kernels that need no scale keep 20,000 plus
// planeBlockWalkBudget, 16 % over the largest there (24,167 on 7.0.14, 28,000).
const planeMeasuredHeadroomPercent = 10

// planeCharge is a kernel family whose verifier charges the plane's unchanged object so much more per reader that
// planeVerifiedBudget plus planeBlockWalkBudget cannot hold it, with the largest plane program's verified count there
// per reader, the same bytes loaded by the same test binary, block walk included.
type planeCharge struct {
	family     string
	matches    func(major, minor, patch int) bool
	measuredOn string
	measured   map[Object]uint32
	// before is the same programs' largest count before the live blocks' walk (ADR 0024's 2026-11-10 amendment),
	// and baseline that count on the last kernel before the family (6.19.3): what the family's charge was, kept for
	// the log line and the table below.
	before   map[Object]uint32
	baseline map[Object]uint32
}

// planeCharges lists the kernel families whose verifier counts the plane's bytes differently enough to break
// planeVerifiedBudget plus planeBlockWalkBudget, with the counts that set each one's budget.
//
// Linux 6.19.4 to 6.19.y. Mainline 6.19.3 verifies the plane's largest programs in 14,562 (rd) and 11,582 (pr), and
// 6.19.4 in 63,939 and 28,681, measured again on 6.19.10, 6.19.14 and Fedora 44's 6.19.10-300.fc44
// (guests). 6.19.4 took the stable backport de2f14d97bda of f597664454bd ("bpf: bpf_scc_visit instance and
// backedges accumulation for bpf_loop()"), the one bpf_loop-specific verifier change between them, after which every
// bpf_loop callback is verified as a loop: T0's spike moved in its bpf_loop forms only (d-rd 1,032 to 3,789) and
// not in its plain-loop forms (a-rd 248,374 on both). 7.0 carries f597664454bd too and verifies the plane in at most
// 24,167 (Fedora's 7.0.14), so it is not in the family.
//
// With the live blocks' walk (ADR 0124's amendment, 6392c64b3) Fedora's 6.19.10-300.fc44 verified the largest rd
// program (fmod_ret path_rename; lsm path_rename 100,292) in 100,417 and the largest pr program in 59,387 (2026-11-24,
// row 6 of that run): the walk costs about 36,500 and 30,700 there, because its bpf_loop callback is verified as a loop.
// The budget is those counts plus planeMeasuredHeadroomPercent, 110,459 (rd) and 65,326 (pr). T0's plain-loop walks alone still cost more than them
// (a-rd 248,374, b-rd 289,281, b-pr 67,514), so a walk that leaves form d for those forms still fails. Form a-pr
// (16,338 there) is cheaper than the plane's larger pr programs on this family, so no budget there can tell it from
// form d; it fails on the other kernels, as before. Mainline 6.19.4 and 6.19.14 were measured before the block walk
// only; they take this family's figures until a guest measures them with it (the 6.19.y counts of one object have not
// differed between the releases measured).
//
// A family is a release range because the change came by stable backport, which no BTF type or kfunc marks. A
// distribution kernel outside it that took the same backport without 7.0's offset fails this budget with its
// counts in the log, which is the sign to measure it and add its family here; it does not pass silently.
var planeCharges = []planeCharge{{
	family:     "Linux 6.19.4 to 6.19.y (f597664454bd backported, de2f14d97bda)",
	matches:    func(major, minor, patch int) bool { return major == 6 && minor == 19 && patch >= 4 },
	measuredOn: "6.19.10-300.fc44.x86_64",
	measured:   map[Object]uint32{ObjectPlaneRdonly: 100417, ObjectPlaneProbe: 59387},
	before:     map[Object]uint32{ObjectPlaneRdonly: 63939, ObjectPlaneProbe: 28681},
	baseline:   map[Object]uint32{ObjectPlaneRdonly: 14562, ObjectPlaneProbe: 11582},
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
// program) on a kernel of release: planeVerifiedBudget plus planeBlockWalkBudget, or where release is in a charged
// family the count measured there plus planeMeasuredHeadroomPercent, rounded up; socket_listen's own budget everywhere.
func planeBudgetFor(hook string, o Object, release string) uint32 {
	if hook == "socket_listen" {
		return planeListenVerifiedBudget
	}
	c := planeChargeFor(release)
	if c == nil || c.measured[o] == 0 {
		return planeVerifiedBudget + planeBlockWalkBudget
	}
	return uint32((uint64(c.measured[o])*(100+planeMeasuredHeadroomPercent) + 99) / 100)
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
			t.Logf("%s on %s (%s): the verifier charges the plane's largest program %d with the block walk (measured on "+
				"%s; %d before it, where 6.19.3 charges %d), so a plane program's budget is %d, %d %% over", o, release,
				c.family, c.measured[o], c.measuredOn, c.before[o], c.baseline[o], planeBudgetFor("", o, release),
				planeMeasuredHeadroomPercent)
		} else {
			t.Logf("%s on %s: a plane program's budget is %d", o, release, planeBudgetFor("", o, release))
		}
	}
	return b
}

// TestPlaneBudgetFollowsTheKernelsChargeForTheSameBytes holds the plane's verified-instruction budget per kernel
// family to the counts the guests measured (one test binary, the same object bytes on
// every kernel). It needs no root: it runs wherever the integration and tegobpf tags build.
func TestPlaneBudgetFollowsTheKernelsChargeForTheSameBytes(t *testing.T) {
	for _, c := range []struct {
		release     string
		hook        string
		o           Object
		want        uint32
		mustHoldMax uint32 // the largest plane program that kernel verified, which the budget must admit
	}{
		// Kernels that charge the plane what the budget was set against: 20,000 and the block walk's 8,000. The
		// counts are the largest walking program measured with the block walk (5.14, 6.12, 6.17, 7.0.14) or, where
		// no guest ran it, before it.
		{"5.14.0-687.53.1.el9_8.x86_64", "path_mknod", ObjectPlaneProbe, 28000, 13959},
		{"5.14.0-687.53.1.el9_8.x86_64", "path_mknod", ObjectPlaneRdonly, 28000, 19171},
		{"5.14.0-687.61.1.el9_8.x86_64", "path_mknod", ObjectPlaneRdonly, 28000, 19171},
		{"6.12.107+deb13-amd64", "path_mknod", ObjectPlaneProbe, 28000, 13959},
		{"6.12.107+deb13-amd64", "path_mknod", ObjectPlaneRdonly, 28000, 19171},
		{"6.12.115+deb13.1-cloud-amd64", "path_mknod", ObjectPlaneRdonly, 28000, 19171},
		{"6.17.0-41-generic", "path_mknod", ObjectPlaneRdonly, 28000, 16864},
		{"6.18.0-061800-generic", "path_mknod", ObjectPlaneRdonly, 28000, 14562},
		{"6.19.0-061900-generic", "path_mknod", ObjectPlaneRdonly, 28000, 14562},
		{"6.19.3-061903-generic", "path_mknod", ObjectPlaneRdonly, 28000, 14562},
		{"6.19.3-061903-generic", "path_mknod", ObjectPlaneProbe, 28000, 11582},
		{"7.0.14-201.fc44.x86_64", "path_rename", ObjectPlaneRdonly, 28000, 24167},
		{"7.0.14-201.fc44.x86_64", "path_rename", ObjectPlaneProbe, 28000, 19098},
		{"7.2.9-300.fc45.x86_64", "path_mknod", ObjectPlaneRdonly, 28000, 18137},
		// Linux 6.19.4 and later 6.19.y: the same bytes cost 63,939 / 14,562 (rd) and 28,681 / 11,582 (pr) of
		// 6.19.3's before the block walk, and with it, on Fedora's 6.19.10 (2026-11-24), 100,417 (rd) and
		// 59,387 (pr); the budget is the measured count plus 10 %. Mainline 6.19.4 was measured before the block
		// walk only (63,939 and 28,681 are what its row must hold at the least).
		{"6.19.4-061904-generic", "path_mknod", ObjectPlaneRdonly, 110459, 63939},
		{"6.19.4-061904-generic", "path_mknod", ObjectPlaneProbe, 65326, 28681},
		{"6.19.10-300.fc44.x86_64", "file_open", ObjectPlaneRdonly, 110459, 100417},
		{"6.19.10-300.fc44.x86_64", "path_rename", ObjectPlaneRdonly, 110459, 100417},
		{"6.19.10-300.fc44.x86_64", "", ObjectPlaneProbe, 65326, 59387},
		{"6.19.14-300.fc44.x86_64", "path_rename", ObjectPlaneProbe, 65326, 28681},
		// socket_listen walks no path and has its own budget, which 6.19.4 did not move (16,768 on both).
		{"6.19.10-300.fc44.x86_64", "socket_listen", ObjectPlaneRdonly, planeListenVerifiedBudget, 16768},
		{"7.0.14-201.fc44.x86_64", "socket_listen", ObjectPlaneProbe, planeListenVerifiedBudget, 43978},
		// A release this test cannot read is held to the unscaled budget.
		{"", "file_open", ObjectPlaneRdonly, 28000, 0},
		{"6.19", "file_open", ObjectPlaneRdonly, 28000, 0},
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
	// loop costs, alone, a-rd 248,374, b-rd 289,281 and b-pr 67,514 (unchanged from 6.19.3), over the budgets.
	if b := planeBudgetFor("file_open", ObjectPlaneRdonly, "6.19.10-300.fc44.x86_64"); b >= 248374 {
		t.Errorf("the 6.19.4+ rd budget %d admits form a's bare walk (248,374)", b)
	}
	if b := planeBudgetFor("file_open", ObjectPlaneProbe, "6.19.10-300.fc44.x86_64"); b >= 67514 {
		t.Errorf("the 6.19.4+ pr budget %d admits form b's bare walk (67,514)", b)
	}
	// A real regression still fails there: a program that costs 11 % more than the measured largest one is over its
	// budget on both readers, and the 2026-11-24 measurement (100,417 and 59,387) is inside it.
	for o, measured := range map[Object]uint32{ObjectPlaneRdonly: 100417, ObjectPlaneProbe: 59387} {
		b := planeBudgetFor("file_open", o, "6.19.10-300.fc44.x86_64")
		if measured > b {
			t.Errorf("%s: the measured %d is over its budget %d", o, measured, b)
		}
		if grown := measured + measured/100*(planeMeasuredHeadroomPercent+1); grown <= b {
			t.Errorf("%s: a program grown 11 %% to %d is inside the budget %d", o, grown, b)
		}
	}
	// Elsewhere, the cheapest loop-form walk T0 measured alone (a-rd, 35,855 on 5.14) still costs more than the budget.
	if b := planeBudgetFor("file_open", ObjectPlaneRdonly, "5.14.0-687.61.1.el9_8.x86_64"); b >= 35855 {
		t.Errorf("the 5.14 rd budget %d admits form a's bare walk there (35,855)", b)
	}
	// Every kernel that needs no scale keeps its headroom over the largest program measured there (24,167 on 7.0.14).
	if b := planeBudgetFor("path_rename", ObjectPlaneRdonly, "7.0.14-201.fc44.x86_64"); b < 24167+24167/10 {
		t.Errorf("the 7.0 rd budget %d leaves under 10 %% over the 24,167 measured", b)
	}
}
