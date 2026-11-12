// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestKernelLineTakesLandlockRowsFromTheProbe: on AlmaLinux 9.8 (RHEL 9, a tested matrix row) D1 listed Landlock
// ABI 2 to 6 as missing from 5.14.0-687.61.1.el9_8 while D4, four lines later, found ABI 6 backported there
// (kit/acc2/alma/02-doctor.out). The Landlock rows now come from the probed ABI: a row is missing only when the
// kernel answers a lower ABI. ABI 7 is still listed there, and the floor clause names the upstream floor that
// CAPABILITIES' minimum-kernel row places RHEL 9's 5.14 below.
func TestKernelLineTakesLandlockRowsFromTheProbe(t *testing.T) {
	const release = "5.14.0-687.61.1.el9_8.x86_64"
	r, v := kernelResult(release, abiProbe(6))
	if !r.OK || r.Fix != "" || v != (Version{5, 14, 0}) {
		t.Fatalf("D1 on RHEL 9.8: %+v, %v", r, v)
	}
	for abi := 2; abi <= 6; abi++ {
		if row := landlockRow(t, abi); strings.Contains(r.Detail, row) {
			t.Errorf("D1 lists %s missing while the probe answered ABI 6: %s", row, r.Detail)
		}
	}
	for _, want := range []string{landlockRow(t, 7), "cgroup connect_unix (6.7.0,",
		"; below the upstream tested floor 6.1.0;"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("D1 on RHEL 9.8 lacks %q: %s", want, r.Detail)
		}
	}
	// The probe also counts the other way: a kernel whose release promises ABI 7 but that answers 6 lacks it.
	if r, _ := kernelResult("6.17.0-41-generic", abiProbe(6)); !strings.Contains(r.Detail, landlockRow(t, 7)) {
		t.Errorf("6.17 answering ABI 6 does not list ABI 7: %s", r.Detail)
	}
	if r, _ := kernelResult("6.17.0-41-generic", abiProbe(7)); strings.Contains(r.Detail, "without:") {
		t.Errorf("6.17 with ABI 7 lists a missing mechanism: %s", r.Detail)
	}
}

// TestKernelLineUnchangedWhereTheProbeAgreesWithTheRelease: Ubuntu 24.04's 6.8 answers ABI 4, which its release
// promises, so its line is the one docs/INSTALL.md and QUICKSTART.md print, byte for byte. A Landlock probe that
// gave no answer (an error other than ENOSYS or EOPNOTSUPP, such as a container filter's EPERM) leaves the
// release's rows as they were.
func TestKernelLineUnchangedWhereTheProbeAgreesWithTheRelease(t *testing.T) {
	const want = "6.8.0-147-generic (>= 5.14.0); without: Landlock ABI 5 (ioctl_dev) (6.10.0, device ioctls are not " +
		"restricted), Landlock ABI 6 (scopes) (6.12.0, abstract unix sockets and signals are not scoped), Landlock ABI 7 " +
		"(audit) (6.15.0, Landlock refusals are not in the audit log)"
	for _, p := range []kernelProbe{abiProbe(4), {asked: true}} {
		r, _ := kernelResult("6.8.0-147-generic", p)
		if !r.OK || r.Detail != want {
			t.Errorf("D1 on 6.8 with %+v:\n got %q\nwant %q", p, r.Detail, want)
		}
	}
	if r, _ := kernelResult("5.10.0", abiProbe(1)); r.OK || !strings.Contains(r.Fix, "boot a kernel >= 5.14.0") {
		t.Errorf("D1 below MinKernel: %+v", r)
	}
	if r, _ := kernelResult("x", abiProbe(6)); r.OK {
		t.Errorf("D1 on an unparsable release: %+v", r)
	}
}

// TestKernelLineLeavesTheTierAndExitAlone: D1 is advice above MinKernel, so the RHEL 9.8 line it now prints keeps
// D1 ok and the tier doctor derives, and doctor's exit code with it, exactly as before.
func TestKernelLineLeavesTheTierAndExitAlone(t *testing.T) {
	old := Result{ID: CheckKernel, OK: true, Detail: "5.14.0-687.61.1.el9_8.x86_64 (>= 5.14.0); below the tested floor " +
		"6.1.0; without: Landlock ABI 2 (refer) (5.19.0, rename and link are confined to one directory)"}
	now, _ := kernelResult("5.14.0-687.61.1.el9_8.x86_64", abiProbe(6))
	var tiers [2]map[backend.Tier]bool
	var codes [2]int
	for i, d1 := range []Result{old, now} {
		st := state(func(st *probeState) {
			st.root = false
			st.kernel, st.landlockABI = Version{5, 14, 0}, 6
			st.byID[CheckKernel] = d1
			for j := range st.results {
				if st.results[j].ID == CheckKernel {
					st.results[j] = d1
				}
			}
		})
		tiers[i] = st.probe()
		codes[i] = st.report(nil, backend.TierLandlock).ExitCode()
	}
	if len(tiers[0]) != len(tiers[1]) || codes[0] != codes[1] {
		t.Fatalf("tiers %v -> %v, exit %d -> %d", tiers[0], tiers[1], codes[0], codes[1])
	}
	for tier, ok := range tiers[0] {
		if tiers[1][tier] != ok {
			t.Errorf("tier %s: %v -> %v", tier, ok, tiers[1][tier])
		}
	}
	if !tiers[1][backend.TierLandlock] {
		t.Errorf("tier landlock withheld on RHEL 9.8's D1: %v", tiers[1])
	}
}

// abiProbe is a D1 probe whose landlock_create_ruleset answered abi.
func abiProbe(abi int) kernelProbe { return kernelProbe{asked: true, landlockABI: abi} }

// landlockRow is how D1 renders Mechanisms' Landlock ABI abi row.
func landlockRow(t *testing.T, abi int) string {
	t.Helper()
	for _, m := range Mechanisms {
		if m.LandlockABI == abi {
			return m.Name + " (" + m.Since.String() + ","
		}
	}
	t.Fatalf("Mechanisms has no Landlock ABI %d row", abi)
	return ""
}

// TestKernelLineListsEveryLandlockRowWhereTheKernelHasNone: a kernel that answers landlock_create_ruleset with
// EOPNOTSUPP (Landlock left out of lsm=) or ENOSYS has no Landlock whatever its release says, and D4 then prints
// "tier landlock unavailable". D1 used to fall back to the release there, so a 6.8 kernel listed only ABI 5 to 7
// as missing under D4's FAIL line (review of DOCTOR-RHEL9, S2). Any other error is still no answer.
func TestKernelLineListsEveryLandlockRowWhereTheKernelHasNone(t *testing.T) {
	r, _ := kernelResult("6.8.0-147-generic", kernelProbe{asked: true, landlockOff: true})
	if !r.OK || r.Fix != "" {
		t.Fatalf("D1 with Landlock off: %+v", r)
	}
	for abi := 1; abi <= 7; abi++ {
		if row := landlockRow(t, abi); !strings.Contains(r.Detail, row) {
			t.Errorf("D1 with Landlock off does not list %s: %s", row, r.Detail)
		}
	}
	if strings.Contains(r.Detail, "cgroup connect_unix") {
		t.Errorf("D1 on 6.8 lists connect_unix: %s", r.Detail)
	}
	if r, _ := kernelResult("6.8.0-147-generic", kernelProbe{asked: true}); strings.Contains(r.Detail, landlockRow(t, 4)) {
		t.Errorf("D1 with no Landlock answer lists ABI 4 on 6.8: %s", r.Detail)
	}
}

// TestKernelLineTakesConnectUnixFromD7: D7 loads cgroup/connect_unix as root, by the backend's own probe of the
// attach type. Where it answered, D1's connect_unix row follows it, in both directions, as the Landlock rows follow
// D4; where it did not, the release decides (review of DOCTOR-RHEL9, S2).
func TestKernelLineTakesConnectUnixFromD7(t *testing.T) {
	yes, no := true, false
	const row = "cgroup connect_unix (6.7.0,"
	for _, tc := range []struct {
		release string
		unix    *bool
		listed  bool
	}{
		{"5.14.0-687.61.1.el9_8.x86_64", &yes, false}, // a backport: D7 loaded it
		{"5.14.0-687.61.1.el9_8.x86_64", &no, true},
		{"5.14.0-687.61.1.el9_8.x86_64", nil, true},
		{"6.8.0-147-generic", &no, true}, // built without it: D7 found the attach type refused
		{"6.8.0-147-generic", &yes, false},
		{"6.8.0-147-generic", nil, false},
	} {
		p := abiProbe(7)
		p.unixConnect = tc.unix
		r, _ := kernelResult(tc.release, p)
		if got := strings.Contains(r.Detail, row); got != tc.listed || !r.OK {
			t.Errorf("%s with D7 %v: listed %v, want %v: %+v", tc.release, deref(tc.unix), got, tc.listed, r)
		}
	}
}

// TestRunRendersD1AgainWithD7sConnectUnixRow: the scope renders D1 again once D7 has answered for connect_unix,
// so the kernel line and D7's row agree; D1's OK and Fix, and so the tier and exit code, stay as they were. A D1
// the check did not ask (a test's stub) and a D7 that gave no answer leave D1 as it was printed.
func TestRunRendersD1AgainWithD7sConnectUnixRow(t *testing.T) {
	const el9 = "5.14.0-687.61.1.el9_8.x86_64"
	run := func(release string, d1Asked bool, row func(*HookResult)) (Result, map[backend.Tier]bool) {
		var n calls
		ch := passingChecks(&n)
		ch.kernel = func() (Result, string, Version, kernelProbe) {
			p := abiProbe(6)
			p.asked = d1Asked
			r, v := kernelResult(release, p)
			return r, release, v, p
		}
		inner := ch.programs
		ch.programs = func(root bool, uid int, k Version, tier, capture []hook) (Result, []HookResult) {
			r, rows := inner(root, uid, k, tier, capture)
			for i := range rows {
				if rows[i].Hook == "cgroup/connect_unix" {
					row(&rows[i])
				}
			}
			return r, rows
		}
		st := scope{root: true, checks: ch}.run(context.Background())
		allBuilt(&st)
		for _, r := range st.results {
			if r.ID == CheckKernel && r != st.byID[CheckKernel] {
				t.Fatalf("results and byID disagree on D1: %+v | %+v", r, st.byID[CheckKernel])
			}
		}
		return st.byID[CheckKernel], st.probe()
	}
	const unixRow = "cgroup connect_unix"
	loaded := func(h *HookResult) {}
	absent := func(h *HookResult) {
		*h = HookResult{Hook: h.Hook, Tier: h.Tier, Absent: true, Detail: "the kernel does not accept cgroup/connect_unix programs"}
	}
	noAnswer := func(h *HookResult) {
		*h = HookResult{Hook: h.Hook, Tier: h.Tier, Detail: "probe: operation not permitted"}
	}
	if r, _ := run(el9, true, noAnswer); !strings.Contains(r.Detail, unixRow) {
		t.Errorf("no D7 answer: D1 should keep the release's row: %s", r.Detail)
	}
	// The same machine and D7 rows, with D1 left as printed (not asked) and rendered again (asked).
	before, beforeTiers := run(el9, false, loaded)
	if !strings.Contains(before.Detail, unixRow) {
		t.Errorf("a D1 the check did not ask was rendered again: %s", before.Detail)
	}
	after, afterTiers := run(el9, true, loaded)
	if strings.Contains(after.Detail, unixRow) {
		t.Errorf("D7 loaded connect_unix, D1 still lists it: %s", after.Detail)
	}
	if after.OK != before.OK || after.Fix != before.Fix || len(afterTiers) != len(beforeTiers) {
		t.Errorf("D7's answer moved D1's verdict: %+v -> %+v", before, after)
	}
	for tier, ok := range beforeTiers {
		if afterTiers[tier] != ok {
			t.Errorf("tier %s: %v -> %v", tier, ok, afterTiers[tier])
		}
	}
	if r, _ := run("6.17.0-41-generic", true, absent); !strings.Contains(r.Detail, unixRow) {
		t.Errorf("D7 found connect_unix absent on 6.17, D1 does not list it: %s", r.Detail)
	}
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// TestKernelLandlockProbeTellsNoLandlockFromNoAnswer: ENOSYS and EOPNOTSUPP are the kernel saying it has no
// Landlock, and D1 then lists every Landlock row; any other error, such as a container filter's EPERM, is no
// answer and leaves the rows to the release.
func TestKernelLandlockProbeTellsNoLandlockFromNoAnswer(t *testing.T) {
	saved := landlockVersion
	t.Cleanup(func() { landlockVersion = saved })
	for _, tc := range []struct {
		abi  int
		err  error
		want kernelProbe
	}{
		{6, nil, kernelProbe{asked: true, landlockABI: 6}},
		{0, fmt.Errorf("landlock_create_ruleset(VERSION): %w", unix.EOPNOTSUPP), kernelProbe{asked: true, landlockOff: true}},
		{0, fmt.Errorf("landlock_create_ruleset(VERSION): %w", unix.ENOSYS), kernelProbe{asked: true, landlockOff: true}},
		{0, fmt.Errorf("landlock_create_ruleset(VERSION): %w", unix.EPERM), kernelProbe{asked: true}},
	} {
		landlockVersion = func() (int, error) { return tc.abi, tc.err }
		if got := kernelLandlockProbe(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("landlock answer (%d, %v): %+v, want %+v", tc.abi, tc.err, got, tc.want)
		}
	}
}
