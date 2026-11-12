// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The Ready or Not ready line tego doctor writes on stderr after its report (limits-check-doctor-cli R27), for a person who
// reads only the end: a fresh guest's answer was on line 12 of 52. A root report is a root run's: a run the same person
// starts without sudo gets tier landlock at most, so its line says "a run started as root here" (2026-11-10 review, M1).
// The fix it points to is the fix line, else the first failing check's own. The text report itself carries none of it:
// its stdout stays as scripts read it.
func TestVerdictSaysReadyOrNotAndForWhom(t *testing.T) {
	user := func(st *probeState) { st.root = false }
	landlockABI1 := func(st *probeState) {
		user(st)
		st.landlockABI = 1
		fail(st, CheckLandlock, "ABI 1 is below the supported minimum 2", "boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)")
	}
	for _, tc := range []struct {
		name    string
		edit    func(*probeState)
		require backend.Tier
		line    string
		fix     bool
	}{
		{"a user at tier 1", user, "", "Ready: this shell can enforce at tier 1 (landlock), no root needed.", false},
		{"root at every tier", nil, "", "Ready: a run started as root here can enforce at tier 3 (bpflsm).", false},
		{"a user below a --require", user, backend.TierCgroup,
			"Not ready for tier 2 (cgroup), which --require asks for: this shell can enforce at tier 1 (landlock).", true},
		{"a user who can only record", landlockABI1, "", "Not ready: this shell can only record.", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := state(tc.edit).report(config.Builtin(), tc.require)
			line, fix := rep.Verdict()
			if line != tc.line {
				t.Errorf("line %q, want %q", line, tc.line)
			}
			if tc.fix != (fix != "") {
				t.Errorf("fix %q, want one: %v", fix, tc.fix)
			}
			var buf bytes.Buffer
			if err := rep.WriteText(&buf); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(buf.String(), "Ready") || strings.Contains(buf.String(), "result:") {
				t.Errorf("the text report carries the verdict, which goes to stderr:\n%s", buf.String())
			}
		})
	}
	// Root that can only record says so for a root run, never for "this shell".
	rep := state(func(st *probeState) {
		st.landlockABI = 1
		fail(st, CheckLandlock, "ABI 1 is below the supported minimum 2", "boot a kernel >= 5.19")
	}).report(config.Builtin(), "")
	if line, _ := rep.Verdict(); line != "Not ready: a run started as root here can only record." {
		t.Errorf("root, no tier: %q", line)
	}
}

// A login over SSH or on a console runs beside its user manager's cgroup: D3's placement refusal is then all tier
// landlock misses, and a shell opened inside that cgroup gets the tier (Report.OutsideUserManager). Neither the
// Not ready line nor the tier line may say the shell "can only record": tego watch is placed in the same cgroup and
// fails too (acceptance B, 2026-11-11). Any other missing check, root, or a ceiling above tier landlock
// is not this case.
func TestOutsideUserManagerIsThePlacementAlone(t *testing.T) {
	beside := func(st *probeState) {
		st.root = false
		r := Result{ID: CheckCgroupV2, Detail: "cgroup: this process runs outside its delegated cgroup v2 subtree: ...",
			Fix:    "start tego from a shell in your user manager's cgroup: open one with systemd-run --user --scope bash, then run tego there",
			beside: true}
		st.byID[CheckCgroupV2] = r
		for i := range st.results {
			if st.results[i].ID == CheckCgroupV2 {
				st.results[i] = r
			}
		}
	}
	notDelegated := func(st *probeState) {
		st.root = false
		fail(st, CheckCgroupV2, "cgroup: no delegated cgroup v2 subtree", "enable systemd user delegation")
	}
	pinned := func(tier string) *config.Machine {
		m := config.Builtin()
		m.Tier.Bounded, m.Tier.Value = true, config.TierSetting{Tier: tier}
		return m
	}
	for _, tc := range []struct {
		name    string
		edit    func(*probeState)
		m       *config.Machine
		outside bool
		line    string
		tier    string
	}{
		{"beside the user manager", beside, config.Builtin(), true,
			"Not ready: this shell is outside your user manager's cgroup, so tego starts no run from it, not even tego watch.",
			"tier: none (this shell is outside your user manager's cgroup, so tego starts no run from it)"},
		{"beside it, under a landlock ceiling", beside, pinned("landlock"), true, "", ""},
		{"beside it, under a cgroup ceiling", beside, pinned("cgroup"), false, "", ""},
		{"beside it, with no Landlock either", func(st *probeState) {
			beside(st)
			st.landlockABI = 1
			fail(st, CheckLandlock, "ABI 1 is below the supported minimum 2", "boot a kernel >= 5.19")
		}, config.Builtin(), false, "Not ready: tego can start no run from this shell, not even tego watch.",
			"tier: none (tego can start no run from here)"},
		{"no delegation", notDelegated, config.Builtin(), false,
			"Not ready: tego can start no run from this shell, not even tego watch.", "tier: none (tego can start no run from here)"},
		{"root", func(st *probeState) {}, config.Builtin(), false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := state(tc.edit).report(tc.m, "")
			if rep.OutsideUserManager != tc.outside {
				t.Errorf("OutsideUserManager %v, want %v (tier %q, missing %v)", rep.OutsideUserManager, tc.outside, rep.Tier, rep.Missing)
			}
			if tc.line != "" {
				if line, _ := rep.Verdict(); line != tc.line {
					t.Errorf("line %q, want %q", line, tc.line)
				}
			}
			if tc.tier != "" {
				var buf bytes.Buffer
				if err := rep.WriteText(&buf); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(buf.String(), "\n"+tc.tier+"\n") {
					t.Errorf("no line %q in:\n%s", tc.tier, buf.String())
				}
				if strings.Contains(buf.String(), "can only record") {
					t.Errorf("the report says the shell can only record:\n%s", buf.String())
				}
			}
		})
	}
}

// TestNoUserManagerIsItsOwnVerdict: D3 refused because no user manager runs for the user (cgroup.ErrNoUserManager: an
// account with a nologin shell reached through su or sudo -u, acceptance 2B, 2026-11-11) is Report.NoUserManager, with
// its own line and tier words, and is not OutsideUserManager: no shell of this user is inside a manager that does not
// run. Under a ceiling above tier landlock, or with another check failing too, it is not.
func TestNoUserManagerIsItsOwnVerdict(t *testing.T) {
	noManager := func(st *probeState) {
		st.root = false
		r := Result{ID: CheckCgroupV2, Detail: "cgroup: no delegated cgroup v2 subtree for uid 1001: no user manager runs for uid 1001: ...",
			Fix: "start a user manager for this user that runs without a login: ...", noManager: true}
		st.byID[CheckCgroupV2] = r
		for i := range st.results {
			if st.results[i].ID == CheckCgroupV2 {
				st.results[i] = r
			}
		}
	}
	rep := state(noManager).report(config.Builtin(), "")
	if !rep.NoUserManager || rep.OutsideUserManager {
		t.Fatalf("NoUserManager %v, OutsideUserManager %v (tier %q, missing %v)", rep.NoUserManager, rep.OutsideUserManager, rep.Tier, rep.Missing)
	}
	if line, fix := rep.Verdict(); line != "Not ready: no user manager runs for this user, so tego starts no run from this shell, not even tego watch." ||
		!strings.HasPrefix(fix, "start a user manager for this user") {
		t.Errorf("line %q, fix %q", line, fix)
	}
	var buf bytes.Buffer
	if err := rep.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\ntier: none (no user manager runs for this user, so tego starts no run from here)\n") {
		t.Errorf("tier line:\n%s", buf.String())
	}
	m := config.Builtin()
	m.Tier.Bounded, m.Tier.Value = true, config.TierSetting{Tier: "cgroup"}
	if state(noManager).report(m, "").NoUserManager {
		t.Error("under a cgroup ceiling")
	}
	if state(func(st *probeState) {
		noManager(st)
		st.landlockABI = 1
		fail(st, CheckLandlock, "ABI 1 is below the supported minimum 2", "boot a kernel >= 5.19")
	}).report(config.Builtin(), "").NoUserManager {
		t.Error("with Landlock missing too")
	}
}
