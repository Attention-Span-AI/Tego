// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestRehearsalDoesNotSkipD3Checks(t *testing.T) {
	root := t.TempDir()
	fs, err := cgroup.NewAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if r := probeCgroupResolved(fs, cgroup.ErrBesideSubtree, nil, false); r.OK || !r.beside {
		t.Fatalf("original placement: %+v", r)
	}
	// Rehearsal replaces the placement refusal only. It does not create authority for the delegated tree.
	r := probeCgroupResolved(fs, cgroup.ErrBesideSubtree, nil, true)
	if r.OK || r.throughUserScope || !strings.Contains(r.Detail, "cgroup.procs not writable") {
		t.Fatalf("missing delegation passed: %+v", r)
	}
	for _, name := range []string{"cgroup.procs", "cgroup.subtree_control"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("cpu memory pids"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r = probeCgroupResolved(fs, cgroup.ErrBesideSubtree, nil, true)
	if r.OK || r.throughUserScope || !strings.Contains(r.Detail, "no writable cgroup.kill") {
		t.Fatalf("missing atomic kill passed: %+v", r)
	}
	if r := probeCgroupResolved(nil, cgroup.ErrBesideSubtree, nil, true); r.OK || r.throughUserScope {
		t.Fatalf("missing detection passed: %+v", r)
	}
	if r := probeCgroupResolved(fs, os.ErrPermission, nil, true); r.OK || r.throughUserScope {
		t.Fatalf("unrelated failure passed: %+v", r)
	}
}

func TestRehearsedReportKeepsTheShell(t *testing.T) {
	var c calls
	st := scope{reach: backend.TierLandlock, checks: passingChecks(&c)}.run(t.Context())
	d3 := st.byID[CheckCgroupV2]
	d3.beside, d3.throughUserScope = true, true
	st.byID[CheckCgroupV2] = d3
	for i := range st.results {
		if st.results[i].ID == CheckCgroupV2 {
			st.results[i] = d3
		}
	}
	allBuilt(&st)
	rep := st.report(nil, "")
	if rep.Tier != backend.TierLandlock || !rep.ThroughUserScope || !rep.OutsideUserManager || rep.Root {
		t.Fatalf("misplaced report: %+v", rep)
	}
	line, _ := rep.Verdict()
	if !strings.Contains(line, "this shell can enforce") || !strings.Contains(line, ThroughScopeFact) ||
		!strings.HasPrefix(line, "Ready:") {
		t.Fatalf("verdict: %s", line)
	}
	// The rehearsal worked: no failure is noted, whatever the context says.
	rep.noteScope(WithUserScopeFailure(t.Context(), "should not be read"))
	if rep.UserScopeFailure != "" {
		t.Errorf("a worked rehearsal kept a failure: %q", rep.UserScopeFailure)
	}
}

// TestFailedRehearsalSaysWhy (ADR 0142, amended 2026-11-19, round 4): when the CLI's rehearsal of entry into a user
// scope failed, the report of the shell outside the user manager's cgroup says why and names the one fix, never "run,
// watch and test can try a user scope", which would send the person to commands that fail the same way. Without a
// rehearsal (--no-scope) it says what it said.
func TestFailedRehearsalSaysWhy(t *testing.T) {
	var c calls
	st := scope{reach: backend.TierLandlock, checks: passingChecks(&c)}.run(t.Context())
	d3 := st.byID[CheckCgroupV2]
	d3.OK, d3.beside, d3.Fix = false, true, "start tego from a shell in your user manager's cgroup: open one with systemd-run --user --scope bash, then run tego there"
	st.byID[CheckCgroupV2] = d3
	for i := range st.results {
		if st.results[i].ID == CheckCgroupV2 {
			st.results[i] = d3
		}
	}
	allBuilt(&st)
	rep := st.report(nil, "")
	if rep.Tier != "" || !rep.OutsideUserManager || rep.ThroughUserScope {
		t.Fatalf("misplaced report: %+v", rep)
	}
	line, _ := rep.Verdict()
	if !strings.Contains(line, "can try a user scope") {
		t.Errorf("no rehearsal: verdict %q", line)
	}
	rep.noteScope(WithUserScopeFailure(t.Context(), "user scope rehearsal exited 1"))
	line, fix := rep.Verdict()
	if !strings.Contains(line, "could not open a user scope from it (user scope rehearsal exited 1)") ||
		strings.Contains(line, "can try") || !strings.Contains(fix, "systemd-run --user --scope bash") {
		t.Errorf("failed rehearsal: verdict %q, fix %q", line, fix)
	}
	if got := rep.tierText(); got != "none in this shell (tego could not open a user scope from it)" {
		t.Errorf("tier line: %q", got)
	}
}
