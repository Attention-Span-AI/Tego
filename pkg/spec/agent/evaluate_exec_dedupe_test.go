// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestExecBasenameEntrySurvivesAPathDeclaredDuplicate pins SEMANTICS §4's name rule against the one
// thing that erases it: deduplication. Two entries that resolve to the same file compile to a single
// ExecRule keeping the *first* spelling (compile_exec.go add), and the command is added before
// exec.allow. So `command: ["/usr/bin/python3"]` beside `exec.allow: ["python3"]` leaves one rule
// whose Raw is a path, even though the author did write a bare basename.
//
// Asking Raw whether the entry may match by name therefore answered for the wrong entry: tier 3,
// whose hook "matches the final component of the file's dentry after symlink resolution", would
// run /tmp/work/python3, while `compile --test` reported it refused. That is the false
// assurance direction — the tool certifying as impossible an exec the run performs — which is
// exactly what the basename guard was added to stop in the other direction.
func TestExecBasenameEntrySurvivesAPathDeclaredDuplicate(t *testing.T) {
	f := newFixture(t)
	pinned := filepath.Join(f.bin, "python")
	elsewhere := "/tmp/work/python"

	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [\"" + pinned + "\", agent.py]\nexec:\n  allow: [python]\n"))

	// The premise: one rule, carrying the path spelling, sourced from both entries.
	var n int
	for _, r := range rt.Exec {
		if r.Path == pinned {
			n++
			if r.Raw != pinned {
				t.Fatalf("rule for %s kept Raw %q, want the first spelling", pinned, r.Raw)
			}
		}
	}
	if n != 1 {
		t.Fatalf("the two spellings of %s compiled to %d rules, want 1", pinned, n)
	}

	// Tier 3's exec hook is the one that matches by dentry name (SEMANTICS §4, "Root tiers").
	got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, backend.TierBPFLSM)
	if got.Verdict != VerdictAllow {
		t.Errorf("tier %s: exec %s = %+v; exec.allow: [python] is a basename entry and tier 3 matches by dentry name", backend.TierBPFLSM, elsewhere, got)
	}
	// The bucket is still the entry as first declared, not the basename: RuleName is
	// unchanged by any of this.
	if got.Verdict == VerdictAllow && got.Rule != "exec["+pinned+"]" {
		t.Errorf("tier %s: rule = %q, want exec[%s]", backend.TierBPFLSM, got.Rule, pinned)
	}
	// Landlock holds one fd per resolved entry and "cannot match by name", and tier 2 installs the
	// same ruleset (evaluate.go execByInode).
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, tier); got.Verdict != VerdictRefused {
			t.Errorf("tier %s matched %s by name: %+v", tier, elsewhere, got)
		}
	}

	// The control: with no bare-basename spelling anywhere, no tier matches by name. The fix
	// widens the guard for the entry the author wrote as a name, and for nothing else.
	rt2, _ := f.compile(f.load("version: 0\nname: a\ncommand: [static-tool]\nexec:\n  allow: [\"" + pinned + "\"]\n"))
	for _, tier := range enforcingTiers() {
		if got := rt2.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, tier); got.Verdict != VerdictRefused {
			t.Errorf("tier %s: a path-only contract matched %s by name: %+v", tier, elsewhere, got)
		}
	}
}
