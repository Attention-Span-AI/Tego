// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestEvaluateExecWithNoExecSection pins SEMANTICS §1's "no `exec:` — deny nothing" against the
// opposite default of "`exec: {}` / `exec.allow: []` — all execs refused except the agent command".
// Contract.Exec is a pointer precisely so the two are distinguishable, and the landlock builder does
// distinguish them (execUnrestricted, internal/runtime/enforce/landlock/landlock.go), adding EXECUTE
// to every read set.
//
// The regression this guards is a false assurance, the worst direction for `compile --test`: a row
// `- action: exec, path: /usr/bin/curl, expect: refused` used to PASS on a contract with no `exec:`
// key, certifying as impossible an exec the run performs.
func TestEvaluateExecWithNoExecSection(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python, agent.py]\nfs:\n  write: [out/]\nnet:\n  allow: [\"mcp.internal:8080\"]\n")
	rt, _ := f.compile(c)

	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionExec, Path: "/usr/bin/curl"}, tier)
		if got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
			t.Errorf("tier %s: exec of an undeclared binary = %+v, want allow/%s", tier, got, UnmatchedRule)
		}
		// A binary an entry does name is still attributed to that entry, so the ledger's rule
		// field stays the declared entry rather than collapsing to "unmatched".
		got = rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "python")}, tier)
		if got.Verdict != VerdictAllow || got.Rule != "exec[python]" {
			t.Errorf("tier %s: exec of the agent command = %+v, want allow/exec[python]", tier, got)
		}
	}
}

// TestEvaluateExecEmptySectionStillRefuses is the other half of the tri-state: `exec: {}` keeps the
// restrictive default, so the fix above must not be a blanket "allow everything".
func TestEvaluateExecEmptySectionStillRefuses(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python, agent.py]\nexec: {}\n"))
	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionExec, Path: "/usr/bin/curl"}, tier)
		if got.Verdict != VerdictRefused {
			t.Errorf("tier %s: exec: {} allowed an undeclared binary: %+v", tier, got)
		}
	}
}

// TestEvaluateExecHandBuiltTableFailsClosed keeps the unrestricted branch keyed on a real contract.
// A RuleTable assembled in code carries no Contract, and "nil Contract" must not read as "the author
// left exec: out" — landlock.go's builder takes the same reading.
func TestEvaluateExecHandBuiltTableFailsClosed(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierCgroup, Exec: []ExecRule{
		{Raw: "python", Path: "/usr/bin/python", Basename: "python", Verdict: VerdictAllow},
	}}
	got := rt.Evaluate(Action{Kind: ActionExec, Path: "/usr/bin/curl"}, backend.TierCgroup)
	if got.Verdict != VerdictRefused {
		t.Errorf("hand-built table allowed an undeclared binary: %+v", got)
	}
}

// TestEvaluateExecBasenameIsNotAWildcard pins SEMANTICS §4's two different name rules. An entry the
// author wrote as a path names one inode: tier 3 matches "the final component of the file's dentry"
// only for an entry declared as a bare basename, and the Landlock ruleset, which tiers 1 and 2 both
// install, "cannot match by name" at all — it holds one fd per resolved entry, so "a same-named binary elsewhere, such as a
// uv- or pyenv-managed Python, is a different inode and must be declared by path or directory".
//
// Compile stamps Basename on every rule, path-declared and implicit ones included, so matching on
// it alone reported a deliberately pinned interpreter as permitting any binary named python3 —
// including one the agent wrote itself into a directory it can write.
func TestEvaluateExecBasenameIsNotAWildcard(t *testing.T) {
	f := newFixture(t)
	pinned := filepath.Join(f.bin, "python")
	elsewhere := "/tmp/work/python"

	t.Run("declared by path", func(t *testing.T) {
		rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [static-tool]\nexec:\n  allow: [\"" + pinned + "\"]\n"))
		for _, tier := range enforcingTiers() {
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, tier); got.Verdict != VerdictRefused {
				t.Errorf("tier %s: a same-named binary at %s matched the path-declared entry %s: %+v", tier, elsewhere, pinned, got)
			}
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: pinned}, tier); got.Verdict != VerdictAllow {
				t.Errorf("tier %s: the declared entry itself was refused: %+v", tier, got)
			}
		}
	})

	t.Run("declared as a basename", func(t *testing.T) {
		rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [static-tool]\nexec:\n  allow: [python]\n"))
		// Tier 3: the exec hook compares the dentry's final component, so a same-named binary
		// anywhere matches and `compile --test` has to say so.
		got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, backend.TierBPFLSM)
		if got.Verdict != VerdictAllow || got.Rule != "exec[python]" {
			t.Errorf("tier %s: basename entry did not match %s by name: %+v", backend.TierBPFLSM, elsewhere, got)
		}
		// Landlock: inode identity only. Tier 2 installs the same Landlock ruleset and its fanotify
		// exec check compares exact and directory paths, so it cannot match by name either.
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, tier); got.Verdict != VerdictRefused {
				t.Errorf("tier %s matched %s by name against a basename entry resolved to %s: %+v", tier, elsewhere, pinned, got)
			}
			// The resolved candidate is still the same inode.
			if got := rt.Evaluate(Action{Kind: ActionExec, Path: pinned}, tier); got.Verdict != VerdictAllow {
				t.Errorf("tier %s refused the entry's own resolved path %s: %+v", tier, pinned, got)
			}
			// A row that names the bare command (argv: [python]) still matches: it names no file,
			// so the entry's resolved candidate is the only thing it can mean.
			if got := rt.Evaluate(Action{Kind: ActionExec, Argv: []string{"python", "x.py"}}, tier); got.Verdict != VerdictAllow {
				t.Errorf("tier %s refused the bare command row: %+v", tier, got)
			}
		}
	})
}

// exec.allow keeps its symlinks in ExecRule.Path (/bin/sh, a linked bin dir), and tier 1's supervisor (execGranted,
// resolved arm) and tier 2's listener (Spellings(Path, resolveNow(Path))) both admit the resolved spelling. Evaluate
// matches Path only, so a compile --test row naming the resolved file (what `readlink -f`, `which -a` on a
// merged-/usr box, or the ledger's own exec path shows) is refused.
func TestEvaluateExecResolvedSpelling(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.root, "lbin")
	if err := os.Symlink(f.bin, link); err != nil {
		t.Skip(err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + filepath.Join(link, "static-tool") + "\"]\n")
	rt, _ := f.compile(c)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		r := rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "static-tool")}, tier)
		if r.Verdict != VerdictAllow {
			t.Errorf("%s: exec of the entry's resolved file = %+v; the tier admits it", tier, r)
		}
	}
}
