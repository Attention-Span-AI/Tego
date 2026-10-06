// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"strings"
	"testing"
)

// TestCommandRuleInvariantHoldsTheGrid is the command-rule invariant's self-test (ADR 0017): over the command-rule
// fixtures, every cell a deny or ask entry refuses is a fail-open if the kernel had run it, at every tier, and no
// cell those fixtures allow breaks it. The invariant reads the contract's entries and the cell alone, so a matcher
// bypass the supervisor and compile --test share (a #! interpreter read only by its #! spelling) still fails there.
func TestCommandRuleInvariantHoldsTheGrid(t *testing.T) {
	ran := 0
	for _, fx := range Fixtures() {
		if fx.Name != "execrules" && fx.Name != "execrules-allow" {
			continue
		}
		for i := range fx.Cells {
			c := &fx.Cells[i]
			w := c.Want[Key{TierLandlock, ModeNone}]
			named := w.Verdict == Refused && (strings.HasPrefix(w.Rule, "exec.deny[") || strings.HasPrefix(w.Rule, "exec.ask["))
			for _, tier := range []Tier{TierLandlock, TierCgroup, TierBPFLSM} {
				got := Invariant(fx.Model, c, tier, Outcome{OK: true})
				if named && !strings.HasPrefix(got, "an exec an exec.deny entry names ran") {
					t.Errorf("%s at %s: run anyway breaks %q, want the command-rule invariant", fx.ID(c), tier, got)
				}
				if w.Verdict == Allow && got != "" {
					t.Errorf("%s at %s: an allowed cell breaks %q", fx.ID(c), tier, got)
				}
				if Invariant(fx.Model, c, tier, Outcome{Errno: 13}) != "" {
					t.Errorf("%s at %s: a refusal broke an invariant", fx.ID(c), tier)
				}
				ran++
			}
		}
	}
	if ran == 0 {
		t.Fatal("no command-rule cell")
	}
	// The invariant's own reading, case by case: short options by letter in any cluster, long options as tokens or
	// --opt=value, operands and subcommands as tokens, the dashed form, and a script's interpreter as Runs names it.
	m := Model{ExecDeny: []string{"rm -r", "git push", "tool --force"}}
	for _, tc := range []struct {
		name string
		c    Cell
		want bool
	}{
		{"rm -fr", Cell{Op: OpExec, Path: "a/rm", Argv: []string{"rm", "-fr", "x"}}, true},
		{"rm -f", Cell{Op: OpExec, Path: "a/rm", Argv: []string{"rm", "-f", "x"}}, false},
		{"rm with r in an operand", Cell{Op: OpExec, Path: "a/rm", Argv: []string{"rm", "readme"}}, false},
		{"git-push", Cell{Op: OpExec, Path: "a/git-push", Argv: []string{"git-push"}}, true},
		{"git status", Cell{Op: OpExec, Path: "a/git", Argv: []string{"git", "status"}}, false},
		{"argv[0] is not the program", Cell{Op: OpExec, Path: "a/ls", Argv: []string{"git", "push"}}, false},
		{"a symlink's target", Cell{Op: OpExec, Path: "a/x", Canon: "b/git", Argv: []string{"x", "push"}}, true},
		{"--force=yes", Cell{Op: OpExec, Path: "a/tool", Argv: []string{"tool", "--force=yes"}}, true},
		{"a #! rm -rf", Cell{Op: OpExec, Path: "s.sh", Script: "/x/y", ScriptArg: "-rf", Runs: "b/rm", Argv: []string{"s.sh", "t"}}, true},
		{"a #! rm with no argument", Cell{Op: OpExec, Path: "s.sh", Script: "/x/y", Runs: "b/rm", Argv: []string{"s.sh", "t"}}, false},
		{"no argv: the actor's noop", Cell{Op: OpExec, Path: "a/rm"}, false},
	} {
		if got := commandDenied(m, &tc.c) != ""; got != tc.want {
			t.Errorf("%s: denied=%v, want %v", tc.name, got, tc.want)
		}
	}
	// An allow list with words constrains its tool (ADR 0048 (1)-(3)): the tool runs only as an allow entry names it,
	// each of the entry's words present (an entry's subcommand admits further options); other programs are not held.
	m = Model{ExecAllowCommands: []string{"git status", "git log --oneline"}}
	for _, tc := range []struct {
		name string
		c    Cell
		want bool
	}{
		{"a listed subcommand with an option", Cell{Op: OpExec, Path: "t/git", Argv: []string{"git", "status", "--short"}}, false},
		{"a required option present", Cell{Op: OpExec, Path: "t/git", Argv: []string{"git", "log", "--oneline", "-3"}}, false},
		{"an unlisted subcommand", Cell{Op: OpExec, Path: "t/git", Argv: []string{"git", "diff"}}, true},
		{"a required option missing", Cell{Op: OpExec, Path: "t/git", Argv: []string{"git", "log"}}, true},
		{"the dashed form of an unlisted subcommand", Cell{Op: OpExec, Path: "t/git-diff", Argv: []string{"git-diff"}}, true},
		{"the dashed form of a listed one", Cell{Op: OpExec, Path: "t/git-status", Argv: []string{"git-status"}}, false},
		{"an unconstrained program", Cell{Op: OpExec, Path: "t/ls", Argv: []string{"ls", "-l"}}, false},
	} {
		if got := commandDenied(m, &tc.c) != ""; got != tc.want {
			t.Errorf("allow list, %s: denied=%v, want %v", tc.name, got, tc.want)
		}
	}
}
