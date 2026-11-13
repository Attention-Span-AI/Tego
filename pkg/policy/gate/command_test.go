// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"strings"
	"testing"
)

// TestExecMatchesReadsCommandPatterns is gate.md R2 as ADR 0048 (5) amends it: `exec matches "<p>"` matches when the
// legacy glob matches or when p, read as a command pattern with the shared matcher, matches under deny semantics. It
// is the union, so no rule matches less than before; the gate still only escalates.
func TestExecMatchesReadsCommandPatterns(t *testing.T) {
	p, err := New([]Rule{{ExecMatches, "rm -rf", 95}, {ExecMatches, "git push", 60}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(executable string, args ...string) Decision {
		return p.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: executable, Invocation: executable, Args: args})
	}
	for _, argv := range []string{"rm -rf x", "rm -fr x", "rm --recursive --force x", "rm x --rec --forc", "busybox rm -rf x"} {
		args := strings.Fields(argv)
		if d := exec("/usr/bin/"+args[0], args...); d.Verdict != Refused || d.Rule != "gate.rules[0]" {
			t.Errorf("%s: %+v", argv, d)
		}
	}
	for _, argv := range []string{"git -C . push", "git --git-dir=.git push origin", "git psuh"} {
		args := strings.Fields(argv)
		if d := exec("/usr/bin/git", args...); d.Verdict != Ask || d.Rule != "gate.rules[1]" {
			t.Errorf("%s: %+v", argv, d)
		}
	}
	for _, argv := range []string{"rm -r x", "git stash push", "git status"} {
		args := strings.Fields(argv)
		if d := exec("/usr/bin/"+args[0], args...); d.Verdict != Allow {
			t.Errorf("%s: %+v", argv, d)
		}
	}
	// The legacy glob reading still holds: a glob command word is no command pattern and matches as before.
	g, err := New([]Rule{{ExecMatches, "cu?l *", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := g.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: "/usr/bin/curl", Args: []string{"curl", "x"}}); d.Verdict != Refused {
		t.Errorf("legacy glob: %+v", d)
	}
	if got := p.CommandReading(0); !strings.Contains(got, "--recursive") || !strings.Contains(got, "--force") {
		t.Errorf("rule 0's command reading %q", got)
	}
	if got := g.CommandReading(0); got != "" {
		t.Errorf("a glob command word has no command reading: %q", got)
	}
}

// TestExecMatchesFailsClosedOnOverflow: the command reading ends
// with a ViaOverflow sentinel when it cannot resolve a dispatch (busybox nested past the depth bound) or holds more
// readings than its count. Decide refuses such an exec; the gate compared each interpretation's tool to the rule's and
// the sentinel names none, so `busybox busybox ... rm -rf x` escaped a gate rule that `busybox rm -rf x` met, in a run
// whose contract has gate rules and no exec: command rules (where the gate is the only check). Now the sentinel scores
// as a match of every command pattern, the worst case of the readings that were dropped. A legacy glob rule, which
// reads no interpretations, is unchanged, and an exec whose reading did not overflow scores as before.
func TestExecMatchesFailsClosedOnOverflow(t *testing.T) {
	p, err := New([]Rule{{ExecMatches, "rm -rf", 95}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	nested := func(n int, tail ...string) []string {
		args := []string{"busybox"}
		for range n {
			args = append(args, "busybox")
		}
		return append(args, tail...)
	}
	exec := func(g *Policy, args []string) Decision {
		return g.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: "/usr/bin/busybox", Invocation: "/usr/bin/busybox", Args: args})
	}
	for _, n := range []int{0, 1, 2} {
		if d := exec(p, nested(n, "rm", "-rf", "x")); d.Verdict != Refused || d.Rule != "gate.rules[0]" {
			t.Errorf("busybox x%d rm -rf x: %+v, want refused by gate.rules[0]", n+1, d)
		}
	}
	for _, tail := range [][]string{{"rm", "-rf", "x"}, {"true"}} {
		args := nested(6, tail...)
		if d := exec(p, args); d.Verdict != Refused || d.Rule != "gate.rules[0]" || d.Score != 95 {
			t.Errorf("%s: %+v, want refused by gate.rules[0] at 95 (the reading overflowed)", strings.Join(args, " "), d)
		}
	}
	// The rule's own weight is what an overflow scores: a lighter command pattern asks, never refuses more.
	light, err := New([]Rule{{ExecMatches, "git push", 60}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := exec(light, nested(6, "true")); d.Verdict != Ask || d.Score != 60 {
		t.Errorf("an overflow under a 60-point pattern: %+v, want ask at 60", d)
	}
	if d := exec(light, nested(1, "true")); d.Verdict != Allow {
		t.Errorf("busybox busybox true under a git pattern: %+v, want allow (no overflow)", d)
	}
	// A legacy glob rule has no command reading, so no sentinel reaches it.
	glob, err := New([]Rule{{ExecMatches, "cu?l *", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := exec(glob, nested(6, "true")); d.Verdict != Allow {
		t.Errorf("a glob rule on an overflowed reading: %+v, want allow", d)
	}
}

func TestExecMatchesRetainsEitherReader(t *testing.T) {
	for _, score := range []int{60, 95} {
		p, err := New([]Rule{{ExecMatches, "npm access --all", score}}, 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		d := p.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: "/usr/bin/npm", Invocation: "/usr/bin/npm", Args: strings.Fields("npm --browser --all access operand")})
		want := Ask
		if score == 95 {
			want = Refused
		}
		if d.Verdict != want || d.Score != score {
			t.Errorf("score %d lost retained refusal: %+v", score, d)
		}
	}
}
