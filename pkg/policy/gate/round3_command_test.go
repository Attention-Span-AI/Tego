// SPDX-License-Identifier: Apache-2.0

package gate

import "testing"

func TestRound3CorrectedAliasGateScores(t *testing.T) {
	for _, c := range []struct{ target, alias, typo string }{
		{"add", "stage", "staeg"}, {"init", "init-db", "init-bd"},
		{"fsck", "fsck-objects", "fsck-objecst"}, {"blame", "pickaxe", "pickxae"},
	} {
		for _, score := range []int{0, 60, 95} {
			p, err := New([]Rule{{ExecMatches, "git " + c.target, score}}, 50, 80)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{c.alias, c.typo} {
				for _, prefix := range [][]string{nil, {"-c", "help.autocorrect=immediate"}, {"-C", "d", "--git-dir=x", "-c", "a=b", "--no-pager"}} {
					argv := append(append([]string{"git"}, prefix...), token)
					for _, floor := range []Verdict{Allow, Ask} {
						want := floor
						if score > 80 {
							want = Refused
						} else if score >= 50 {
							want = max(want, Ask)
						}
						a := Action{Kind: Exec, Complete: true, Executable: "/usr/bin/git", Invocation: "/usr/bin/git", Args: argv}
						if d := p.Evaluate(floor, a); d.Score != score || d.Verdict != want || d.Rule != "gate.rules[0]" {
							t.Fatalf("%s score=%d floor=%d %q: %+v, want score=%d verdict=%d", c.target, score, floor, argv, d, score, want)
						}
					}
				}
			}
		}
	}
}
