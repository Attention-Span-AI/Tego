// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// Fuzz vocabulary: whole units, so an insertion never splits an option from its value or a two-word subcommand.
var (
	fuzzTools = []string{"git", "rm", "mytool"}
	fuzzPre   = [][]string{{"-C", "."}, {"-c", "a=b"}, {"--git-dir=.git"}, {"--no-pager"}, {"--bare"}, {"--work-tree", "w"}, {"-p"}}
	fuzzSubs  = [][]string{{"push"}, {"status"}, {"stash", "push"}, {"stash", "drop"}, {"log"}, {"commit"}, {"psh"}, {"fetch"}, {"x"}}
	fuzzPost  = [][]string{{"-f"}, {"--force"}, {"origin"}, {"main"}, {"-m", "msg"}, {"--quiet"}, {"-r"}, {"-rf"}, {"--recursive"}, {"x"}, {"--oneline"}, {"-n", "5"}}
	fuzzIns   = [][]string{{"--zz"}, {"-Z"}, {"--zz=1"}, {"-C", "y"}, {"-c", "k=v"}, {"--no-pager"}, {"-q"}, {"--verbose"}}
	fuzzDeny  = []string{"deny: git push", "deny: git push --force", "deny: git stash drop", "deny: rm -r", "deny: mytool x --force", "deny: git -C . push origin"}
	fuzzAllow = []string{"allow: git status", "allow: git log", "allow: git stash push"}
)

// FuzzMonotone is ADR 0048 C1a's fuzz target: no panic and bounded readings for any token vector, and for vectors
// built from whole units, inserting an unknown option or a complete known option with its value at any unit
// boundary before `--` never turns a definite deny match into a miss, and never turns a miss of an allow entry that
// names no option into a match.
func FuzzMonotone(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0}, []byte("x"))
	f.Add([]byte{0, 2, 1, 3, 1}, []byte("--zz"))
	f.Add([]byte{1, 5, 6, 7, 2}, []byte("-rf"))
	deny := rules(f, fuzzDeny...)
	allow := rules(f, fuzzAllow...)
	f.Fuzz(func(t *testing.T, plan []byte, raw []byte) {
		// Any vector at all: no panic, bounded readings.
		if len(raw) > 0 && len(raw) < 512 {
			var toks []string
			start := 0
			for i := 0; i <= len(raw); i++ {
				if i == len(raw) || raw[i] == ' ' {
					toks = append(toks, string(raw[start:i]))
					start = i + 1
				}
			}
			for _, tool := range fuzzTools {
				argv := append([]string{tool}, toks...)
				fx := execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: argv, ArgvComplete: true}
				deny.Decide(&fx)
				for _, inv := range deny.Interpretations(&fx) {
					if len(inv.Readings) > execmatch.MaxReadings {
						t.Fatalf("%v: %d readings", argv, len(inv.Readings))
					}
				}
			}
		}
		if len(plan) < 5 {
			return
		}
		pick := func(b byte, set [][]string) []string { return set[int(b)%len(set)] }
		tool := fuzzTools[int(plan[0])%len(fuzzTools)]
		var units [][]string
		n := 1
		for i := 1; i+1 < len(plan) && n < 8; i += 2 {
			switch plan[i] % 3 {
			case 0:
				units = append(units, pick(plan[i+1], fuzzPre))
			case 1:
				units = append(units, pick(plan[i+1], fuzzSubs))
			case 2:
				units = append(units, pick(plan[i+1], fuzzPost))
			}
			n++
		}
		ins := pick(plan[len(plan)-1], fuzzIns)
		at := int(plan[len(plan)-2]) % (len(units) + 1)
		flat := func(us [][]string) []string {
			out := []string{tool}
			for _, u := range us {
				out = append(out, u...)
			}
			return out
		}
		before := flat(units)
		withUnits := append(append(append([][]string{}, units[:at]...), ins), units[at:]...)
		after := flat(withUnits)
		decide := func(ix *execmatch.Index, argv []string) execmatch.Result {
			fx := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
			return ix.Decide(&fx)
		}
		// A definite match only: an ambiguous one may rest on an unknown option taking the next token, which an
		// insertion right after it rightly takes away (the tool would then read the inserted token as its value).
		if b := decide(deny, before); b.Outcome == execmatch.OutcomeRefused && b.Match == execmatch.MatchDefinite {
			if a := decide(deny, after); a.Outcome != execmatch.OutcomeRefused {
				t.Fatalf("deny %s refused %q; inserting %q made it %s", b.Rule(), before, ins, a.Outcome)
			}
		}
		if b := decide(allow, before); b.Outcome == execmatch.OutcomeRefused {
			if a := decide(allow, after); a.Outcome == execmatch.OutcomeAllowed {
				t.Fatalf("%q was unlisted; inserting %q made it allowed by %s", before, ins, a.Rule())
			}
		}
	})
}
