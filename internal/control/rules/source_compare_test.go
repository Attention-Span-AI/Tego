// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"
	"testing"
)

// A rules file edited outside Tego is compared with the rules a run ran, through the compiled families, so the page
// says what the next run does differently and which way it moves, not only that the file differs.
func TestCompareSourceSaysWhatAnExternalEditChanged(t *testing.T) {
	f := realFixture(t)
	ran := directionHead + "fs:\n  write: [./out/]\n"
	writeFile(t, filepath.Join(f.ledger, runA, "contract.yaml"), ran)
	for _, tc := range []struct {
		name, file string
		err        string
		direction  string
		families   map[string]string
		words      string
	}{
		{"widened", directionHead + "fs:\n  write: [./out/, ./docs/]\n", "", "widens", map[string]string{"filesystem": "widens"}, "Files it may change: the next run may do more than before"},
		{"narrowed", directionHead + "fs:\n  write: [./out/]\nnet:\n  allow: [example.com:443]\n", "", "narrows", map[string]string{"destinations": "narrows"}, "Places it may connect to: the next run may do less than before"},
		{"the same rules", "# a note\n" + ran, "", "same", map[string]string{}, ""},
		{"a file that no longer compiles", ran + "  broken: [\n", "does not compile", "", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, f.contract, tc.file)
			got := f.s.CompareSource(t.Context(), runA)
			if tc.err != "" {
				if !strings.Contains(got.Err, tc.err) || len(got.Families) != 0 {
					t.Fatalf("got %+v, want an error containing %q", got, tc.err)
				}
				return
			}
			if got.Err != "" || got.Direction != tc.direction {
				t.Fatalf("got %+v, want direction %s", got, tc.direction)
			}
			seen := map[string]string{}
			for _, fc := range got.Families {
				seen[fc.Family] = fc.Direction
				if tc.words != "" && !strings.HasPrefix(fc.Words, tc.words) {
					t.Errorf("words %q lack %q", fc.Words, tc.words)
				}
			}
			if len(seen) != len(tc.families) {
				t.Fatalf("families %v, want %v", seen, tc.families)
			}
			for fam, dir := range tc.families {
				if seen[fam] != dir {
					t.Errorf("%s is %q, want %q", fam, seen[fam], dir)
				}
			}
		})
	}
	if got := f.s.CompareSource(t.Context(), runG); got.Err == "" {
		t.Error("a run that named no rules file was compared")
	}
	if got := f.s.CompareSource(t.Context(), "../../etc"); got.Err == "" {
		t.Error("a path was taken for a run")
	}
}
