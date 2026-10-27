// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"path/filepath"
	"strings"
	"testing"
)

// globPatterns and globPaths are the differential corpus: path patterns New accepts, non-ASCII ones among them, and
// clean paths, names holding a multibyte rune or a byte that is no UTF-8 among them.
var (
	globPatterns = []string{"a/*", "a/b", "*/b", "a/*/c", "a*/b?/c", "[ab]/*", "[^a/]/*", `a\b/c`, `\a/\*`, "/a/*",
		"/a/b/c", "/*/b", "[a-c]*/[!]", `a/[\]]x`, "?/?", "/", "a/[b-d]/?", "*/*/*", "a/[^/]*", "../a/*",
		"../*", "*/..", "*[^é/]/*", "w/*[가-�]/key", "é*/?", "?/é", "*é/*", "[é-ê]/*", "*?/x", "*[^a/]*/k",
		"/home/u/.ssh/*", "../../x/*", "/*", "/?", "/*/*"}
	globPaths = []string{"a/b", "a/b/c", "a/x/c", "ab/bb/c", "b/c", "c/d", "a/b/c/d", "/a/b", "/a/b/c", "/x/b", "a/]",
		"ab/c", "a/b/b", "x/y", "a/*", "a/]x", "a/c/z", "a/ab", "é/k", "w/é/key", "w/éa/key", "éa/b", "x/é", "aé/x",
		"\xff/k", "é\xff/k", "ê/z", "../a/b", "../x", "../..", "a/..", "/home/u/.ssh/id", "../../x/y", "ba/k", "é/b", "/"}
)

// The component reading agrees with filepath.Match on the whole string for every pattern New accepts: a path
// matches when filepath.Match says so, and every proper ancestor of a path the pattern matches lies above a match
// (holdsMatch's question), multibyte names included, where the rune-stepping automaton this replaced missed
// "*[^é/]/*" above é/ (RD4-2), and the root "/", whose one name is empty, which "/" and "/*" match (RD5-1). An
// ancestor is no match of its own, nor is a path one component longer.
func TestReadPatternAgreesWithFilepathMatch(t *testing.T) {
	checked := 0
	for _, p := range globPatterns {
		rp, err := newReadPattern(p)
		if err != nil || !rp.path {
			t.Errorf("newReadPattern(%q) = %+v, %v; want a path pattern", p, rp, err)
			continue
		}
		for _, path := range globPaths {
			if filepath.IsAbs(path) != rp.abs {
				continue // target() hands an absolute pattern an absolute path, a relative one the path from the worktree
			}
			want, _ := filepath.Match(p, path)
			if got := rp.match(path); got != want {
				t.Errorf("pattern %q path %q: component reading %v, filepath.Match %v", p, path, got, want)
			}
			if !want {
				continue
			}
			for i := 1; i < len(path); i++ {
				if path[i] != '/' {
					continue
				}
				checked++
				if n, ok := rp.above(path[:i]); !ok || n >= len(rp.comps) {
					t.Errorf("pattern %q matches %q but %q does not lie above it", p, path, path[:i])
				}
			}
			// "/*" matches the root and every name in it, the one pattern that matches a path and one below it.
			if n, ok := rp.above(path + "/z"); path != "/" && ok && n <= len(rp.comps) {
				t.Errorf("pattern %q matches %q and %q below it", p, path, path+"/z")
			}
		}
	}
	if checked < 30 {
		t.Fatalf("only %d ancestor checks ran", checked)
	}
	// It is not every prefix: a component that does not match, or a name the whole pattern already spans, ends it.
	rp, _ := newReadPattern("a/*/c")
	for _, name := range []string{"b", "a/x/y", "a/x/c", "ab", "a/x/c/d"} {
		if n, ok := rp.above(name); ok && n < len(rp.comps) {
			t.Errorf("a/*/c above %q", name)
		}
	}
}

// Every pattern New accepts has a clean path filepath.Match matches (the witness newReadPattern found), so no rule
// compile accepts is one that never fires; parseGlob refuses exactly the malformed patterns of the corpus.
func TestReadPatternHasAWitnessAndTheGrammarIsReadWhole(t *testing.T) {
	for _, p := range append(globPatterns, "*.env", "..*", `a\*b`, "[^/]*.env", "id_[rd]sa*", "?", "[^.]*") {
		rp, err := newReadPattern(p)
		if err != nil {
			t.Errorf("newReadPattern(%q): %v", p, err)
			continue
		}
		var names []string
		comps := rp.comps
		if !rp.path {
			comps = []string{p}
		}
		for i, c := range comps {
			if m, _ := filepath.Match(c, ".."); m && !rp.abs && (i == 0 || names[i-1] == "..") {
				names = append(names, "..")
				continue
			}
			w, ok := witness(c)
			if !ok {
				t.Fatalf("pattern %q component %q has no witness", p, c)
			}
			names = append(names, w)
		}
		path := strings.Join(names, "/")
		if rp.abs {
			path = "/" + path
		}
		if m, err := filepath.Match(p, path); !m || err != nil {
			t.Errorf("pattern %q: witness %q not matched (%v)", p, path, err)
		}
	}
	for _, p := range []string{"[", "a[", "a*[", "x/a*[^", `a\`, `a*\`, "[]", "[^]", "a[b-", "[a-]", "[-a]", "[a"} {
		if _, _, _, err := parseGlob(p); err == nil {
			t.Errorf("parseGlob(%q) accepted a malformed pattern", p)
		}
		bad := false
		for _, s := range []string{"", "a", "ab", "abc", "a/b", "xa", "a]", "x/ab"} {
			if _, err := filepath.Match(p, s); err != nil {
				bad = true
			}
		}
		if !bad {
			t.Errorf("%q: filepath.Match found no fault on the corpus; the case proves nothing", p)
		}
	}
}

// The worktree check (beyond) refuses a relative pattern exactly when no path from the
// worktree matches it: for each count k of leading ".." a worktree of that depth allows, a path of k ".." and then a
// witness name for each later component is built, and the pattern accepts the worktree when one of them matches, as
// filepath.Match confirms.
func TestReadPatternBeyondAgreesWithAPathFromTheWorktree(t *testing.T) {
	patterns := append([]string{"../../x/*", "../*/../x", "../..", "*/../x", "../?.", "../.*/k"}, globPatterns...)
	refused := 0
	for _, p := range patterns {
		rp, err := newReadPattern(p)
		if err != nil {
			t.Fatalf("newReadPattern(%q): %v", p, err)
		}
		if rp.abs {
			continue
		}
		for depth, wt := range []string{"/", "/w", "/w/p", "/a/b/c"} {
			some := false
			for k := 0; k <= depth && k <= len(rp.comps); k++ {
				names := make([]string, 0, len(rp.comps))
				for range k {
					names = append(names, "..")
				}
				for _, c := range rp.comps[k:] {
					if w, ok := witness(c); ok {
						names = append(names, w)
					}
				}
				path := strings.Join(names, "/")
				if len(names) == len(rp.comps) && rp.match(path) {
					if m, _ := filepath.Match(p, path); !m {
						t.Errorf("pattern %q: component reading matches %q, filepath.Match does not", p, path)
					}
					some = true
				}
			}
			if err := rp.beyond(p, wt); (err == nil) != some {
				t.Errorf("pattern %q in worktree %s: beyond %v, a path from the worktree matches: %v", p, wt, err, some)
			} else if err != nil {
				refused++
			}
		}
	}
	if refused < 5 {
		t.Fatalf("only %d refusals checked", refused)
	}
}
