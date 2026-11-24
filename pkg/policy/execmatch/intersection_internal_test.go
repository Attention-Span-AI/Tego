// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"strings"
	"testing"
)

func TestBaselineGlobIntersectionAutomaton(t *testing.T) {
	patterns := []string{"", "a", "b", "*", "?", "a*", "*b", "a?", "?b", "a*b", "*a*", "[ab]", "[!ab]", "[^a]", "[a-b]", "[0-9]", "[a-z]", "[]", "[", "[!", "[a", "[a]", "[a-b", "**", "*?*"}
	words := []string{"", "a", "b", "x", "0", "[", "]", "!", "ab", "ba", "aa", "bb", "ax", "xb", "a0b", "[a", "aaa", "aab", "bab"}
	pairs, checks := 0, 0
	for _, p := range patterns {
		for _, q := range patterns {
			pairs++
			s := intersectionSearch{left: 100000}
			word, ok := s.globIntersection(p, q)
			if s.exhausted {
				t.Fatalf("ordinary glob pair exhausted bound: %q %q", p, q)
			}
			if ok && (!Glob(p, word) || !Glob(q, word)) {
				t.Fatalf("invalid common word: %q %q -> %q", p, q, word)
			}
			for _, candidate := range words {
				checks++
				if !ok && Glob(p, candidate) && Glob(q, candidate) {
					t.Fatalf("false disjoint: %q %q witness %q", p, q, candidate)
				}
			}
		}
	}
	t.Logf("%d glob language pairs, %d matcher oracle checks", pairs, checks)
}

func TestBaselineGlobIntersectionBound(t *testing.T) {
	s := intersectionSearch{left: 1}
	if _, ok := s.globIntersection(strings.Repeat("a*", 20), strings.Repeat("*a", 20)); ok || !s.exhausted {
		t.Fatal("exhausted automaton must retain uncertainty")
	}
}

func FuzzBaselineGlobIntersection(f *testing.F) {
	for _, pair := range [][2]string{{"a*", "*b"}, {"[!0-9]", "[0-9]"}, {"[", "[?"}, {"a?b", "a*b"}, {"*", ""}} {
		f.Add(pair[0], pair[1], "ab")
	}
	f.Fuzz(func(t *testing.T, p, q, candidate string) {
		if len(p) > MaxWordBytes || len(q) > MaxWordBytes || len(candidate) > MaxWordBytes || strings.IndexByte(p+q+candidate, 0) >= 0 {
			return
		}
		s := intersectionSearch{left: 100000}
		word, ok := s.globIntersection(p, q)
		if ok && (!Glob(p, word) || !Glob(q, word)) {
			t.Fatalf("invalid common word: %q %q -> %q", p, q, word)
		}
		if !ok && !s.exhausted && Glob(p, candidate) && Glob(q, candidate) {
			t.Fatalf("false disjoint: %q %q witness %q", p, q, candidate)
		}
	})
}
