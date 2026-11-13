// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"sort"
	"strings"
)

// similarityFloor is git's SIMILARITY_FLOOR (help.c): a best score at or above it corrects nothing.
const similarityFloor = 7

// maxCandidate bounds a candidate's length for the fixed-size distance rows; git's longest command name is far
// shorter.
const maxCandidate = 63

// Candidates is the candidate set of git's help_unknown_cmd that the matcher uses: a subset of every supported git's
// own (ADR 0048 (2)). Built once; read concurrently.
type Candidates struct {
	names  []string
	common map[string]bool
	maxLen int
}

// NewCandidates builds a candidate set from command names (git's main commands: built-ins and the exec-path's
// git-* files, without the prefix) and the common-command group. Names longer than 63 bytes are dropped.
func NewCandidates(names, common []string) *Candidates {
	c := &Candidates{common: map[string]bool{}}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || len(n) > maxCandidate || seen[n] {
			continue
		}
		seen[n] = true
		c.names = append(c.names, n)
		c.maxLen = max(c.maxLen, len(n))
	}
	sort.Strings(c.names)
	for _, n := range common {
		if seen[n] {
			c.common[n] = true
		}
	}
	return c
}

// Names lists the candidates, sorted.
func (c *Candidates) Names() []string { return c.names }

// Has reports whether name is a candidate.
func (c *Candidates) Has(name string) bool {
	i := sort.SearchStrings(c.names, name)
	return i < len(c.names) && c.names[i] == name
}

// Autocorrect is a pure-function port of git 2.51.0's help.c help_unknown_cmd under help.autocorrect=immediate: the
// command git runs for a token that names no command, and ok false when it runs none.
//
//   - A candidate in the common group that starts with the token scores 0; any other scores
//     levenshtein(token, candidate; swap 0, substitution 2, insertion 1, deletion 3) + 1.
//   - git corrects only when no candidate scores 0, exactly one candidate has the best score, and that score is
//     below SIMILARITY_FLOOR (7). A token equal to a candidate corrects nothing (git dies with its bad-interpreter
//     advice).
//
// A token longer than the longest candidate plus one cannot score below 7, since each surplus byte is a deletion at
// 3, so the dynamic program runs only for shorter tokens. It allocates nothing.
func Autocorrect(token string, c *Candidates) (target string, ok bool) {
	if c == nil || token == "" || len(token) > c.maxLen+1 || len(token) > maxCandidate {
		return "", false
	}
	best, count := 1<<30, 0
	for _, cand := range c.names {
		if cand == token {
			return "", false
		}
		if c.common[cand] && strings.HasPrefix(cand, token) {
			return "", false // a prefix match of a common command: git counts it first, so n >= 2 or none at all
		}
		score := levenshtein(token, cand) + 1
		switch {
		case score < best:
			best, count, target = score, 1, cand
		case score == best:
			count++
		}
	}
	if count == 1 && best < similarityFloor {
		return target, true
	}
	return "", false
}

// levenshtein is git's levenshtein.c with w (swap) 0, s (substitution) 2, a (insertion) 1 and d (deletion) 3, the
// weights help_unknown_cmd passes, over bytes. a and b are at most maxCandidate bytes.
func levenshtein(a, b string) int {
	const w, s, ins, del = 0, 2, 1, 3
	var r0, r1, r2 [maxCandidate + 2]int
	row0, row1, row2 := r0[:len(b)+1], r1[:len(b)+1], r2[:len(b)+1]
	for j := 0; j <= len(b); j++ {
		row1[j] = j * ins
	}
	for i := 0; i < len(a); i++ {
		row2[0] = (i + 1) * del
		for j := 0; j < len(b); j++ {
			v := row1[j]
			if a[i] != b[j] {
				v += s
			}
			if i > 0 && j > 0 && a[i-1] == b[j] && a[i] == b[j-1] && v > row0[j-1]+w {
				v = row0[j-1] + w
			}
			if v > row1[j+1]+del {
				v = row1[j+1] + del
			}
			if v > row2[j]+ins {
				v = row2[j] + ins
			}
			row2[j+1] = v
		}
		row0, row1, row2 = row1, row2, row0
	}
	return row1[len(b)]
}
