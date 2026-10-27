// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// userDenyWrite is a table's fs.deny_write entries (ADR 0071, agent.FSRule.IsDeclaredDenyWrite) indexed for nearest
// wins: a write entry strictly beneath an entry reopens its subtree, so the entry reaches a path only when no reopen
// spelling (agent.RuleTable.DenyWriteReopens) lies strictly beneath the spelling it matched at and at or above the path.
// Both indexes that answer agent.RuleTable.DenyWriteTarget ask it, the supervisor's (FSIndex) and the plane rows'
// (planeIndex), with the answer the scan gives (TestUserDenyWriteIndexMatchesScan): one walk from the path upward,
// where a reopen spelling met shadows its entries at every level above it.
type userDenyWrite struct {
	// at is each entry's clean spellings, to its positions in RuleTable.DenyWrite; reopen is each reopen spelling, to
	// the positions of the entries it reopens.
	at, reopen map[string][]int
	// below is the entries as a targetIndex, for a rename's question of the entries beneath a path, which no write
	// entry reopens.
	below *targetIndex
	// scan is set when an entry's spelling is one the index cannot key as Covers compares it: FSIndex then asks the
	// scan.
	scan bool
}

// newUserDenyWrite indexes rt's fs.deny_write entries, nil when it has none.
func newUserDenyWrite(rt *agent.RuleTable) *userDenyWrite {
	var u *userDenyWrite
	for j := range rt.DenyWrite {
		r := &rt.DenyWrite[j]
		if !r.IsDeclaredDenyWrite() {
			continue
		}
		if u == nil {
			u = &userDenyWrite{at: map[string][]int{}, reopen: map[string][]int{}, below: newTargetIndex(rt.DenyWrite, declaredDenyWrite)}
			u.scan = u.below.scan
		}
		for _, t := range [2]string{r.Path, r.Resolved} {
			if t == "" {
				continue
			}
			if c := filepath.Clean(t); c != "." && !slices.Contains(u.at[c], j) {
				u.at[c] = append(u.at[c], j)
			}
		}
		for _, s := range rt.DenyWriteReopens(r) {
			u.reopen[s] = append(u.reopen[s], j)
		}
	}
	return u
}

// declaredDenyWrite selects the fs.deny_write entries of RuleTable.DenyWrite.
func declaredDenyWrite(r *agent.FSRule) bool { return r.IsDeclaredDenyWrite() }

// builtInDenyWrite selects the built-in targets (and a hand-built table's unmarked rules).
func builtInDenyWrite(r *agent.FSRule) bool { return !r.IsDeclaredDenyWrite() }

// nearest is the lowest position of an entry at or above the clean path p that no reopen spelling met beneath it
// shadows, -1 for none; with name (a rename of p, or a modification that makes the name p: agent.RuleTable's
// DenyWriteNameTarget) a reopen spelling at p itself shadows nothing, since the write entry's own name is the
// entry's. It allocates nothing (it collected the shadowed positions in a slice, one allocation per question in a
// reopened subtree, the supervisor's per-notification path): a candidate's shadow is looked up again
// on the levels between p and where it was met.
func (u *userDenyWrite) nearest(p string, name bool) int {
	best := -1
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		for _, j := range u.at[cur] {
			if (best < 0 || j < best) && !u.reopenedBelow(p, cur, j, name) {
				best = j
			}
		}
	}
	return best
}

// reopenedBelow reports whether a reopen spelling of entry j lies at (unless name) or above p and strictly beneath t,
// an ancestor of p (or p itself) at which j has a spelling.
func (u *userDenyWrite) reopenedBelow(p, t string, j int, name bool) bool {
	cur, ok := p, true
	if name {
		cur, ok = parent(p)
	}
	for ; ok && p != t && cur != t; cur, ok = parent(cur) {
		if slices.Contains(u.reopen[cur], j) {
			return true
		}
	}
	return false
}

// lowerPos is the lower of two positions, -1 meaning none.
func lowerPos(a, b int) int {
	if a < 0 || (b >= 0 && b < a) {
		return b
	}
	return a
}
