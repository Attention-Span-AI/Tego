// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// targetIndex is one of the move-reach predicates on an index: agent.RuleTable.DenyWriteTarget over the
// built-in deny_write targets (supervisor.md R15c), or agent.RuleTable.DenyReadMoveTarget over the deny_read
// entries the Landlock ruleset leaves unenforced (R15d). The supervisor asks the first for each end of every
// notified modification and the second for every link and rename at tier 2, at each end and again where each
// end lands; by scan a miss walked every entry, 12–15 ms against the 50,000 the .env scan can plant, and the
// deny_write set grows with every repository the compile's search finds beneath a write entry. at maps each spelling to the lowest position spelled there, for the entries at or above a path,
// one map lookup per ancestor; sorted holds the spellings in byte order with a range-minimum tree over their
// positions, for the entries beneath a path (a rename's ancestors case), which lie in one contiguous run of it.
type targetIndex struct {
	at     map[string]int
	sorted []string
	// tree is a range-minimum segment tree over the positions of sorted, of size 2*len(sorted).
	tree []int
	// scan is set when a spelling is one the index cannot key as Covers compares it (not clean, or "."):
	// every question is then the scan's.
	scan bool
}

// newTargetIndex indexes the rules keep selects (all of them when keep is nil), by position in rules.
func newTargetIndex(rules []agent.FSRule, keep func(*agent.FSRule) bool) *targetIndex {
	tx := &targetIndex{at: map[string]int{}}
	type spelled struct {
		s string
		i int
	}
	var all []spelled
	for i := range rules {
		r := &rules[i]
		if keep != nil && !keep(r) {
			continue
		}
		for _, s := range [2]string{r.Path, r.Resolved} {
			if s == "" {
				continue
			}
			if filepath.Clean(s) != s || s == "." {
				tx.scan = true
				return tx
			}
			if _, ok := tx.at[s]; !ok {
				tx.at[s] = i
				all = append(all, spelled{s, i})
			}
		}
	}
	sort.Slice(all, func(a, b int) bool { return all[a].s < all[b].s })
	n := len(all)
	tx.sorted = make([]string, n)
	tx.tree = make([]int, 2*n)
	for k, e := range all {
		tx.sorted[k] = e.s
		tx.tree[n+k] = e.i
	}
	for k := n - 1; k > 0; k-- {
		tx.tree[k] = min(tx.tree[2*k], tx.tree[2*k+1])
	}
	return tx
}

// unenforcedDenyRead selects the entries agent.RuleTable.DenyReadMoveTarget matches.
func unenforcedDenyRead(r *agent.FSRule) bool { return r.Kind == agent.FSDenyRead && r.Unenforced }

// minIn is the lowest position among sorted[lo:hi], -1 when the run is empty.
func (tx *targetIndex) minIn(lo, hi int) int {
	best := -1
	n := len(tx.sorted)
	for lo, hi = lo+n, hi+n; lo < hi; lo, hi = lo/2, hi/2 {
		if lo&1 == 1 {
			if best < 0 || tx.tree[lo] < best {
				best = tx.tree[lo]
			}
			lo++
		}
		if hi&1 == 1 {
			hi--
			if best < 0 || tx.tree[hi] < best {
				best = tx.tree[hi]
			}
		}
	}
	return best
}

// lookup is the lowest position of an entry at or above the clean path p or, with ancestors, beneath it.
func (tx *targetIndex) lookup(p string, ancestors bool) int {
	best := -1
	if p == "." {
		return best
	}
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if i, hit := tx.at[cur]; hit && (best < 0 || i < best) {
			best = i
		}
	}
	if !ancestors {
		return best
	}
	return lowerPos(best, tx.below(p))
}

// below is the lowest position of an entry strictly beneath the clean path p, -1 for none.
func (tx *targetIndex) below(p string) int {
	// Every spelling beneath p starts with base+"/", and those sort in one run from the first at or after it.
	// The prefix is compared in place: a path longer than the compiler's stack buffer allocated its join.
	base := p
	if p == "/" {
		base = ""
	}
	lo := sort.Search(len(tx.sorted), func(k int) bool { return cmpSlash(tx.sorted[k], base) >= 0 })
	hi := lo + sort.Search(len(tx.sorted)-lo, func(k int) bool { return !underSlash(tx.sorted[lo+k], base) })
	return tx.minIn(lo, hi)
}

// cmpSlash is strings.Compare(s, base+"/") without the join.
func cmpSlash(s, base string) int {
	n := min(len(s), len(base))
	if c := strings.Compare(s[:n], base[:n]); c != 0 {
		return c
	}
	// One begins with the other.
	switch {
	case len(s) <= len(base) || s[len(base)] < '/':
		return -1
	case s[len(base)] > '/':
		return 1
	case len(s) == len(base)+1:
		return 0
	}
	return 1
}

// underSlash is strings.HasPrefix(s, base+"/") without the join.
func underSlash(s, base string) bool {
	return len(s) > len(base) && s[len(base)] == '/' && s[:len(base)] == base
}

// DenyWriteTarget is rt.DenyWriteTarget(p, ancestors) on the index: the same target, the lowest position among
// those that match, at the cost of a map lookup per ancestor of p and two binary searches whatever the number of
// targets (TestDenyWriteTargetCostDoesNotGrowWithEntries). A table with a target spelled unclean is asked by scan. The
// built-in targets are one targetIndex; the fs.deny_write entries, which a nested write entry reopens (ADR 0071), are
// asked by nearest wins at or above p (userDenyWrite) and as the built-in targets are beneath it.
func (ix *FSIndex) DenyWriteTarget(p string, ancestors bool) (agent.FSRule, bool) {
	if ix == nil || p == "" {
		return agent.FSRule{}, false
	}
	i, scan := ix.denyWritePos(filepath.Clean(p), ancestors, ancestors)
	if scan {
		return ix.rt.DenyWriteTarget(p, ancestors)
	}
	if i >= 0 {
		return ix.rt.DenyWrite[i], true
	}
	return agent.FSRule{}, false
}

// DenyWriteNameTarget is rt.DenyWriteNameTarget(p) on the index: the deny_write rule a modification that makes the name
// p reaches (a mkdir, a mknod, a symlink, an exclusive create, a hard link's new name), at DenyWriteTarget's cost.
func (ix *FSIndex) DenyWriteNameTarget(p string) (agent.FSRule, bool) {
	if ix == nil || p == "" {
		return agent.FSRule{}, false
	}
	i, scan := ix.denyWritePos(filepath.Clean(p), false, true)
	if scan {
		return ix.rt.DenyWriteNameTarget(p)
	}
	if i >= 0 {
		return ix.rt.DenyWrite[i], true
	}
	return agent.FSRule{}, false
}

// denyWritePos is DenyWriteTarget's answer for the clean path p as a position in RuleTable.DenyWrite, -1 for none, and
// with name DenyWriteNameTarget's; scan reports a table the index cannot answer, which the caller asks by scan.
func (ix *FSIndex) denyWritePos(p string, ancestors, name bool) (i int, scan bool) {
	if ix.denyWrite == nil || ix.denyWrite.scan || (ix.userDW != nil && ix.userDW.scan) {
		return -1, true
	}
	i = ix.denyWrite.lookup(p, ancestors)
	if u := ix.userDW; u != nil {
		i = lowerPos(i, u.nearest(p, name))
		if ancestors {
			i = lowerPos(i, u.below.below(p))
		}
	}
	return i, false
}

// DenyReadMoveTarget is rt.DenyReadMoveTarget(p, ancestors) on the index: the same entry, the lowest position
// among those that match, at the cost of a map lookup per ancestor of p and two binary searches whatever the
// number of entries (TestDenyReadMoveTargetCostDoesNotGrowWithEntries).
func (ix *FSIndex) DenyReadMoveTarget(p string, ancestors bool) (agent.FSRule, bool) {
	if ix == nil || p == "" {
		return agent.FSRule{}, false
	}
	if ix.scan || ix.move == nil || ix.move.scan {
		return ix.rt.DenyReadMoveTarget(p, ancestors)
	}
	if i := ix.move.lookup(filepath.Clean(p), ancestors); i >= 0 {
		return ix.rt.FS[i], true
	}
	return agent.FSRule{}, false
}

// HasDenyReadMove reports whether any entry could answer DenyReadMoveTarget: a deny_read the Landlock ruleset
// leaves unenforced.
func (ix *FSIndex) HasDenyReadMove() bool {
	if ix == nil {
		return false
	}
	if ix.scan || ix.move == nil || ix.move.scan {
		return HasDenyReadMove(ix.rt)
	}
	return len(ix.move.sorted) > 0
}

// HasDenyReadMove reports whether rt has a deny_read entry the Landlock ruleset leaves unenforced, the entries
// rt.DenyReadMoveTarget matches.
func HasDenyReadMove(rt *agent.RuleTable) bool {
	if rt == nil {
		return false
	}
	for i := range rt.FS {
		if unenforcedDenyRead(&rt.FS[i]) {
			return true
		}
	}
	return false
}
