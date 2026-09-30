// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file is the root model reduced to what tier 3's decision plane keys by inode (ADR 0024, ADR 0025 (1);
// docs/p0/TIER3-PLAN.md §3): one row per path an entry names, each carrying the answer the nearest-wins walk
// takes when it stops there. The plane's row compiler (ADR 0028 S4, TIER3-PLAN T5; planerows.go) completes these
// rows into the ones the kernel walks. What is here is the reference the rows are checked against: RootIndex.Walk is the walk bpf/decide.bpf.c makes, over the rows alone, and
// TestRootWalkMatchesEvaluate holds it, through the test oracle in rootoracle_test.go, to Evaluate's bpflsm column, so the plane and compile --test cannot
// disagree about the contract (TIER3-PLAN §5).

// RootCell is one question's answer at one row: the entry that decides it there, and its verdict.
type RootCell struct {
	// Rule is the deciding entry's position in RuleTable.FS (the source of the plane's rule_idx), -1 when no
	// entry naming this row's path decides the question and the walk goes on to the parent.
	Rule  int
	Allow bool
}

// Decides reports whether the walk stops at this cell.
func (c RootCell) Decides() bool { return c.Rule >= 0 }

// RootRow is one path the root model's walk can stop at: the canonical path (agent.FSRule.Canonical) of at
// least one fs entry, which is the spelling the kernel's dentry walk meets and so the inode the plane keys.
type RootRow struct {
	Path string
	// Named is the entry that names an action stopping here: the first entry of any kind, watch and implicit
	// included, naming Path (SEMANTICS §7's attribution); never -1.
	Named int
	// Read is a read's answer here: a file_open without a write mode, and the open of an exec. Only a write
	// or a deny_read entry decides one, and a write entry nested at or beneath an enforced deny_read target
	// reopens it (FSDecider).
	Read RootCell
	// Modify is a modification's answer here: a write, create, delete, rename, mkdir or link. Every entry but
	// a watch entry decides one; only a write entry allows it.
	Modify RootCell
}

// RootVerdict is what the root model's walk answers for one path.
type RootVerdict struct {
	// Allow is the verdict.
	Allow bool
	// Rule is the deciding entry's position in RuleTable.FS, -1 when no entry decided: an unmatched read
	// (allowed) or modification (refused), or an exhausted walk.
	Rule int
	// Named is the entry that names the action, the nearest of any kind, -1 when none lies within the bound.
	Named int
	// Unresolved is an exhausted walk: no row within agent.MaxWalk steps of a path deeper than that, refused
	// path-unresolved (SEMANTICS §2).
	Unresolved bool
}

// RootIndex is a table's root rows (rowIndex.rows, PlaneRows.RootRows) by path, for the reference walk.
type RootIndex struct {
	rows  []RootRow
	byKey map[string]int
}

// NewRootIndex indexes rows by path.
func NewRootIndex(rows []RootRow) RootIndex {
	x := RootIndex{rows: rows, byKey: make(map[string]int, len(rows))}
	for i, r := range rows {
		x.byKey[r.Path] = i
	}
	return x
}

// Walk is the root model's walk over the rows alone, as the plane makes it (TIER3-PLAN §3): from path, a
// clean absolute canonical path, through each parent to "/", at most agent.MaxWalk steps, the first row whose
// cell for the question decides answers it. A walk that meets no deciding cell is unmatched: a read is
// allowed and a modification refused. One that meets no row at all within the bound, on a path deeper than
// the bound, is exhausted and refused path-unresolved.
func (x *RootIndex) Walk(path string, read bool) RootVerdict {
	v := RootVerdict{Rule: -1, Named: -1}
	cur := path
	for step := 0; step <= agent.MaxWalk; step++ {
		if i, ok := x.byKey[cur]; ok {
			r := &x.rows[i]
			if v.Named < 0 {
				v.Named = r.Named
			}
			c := r.Modify
			if read {
				c = r.Read
			}
			if c.Decides() {
				v.Rule, v.Allow = c.Rule, c.Allow
				return v
			}
		}
		if cur == "/" {
			v.Allow = read
			return v
		}
		cur = filepath.Dir(cur)
	}
	if v.Named < 0 && pathDepth(path) > agent.MaxWalk {
		v.Unresolved = true
		return v
	}
	v.Allow = read
	return v
}

// walkBeneath is Walk from path with the row at path itself passed over: the answer the walk gives a file whose own
// row the plane dropped (ADR 0043 D6, compactRows), counted from the file.
func (x *RootIndex) walkBeneath(path string, read bool) RootVerdict {
	v := RootVerdict{Rule: -1, Named: -1}
	cur := path
	for step := 0; step <= agent.MaxWalk; step++ {
		if i, ok := x.byKey[cur]; ok && step > 0 {
			r := &x.rows[i]
			if v.Named < 0 {
				v.Named = r.Named
			}
			c := r.Modify
			if read {
				c = r.Read
			}
			if c.Decides() {
				v.Rule, v.Allow = c.Rule, c.Allow
				return v
			}
		}
		if cur == "/" {
			v.Allow = read
			return v
		}
		cur = filepath.Dir(cur)
	}
	if v.Named < 0 && pathDepth(path) > agent.MaxWalk {
		v.Unresolved = true
		return v
	}
	v.Allow = read
	return v
}
