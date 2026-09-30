// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The root tiers' rule (Evaluator.root): the nearest ancestor with an entry for
// this run decides, bounded at MaxWalk steps; a walk that ends without a hit
// is unmatched (reads allowed, everything else refused) and an exhausted walk
// is refused with path-unresolved (SEMANTICS §2).
//
// The walk that decides skips fs.watch entries. A watch entry is a recording
// selector, not a right: SEMANTICS §7 gives it one effect, whether reads are
// aggregated or emitted individually, and no tier refuses anything because of
// one — Landlock holds the watch path with access 0 and the enclosing write
// rule's mask still grants the mutation, and tier 2's listener gives them no part
// in any decision (a watch entry once reopened a deny_read there,
// enforce-cgroup-observe R8). Letting it decide made `write: [/work]`
// plus `watch: [/work/logs]` refuse every write under /work/logs in the root
// tiers and allow it in tier 1: one contract, two opposite verdicts, and the
// author punished for asking for finer recording.
// internal/runtime/supervisor's own table drops watch entries for this reason.
//
// The walk that *names* the event keeps them, because that is where §7's
// attribution lives and what internal/runtime/observe's rule index reports.

// FSDecider is the entry whose verdict an fs action on path takes in the nearest-wins walk, the chooser
// Evaluator.root decides by and tier 2's recorder infers a record-only sample's verdict by
// (internal/runtime/observe), so the two cannot drift apart. Naming the action is another question: the
// nearest entry of any kind names it, watch and implicit entries included (§7).
//
// A read is decided by the nearest write or deny_read entry (nearestReadDeciding): a watch entry grants and
// withholds nothing and an implicit one is a write guard that grants no read. Under a deny_read the Landlock
// ruleset enforces, a write entry nested at or beneath the target that covers path grants the read by
// Landlock's union (nestedReadGrant), and is returned instead. A modification is decided by the nearest entry
// that is not a watch entry (nearestDeciding). ok is false when no such entry lies within MaxWalk steps.
// The entry is returned in place, not copied: the recorder asks twice per sample, and a copy of each it keeps
// was two allocations on its drain path (CI bench gate, run #36).
func FSDecider(rt *agent.RuleTable, path string, read bool) (*agent.FSRule, bool) {
	if rt == nil || path == "" {
		return nil, false
	}
	if i, ok := fsDecider(rt, Canonical(rt, cleanPath(path)), read); ok {
		return &rt.FS[i], true
	}
	return nil, false
}

// fsDecider is FSDecider's index into rt.FS, on a cleaned path.
func fsDecider(rt *agent.RuleTable, path string, read bool) (int, bool) {
	if !read {
		return nearestDeciding(rt, path)
	}
	i, ok := nearestReadDeciding(rt, path)
	if !ok {
		return -1, false
	}
	if rt.FS[i].Kind == agent.FSDenyRead && !denyUnenforced(rt, i) {
		if w, ok := nestedReadGrant(rt, path, i, true); ok {
			return w, true
		}
	}
	return i, true
}

// nearestReadDeciding is nearestDeciding for a read, which only a write entry (write implies read) or a
// deny_read entry decides. An implicit entry is a write guard, deny-by-design for mutations (R9/R10), and
// grants no read: nearer than a deny_read above it, it answered allow for a read the tiers refuse, as for
// the ledger root beneath ~/.tego (R6a). Tier 2's open decision reads it the same way (its readable set
// holds write entries only), and Landlock grants nothing on an access-0 entry. A watch entry grants nothing
// either (SEMANTICS §7), so it is skipped here too.
func nearestReadDeciding(rt *agent.RuleTable, path string) (int, bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		if k := rt.FS[i].Kind; k != agent.FSWrite && k != agent.FSDenyRead {
			continue
		}
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered || n > agent.MaxWalk {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, best >= 0
}

// nearestDeciding is nearestFS restricted to the entries that carry a verdict
// and to the walk bound: every kind but fs.watch, which selects what is
// recorded and grants or withholds nothing (SEMANTICS §7). Implicit entries
// stay in — they are deny-by-design under R9/R10 and the deny-all-writes rule
// at "/" that `fs: {}` compiles to is one of them.
func nearestDeciding(rt *agent.RuleTable, path string) (int, bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		if rt.FS[i].Kind == agent.FSWatch {
			continue
		}
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered || n > agent.MaxWalk {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, best >= 0
}

// pathDepth counts the components of a cleaned path: the walk length the root
// tiers' 64-step bound applies to.
func pathDepth(path string) int {
	trimmed := strings.Trim(path, string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, string(filepath.Separator)) + 1
}
