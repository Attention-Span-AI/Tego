// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Canonical rewrites the longest prefix of path that is a symlinked entry's declared Path into the entry's
// Resolved path, the spelling every tier decides on: Landlock holds the link's target, tier 2's listener is
// handed the opened file's canonical path, and tier 3's hooks see the dentry. It reads the table alone (I6), so
// only a link some entry declares is followed. ruleSteps matched both spellings of an entry, but a path through
// one entry's link lying under *another* entry's canonical path never met that entry: with `deny_read: [/l]`
// (→ /w/a) and `write: [/w/a/b]`, a read of /l/b/f was refused where every tier allows it (R15). The
// common case, no link or no hit, returns path itself and allocates nothing.
func Canonical(rt *agent.RuleTable, path string) string {
	best, bestLen := -1, -1
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Resolved == "" || r.Resolved == r.Path || len(r.Path) <= bestLen {
			continue
		}
		if agent.Covers(r.Path, path) && filepath.Clean(r.Resolved) != filepath.Clean(r.Path) {
			best, bestLen = i, len(r.Path)
		}
	}
	if best < 0 {
		return path
	}
	r := &rt.FS[best]
	rest := strings.TrimPrefix(path, filepath.Clean(r.Path))
	return filepath.Join(filepath.Clean(r.Resolved), rest)
}

// nearestFS returns the entry that is path or its nearest ancestor and how
// many walk steps above path it sits.
func nearestFS(rt *agent.RuleTable, path string) (idx, steps int, ok bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, bestSteps, best >= 0
}

// nearestFSOfKind is nearestFS restricted to one entry kind. It is the Landlock arm's question (tiers 1
// and 2, and the loader grant Prepare refuses), so it bounds no depth: Landlock unions the rules on the
// whole path, and agent.MaxWalk is the root tiers' walk alone (R15, SEMANTICS §2).
func nearestFSOfKind(rt *agent.RuleTable, path string, kind agent.FSKind) (int, bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		if rt.FS[i].Kind != kind {
			continue
		}
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, best >= 0
}

// ruleSteps is CoverSteps for an entry under every spelling it is matched by: the path as compiled and,
// where it differs, the resolved subtree it governs (FSRule.Resolved). Landlock opens each entry following
// its links and tier 2's listener matches both spellings (FSRule.Spellings), so a
// walk over the declared spelling alone answered for a symlinked entry as if it did not exist: a read of the
// target of `deny_read: [secretlink]` was reported allow (R15). The nearer of the
// two decides; the entry's name stays its declared text (RuleName).
func ruleSteps(r agent.FSRule, path string) (int, bool) {
	n, ok := agent.CoverSteps(r.Path, path)
	if r.Resolved != "" && filepath.Clean(r.Resolved) != filepath.Clean(r.Path) {
		if m, rok := agent.CoverSteps(r.Resolved, path); rok && (!ok || m < n) {
			n, ok = m, true
		}
	}
	return n, ok
}
