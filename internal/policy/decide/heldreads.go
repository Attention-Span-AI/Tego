// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file is held reads' floor in the decision core (ADR 0069 D3): what a read open the open deputy completes is
// refused for, asked of the object the deputy reached. The supervisor asks it of every held read open
// (supervisor held_reads.go), and Evaluate of a read at a tier whose runs hold their reads, so compile --test and the
// run answer alike (ADR 0028: one model).

// HeldReadIndex is a table's held-read floor, indexed once: its queries allocate one folded copy of the path and
// nothing else. A nil index refuses nothing.
type HeldReadIndex struct {
	rt     *agent.RuleTable
	pinned map[HeldReadID]string
	// literal is every literal deny_read name rule (a built-in home path, a glob with no metacharacter left after its
	// escapes), ASCII folded, to its rule; globs are the rest, as compiled and folded.
	literal map[string]string
	globs   []heldGlob
	// exempt is ADR 0043 D3's exemptions of the built-in .env names: folded final names in each canonical directory.
	exempt map[string]map[string]bool
}

type heldGlob struct{ pattern, folded, rule string }

// HeldReadID identifies a live object. The caller retains its descriptor so an
// unlinked inode cannot be recycled while the index is in use.
type HeldReadID struct{ Dev, Ino uint64 }

// HeldReadPin is a launch-pinned object and the entry that refuses its reads.
type HeldReadPin struct {
	ID   HeldReadID
	Rule string
}

// NewHeldReadIndex indexes rt's held-read floor (agent.RuleTable.Reads), nil for a nil table.
func NewHeldReadIndex(rt *agent.RuleTable, pins ...HeldReadPin) *HeldReadIndex {
	if rt == nil {
		return nil
	}
	x := &HeldReadIndex{rt: rt, literal: map[string]string{}, pinned: map[HeldReadID]string{}}
	for _, p := range pins {
		x.pinned[p.ID] = p.Rule
	}
	for _, p := range rt.Reads.Patterns {
		if lit, ok := literalPattern(p.Pattern); ok {
			if _, dup := x.literal[agent.FoldName(lit)]; !dup {
				x.literal[agent.FoldName(lit)] = p.Rule
			}
			continue
		}
		x.globs = append(x.globs, heldGlob{pattern: p.Pattern, folded: agent.FoldName(p.Pattern), rule: p.Rule})
	}
	for _, e := range rt.Reads.Exempt {
		if x.exempt == nil {
			x.exempt = map[string]map[string]bool{}
		}
		if x.exempt[e.Parent] == nil {
			x.exempt[e.Parent] = map[string]bool{}
		}
		x.exempt[e.Parent][e.Name] = true
	}
	return x
}

// literalPattern is a filepath.Match pattern's literal path when it has no metacharacter but escaped ones.
func literalPattern(p string) (string, bool) {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			if i+1 == len(p) {
				return "", false
			}
			i++
			out = append(out, p[i])
		case '*', '?', '[':
			return "", false
		default:
			out = append(out, c)
		}
	}
	return string(out), true
}

// Refusal is the held-read floor of a read open of the object at path, a clean absolute canonical path (dir: the
// object is a directory). It refuses, naming the entry:
//
//	(a) an object at or beneath a deny_read entry that is the nearest entry deciding a read there, whether the
//	    Landlock ruleset enforces it or not (nested in a write entry): a nested target directory itself included;
//	(c) an object a deny_read name rule covers, whenever it was made: a RuleTable.Reads.Patterns entry at it or at an
//	    ancestor, ASCII folded too, or, for a file, a built-in .env name beneath one of the .env scan's roots outside
//	    the dependency directories (ADR 0043 Terms, F3), unless D3 exempts it. A climb that cannot decide within
//	    agent.MaxWalk refuses (fail closed). A write entry nearer the object than the ancestor a name rule matched
//	    reopens its own subtree, as it does under (a).
//
// rules is the table's resolved advisory list where the caller has one (the supervisor's), nil to ask the table by
// scan. RefusalOn also checks (b), the launch-pinned identity; (d), tego's own
// state, is the supervisor's (ownStateOf).
func (x *HeldReadIndex) Refusal(rules *AdvisoryList, path string, dir bool) (rule string, refused bool) {
	return x.RefusalOn(rules, path, dir, HeldReadID{})
}

// RefusalOn checks the retained launch identity before the object's current name.
// This also refuses a hard-link alias or a nameless reopened descriptor.
func (x *HeldReadIndex) RefusalOn(rules *AdvisoryList, path string, dir bool, id HeldReadID) (rule string, refused bool) {
	if x != nil {
		if rule, ok := x.pinned[id]; ok {
			return rule, true
		}
	}
	if x == nil || path == "" || path[0] != '/' {
		return "", false
	}
	// reopen is how many steps above the object the nearest write entry deciding a read there lies, -1 for none: a
	// name rule matched farther up is outvoted by it, as (a)'s nearest entry is (SEMANTICS §2), and one matched at the
	// write entry itself or nearer still refuses (a tie goes to the deny_read, fail closed).
	reopen := -1
	if rules != nil {
		if d := nearestReadIn(rules, path); d != nil {
			if d.DenyRead {
				return d.Name, true
			}
			reopen = advisorySteps(d.Path, path)
		}
	} else if i, ok := heldNearestRead(x.rt, path); ok {
		if x.rt.FS[i].Kind == agent.FSDenyRead {
			return x.rt.FS[i].RuleName(), true
		}
		reopen, _ = ruleSteps(x.rt.FS[i], path)
	}
	folded := agent.FoldName(path)
	if len(x.literal) > 0 || len(x.globs) > 0 {
		for end, steps := len(path), 0; end > 0 && (reopen < 0 || steps <= reopen); steps++ {
			q, fq := path[:end], folded[:end]
			if r, ok := x.literal[fq]; ok {
				return r, true
			}
			for _, g := range x.globs {
				if ok, _ := filepath.Match(g.pattern, q); ok {
					return g.rule, true
				}
				if ok, _ := filepath.Match(g.folded, fq); ok {
					return g.rule, true
				}
			}
			end = lastSlash(path, end)
		}
	}
	if dir || len(x.rt.Reads.Names) == 0 {
		return "", false
	}
	i := len(path) - 1
	for i > 0 && path[i] != '/' {
		i--
	}
	name, parent := path[i+1:], path[:i]
	if parent == "" {
		parent = "/"
	}
	for j := range x.rt.Reads.Names {
		e := &x.rt.Reads.Names[j]
		if !e.Matches(name) {
			continue
		}
		if x.exempt[parent][folded[i+1:]] {
			return "", false
		}
		scope, _, covered, unresolved := agent.NameClimbDir(e.Scopes, parent)
		switch {
		case unresolved:
			return e.RuleName(0), true
		case covered:
			return e.RuleName(scope), true
		}
	}
	return "", false
}

// lastSlash is the length of path[:end]'s parent: the position of the last "/" before end, 1 for a parent of "/"
// itself, and 0 once "/" was asked.
func lastSlash(path string, end int) int {
	if end == 1 {
		return 0
	}
	for i := end - 1; i > 0; i-- {
		if path[i] == '/' {
			return i
		}
	}
	return 1
}

// heldNearestRead is nearestReadDeciding with no walk bound: a held read is decided in userspace on the object's
// whole path, as Landlock checks every rule up to the root, however deep (evalFSLandlock).
func heldNearestRead(rt *agent.RuleTable, path string) (int, bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		if k := rt.FS[i].Kind; k != agent.FSWrite && k != agent.FSDenyRead {
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
