// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file is ADR 0043's name entries in the decision core: one index of a table's RuleTable.NameDeny and
// NameExempt that every model asks by canonical path (ADR 0028: one model), Evaluate's root tiers and, through the
// plane's rows, compile --test's bpflsm column (planerows.go). It answers two questions: does a name entry cover the
// object at a path (D1 to D4), and does a directory rename take covered files out of coverage (D5).

// NameIndex is a table's name entries indexed for the root tiers' models. A nil NameIndex covers nothing, which is
// what a table without name entries gets. It is built once and read only; its queries allocate nothing.
type NameIndex struct {
	rt *agent.RuleTable
	// exempt is D3's exemptions: the folded final names exempt in each canonical parent directory.
	exempt map[string]map[string]bool
	// labels is each entry's rule name per scope (agent.NameDenyRule.RuleName), built once so naming a refusal
	// allocates nothing.
	labels [][]string
	// minLen is the shortest literal: a shorter final name matches nothing, which keeps a miss to one compare.
	minLen int
}

// NewNameIndex indexes rt's name entries, nil when there are none or no mechanism of this build enforces them.
func NewNameIndex(rt *agent.RuleTable) *NameIndex {
	n := newNameIndex(rt)
	if n == nil {
		return nil
	}
	n.labels = make([][]string, len(rt.NameDeny))
	for i := range rt.NameDeny {
		e := &rt.NameDeny[i]
		n.labels[i] = make([]string, len(e.Scopes))
		for j := range e.Scopes {
			n.labels[i][j] = e.RuleName(j)
		}
	}
	return n
}

// newNameIndex is NewNameIndex without the prebuilt rule names: the reference Evaluate's, built per call, which
// names a refusal as it makes it.
func newNameIndex(rt *agent.RuleTable) *NameIndex {
	if rt == nil || len(rt.NameDeny) == 0 {
		return nil
	}
	n := &NameIndex{rt: rt, minLen: -1}
	for i := range rt.NameDeny {
		if l := len(rt.NameDeny[i].Literal); n.minLen < 0 || l < n.minLen {
			n.minLen = l
		}
	}
	for _, x := range rt.NameExempt {
		if n.exempt == nil {
			n.exempt = map[string]map[string]bool{}
		}
		if n.exempt[x.Parent] == nil {
			n.exempt[x.Parent] = map[string]bool{}
		}
		n.exempt[x.Parent][x.Name] = true
	}
	return n
}

// NameMatch is a name entry's answer for one object: the entry (its position in RuleTable.NameDeny) and the scope
// that covered it, or a climb that could not decide within the walk's bound, which refuses path-unresolved.
type NameMatch struct {
	Entry, Scope int
	Unresolved   bool
}

// Match is ADR 0043's question of the object at path, a clean absolute canonical path: the first name entry in
// NameDeny order that covers it, or ok false. dir is the object being a directory, which no name entry decides
// (D1). An object D3 exempts (a top-level write entry at that name in that directory) is covered by none. The first
// entry whose name matches decides: covered, it refuses; unresolved (its climb passed agent.MaxWalk levels before it
// met one of its scopes, a dependency directory or "/"), it refuses path-unresolved; neither, the next entry is
// asked.
func (n *NameIndex) Match(path string, dir bool) (m NameMatch, ok bool) {
	if n == nil || dir || path == "" || path == "/" {
		return NameMatch{}, false
	}
	i := len(path) - 1
	for i >= 0 && path[i] != '/' {
		i--
	}
	if i < 0 {
		return NameMatch{}, false
	}
	name := path[i+1:]
	if len(name) < n.minLen {
		return NameMatch{}, false
	}
	parentPath := path[:i]
	if parentPath == "" {
		parentPath = "/"
	}
	for j := range n.rt.NameDeny {
		e := &n.rt.NameDeny[j]
		if !e.Matches(name) {
			continue
		}
		if n.exempted(parentPath, name) {
			return NameMatch{}, false
		}
		scope, _, covered, unresolved := agent.NameClimbDir(e.Scopes, parentPath)
		switch {
		case unresolved:
			return NameMatch{Entry: j, Scope: -1, Unresolved: true}, true
		case covered:
			return NameMatch{Entry: j, Scope: scope}, true
		}
	}
	return NameMatch{}, false
}

// exempted reports D3's exemption of name in dir: an exemption names the folded final name, and cancels every
// spelling of it there. The name is folded into a stack buffer so the lookup allocates nothing.
func (n *NameIndex) exempted(dir, name string) bool {
	names := n.exempt[dir]
	if names == nil || len(name) > 255 {
		return false
	}
	var buf [255]byte
	for i := 0; i < len(name); i++ {
		buf[i] = agent.FoldByte(name[i])
	}
	return names[string(buf[:len(name)])]
}

// Rule is the rule a refusal by m names (ADR 0043 D8): the RuleTable's own deny_read entry at the object's
// canonical path when it has one (the expansion's, so a refusal of a file the plane compacted is named as before),
// else the entry's own rule name: a declared glob's, or the built-in label naming the scope that decided. at is
// the deny_read entry at the path, -1 for none.
func (n *NameIndex) Rule(m NameMatch, at int) string {
	if at >= 0 {
		return n.rt.FS[at].RuleName()
	}
	if n.labels == nil || m.Scope < 0 || m.Scope >= len(n.labels[m.Entry]) {
		return n.rt.NameDeny[m.Entry].RuleName(m.Scope)
	}
	return n.labels[m.Entry][m.Scope]
}

// MoveRefused is D5's question of a directory rename from src to dst, clean absolute canonical paths: some name
// entry covers files beneath the directory at its old place under its old name and would not at its new place under
// its new name (it leaves every scope of the entry, passes beneath a dependency directory, or takes a dependency
// directory's name). A place's coverage is the climb from it (agent.NameClimbDir: the directory's own name at level
// 1); an entry one of whose scopes is the directory itself is not asked, since its scope moves with it, and nor is
// one that does not cover the old place or that covers the new one. A climb that cannot decide within the bound, at
// an old place that may be covered or a new one that may not, refuses path-unresolved (fail closed). m names the
// entry and the scope that covered the old place.
func (n *NameIndex) MoveRefused(src, dst string) (m NameMatch, refused bool) {
	if n == nil || src == "" || dst == "" || src == dst {
		return NameMatch{}, false
	}
	for j := range n.rt.NameDeny {
		e := &n.rt.NameDeny[j]
		moves := false
		for _, s := range e.Scopes {
			moves = moves || s.Canonical == src
		}
		if moves {
			continue
		}
		scope, _, covered, unresolved := agent.NameClimbDir(e.Scopes, src)
		if !covered && !unresolved {
			continue
		}
		_, _, after, afterUnresolved := agent.NameClimbDir(e.Scopes, dst)
		if after {
			continue // covered at the new place: whatever the old place was, nothing leaves coverage
		}
		return NameMatch{Entry: j, Scope: scope, Unresolved: unresolved || afterUnresolved}, true
	}
	return NameMatch{}, false
}
