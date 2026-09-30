// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"sort"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// listenerIndexes builds tier 2's listener indexes from rt as internal/runtime/enforce/cgroup's newPolicy does:
// every deny_read and write entry under each of its spellings, as a directory, longest path first.
func listenerIndexes(rt *agent.RuleTable) (deny, readable PathIndex, denyNames []string) {
	type entry struct {
		path, rule string
	}
	var d, w []entry
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Path == "" {
			continue
		}
		for _, p := range r.Spellings() {
			switch r.Kind {
			case agent.FSDenyRead:
				d = append(d, entry{p, r.RuleName()})
			case agent.FSWrite:
				w = append(w, entry{p, r.RuleName()})
			}
		}
	}
	index := func(list []entry) (PathIndex, []string) {
		sort.Slice(list, func(i, j int) bool { return len(list[i].path) > len(list[j].path) })
		keys := make([]IndexEntry, len(list))
		names := make([]string, len(list))
		for i, e := range list {
			keys[i], names[i] = IndexEntry{Path: e.path, Dir: true}, e.rule
		}
		return NewPathIndex(keys), names
	}
	deny, denyNames = index(d)
	readable, _ = index(w)
	return deny, readable, denyNames
}

// TestListenerOpenMatchesTheTableWalk: tier 2's listener decides an open on its index (ListenerOpen), and
// Evaluate's tier-2 column and the supervisor's advisory write-open verdict on a walk of the table
// (ListenerOpenRefused). The two give every canonical path of every generated table one answer, and a refusal
// one rule.
func TestListenerOpenMatchesTheTableWalk(t *testing.T) {
	bad := 0
	genTables(backend.TierCgroup, func(desc string, rt *agent.RuleTable) {
		deny, readable, names := listenerIndexes(rt)
		for _, p := range genPaths {
			i, refused := ListenerOpen(&deny, &readable, p)
			r, want := ListenerOpenRefused(rt, p)
			if refused != want || (refused && names[i] != r.RuleName()) {
				bad++
				if bad < 20 {
					got := ""
					if refused {
						got = names[i]
					}
					t.Errorf("%s %s: index refused=%v %s, walk refused=%v %s", desc, p, refused, got, want, r.RuleName())
				}
			}
		}
	})
}

// TestListenerExec: a binary no entry covers is refused unless the contract has no exec: section.
func TestListenerExec(t *testing.T) {
	x := NewPathIndex([]IndexEntry{{Path: "/usr/bin/git"}, {Path: "/opt/tools", Dir: true}})
	for _, tc := range []struct {
		open bool
		path string
		want bool
	}{
		{false, "/usr/bin/git", true},
		{false, "/opt/tools/rg", true},
		{false, "/usr/bin/curl", false},
		{false, "/usr/bin/git/x", false},
		{true, "/usr/bin/curl", true},
	} {
		if got := ListenerExec(tc.open, &x, tc.path); got != tc.want {
			t.Errorf("ListenerExec(%v, %s) = %v, want %v", tc.open, tc.path, got, tc.want)
		}
	}
}
