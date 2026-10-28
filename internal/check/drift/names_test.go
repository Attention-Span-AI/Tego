// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestDriftDeclaresNameEntries is ADR 0043 D8 in drift (R14, R15): each name entry is
// declared under every name its refusals carry, read-only as a deny_read entry is: a declared glob that matched no
// file at compile (so the table has no fs entry of it) is the author's own entry, and the built-in .env list's label
// under each scope's spelling is declared but no entry of the author's.
func TestDriftDeclaresNameEntries(t *testing.T) {
	scopes := []agent.NameScope{{Canonical: "/home/u/p", Spelling: "/home/u/p"}, {Canonical: "/srv/w", Spelling: "/srv/w"}}
	rt := &agent.RuleTable{
		Contract: &agent.Contract{Name: "tester"},
		FS:       []agent.FSRule{{Path: "/home/u/p", Raw: ".", Kind: agent.FSWrite}},
		NameDeny: []agent.NameDenyRule{
			{Literal: "token.json", Raw: "cfg/*/token.json", Scopes: scopes[:1]},
			{Literal: ".env", BuiltIn: true, Scopes: scopes},
		},
	}
	glob, labels := rt.NameDeny[0].RuleName(0), []string{rt.NameDeny[1].RuleName(0), rt.NameDeny[1].RuleName(1)}
	if glob != "fs.deny_read[cfg/*/token.json]" || labels[0] == labels[1] {
		t.Fatalf("the entries' names are %q and %v", glob, labels)
	}
	b := newBuckets()
	b.declare(rt)
	for _, name := range append([]string{glob}, labels...) {
		if c := b.get(SectionFS, name); !c.Declared || !b.readOnly[name] {
			t.Errorf("%s declared=%v read-only=%v, want both", name, c.Declared, b.readOnly[name])
		}
	}
	if !slices.Contains(b.declared[SectionFS], glob) {
		t.Errorf("the declared glob is not the author's own entry")
	}
	for _, l := range labels {
		if slices.Contains(b.declared[SectionFS], l) {
			t.Errorf("the built-in label %s was listed as the author's own entry", l)
		}
	}
}
