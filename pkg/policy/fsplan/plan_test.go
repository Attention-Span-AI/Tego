// SPDX-License-Identifier: Apache-2.0

package fsplan

import (
	"reflect"
	"testing"
)

func TestCompileAndHeldPlan(t *testing.T) {
	targets := []Target{{"/work/key", 1}, {"/vault", 2}, {"/vault/deep/key", 3}, {"/vault2/key", -1}, {"/workmate/key", 4}}
	p := Build(targets, []string{"/work"})
	if !reflect.DeepEqual(p.Unenforced, []bool{true, false, false, false, false}) {
		t.Fatalf("containment %v", p.Unenforced)
	}
	if !reflect.DeepEqual(p.Targets, []Target{{"/vault", 2}, {"/vault2/key", -1}, {"/workmate/key", 4}}) {
		t.Fatalf("outer targets %v", p.Targets)
	}
	if len(p.Levels) != 3 || p.Levels[0].Path != "/" || !p.Levels[0].Exclude["vault"] || !p.Levels[1].Exclude["key"] {
		t.Fatalf("levels %+v", p.Levels)
	}
	// /vault2 aliases the held outer deny target. Its whole tree stays sealed;
	// an unrelated /workmate ancestor remains eligible for enumeration.
	if got := p.Enumerate([]int{0, 2, 5}); !reflect.DeepEqual(got, []bool{true, false, true}) {
		t.Fatalf("identity exclusion %v", got)
	}
}

func TestAliasExclusionPropagates(t *testing.T) {
	p := Build([]Target{{"/vault", 4}, {"/alias/a/b/key", 8}}, nil)
	refs := []int{0, 4, -1, -1}
	if got := p.Enumerate(refs); !reflect.DeepEqual(got, []bool{true, false, false, false}) {
		t.Fatalf("alias subtree grants %v", got)
	}
	s := p.Selection()
	for i, ref := range refs {
		if s.NeedsHold() != (i < 2) {
			t.Fatalf("level %d: unnecessary denied-descendant lookup", i)
		}
		if got := s.Advance(ref); got != (i == 0) {
			t.Fatalf("level %d selection=%v", i, got)
		}
	}
}

func TestGrantIndexPreservesDeclarationOrder(t *testing.T) {
	paths := []string{"/work", "/work/secret", "/", "/work"}
	g := NewGrants(paths)
	for _, target := range []string{"/work/secret/x", "/workmate/x", "/work"} {
		want := -1
		for i, p := range paths {
			if Contains(p, target) {
				want = i
				break
			}
		}
		if got := g.FirstCover(target); got != want {
			t.Errorf("%s: first=%d want %d", target, got, want)
		}
	}
}
