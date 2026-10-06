// SPDX-License-Identifier: Apache-2.0

// Package fsplan computes the path and held-reference portion of a Landlock
// filesystem plan. It performs no I/O; callers supply resolved compile names or
// names obtained from their held descriptors at Prepare.
package fsplan

import (
	"path/filepath"
	"sort"
	"strings"
)

// Contains compares clean absolute paths at component boundaries.
func Contains(parent, path string) bool {
	return parent == path || parent == "/" || strings.HasPrefix(path, parent+"/")
}

// FirstCover is the first listed grant covering target, or -1. Keeping order
// makes compile diagnostics name the same grant as the Prepare prediction.
func FirstCover(target string, grants []string) int {
	return NewGrants(grants).FirstCover(target)
}

// Grants is the immutable ancestor index shared by compile prediction and the
// held-object plan. Queries cost path depth, even with many scanned deny files.
type Grants struct{ at map[string]int }

func NewGrants(paths []string) *Grants {
	g := &Grants{at: make(map[string]int, len(paths))}
	for i, p := range paths {
		if _, exists := g.at[p]; !exists {
			g.at[p] = i
		}
	}
	return g
}

// FirstCover returns the first declared enclosing grant, rather than the
// nearest one, preserving compile's diagnostic attribution.
func (g *Grants) FirstCover(target string) int {
	best := -1
	if g == nil {
		return best
	}
	for cur := target; ; cur = filepath.Dir(cur) {
		if i, ok := g.at[cur]; ok && (best < 0 || i < best) {
			best = i
		}
		if cur == "/" || cur == "." || filepath.Dir(cur) == cur {
			return best
		}
	}
}

// Target identifies a deny target. Ref is an index into the caller's immutable
// held-object set; -1 is a vanished target whose held parent supplied its name.
type Target struct {
	Path string
	Ref  int
}

// Level is a directory to seal and enumerate, excluding the named target paths.
type Level struct {
	Path    string
	Exclude map[string]bool
}

// Plan contains one answer per input target and the joint enumeration. Its maps
// and slices are read only after construction.
type Plan struct {
	Unenforced []bool
	Targets    []Target
	Levels     []Level
}

// Build applies the same containment rule to compile or held-object snapshots.
// Outermost targets determine the joint enumeration; nested targets cannot add
// grants inside a denied subtree. Work is proportional to path length rather
// than the product of target and grant counts.
func Build(targets []Target, grants []string) Plan {
	p := Plan{Unenforced: make([]bool, len(targets))}
	grantIndex := NewGrants(grants)
	refs := make(map[string]int, len(targets))
	var paths []string
	for i, t := range targets {
		p.Unenforced[i] = grantIndex.FirstCover(t.Path) >= 0
		if !p.Unenforced[i] {
			paths = append(paths, t.Path)
			if _, ok := refs[t.Path]; !ok {
				refs[t.Path] = t.Ref
			}
		}
	}
	paths = Outermost(paths)
	for _, path := range paths {
		p.Targets = append(p.Targets, Target{Path: path, Ref: refs[path]})
	}
	levels, excludes := Ancestors(paths)
	for _, l := range levels {
		p.Levels = append(p.Levels, Level{Path: l, Exclude: excludes[l]})
	}
	return p
}

// Outermost keeps the first occurrence of each target not beneath another.
// A root target is rejected by the builder before this enumeration helper.
func Outermost(paths []string) []string {
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[p] = true
	}
	kept := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if kept[p] {
			continue
		}
		inside := false
		for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
			if set[p[:i]] {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, p)
			kept[p] = true
		}
	}
	return out
}

// Enumerate selects ancestor references after the caller holds them. A level
// aliasing a held deny target, and every level below it, receives no grant. The
// sorted parent-before-child order also handles a mount stacked below an alias.
// refs corresponds to Levels; identity-deduplicated held objects use one ref.
func (p Plan) Enumerate(refs []int) []bool {
	out := make([]bool, len(p.Levels))
	s := p.Selection()
	for i := range p.Levels {
		ref := -1
		if i < len(refs) {
			ref = refs[i]
		}
		out[i] = s.Advance(ref)
	}
	return out
}

// Selection applies the identity exclusions as ancestor descriptors are held.
// It lets the builder skip opening descendants of an alias to a denied inode,
// without duplicating any pruning decision outside this pure plan.
func (p Plan) Selection() *Selection {
	s := &Selection{levels: p.Levels, denied: make(map[int]bool, len(p.Targets)), inside: make(map[string]bool, len(p.Levels))}
	for _, t := range p.Targets {
		if t.Ref >= 0 {
			s.denied[t.Ref] = true
		}
	}
	return s
}

// Selection is private construction state over a Plan's parent-first levels.
// Advance is called once per level, in order; -1 is a skipped/missing reference.
type Selection struct {
	levels []Level
	denied map[int]bool
	inside map[string]bool
	next   int
}

// NeedsHold reports whether the next level is outside an already denied alias.
func (s *Selection) NeedsHold() bool {
	return s.next < len(s.levels) && !s.inside[filepath.Dir(s.levels[s.next].Path)]
}

// Advance records the next held reference and returns whether to enumerate it.
func (s *Selection) Advance(ref int) bool {
	if s.next >= len(s.levels) {
		return false
	}
	l := s.levels[s.next]
	s.next++
	if ref < 0 || s.denied[ref] || s.inside[filepath.Dir(l.Path)] {
		s.inside[l.Path] = true
		return false
	}
	return true
}

// Ancestors returns every ancestor level and the names it must exclude.
func Ancestors(targets []string) ([]string, map[string]map[string]bool) {
	onPath := map[string]map[string]bool{}
	for _, path := range targets {
		for cur := path; cur != "/" && cur != "."; {
			parent := filepath.Dir(cur)
			if onPath[parent] == nil {
				onPath[parent] = map[string]bool{}
			}
			onPath[parent][filepath.Base(cur)] = true
			cur = parent
		}
	}
	levels := make([]string, 0, len(onPath))
	for l := range onPath {
		levels = append(levels, l)
	}
	sort.Strings(levels)
	return levels, onPath
}
