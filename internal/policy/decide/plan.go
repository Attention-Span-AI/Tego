// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
)

// This file is the pure half of the Landlock rule plan (enforce-landlock R3, R4; ADR 0028): which deny_read
// targets are unenforced, which are enumerated, and the ancestor levels the enumeration holds. The builder
// (internal/runtime/enforce/landlock) resolves the targets live, holds and lists the directories, and applies
// what these answer; it computes none of it. Evaluate's denyUnenforced asks the unenforced question of the
// compiled table, and the builder's I5 compares its own answer on the same strings with compile's
// (FSRule.Unenforced), which catches a containment that changed between compile and run.

// Outermost drops every target that lies at or below another target (E29). A nested target would make the
// enumeration walk the levels *inside* the outer target, and R3 (2) grants the read set to every entry of a
// walked level that is not on the path to a target. Landlock rules only ever add rights — an access is
// allowed when any rule on the path grants it — and the outer target is denied only by having no rule of its
// own, so nothing on it can take those grants back: they would re-open exactly what it denies. Dropping the
// inner target loses nothing — the outer entry already denies its whole subtree — so a more specific deny_read
// entry can never make the deny weaker than the broader one alone. Comparison is on resolved paths (the
// enumeration walks resolved locations, E12) and table order is preserved for deterministic diagnostics;
// duplicates keep their first occurrence so an exactly repeated entry still enumerates once. A target inside
// another only through a bind mount of the whole outer target escapes this string test, and is not dropped;
// the builder's walk then skips the level that is the outer target's own inode and every level beneath it
// (E32 (d)); E32 records the shape neither can see.
//
// Each target is looked up in a set by each of its ancestors, the component boundaries of its own path, so
// the filter costs the targets' total length. It compared every target with every other, and built a string
// for each comparison: the built-in .env scan names up to 50000 files where the agent writes, and 15000
// planted .env.<n> files made a run's start take 21 s, 5000 of them 2.7 s (E22). "/" is never an ancestor
// here, as other+"/" never prefixed a clean path when other was "/"; the builder refuses a "/" target before
// this (E5).
func Outermost(resolved []string) []string { return fsplan.Outermost(resolved) }

// AncestorSet computes the ancestor directories the enumeration must hold, from a set of already-resolved
// (symlink-free) target paths: every directory level between each target's parent and "/", paired with the
// child name on that level which lies on the path to a target — that name is on the path itself (about to get
// its own deny-target rule) and so must never also receive a sibling grant (R3 (2)). levels is sorted for
// deterministic processing order. Pure and syscall-free, unlike the builder's resolve and hold, so the
// ancestry logic itself can be pinned with a golden test independent of any real filesystem (see
// internal/runtime/enforce/landlock TestAncestorSetGolden).
func AncestorSet(resolvedTargets []string) (levels []string, onPath map[string]map[string]bool) {
	return fsplan.Ancestors(resolvedTargets)
}
