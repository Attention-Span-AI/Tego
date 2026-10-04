// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
)

// unenforcedUnder is R4 on the same strings compile used (fsplan.FirstCover, as the decision core's plan).
func unenforcedUnder(target string, writes []string) bool {
	return fsplan.FirstCover(target, writes) >= 0
}

// walk is the compatibility helper for an already-resolved target list. Both
// paths use the held-object plan, including identity alias exclusions.
func (bd *builder) walk(resolved []string) error {
	targets := make([]fsplan.Target, 0, len(resolved))
	for _, path := range resolved {
		t, err := bd.snapshotTarget(path, fsplan.NewGrants(nil))
		if err != nil {
			return err
		}
		targets = append(targets, t)
	}
	return bd.applyEnumeration(fsplan.Build(targets, nil))
}

// outermost drops every target that lies at or below another target (E29): decide.Outermost, the decision
// core's plan, which says why a nested target would re-open what the outer one denies.
func outermost(resolved []string) []string { return decide.Outermost(resolved) }

// ancestorSet is the ancestor levels the enumeration holds, each with the names on it that lie on the path to a
// target (decide.AncestorSet, the decision core's plan).
func ancestorSet(resolvedTargets []string) (levels []string, onPath map[string]map[string]bool) {
	return decide.AncestorSet(resolvedTargets)
}
