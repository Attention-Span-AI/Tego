// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

// newlyAllows compares the immutable compiler outputs family by family. It links
// no decision engine, and no authority-bearing family may change silently.
func (s *Service) newlyAllows(ctx context.Context, cc CheckContext, before, after []byte, plan *ChangePlan) ([]string, error) {
	if s.Compile == nil && s.Check == nil {
		return s.compareSnapshots(ctx, cc, before, after, plan)
	}
	a, beforeSnapshot, oldErr := s.compileSnapshot(ctx, cc, before)
	b, afterSnapshot, err := s.compileSnapshot(ctx, cc, after)
	if err != nil {
		return nil, err
	}
	if oldErr != nil {
		if b == nil {
			return nil, fmt.Errorf("the repaired contract could not be compiled for comparison")
		}
		plan.Compiled = fmt.Sprintf("invalid:%s:%x", rulefile.Sum(before), b.Hash)
		plan.repair = true
		plan.dependencies = "invalid:" + afterSnapshot
		plan.ComparisonReview = append(plan.ComparisonReview, "The previous file does not compile. Review every rule in the repaired contract.")
		return []string{"Start a run with a valid contract (the previous file could not compile)"}, nil
	}
	plan.dependencies = beforeSnapshot + ":" + afterSnapshot
	if a == nil || b == nil {
		return nil, nil
	} // test-only compiler hooks have no table
	plan.Compiled = fmt.Sprintf("%x:%x", a.Hash, b.Hash)
	var out []string
	rows := agentdiff.Compare(a, b)
	plan.rows, plan.compared = rows, true
	for _, r := range rows {
		out = append(out, r.NewlyAllowed...)
		if r.Direction == agentdiff.CannotClassify {
			plan.ComparisonReview = append(plan.ComparisonReview, "Also review: "+r.Family+" changed and Tego cannot tell whether it allows more")
		}
	}
	return out, nil
}
