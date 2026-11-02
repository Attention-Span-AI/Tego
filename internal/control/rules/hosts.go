// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/nextrun"
)

// UnresolvedHost is a host name a change adds that did not resolve here, and what its lookup said
// (nextrun.Unresolved): a preview's warning, never a refusal.
type UnresolvedHost = nextrun.Unresolved

// unresolved is the host names changes add to net.allow or net.ask that do not resolve here, looked up all at once
// within nextrun.HostBudget through s.Resolver. A check compiles with no DNS (nextrun.Compile), so this is the one
// lookup a change makes, and only a preview makes it: a write does not wait on DNS again for a warning no page shows.
// The next run resolves every host when it starts and does not start while one fails, so the preview says it first.
func (s *Service) unresolved(ctx context.Context, changes []rule.Change) []UnresolvedHost {
	budget := s.hostBudget
	if budget <= 0 {
		budget = nextrun.HostBudget
	}
	return nextrun.UnresolvedHosts(ctx, s.Resolver, rule.NetAdded(changes), budget)
}
