// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"net/netip"
	"strings"

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
// Caller resolver selectors are framed as names, not restored into the worker.
// When present they yield a cannot-tell warning instead of a different lookup.
func (s *Service) unresolved(ctx context.Context, changes []rule.Change) []UnresolvedHost {
	budget := s.hostBudget
	if budget <= 0 {
		budget = nextrun.HostBudget
	}
	resolver := s.Resolver
	if resolver == nil {
		if settings := s.callerContext().ResolverSettings; len(settings) != 0 {
			resolver = unavailableCallerResolver{why: "cannot tell: name resolution with the caller's " + strings.Join(settings, ", ") +
				" resolver settings was not checked here; the next run resolves this host independently"}
		}
	}
	return nextrun.UnresolvedHosts(ctx, resolver, rule.NetAdded(changes), budget)
}

type unavailableCallerResolver struct{ why string }

func (r unavailableCallerResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New(r.why)
}
