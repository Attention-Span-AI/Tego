// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
)

// SetSuggestBudget sets the learn step's read budget (suggestBudget) for one test.
func SetSuggestBudget(t *testing.T, d time.Duration) {
	prev := suggestBudget
	suggestBudget = d
	t.Cleanup(func() { suggestBudget = prev })
}

// AgentsAfterDiscovery exercises a replacement after the discovery reader closed.
func AgentsAfterDiscovery(ctx context.Context, in Inputs, replace func()) []agentid.Agent {
	f := &facts{in: &in, ctx: ctx, verdicts: map[string]verdict{}}
	f.runs, f.runsErr = readRuns(in.LedgerRoot)
	replace()
	for _, r := range f.runs.all {
		f.verify(r)
	}
	return f.agentRows()
}
