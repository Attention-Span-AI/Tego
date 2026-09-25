// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAFloodCannotHideSpendFromTheBudget: the budget watcher sees usage as a pipeline stage, and the
// ssl_response carrying it shared one droppable queue with every refusal the agent chose to make, so a flood
// dropped it and a token ceiling was crossed with no limit and no kill. The response now has the capture
// lane: a full supervisor lane leaves it room, and the watcher ends the run.
func TestAFloodCannotHideSpendFromTheBudget(t *testing.T) {
	r, cgroups, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 100})
	sup := r.queue.Lane(LaneSupervisor)
	for range 16 { // budgetRunner's lanes hold 16: the flood fills the supervisor's
		sup.Emit(&record.Event{Kind: record.KindNet, Source: record.SourceSeccomp,
			Verdict: record.VerdictRefused, Reason: record.ReasonNetNotAllowed})
	}
	r.queue.Lane(LaneCapture).Emit(sslResponse(t, 150, 50)) // 200 tokens against a ceiling of 100
	r.pipe.drain()
	if r.terminal != identity.ReasonLimit || cgroups.killed != 1 {
		t.Fatalf("200 tokens against a ceiling of 100 left the run %q after %d kills", r.terminal, cgroups.killed)
	}
}

// TestLostModelTrafficEndsABudgetedRun: should the capture lane drop an exchange anyway (a pipeline stalled
// past its wait), a run with a token or cost budget can no longer enforce it and ends, reason error; one with
// no such budget keeps running with the loss in its channel-full gap.
func TestLostModelTrafficEndsABudgetedRun(t *testing.T) {
	r, cgroups, _, _ := budgetRunner(t, agent.ResolvedLimits{CostUSD: 1})
	r.captureLost(2)
	if r.terminal != identity.ReasonError || cgroups.killed != 1 {
		t.Fatalf("a budgeted run that lost model traffic is %q after %d kills, want error and one kill", r.terminal, cgroups.killed)
	}
	r2, cgroups2, _, _ := budgetRunner(t, agent.ResolvedLimits{})
	r2.captureLost(2)
	if r2.terminal != "" || cgroups2.killed != 0 {
		t.Fatalf("a run with no budget was ended (%q, %d kills)", r2.terminal, cgroups2.killed)
	}
}

// A drop counted once the run has quiesced (teardown's final drain) records gap unmetered-after-exit and leaves
// the end as the agent's own exit, as an unmetered report does.
func TestLostModelTrafficAfterQuiesceDoesNotChangeTheEnd(t *testing.T) {
	r, cgroups, sink, _ := budgetRunner(t, agent.ResolvedLimits{CostUSD: 1})
	r.quiesced.Store(true)
	r.captureLost(2)
	r.pipe.drain()
	reason, code, _, _ := r.ending()
	if reason != identity.ReasonExit || code != 0 || cgroups.killed != 0 {
		t.Fatalf("reason %q code %d after %d kills, want a clean exit and no kill", reason, code, cgroups.killed)
	}
	if !hasUnmeteredAfterExitGap(t, sink, 2) {
		t.Errorf("no gap what=capture why=%s count=2 in the record", GapUnmeteredAfterExit)
	}
}

// TestUnmeteredSpendEndsABudgetedRun: a capture source that could not count an exchange's spend says so
// through the capture lane, and a run with a token or cost budget ends there, reason error, the cause in its
// detail; a run with no such budget keeps running.
func TestUnmeteredSpendEndsABudgetedRun(t *testing.T) {
	r, cgroups, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
	source.ReportUnmetered(meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}, 1, "POST /v1/messages/batches")
	if r.terminal != identity.ReasonError || cgroups.killed != 1 {
		t.Fatalf("a budgeted run with uncounted spend is %q after %d kills, want error and one kill", r.terminal, cgroups.killed)
	}
	if !strings.Contains(r.detail, "/v1/messages/batches") {
		t.Errorf("detail %q does not name the cause", r.detail)
	}
	r2, cgroups2, _, _ := budgetRunner(t, agent.ResolvedLimits{Wall: time.Hour})
	source.ReportUnmetered(meteredLane{Sink: r2.queue.Lane(LaneCapture), r: r2}, 1, "x")
	if r2.terminal != "" || cgroups2.killed != 0 {
		t.Fatalf("a run with no token or cost budget was ended (%q, %d kills)", r2.terminal, cgroups2.killed)
	}
	// A sink that does not listen is told nothing, and nothing panics.
	source.ReportUnmetered(r.queue.Lane(LaneCapture), 1, "x")
}

// A response reporting server-tool requests to a price table that names no fee for any ends a run with a cost
// budget, reason error, as an exchange capture could not read does: charging them $0 let the budget pass spend
// it could not bound (ADR 0037 amendment 2026-09-24).
func TestUnfeedServerToolEndsACostBudgetedRun(t *testing.T) {
	prices := &limits.PriceTable{Version: limits.PriceVersion,
		Models: map[string]limits.ModelPrice{"claude-sonnet-4-5-20250929": {InputPerMTok: 3, OutputPerMTok: 15}}}
	r, cgroups, _, _ := pricedBudgetRunner(t, agent.ResolvedLimits{CostUSD: 100, Set: agent.BudgetCostUSD}, prices)
	ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}
	if err := ev.SetPayload(record.SSLResponsePayload{Status: 200, Model: "claude-sonnet-4-5-20250929",
		ParserVersion: "1", Usage: &record.Usage{Input: 1, ServerTool: map[string]int{"web_search_requests": 1000}}}); err != nil {
		t.Fatal(err)
	}
	r.pipe.handle(ev)
	if r.terminal != identity.ReasonError || cgroups.killed != 1 || !strings.Contains(r.detail, "server_tool_per_request") {
		t.Fatalf("run is %q (%q) after %d kills, want error naming the missing fee and one kill", r.terminal, r.detail, cgroups.killed)
	}
}
