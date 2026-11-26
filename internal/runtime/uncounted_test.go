// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The run that a token budget ended for an answer it could not count keeps what the closing lines tell the person
// (Result.Uncounted): the exchange count and the capture source's account of it. The record's detail is unchanged.
func TestAnUncountedAnswerIsKeptForTheClosingLines(t *testing.T) {
	r, _, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
	source.ReportUnmetered(meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}, 3, "POST /v1/chat/completions: usage unreadable")
	got := r.uncountedEnd()
	r.termMu.Lock()
	detail := r.detail
	r.termMu.Unlock()
	if got == nil || got.Exchanges != 3 || got.Why != "POST /v1/chat/completions: usage unreadable" {
		t.Fatalf("uncounted = %+v, want 3 exchanges and the POST /v1/chat/completions account", got)
	}
	const want = "capture: 3 model exchanges spent tokens no budget could count (POST /v1/chat/completions: usage unreadable); " +
		"a token or cost budget cannot be enforced"
	if detail != want {
		t.Fatalf("run_end detail = %q, want it unchanged: %q", detail, want)
	}
}

// An end another worker decided first is not the uncounted answer's: its reason stays, and nothing says otherwise.
func TestAnEndDecidedFirstKeepsNoUncountedSpend(t *testing.T) {
	r, _, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
	r.ledgerFailed(errors.New("disk full"))
	source.ReportUnmetered(meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}, 1, "POST /v1/chat/completions: usage unreadable")
	got := r.uncountedEnd()
	if got != nil {
		t.Fatalf("uncounted = %+v after the ledger had already ended the run, want nil", got)
	}
}
