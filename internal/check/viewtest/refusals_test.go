// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDriftAndMeasureCountRefusalsAlike: drift's refused cells (R13) and measure's refused column (R19)
// count one ledger's refusals the same, a mirrored refusal once, a refusal written on its own once, and a
// refused line that follows no matching refused action as a refusal of its own.
func TestDriftAndMeasureCountRefusalsAlike(t *testing.T) {
	action := func(rule string, v record.Verdict) *record.Event {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 7, TID: 7,
			Rule: rule, Verdict: v, Authority: record.AuthorityRule, Attr: record.Unattributed()}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/x"}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	refusedLine := func(rule string) *record.Event {
		e := &record.Event{Kind: record.KindRefused, Source: record.SourceSupervisor, PID: 7, TID: 7,
			Rule: rule, Reason: record.ReasonReadDenied}
		if err := e.SetPayload(record.RefusedPayload{Op: "open", Reason: record.ReasonReadDenied, Rule: rule}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	dir := writeRun(t,
		action("deny_read[~/.ssh]", record.VerdictRefused), refusedLine("deny_read[~/.ssh]"), // one refusal, mirrored
		keyringRefusal(t), // one, on its own
		action("deny_read[~/.aws]", record.VerdictRefused), refusedLine("other"), // two: another rule
		action("fs.write[./out]", record.VerdictAllow), refusedLine("fs.write[./out]"), // one: the action was allowed
	)
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := measure.ComputeAt(t.Context(), reader(t, dir), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, s := range [][]drift.RuleCount{rep.FS, rep.Net, rep.Exec, rep.MCP, rep.Other} {
		for _, c := range s {
			refused += c.Refused
		}
	}
	if refused != 5 || m.Refused != refused {
		t.Fatalf("drift counts %d refusals, measure %d, want 5 each", refused, m.Refused)
	}
	// The receipt counts them the same, through the same mirror rule.
	rc, err := receipt.Compute(t.Context(), reader(t, dir), receipt.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Refusals.Total != refused {
		t.Fatalf("the receipt counts %d refusals, drift and measure %d", rc.Refusals.Total, refused)
	}
}
