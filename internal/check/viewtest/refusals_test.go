// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// driftRefused is the refusals drift counts, over every section.
func driftRefused(rep *drift.Report) int {
	n := 0
	for _, s := range [][]drift.RuleCount{rep.FS, rep.Net, rep.Exec, rep.MCP, rep.Other} {
		for _, c := range s {
			n += c.Refused
		}
	}
	return n
}

// TestViewsCountSplitMirrorsOnce: spec/record/v1/fixtures/mirror-split.jsonl holds three refused connects whose
// refused mirrors do not each follow their action, as a ledger with more than one writer can hold them: a write lands
// between one connect and its mirror, and two connects under the same rule and reason are both written before either
// mirror. Drift (R13), measure (R19), the receipt and learn count three refusals each, as the dashboard does
// (internal/control/ledgerview TestReceiptAgreesWithDashboardAndMeasure); pairing a mirror only with the line just
// before it counted five.
func TestViewsCountSplitMirrorsOnce(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "mirror-split.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := measure.ComputeAt(t.Context(), reader(t, dir), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := receipt.Compute(t.Context(), reader(t, dir), receipt.Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := learn.New(learn.Options{})
	for e, err := range reader(t, dir).Iter() {
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := l.Proposal()
	if err != nil {
		t.Fatal(err)
	}
	if d := driftRefused(rep); d != 3 || m.Refused != 3 || rc.Refusals.Total != 3 || p.Refused != 3 {
		t.Errorf("refusals: drift %d, measure %d, receipt %d, learn %d; want 3 each", d, m.Refused, rc.Refusals.Total,
			p.Refused)
	}
}

// TestDriftAndMeasureCountRefusalsAlike: drift's refused cells (R13) and measure's refused column (R19)
// count one ledger's refusals the same, a mirrored refusal once, a refusal written on its own once, and a
// refused line that follows no matching refused action as a refusal of its own.
func TestDriftAndMeasureCountRefusalsAlike(t *testing.T) {
	action := func(rule string, v record.Verdict) *record.Event {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 7, TID: 7,
			Rule: rule, Verdict: v, Authority: record.AuthorityRule, Attr: record.Unattributed()}
		if v == record.VerdictRefused {
			e.Reason = record.ReasonReadDenied // a refused open's reason, which its refused mirror copies
		}
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
	refused := driftRefused(rep)
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
