// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lostDecisionExec is the line the recorder writes for an exec that failed with EACCES whose decision record the run lost
// (public issue 65): observed, unmatched, the exec's own result, decision_lost naming the gap.
func lostDecisionExec(t *testing.T) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindExec, Source: record.SourceKernel, PID: 9, TID: 9, MonoNS: 2, Rule: "unmatched",
		Verdict: record.VerdictObserved, Authority: record.AuthorityRule, Attr: record.Unattributed()}
	if err := e.SetPayload(record.ExecPayload{Path: "/usr/bin/tool", Argv: []string{"tool"}, ExecID: runID + "/9/1",
		ArgvFrom: "attempt", SyscallRet: -13, DecisionLost: []string{record.DecisionLostRingbufFull}}); err != nil {
		t.Fatal(err)
	}
	return e
}

// writeRunAt41 is writeRun for a ledger at revision 41, the one every launch writes and the one that has decision_lost.
func writeRunAt41(t *testing.T, evs ...*record.Event) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runs", runID)
	w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"x"}, RecordMinor: record.MinorEveryLaunch}); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if err := w.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Kind, err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestViewsAgreeOnAnExecWhoseDecisionWasLost: through the real writer (which validates the line at revision 41), every view
// reads the line the same way: no view counts it a refusal (drift, measure, the receipt, learn: it is not one), the receipt
// counts it in its own figure and in no program list, and `tego events` shows the line and says what is known of it in the
// table and keeps the field in JSON.
func TestViewsAgreeOnAnExecWhoseDecisionWasLost(t *testing.T) {
	dir := writeRunAt41(t, lostDecisionExec(t))
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
	if d := driftRefused(rep); d != 0 || m.Refused != 0 || rc.Refusals.Total != 0 || p.Refused != 0 {
		t.Errorf("refusals: drift %d, measure %d, receipt %d, learn %d; a line nothing decided is none", d, m.Refused,
			rc.Refusals.Total, p.Refused)
	}
	if rc.ExecsDecisionLost != 1 || len(rc.Programs) != 0 {
		t.Errorf("receipt: %d decision-lost execs and %d programs, want 1 and none", rc.ExecsDecisionLost, len(rc.Programs))
	}
	var table, js bytes.Buffer
	if _, err := eventsTable(t, &table, dir, events.Filter{Kinds: []record.Kind{record.KindExec}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "[failed: permission denied; decision record may be lost: ringbuf-full]") {
		t.Errorf("tego events does not say what is known:\n%s", table.String())
	}
	if _, err := eventsJSON(t, &js, dir, events.Filter{Kinds: []record.Kind{record.KindExec}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"decision_lost":["ringbuf-full"]`) {
		t.Errorf("the JSON line lost the field:\n%s", js.String())
	}
}

// TestWriterRefusesALostDecisionLineThatIsAnotherLine: the writer holds the field to the line it is for, so no view can be
// handed a refused or allowed line that claims its decision was lost.
func TestWriterRefusesALostDecisionLineThatIsAnotherLine(t *testing.T) {
	for _, edit := range []func(*record.Event){
		func(e *record.Event) { e.Verdict = record.VerdictAllow },
		func(e *record.Event) { e.Verdict, e.Reason = record.VerdictRefused, record.ReasonExecNotAllowed },
	} {
		e := lostDecisionExec(t)
		edit(e)
		dir := filepath.Join(t.TempDir(), runID)
		w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"x"}, RecordMinor: record.MinorEveryLaunch}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); record.FieldCode(err) != "decision-lost" {
			t.Errorf("verdict %s: appended with %v, want [decision-lost]", e.Verdict, err)
		}
		_ = w.Close(record.RunEndPayload{Reason: "exit"})
	}
}

// decisionLostSeed is a whole ledger holding the line, as a fuzz seed.
func decisionLostSeed(t testing.TB) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), runID)
	w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"x"}, RecordMinor: record.MinorEveryLaunch}); err != nil {
		t.Fatal(err)
	}
	e := &record.Event{Kind: record.KindExec, Source: record.SourceKernel, PID: 9, TID: 9, MonoNS: 2, Rule: "unmatched",
		Verdict: record.VerdictObserved, Authority: record.AuthorityRule, Attr: record.Unattributed()}
	if err := e.SetPayload(record.ExecPayload{Path: "/usr/bin/tool", Argv: []string{"tool"}, ExecID: runID + "/9/1",
		ArgvFrom: "attempt", SyscallRet: -13, DecisionLost: []string{record.DecisionLostFragmentOverflow, record.DecisionLostRingbufFull}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
