// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func lostExecLine(at time.Duration, lost ...string) line {
	return line{kind: record.KindExec, at: at, verdict: record.VerdictObserved, rule: "unmatched",
		payload: record.ExecPayload{Path: "/usr/bin/tool", Argv: []string{"tool"}, ExecID: "x", ArgvFrom: "attempt",
			SyscallRet: -13, DecisionLost: lost}}
}

func startAt(minor int) line {
	return line{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "bpflsm", Capture: "off", RecordMinor: minor,
		Command: []string{"sh", "agent.sh"}, Cwd: "/p",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true}}}
}

// TestReceiptCountsAnExecWhoseDecisionWasLost (public issue 65): an exec that failed with permission denied and says its
// decision record was lost is a figure of its own: not a refusal, not a program that ran, and not hidden. "Nothing was
// refused" is not said beside it.
func TestReceiptCountsAnExecWhoseDecisionWasLost(t *testing.T) {
	rc := compute(t, []line{
		startAt(record.MinorEveryLaunch),
		lostExecLine(time.Second, record.DecisionLostRingbufFull),
		lostExecLine(2*time.Second, record.DecisionLostFragmentOverflow, record.DecisionLostRingbufFull),
		// the same failure with no loss stated is another module's, or the file's own mode: no figure
		lostExecLine(3 * time.Second),
		// a program that ran
		{kind: record.KindExec, at: 4 * time.Second, verdict: record.VerdictAllow, rule: "exec.allow[/bin/ls]",
			payload: record.ExecPayload{Path: "/bin/ls", Argv: []string{"ls"}, ExecID: "y"}},
		end(5*time.Second, 0),
	}, Options{})
	if rc.ExecsDecisionLost != 2 || rc.Refusals.Total != 0 {
		t.Fatalf("decision-lost execs %d, refusals %d, want 2 and 0", rc.ExecsDecisionLost, rc.Refusals.Total)
	}
	if len(rc.Programs) != 1 || rc.Programs[0].Path != "/bin/ls" {
		t.Fatalf("a failed exec counted among the programs that ran: %+v", rc.Programs)
	}
	words := rc.RefusedWords()
	if strings.Contains(words, "Nothing was refused") || !strings.Contains(words, "2 execs failed with permission denied") ||
		!strings.Contains(words, "neither a refusal nor a program that ran") {
		t.Fatalf("refused words = %q", words)
	}
	var text, js bytes.Buffer
	if err := rc.Text(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "2 execs failed with permission denied") {
		t.Fatalf("the text receipt hides the figure:\n%s", text.String())
	}
	if err := rc.JSON(&js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"execs_decision_lost": 2`) {
		t.Fatalf("the JSON receipt has no execs_decision_lost:\n%s", js.String())
	}
}

// TestReceiptWithNoLostDecisionsHasNoFigure: a run that lost none writes no key and says what it said before.
func TestReceiptWithNoLostDecisionsHasNoFigure(t *testing.T) {
	rc := compute(t, []line{startAt(record.MinorEveryLaunch), lostExecLine(time.Second), end(2*time.Second, 0)}, Options{})
	var js bytes.Buffer
	_ = rc.JSON(&js)
	if rc.ExecsDecisionLost != 0 || strings.Contains(js.String(), "execs_decision_lost") || rc.RefusedWords() != "Nothing was refused." {
		t.Fatalf("figure %d, words %q", rc.ExecsDecisionLost, rc.RefusedWords())
	}
}

// TestReceiptReadsDecisionLostOnlyAsTheRevisionAllows: a line that carries the field below revision 41, or on a line that is
// not an observed EACCES, is no figure: a reader trusts the line's own terms, not the key alone.
func TestReceiptReadsDecisionLostOnlyAsTheRevisionAllows(t *testing.T) {
	refused := line{kind: record.KindExec, at: time.Second, verdict: record.VerdictRefused, rule: "exec.deny",
		reason: record.ReasonExecNotAllowed, payload: record.ExecPayload{Path: "/usr/bin/tool", Argv: []string{"tool"}, ExecID: "x",
			SyscallRet: -13, DecisionLost: []string{record.DecisionLostRingbufFull}}}
	other := lostExecLine(time.Second, record.DecisionLostRingbufFull)
	other.payload = record.ExecPayload{Path: "/usr/bin/tool", Argv: []string{"tool"}, ExecID: "x", SyscallRet: -8,
		DecisionLost: []string{record.DecisionLostRingbufFull}}
	for name, c := range map[string][]line{
		"revision 40":   {startAt(record.MinorAppliedLimits), lostExecLine(time.Second, record.DecisionLostRingbufFull), end(2*time.Second, 0)},
		"a refusal":     {startAt(record.MinorEveryLaunch), refused, end(2*time.Second, 0)},
		"another errno": {startAt(record.MinorEveryLaunch), other, end(2*time.Second, 0)},
	} {
		if rc := compute(t, c, Options{}); rc.ExecsDecisionLost != 0 {
			t.Errorf("%s: counted %d", name, rc.ExecsDecisionLost)
		}
	}
}
