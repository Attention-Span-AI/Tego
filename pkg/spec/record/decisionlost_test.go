// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
	"time"
)

// lostExec is the exec line a failed exec becomes when the ring lost the decision record of its refusal and only the
// exec's own result arrived (ExecPayload.DecisionLost).
func lostExec(t *testing.T, f func(*Event, map[string]any)) *Event {
	t.Helper()
	p := map[string]any{"path": "/usr/bin/tool", "argv": []string{"tool"}, "exec_id": "r-00000000-000000000000a-aaaaaa/4242/1000",
		"argv_from": "attempt", "syscall_ret": -13, "decision_lost": []string{DecisionLostRingbufFull}}
	e := &Event{V: Version, Kind: KindExec, Source: SourceKernel, Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever",
		TS: time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC), Rule: "unmatched", Verdict: VerdictObserved,
		Authority: AuthorityRule, Attr: Unattributed()}
	if f != nil {
		f(e, p)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload = b
	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope is not valid: %v", err)
	}
	return e
}

// TestExecDecisionLost (record_minor 41): the field is allowed from revision 41 on an observed exec line that is the exec's
// own result (EACCES, no decision field), refused below 41 [below-minor], and refused [decision-lost] on a line a decision
// wrote or one whose result is another errno.
func TestExecDecisionLost(t *testing.T) {
	for _, c := range []struct {
		name  string
		minor int
		f     func(*Event, map[string]any)
		code  string
	}{
		{"observed at 41", MinorEveryLaunch, nil, ""},
		{"both gaps", MinorEveryLaunch, func(_ *Event, p map[string]any) {
			p["decision_lost"] = []string{DecisionLostFragmentOverflow, DecisionLostRingbufFull}
		}, ""},
		{"at 40", MinorAppliedLimits, nil, "below-minor"},
		{"at 31", MinorLearn, nil, "below-minor"},
		{"on an allowed line", MinorEveryLaunch, func(e *Event, _ map[string]any) { e.Verdict, e.Rule = VerdictAllow, "exec.allow[/usr/bin/tool]" }, "decision-lost"},
		{"on a refused line", MinorEveryLaunch, func(e *Event, _ map[string]any) {
			e.Verdict, e.Rule, e.Reason = VerdictRefused, "exec.deny", ReasonExecNotAllowed
		}, "decision-lost"},
		{"another errno", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["syscall_ret"] = -8 }, "decision-lost"},
		{"no result", MinorEveryLaunch, func(_ *Event, p map[string]any) { delete(p, "syscall_ret") }, "decision-lost"},
		{"a plane reason", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["plane_reason"] = "pin-mismatch" }, "decision-lost"},
		{"the gate's copied argv facts", MinorEveryLaunch, func(_ *Event, p map[string]any) {
			p["argv_facts"], p["argv_read"], p["command_rule"] = ArgvFactsCopied, 2, "git status"
		}, ""},
		{"the plane's pinned argv facts", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["argv_facts"] = ArgvFactsKernelPinned }, "decision-lost"},
		{"unproven argv facts", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["argv_facts"] = ArgvFactsUnproven }, "decision-lost"},
		{"errno zero", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["errno"] = 0 }, "decision-lost"},
		{"empty mechanism", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["mechanism"] = "" }, "decision-lost"},
		{"empty signal", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["signal"] = "" }, "decision-lost"},
		{"by", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["by"] = "x" }, "decision-lost"},
		{"detected bypass", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["detected_bypass"] = true }, "decision-lost"},
		{"kill failed", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["kill_failed"] = 1 }, "decision-lost"},
		{"argv decided", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["argv_decided"] = []string{"a"} }, "decision-lost"},
		{"pin unavailable", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["pin_unavailable"] = true }, "decision-lost"},
		{"a rule that matched", MinorEveryLaunch, func(e *Event, _ map[string]any) { e.Rule = "exec.allow[/usr/bin/tool]" }, "decision-lost"},
		{"a seccomp source", MinorEveryLaunch, func(e *Event, _ map[string]any) { e.Source = SourceSeccomp }, "decision-lost"},
		{"another gap", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["decision_lost"] = []string{"ringbuf-undrained"} }, "decision-lost"},
		{"empty", MinorEveryLaunch, func(_ *Event, p map[string]any) { p["decision_lost"] = []string{} }, "decision-lost"},
		{"unsorted", MinorEveryLaunch, func(_ *Event, p map[string]any) {
			p["decision_lost"] = []string{DecisionLostRingbufFull, DecisionLostFragmentOverflow}
		}, "decision-lost"},
		{"repeated", MinorEveryLaunch, func(_ *Event, p map[string]any) {
			p["decision_lost"] = []string{DecisionLostRingbufFull, DecisionLostRingbufFull}
		}, "decision-lost"},
	} {
		if got := FieldCode(lostExec(t, c.f).ValidateAt(c.minor)); got != c.code {
			t.Errorf("%s: [%s], want [%s]", c.name, got, c.code)
		}
	}
}

// TestDecisionLostIsKeptOnTheLine: the Writer never moves the field to a blob, and a line without it validates as before.
func TestDecisionLostIsKeptOnTheLine(t *testing.T) {
	if !IsMVPField(KindExec, "decision_lost") || !IsMVPField(KindExec, "Decision_Lost") || IsMVPField(KindFS, "decision_lost") {
		t.Fatal("decision_lost is an exec line's reserved field and no other kind's")
	}
	e := lostExec(t, func(_ *Event, p map[string]any) { delete(p, "decision_lost") })
	for _, m := range []int{MinorLearn, MinorEveryLaunch} {
		if err := e.ValidateAt(m); err != nil {
			t.Errorf("an exec line without decision_lost at %d: %v", m, err)
		}
	}
}
