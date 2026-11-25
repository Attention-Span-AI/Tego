// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lostExecResult runs one failed exec (the result alone, with its attempt joined) through a recorder whose lost counter
// answers lost in turn (the first is the run's baseline), and returns its line, payload and the recorder.
func lostExecResult(t *testing.T, ret int64, lost []uint64, before ...[]byte) (*record.Event, execOutcomePayload, *Recorder) {
	t.Helper()
	f := newFixture(t)
	n := outcomeNaming(10)
	r, sink := runRecorder(t, f, Options{ExecResults: true, Lost: &stepLost{values: lost},
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		append(before, execResultSample(execOutcomeHeader(30), ret))...)
	ev, p := oneExecOutcome(t, sink)
	return ev, p, r
}

// TestExecResultNamesTheGapThatLostItsDecision (public issue 65): a failed exec with EACCES and no decision record, in a
// run whose ring lost records, is an observed line that says its decision may be among them; it is no refusal. The
// lost counter is read when the line is written, so the ring's drop that came with this very exec is counted.
func TestExecResultNamesTheGapThatLostItsDecision(t *testing.T) {
	ev, p, r := lostExecResult(t, -13, []uint64{0, 4})
	if ev.Verdict != record.VerdictObserved || ev.Rule != RuleUnmatched || ev.Reason != "" || p.SyscallRet != -13 ||
		p.Mechanism != "" || p.PlaneReason != "" || p.ArgvFrom != "attempt" {
		t.Fatalf("the line is no longer the exec's own result: %+v / %+v", ev, p)
	}
	if !slices.Equal(p.DecisionLost, []string{record.DecisionLostRingbufFull}) {
		t.Fatalf("decision_lost = %v, want [ringbuf-full]", p.DecisionLost)
	}
	if n := gapCount(r.Gaps())[GapRingbufFull]; n != 4 {
		t.Fatalf("the gap the line names counts %d records, want the 4 the ring lost", n)
	}
	if err := ev.ValidateAt(record.MinorEveryLaunch); err != nil {
		t.Fatalf("the line does not validate at revision 41: %v", err)
	}
}

// A run that lost nothing says nothing: its EACCES is another module's or the file's own mode, and the line stays as it was.
func TestExecResultWithNoLossIsNotMarked(t *testing.T) {
	ev, p, _ := lostExecResult(t, -13, []uint64{0})
	if p.DecisionLost != nil || ev.Verdict != record.VerdictObserved || p.SyscallRet != -13 {
		t.Fatalf("a run that lost no record marked its EACCES line: %+v / %+v", ev, p)
	}
}

// Only EACCES is what the plane refuses with: another errno of a run that lost records names nothing.
func TestExecResultOfAnotherErrnoIsNotMarked(t *testing.T) {
	for _, ret := range []int64{-8, -26, -2, -1} {
		_, p, _ := lostExecResult(t, ret, []uint64{0, 4})
		if p.DecisionLost != nil {
			t.Errorf("syscall_ret %d carries decision_lost %v", ret, p.DecisionLost)
		}
	}
}

// A decision record that survived is the decision: the line is the refusal, and a loss elsewhere in the run marks nothing.
func TestExecResultWithItsDecisionIsNotMarked(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	h := execOutcomeHeader(20)
	h.Reason = uint8(bpf.ReasonExecNotAllowed)
	n := outcomeNaming(10)
	_, sink := runRecorder(t, f, Options{ExecResults: true, Lost: &stepLost{values: []uint64{0, 9}},
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		planeExecSample(h, uint32(bpf.PlaneRuleNone), "/refused/tool"), execResultSample(execOutcomeHeader(30), -13))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictRefused || p.DecisionLost != nil {
		t.Fatalf("a refusal that was read carries decision_lost: %+v / %+v", ev, p)
	}
}

// exec-fragment-overflow is the recorder's own loss of decision fragments, named beside the ring's when both occurred.
func TestExecResultNamesFragmentOverflowToo(t *testing.T) {
	var fill [][]byte
	for i := 0; i <= execFragmentLimit; i++ {
		h := sample{PID: uint32(1000 + i), TID: uint32(1000 + i), Start: execOutcomeHeader(0).Start, MonoNS: uint64(1 + i)}
		h.Reason = uint8(bpf.ReasonExecNotAllowed)
		fill = append(fill, planeExecSample(h, uint32(bpf.PlaneRuleNone), "/elsewhere"))
	}
	_, p, r := lostExecResult(t, -13, []uint64{0}, fill...)
	if gapCount(r.Gaps())[GapExecFragmentOverflow] == 0 {
		t.Fatalf("the fixture did not overflow the fragment ring: %v", r.Gaps())
	}
	if !slices.Equal(p.DecisionLost, []string{record.DecisionLostFragmentOverflow}) {
		t.Fatalf("decision_lost = %v, want [exec-fragment-overflow]", p.DecisionLost)
	}
	_, p, _ = lostExecResult(t, -13, []uint64{0, 2}, fill...)
	if !slices.Equal(p.DecisionLost, []string{record.DecisionLostFragmentOverflow, record.DecisionLostRingbufFull}) {
		t.Fatalf("decision_lost = %v, want both, sorted", p.DecisionLost)
	}
}

// The names the field may carry are the recorder's own gap names.
func TestDecisionLostNamesAreTheRecordersGaps(t *testing.T) {
	if record.DecisionLostRingbufFull != GapRingbufFull || record.DecisionLostFragmentOverflow != GapExecFragmentOverflow ||
		len(record.DecisionLostWhys) != 2 {
		t.Fatal("record.DecisionLostWhys names a gap this recorder does not write")
	}
}

// A command rule that admitted the exec names its facts on the kernel's line too (ADR 0048 (8)): the rule and the copy of
// argv its decision read. An admitted exec can fail with EACCES with no decision record (a pin's refusal whose sample the ring
// lost, another module, the file's mode), so the line carries both the gate's facts and decision_lost, and the writer takes
// it at revision 41. Before the validator admitted the gate's own copied_syscall mark, the writer refused this line and the
// run ended with a ledger error.
func TestExecResultOfAnAdmittedCommandNamesTheGatesFactsAndTheLoss(t *testing.T) {
	f := newFixture(t)
	n := outcomeNaming(10)
	n.CommandRule, n.CommandList, n.CommandMatch = "git status", "allow", "prefix"
	n.ArgvFacts, n.ArgvRead = record.ArgvFactsCopied, 2
	_, sink := runRecorder(t, f, Options{ExecResults: true, Lost: &stepLost{values: []uint64{0, 4}},
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		execResultSample(execOutcomeHeader(30), -13))
	ev, p := oneExecOutcome(t, sink)
	if p.ArgvFacts != record.ArgvFactsCopied || p.CommandRule != "git status" ||
		!slices.Equal(p.DecisionLost, []string{record.DecisionLostRingbufFull}) {
		t.Fatalf("the line lost the gate's facts or the loss: %+v", p)
	}
	line, err := ev.MarshalLineAt(record.MinorEveryLaunch)
	if err != nil {
		t.Fatalf("the writer refuses the line the recorder wrote: %v", err)
	}
	if !strings.Contains(string(line), `"decision_lost":["ringbuf-full"]`) || !strings.Contains(string(line), `"argv_facts":"copied_syscall"`) {
		t.Fatalf("the written line lacks a field: %s", line)
	}
}

// The field names the gaps the run has lost so far, not the ones that rose since the previous exec result: a record
// the ring lost is counted when the kernel drops it, and another attempt's result (exec results of one run arrive in
// any order) may read the counter between that drop and this attempt's own result. A since-the-last-result rule would
// leave this attempt's line unmarked, a refusal's loss stated by no line, so the meaning stays run-wide.
func TestExecResultIsMarkedAfterAnotherResultReadTheSameLoss(t *testing.T) {
	f := newFixture(t)
	n := outcomeNaming(10)
	_, sink := runRecorder(t, f, Options{ExecResults: true, Lost: &stepLost{values: []uint64{0, 4, 4}},
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		execResultSample(execOutcomeHeader(30), -13), execResultSample(execOutcomeHeader(40), -13))
	evs := sink.byKind(record.KindExec)
	if len(evs) != 2 {
		t.Fatalf("%d exec lines, want 2", len(evs))
	}
	for i, ev := range evs {
		if p := payload[execOutcomePayload](t, ev); !slices.Equal(p.DecisionLost, []string{record.DecisionLostRingbufFull}) {
			t.Errorf("exec line %d: decision_lost = %v, want [ringbuf-full]", i, p.DecisionLost)
		}
	}
}
