// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An event is a record of a decision the run made: one for a notification this loop never answered would
// claim a verdict nobody delivered (R19, E1).
func TestEmitForRecordsOnlyAnsweredNotifications(t *testing.T) {
	l, sink := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	n := notifFor(0, 1234)

	l.emitFor(n, l.event(n, record.KindGap, record.SourceSupervisor), record.GapPayload{What: "x", Why: "y"})
	if got := len(sink.all()); got != 0 {
		t.Fatalf("an unanswered notification recorded %d events", got)
	}
	n.answered = true
	l.emitFor(n, l.event(n, record.KindGap, record.SourceSupervisor), record.GapPayload{What: "x", Why: "y"})
	if got := len(sink.all()); got != 1 {
		t.Fatalf("an answered notification recorded %d events, want 1", got)
	}
}

func TestEmitDropsWhatCannotBeEncodedAndNilEvents(t *testing.T) {
	l, sink := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	n := notifFor(0, 1234)
	l.emit(nil, record.GapPayload{})
	// A channel cannot be marshalled: the event is dropped and logged, never emitted half-formed.
	l.emit(l.event(n, record.KindGap, record.SourceSupervisor), make(chan int))
	if got := len(sink.all()); got != 0 {
		t.Fatalf("%d events emitted, want none", got)
	}
}

func TestEmitGapCarriesTheReasonAndNoAgentData(t *testing.T) {
	l, sink := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	l.emitGap(notifFor(0, 1234), "enforce", "handler panic")
	ev := sink.one(t)
	var p record.GapPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != record.KindGap || p.What != "enforce" || p.Why != "handler panic" || p.Count != 1 {
		t.Fatalf("gap = %+v %+v", ev, p)
	}
}

func TestObserveStampsOnlyActionKinds(t *testing.T) {
	for kind, stamped := range map[record.Kind]bool{
		record.KindExec: true, record.KindFS: true, record.KindNet: true, record.KindMCP: true, record.KindGap: false,
	} {
		ev := &record.Event{Kind: kind, Verdict: record.VerdictRefused, Reason: "net-outside-contract"}
		stampObserved(ev)
		if got := ev.Verdict == record.VerdictObserved; got != stamped {
			t.Errorf("%s: observed=%v, want %v", kind, got, stamped)
		}
		if stamped && ev.Reason != "" {
			t.Errorf("%s: an observed event carries no reason, got %q", kind, ev.Reason)
		}
		if !stamped && (ev.Verdict != record.VerdictRefused || ev.Reason == "") {
			t.Errorf("%s: a non-action event must be left as it is", kind)
		}
	}
}
