// SPDX-License-Identifier: Apache-2.0

package livestatus

import (
	"testing"
	"time"
)

// TestStatusRecordedFollowsTheLaunchersClock (C215): a block's limit ends when the run's launcher says it did (the
// line it recorded), not when a wall clock reads past it. The launcher judges an end on the wall clock and on a
// clock no step moves, so after a clock step the wall clock alone is wrong both ways: StatusAt said Expired for a
// block the launcher still enforced, and in force for one it had ended. The clock is passed in, so no test sleeps.
func TestStatusRecordedFollowsTheLaunchersClock(t *testing.T) {
	until := time.Date(2026, 11, 21, 17, 0, 0, 0, time.UTC)
	run := Facts{ReadsSeen: true, RecordMinor: 25, Timed: true}
	var zero time.Time
	end := func() Limits { var l Limits; l.Record(WhyBlockExpired, KindExec, "/bin/ls", until); return l }
	begun := func() Limits { var l Limits; l.Record(WhyUnblockExpired, KindExec, "/bin/ls", until); return l }

	cases := []struct {
		name        string
		now         time.Time
		from, until time.Time
		lim         Limits
		partial     bool
		want        Result
	}{
		// The wall clock was stepped forward two hours: its reading is past the limit, the launcher's other clock is not.
		{"clock stepped forward, no line", until.Add(2 * time.Hour), zero, until, Limits{}, false, Result{InForce, SentenceInForceReached}},
		// The clock is back in step and the launcher recorded the end.
		{"line recorded", until.Add(time.Second), zero, until, end(), false, Result{Expired, SentenceExpired}},
		// The wall clock was stepped back an hour after the launcher recorded the end: it stays ended.
		{"clock stepped back, line recorded", until.Add(-time.Hour), zero, until, end(), false, Result{Expired, SentenceExpired}},
		{"ahead, no line", until.Add(-time.Hour), zero, until, Limits{}, false, Result{InForce, SentenceInForceUntil}},
		// The line is for another end of the same block.
		{"line for an earlier end", until.Add(time.Second), zero, until.Add(time.Hour), end(), false, Result{InForce, SentenceInForceUntil}},
		// Unblocked for a while: it refuses again when the launcher says so.
		{"unblock ahead, no line", until.Add(-time.Hour), until, zero, Limits{}, false, Result{Dormant, SentenceDormant}},
		{"unblock, clock stepped back, line recorded", until.Add(-time.Hour), until, zero, begun(), false, Result{InForce, SentenceInForce}},
		{"unblock, wall clock past it", until.Add(time.Minute), until, zero, Limits{}, false, Result{InForce, SentenceInForce}},
		// Only part of the record was read: an absent line proves nothing, so the wall clock decides, as StatusAt does.
		{"partial record, past its limit", until.Add(time.Minute), zero, until, Limits{}, true, Result{Expired, SentenceExpired}},
		{"partial record, ahead", until.Add(-time.Minute), zero, until, Limits{}, true, Result{InForce, SentenceInForceUntil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lim := c.lim
			lim.Partial = c.partial
			got := StatusRecorded(KindExec, "/bin/ls", run, 3, 3, c.now, c.from, c.until, lim)
			if got != c.want {
				t.Fatalf("StatusRecorded = %+v, want %+v", got, c.want)
			}
		})
	}
	// A run that has ended or is only watched is what Status says, whatever its limits.
	if got := StatusRecorded(KindExec, "/bin/ls", Facts{Ended: true}, 3, 3, until.Add(time.Hour), zero, until, Limits{}); got.State != Ended {
		t.Errorf("an ended run reads %+v", got)
	}
	var lim Limits
	if at := lim.At(KindExec, "/bin/ls", until.Add(time.Minute), zero, until); !at.Reached || at.Ended || at.Dormant {
		t.Errorf("a limit this clock has passed, with no line: %+v", at)
	}
	lim.Record(WhyBlockExpired, KindExec, "/bin/ls", until)
	if at := lim.At(KindExec, "/bin/ls", until.Add(time.Minute), zero, until); at.Reached || !at.Ended {
		t.Errorf("a limit the launcher recorded: %+v", at)
	}
}
