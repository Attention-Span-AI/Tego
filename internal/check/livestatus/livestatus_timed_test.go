// SPDX-License-Identifier: Apache-2.0

package livestatus

import (
	"testing"
	"time"
)

// TestStatusAt: a block with a time limit says what it does at the instant: dormant while it is unblocked for a while,
// expired once its limit passed, "until its time limit ends" while it refuses, and an ended or watched run's state
// before any of those. A block with no limit is Status word for word.
func TestStatusAt(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	past, ahead := now.Add(-time.Hour), now.Add(time.Hour)
	var zero time.Time
	run := Facts{ReadsSeen: true, RecordMinor: 25, Timed: true}
	cases := []struct {
		name              string
		f                 Facts
		serial, confirmed uint64
		from, until       time.Time
		want              Result
	}{
		{"no limit", run, 3, 3, zero, zero, Result{InForce, SentenceInForce}},
		{"no limit, waiting", run, 3, 2, zero, zero, Result{Waiting, SentenceWaiting}},
		{"limit ahead", run, 3, 3, zero, ahead, Result{InForce, SentenceInForceUntil}},
		{"limit at now", run, 3, 3, zero, now, Result{Expired, SentenceExpired}},
		{"limit passed", run, 3, 3, zero, past, Result{Expired, SentenceExpired}},
		{"unblocked for a while", run, 3, 3, ahead, zero, Result{Dormant, SentenceDormant}},
		{"unblocked for a while, unconfirmed", run, 3, 2, ahead, zero, Result{Dormant, SentenceDormant}},
		{"unblock ended", run, 3, 3, past, zero, Result{InForce, SentenceInForce}},
		{"unblock ended, limit ahead", run, 3, 3, past, ahead, Result{InForce, SentenceInForceUntil}},
		{"dormant past its limit", run, 3, 3, ahead, past, Result{Expired, SentenceExpired}},
		{"path, reads unseen, limit ahead", Facts{RecordMinor: 25, Timed: true}, 3, 3, zero, ahead, Result{Partial, SentencePartial}},
		{"run ended", Facts{Ended: true}, 3, 3, ahead, past, Result{Ended, SentenceEnded}},
		{"watched", Facts{Observe: true}, 3, 3, ahead, past, Result{RecordedOnly, SentenceRecordedOnly}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind := KindExec
			if c.name == "path, reads unseen, limit ahead" {
				kind = KindPath
			}
			got := StatusAt(kind, c.f, c.serial, c.confirmed, now, c.from, c.until)
			if got != c.want {
				t.Fatalf("StatusAt = %+v, want %+v", got, c.want)
			}
			if c.from.IsZero() && c.until.IsZero() && got != Status(kind, c.f, c.serial, c.confirmed) {
				t.Fatalf("an untimed block differs from Status: %+v", got)
			}
		})
	}
	if Dormant.Refuses() || Expired.Refuses() {
		t.Error("a dormant or expired block claims a refusal")
	}
}
