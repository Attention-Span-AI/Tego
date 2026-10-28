// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"
	"time"
)

// TestLiveAckBindsEachField: a lift's acknowledgement checks only for the run, kind, value, limit, permanent flag and
// overlay serial it was made for, and never under another service's key.
func TestLiveAckBindsEachField(t *testing.T) {
	s := &Service{}
	until := time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC)
	const run, kind, value = "r-aaaaaaaa-0000000000006-askedx", "read", "/srv/exports"
	ack := s.LiveAck(run, kind, value, until, false, 3)
	if !s.LiveAckOK(ack, run, kind, value, until, false, 3) {
		t.Fatal("the acknowledgement does not check for the fields it was made for")
	}
	if !s.LiveAckOK(ack, run, kind, value, until.In(time.FixedZone("x", 3600)), false, 3) {
		t.Error("the same instant in another zone does not check")
	}
	for name, ok := range map[string]bool{
		"another run":       s.LiveAckOK(ack, "r-aaaaaaaa-0000000000007-askedx", kind, value, until, false, 3),
		"another kind":      s.LiveAckOK(ack, run, "exec", value, until, false, 3),
		"another value":     s.LiveAckOK(ack, run, kind, "/srv/exports/x", until, false, 3),
		"a later limit":     s.LiveAckOK(ack, run, kind, value, until.Add(time.Second), false, 3),
		"no limit":          s.LiveAckOK(ack, run, kind, value, time.Time{}, false, 3),
		"permanent":         s.LiveAckOK(ack, run, kind, value, until, true, 3),
		"a later serial":    s.LiveAckOK(ack, run, kind, value, until, false, 4),
		"none posted":       s.LiveAckOK("", run, kind, value, until, false, 3),
		"another key":       (&Service{}).LiveAckOK(ack, run, kind, value, until, false, 3),
		"a value colon":     s.LiveAckOK(s.LiveAck(run, kind, "a:b", until, false, 3), run, kind+":a", "b", until, false, 3),
		"a change ack's":    s.LiveAckOK(s.ack(liveAckRef(run, kind, value), "", ""), run, kind, value, until, false, 3),
		"no limit vs limit": s.LiveAckOK(s.LiveAck(run, kind, value, time.Time{}, true, 3), run, kind, value, until, true, 3),
	} {
		if ok {
			t.Errorf("%s: the acknowledgement checks", name)
		}
	}
	// The same preview gives the same acknowledgement (no nonce, no clock), so a re-rendered page keeps its bytes.
	if again := s.LiveAck(run, kind, value, until, false, 3); again != ack {
		t.Error("the acknowledgement is not deterministic")
	}
}
