// SPDX-License-Identifier: Apache-2.0

package livestatus

import (
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The whys of the gap lines in which a run's launcher records that a time limit passed.
const (
	WhyBlockExpired   = record.GapLiveBlockExpired
	WhyUnblockExpired = record.GapLiveUnblockExpired
)

// Limits are the time limits of a run's blocks that its launcher recorded as passed: the end of a block (its Until),
// and the end of an unblock for a while (its From, after which the block refuses again). The launcher decides each on
// its wall clock and on CLOCK_BOOTTIME, which no clock step moves (internal/liveblock Ended and Begun), so only its own
// line says a limit passed. A reader's wall clock, read past the limit after a step of the clock, says it too early;
// read before it after a step back, too late. StatusRecorded judges by these lines and uses the reader's clock only
// for what the lines cannot say.
type Limits struct {
	ended, begun map[string]bool
	// Partial: the lines read are a part of the run's record (older lines were left out), so a missing line proves
	// nothing, and the reader's clock decides as StatusAt does.
	Partial bool
}

// limitKey names one limit of one block: the block's kind and value and the instant. The instant is the nanosecond
// count of its UTC time, so a time read back from a ledger line equals the one the overlay holds.
func limitKey(kind, value string, t time.Time) string {
	return kind + "\x00" + value + "\x00" + strconv.FormatInt(t.UnixNano(), 10)
}

// Record notes a launcher's line of why (WhyBlockExpired or WhyUnblockExpired) for the block of kind and value whose
// limit was t. Any other why is ignored.
func (l *Limits) Record(why, kind, value string, t time.Time) {
	switch why {
	case WhyBlockExpired:
		if l.ended == nil {
			l.ended = map[string]bool{}
		}
		l.ended[limitKey(kind, value, t)] = true
	case WhyUnblockExpired:
		if l.begun == nil {
			l.begun = map[string]bool{}
		}
		l.begun[limitKey(kind, value, t)] = true
	}
}

// BlockEnded reports whether the launcher recorded the block's end at until.
func (l Limits) BlockEnded(kind, value string, until time.Time) bool {
	return l.ended[limitKey(kind, value, until)]
}

// UnblockBegun reports whether the launcher recorded that the unblock for a while ended at from.
func (l Limits) UnblockBegun(kind, value string, from time.Time) bool {
	return l.begun[limitKey(kind, value, from)]
}

// Standing is where a block's time limits stand at an instant, by the launcher's lines.
type Standing struct {
	// Ended: the block's end passed, so it refuses nothing. Recorded by the launcher, or (a partial record) read past
	// until on the reader's clock.
	Ended bool
	// Dormant: an unblock for a while is still on, so the block refuses nothing yet.
	Dormant bool
	// Reached: the reader's clock has passed until but the launcher has not recorded the end. The wall clock was
	// stepped, or the line is a moment away; the run decides by its own clock, and the block still refuses.
	Reached bool
}

// At is the standing of the block of kind and value at now, with the instants of its unblock (from) and of its end
// (until), either of which may be zero:
//   - Ended: the block's end recorded at until (with a partial record, now at or past until);
//   - Dormant: from is ahead of now and the launcher has not recorded that it passed (it may have, if the wall clock was
//     stepped back);
//   - Reached: now is at or past until and Ended is not.
//
// An unblock whose from now has passed is over, recorded or not: the launcher ends it as soon as its wall clock reaches
// it, which is the clock now reads, so the block is not Dormant then.
func (l Limits) At(kind, value string, now, from, until time.Time) Standing {
	var s Standing
	switch {
	case !until.IsZero() && (l.BlockEnded(kind, value, until) || l.Partial && !now.Before(until)):
		s.Ended = true
	case !from.IsZero() && now.Before(from) && !l.UnblockBegun(kind, value, from):
		s.Dormant = true
	case !until.IsZero() && !now.Before(until):
		s.Reached = true
	}
	return s
}

// SentenceInForceReached is SentenceInForce for a block whose limit has passed on the reader's clock but that the
// launcher has not ended: it says whose clock decides.
const SentenceInForceReached = "In force: its time limit has passed on this clock, but the run keeps its own time and ends it by that"

// StatusRecorded is StatusAt with the launcher's own word on each limit (lim, from its recorded lines) in place of the
// reader's clock. The first rule that matches decides:
//   - an ended run: Ended; a watched run: RecordedOnly (as Status);
//   - the block's end passed (Limits.At): Expired; an unblock for a while still on: Dormant;
//   - otherwise Status, saying "until its time limit ends" for an in-force block with an until, and
//     SentenceInForceReached once now has passed it with no line.
func StatusRecorded(kind, value string, f Facts, serial, confirmed uint64, now, from, until time.Time, lim Limits) Result {
	if f.Ended || f.Observe {
		return Status(kind, f, serial, confirmed)
	}
	at := lim.At(kind, value, now, from, until)
	switch {
	case at.Ended:
		return Result{Expired, SentenceExpired}
	case at.Dormant:
		return Result{Dormant, SentenceDormant}
	}
	r := Status(kind, f, serial, confirmed)
	if r.State == InForce && !until.IsZero() {
		r.Sentence = SentenceInForceUntil
		if at.Reached {
			r.Sentence = SentenceInForceReached
		}
	}
	return r
}
