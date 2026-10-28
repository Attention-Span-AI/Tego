// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// LiveFacts is what a run's record says about its live blocks: whether the run can enforce one (run_start's tier and
// reads, run_end) and which overlay serials its launcher recorded putting in force. A view compares a block's serial
// with Confirmed to say "Waiting for the run…" or "In force since line #N" (internal/check/livestatus).
type LiveFacts struct {
	// Facts is Observe and ReadsSeen from the run's run_start line (livestatus.FromStartJSON) and Ended from its
	// run_end.
	livestatus.Facts
	// Confirmed is the highest overlay serial a gap line what=enforce why=live-block-added or live-block-removed
	// carries (record.GapPayload.LiveBlock): the launcher wrote the line once it had put that change in force, so
	// every change up to it is in force. 0 when no such line was read. ConfirmedSeq is that line's seq.
	Confirmed    uint64
	ConfirmedSeq uint64
	// confirms is each confirming line's serial and seq, in ledger order (serials grow with it).
	confirms []liveConfirm

	// The run's pause as its launcher recorded it (record.MinorLiveControl): the last gap line what=enforce why
	// run-paused, run-resumed, pause-failed or resume-failed. Paused is true from a run-paused or resume-failed line
	// until a later run-resumed line, and never once the run has ended (its run_end ends the pause). Pause is that
	// last line's why ("" when the run was never paused), PausedBy and PausedAt who asked for it and when the
	// launcher applied it (the line's ts), PauseSeq the line's seq and PauseSerial the overlay serial it records. A
	// view says "Paused by you at 12:03" only from these: a pause the launcher has not confirmed is not shown as one
	// (a request it has not answered yet has a serial above PauseSerial).
	Paused      bool
	Pause       string
	PausedBy    string
	PausedAt    time.Time
	PauseSeq    uint64
	PauseSerial uint64
}

type liveConfirm struct{ serial, seq uint64 }

// liveMemo is runMemo's one field for this file: the run's LiveFacts, built once per published version. Later
// views of live blocks add their derived state here, never to runMemo.
type liveMemo struct {
	once  sync.Once
	facts LiveFacts
}

// LiveFactsOf is r's LiveFacts. Everything but Ended is built from the run's lines once per published version (the
// run_start payload is decoded once, and only gap lines naming a live block are decoded); Ended is the run's own.
func LiveFactsOf(r *Run) LiveFacts {
	m := &r.memoOf().live
	m.once.Do(func() { m.facts = liveFactsOf(r.AllEvents()) })
	f := m.facts
	f.Ended = r.Ended
	if f.Ended {
		f.Paused = false // run_end ends a pause: its processes were thawed or killed
	}
	return f
}

// liveFactsOf builds LiveFacts from a run's lines.
func liveFactsOf(evs []Event) LiveFacts {
	var f LiveFacts
	for i := range evs {
		e := &evs[i]
		switch {
		case e.Kind == string(record.KindRunStart):
			f.Facts = livestatus.FromStartJSON([]byte(e.Raw))
		case e.Kind == string(record.KindGap) && pauseGapWhy(e.Target) != "":
			var p record.GapPayload
			if json.Unmarshal([]byte(e.Raw), &p) != nil || p.LiveControl == nil {
				continue
			}
			f.Pause, f.PauseSeq, f.PauseSerial = p.Why, e.Seq, p.LiveControl.Serial
			switch p.Why {
			case record.GapRunPaused:
				f.Paused, f.PausedBy, f.PausedAt = true, p.LiveControl.By, e.TS
			case record.GapRunResumed:
				f.Paused = false
			case record.GapResumeFailed:
				f.Paused = true // the thaw failed: the run stays frozen, paused by whoever paused it
			}
		case e.Kind == string(record.KindGap) && liveGapTarget(e.Target):
			var p record.GapPayload
			if json.Unmarshal([]byte(e.Raw), &p) != nil || p.LiveBlock == nil {
				continue
			}
			f.confirms = append(f.confirms, liveConfirm{p.LiveBlock.Serial, e.Seq})
			if p.LiveBlock.Serial >= f.Confirmed {
				f.Confirmed, f.ConfirmedSeq = p.LiveBlock.Serial, e.Seq
			}
		}
	}
	return f
}

// liveGapTarget reports whether a gap line's target ("<what> <why>") is a live block's add or remove.
func liveGapTarget(t string) bool {
	what, why, _ := strings.Cut(t, " ")
	return what == record.GapEnforce && (why == record.GapLiveBlockAdded || why == record.GapLiveBlockRemoved)
}

// pauseGapWhy is a gap line's why when its target ("<what> <why>") records a pause or a resume, else "".
func pauseGapWhy(t string) string {
	what, why, _ := strings.Cut(t, " ")
	if what != record.GapEnforce {
		return ""
	}
	switch why {
	case record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed:
		return why
	}
	return ""
}

// Status is a live block's state on the run: kind is liveblock's exec, net or path, serial the overlay serial of the
// change that added it.
func (f LiveFacts) Status(kind string, serial uint64) livestatus.Result {
	return livestatus.Status(kind, f.Facts, serial, f.Confirmed)
}

// The live states as plain strings (livestatus.State's values), for the views above this package, which do not import
// the core (the dashboard's edge renders what its services hand it).
const (
	LiveInForce      = string(livestatus.InForce)
	LivePartial      = string(livestatus.Partial)
	LiveWaiting      = string(livestatus.Waiting)
	LiveRecordedOnly = string(livestatus.RecordedOnly)
	LiveEnded        = string(livestatus.Ended)
	LiveDormant      = string(livestatus.Dormant)
	LiveExpired      = string(livestatus.Expired)
)

// LiveStatus is a live block's state as plain values: State one of the Live* strings, Sentence livestatus's, and
// Since the seq of the line that confirmed the block (0 while none has).
type LiveStatus struct {
	State, Sentence string
	Since           uint64
}

// StatusOf is Status as plain values, with the confirming line's seq.
func (f LiveFacts) StatusOf(kind string, serial uint64) LiveStatus {
	r := f.Status(kind, serial)
	s := LiveStatus{State: string(r.State), Sentence: r.Sentence}
	if seq, ok := f.Since(serial); ok {
		s.Since = seq
	}
	return s
}

// StatusAt is StatusOf for a block that may carry a time limit (liveblock.Entry's From and Until), judged at now
// (livestatus.StatusAt): dormant while it is unblocked for a while, expired once its limit passed.
func (f LiveFacts) StatusAt(kind string, serial uint64, now, from, until time.Time) LiveStatus {
	r := livestatus.StatusAt(kind, f.Facts, serial, f.Confirmed, now, from, until)
	s := LiveStatus{State: string(r.State), Sentence: r.Sentence}
	if r.State == livestatus.Dormant || r.State == livestatus.Expired {
		return s // refuses nothing now: no "since line #N"
	}
	if seq, ok := f.Since(serial); ok {
		s.Since = seq
	}
	return s
}

// Since is the seq of the first line that confirmed serial: the first confirming gap line whose serial is serial or
// later. ok is false while no line has.
func (f LiveFacts) Since(serial uint64) (seq uint64, ok bool) {
	i := sort.Search(len(f.confirms), func(i int) bool { return f.confirms[i].serial >= serial })
	if i == len(f.confirms) {
		return 0, false
	}
	return f.confirms[i].seq, true
}
