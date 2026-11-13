// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The run page's live-block chips: each block in the Block now panel says what it does to the run now, from
// internal/check/livestatus over the run's own record (ledgerview.LiveFacts.StatusOf hands it as plain values: the
// edge imports no core) and the overlay's serials (runact.Live). The panel is the r-run-live region, so a chip moves
// from "Waiting for the run…" to "In force since line #N" over the page's live updates, with no reload, once the
// launcher's gap line arrives.

func init() {
	funcs["liveChip"] = liveChipOf
	funcs["markLine"] = markLine
}

// markLine is blockLine for a watched run, where a block refuses nothing: "Program ls: marked by alice at 23:40:12".
func markLine(b liveblock.Entry, r *ledgerview.Run, home string) blockText {
	t := blockLine(b, r, home)
	t.Rest = strings.Replace(t.Rest, ": blocked by ", ": marked by ", 1)
	return t
}

// liveView is the Block now panel's facts: the run's live facts and each block's serial.
type liveView struct {
	Facts ledgerview.LiveFacts
	// Serials maps each block's key to the serial of its add; Serial is the overlay's own (runact.LiveBlocks).
	Serials map[string]uint64
	Serial  uint64
	// Pause is the pause or resume the run's overlay asks that its launcher has not answered yet (pause.go).
	Pause pauseAsk
	// LauncherUnknown is why the run's launcher could not be confirmed alive or gone (runlock.LauncherCheck), "" when
	// it was judged: the run then reads as running, and the page says the check failed and what to do.
	LauncherUnknown string
	// Now is the instant a block's time limit is judged at (ADR 0125 decision 4); zero is time.Now.
	Now time.Time
}

// Observe is a watched run: a block there is recorded, not enforced.
func (v liveView) Observe() bool { return v.Facts.Observe }

// liveChip is one block's chip: State is livestatus's word, Label the chip's text, Sentence livestatus's sentence (the
// chip's title), Note the plain line beside the chip, and Class the badge class it reuses (app.css .b-*).
type liveChip struct {
	State, Label, Sentence, Note, Class string
}

// liveChipOf is block b's chip on the run v describes.
func liveChipOf(b liveblock.Entry, v liveView) liveChip {
	serial, ok := v.Serials[b.Key()]
	if !ok {
		serial = v.Serial
	}
	now := v.Now
	if now.IsZero() {
		now = time.Now()
	}
	// A block with a time limit is judged at now (livestatus.StatusAt): an unblock for a while refuses nothing until
	// its From, and a block past its Until refuses nothing, though the overlay keeps it for a while.
	st := v.Facts.StatusAt(string(b.Kind), serial, now, b.From, b.Until)
	c := liveChip{State: st.State, Sentence: st.Sentence}
	since := ""
	if st.Since > 0 {
		since = " since line #" + strconv.FormatUint(st.Since, 10)
	}
	switch st.State {
	case ledgerview.LiveInForce:
		c.Label, c.Class, c.Note = "In force"+since, "b-active", "Refused from the next try until the run ends."
		if !b.Until.IsZero() {
			c.Note = "Refused from the next try until " + limitAt(b.Until) + "."
		}
	case ledgerview.LiveDormant:
		c.Label, c.Class, c.Note = "Unblocked for a while", "b-neutral", "Refuses nothing until "+limitAt(b.From)+"; then it is refused again."
	case ledgerview.LiveExpired:
		c.Label, c.Class, c.Note = "Ended by its time limit", "b-done", "Its time limit passed at "+limitAt(b.Until)+", so it refuses nothing."
	case ledgerview.LivePartial:
		c.Label, c.Class, c.Note = "Changes refused"+since, "b-besteffort", "Edits are refused; this run's reads are not seen, so reading it still works."
	case ledgerview.LiveWaiting:
		c.Label, c.Class, c.Note = "Waiting for the run…", "b-waiting", "The run picks up a new block within about a second."
	case ledgerview.LiveRecordedOnly:
		c.Label, c.Class, c.Note = "Recorded, not enforced", "b-observed", "This run is only watched: matching actions are recorded, not stopped."
	default: // ledgerview.LiveEnded
		c.Label, c.Class, c.Note = "Ended", "b-done", "The run has ended, so it refuses nothing."
	}
	return c
}

// limitAt is a time limit's instant in this machine's zone, as a chip's note says it: "Fri 31 Oct 17:00".
func limitAt(t time.Time) string {
	lt := t.Local()
	if lt.Year() != time.Now().Year() {
		return lt.Format("Mon 2 Jan 2006 15:04")
	}
	return lt.Format("Mon 2 Jan 15:04")
}
