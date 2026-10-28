// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An Adjustable run's fence as its launcher applied it (ADR 0125): each entry run_start's live_fence lists, folded with
// the launcher's own lines about it (live-rule-lifted, live-rule-restored, live-lift-expired, live-lift-refused).
// These lines are written from what took effect, never from what a writer asked, so the rows say what Tego's live
// layer did; a lift asked and not yet applied is not shown as lifted.

// The states of a FenceRow.
const (
	// FenceRefused: Tego's live layer refuses the entry (the start, a restore, an expiry).
	FenceRefused = "refused"
	// FenceLifted: the launcher applied a lift or a grant of it, which has not ended.
	FenceLifted = "lifted"
)

// FenceRow is one fence entry of a run, as the launcher last applied it.
type FenceRow struct {
	// Kind (read, net or exec), Value (normalized), Source (deny or new: record.LiveFenceSource*) and Rule
	// (live.fence[<kind>:<value>]) are run_start's.
	Kind, Value, Source, Rule string
	// State is FenceRefused or FenceLifted.
	State string
	// Until is a lifted entry's limit (zero: the rest of the run); At is when the launcher applied the row's last
	// change a person or the launcher asked for (zero: none since the start; a lift's expiry keeps its lift's) and By
	// who asked it ("uid:<uid> pid:<pid> <via>", or the launcher's own words for a restore no person asked for).
	Until, At time.Time
	By        string
	// Note says what the last line about the entry was when the state alone does not: a lift that ended, a lift the
	// launcher refused, a restore made because the overlay could not be read.
	Note string
}

// The Notes FenceRows writes.
const (
	FenceNoteExpired = "The last lift ended at its time limit."
	// FenceNoteUnreadable is the note of a restore the launcher made with FenceByOverlay: it drops every lift when it
	// cannot trust the overlay's changes (the file unreadable, removed and written again, or changes trimmed from it
	// before it read them), so a restore it never saw cannot leave a lift in force.
	FenceNoteUnreadable = "Refused again: Tego could not trust the live overlay (unreadable, replaced, or changes lost), so it dropped every lift."
	// FenceNoteByTegoPrefix is followed by the launcher's own words for any other restore no person asked for.
	FenceNoteByTegoPrefix = "Refused again by Tego: "
	// FenceNoteRefusedPrefix is followed by the launcher's reason in words (fenceRefusedWords).
	FenceNoteRefusedPrefix = "A lift was refused: "
)

// FenceByOverlay is the by of the restore lines the launcher writes when it drops every lift because it cannot trust
// the overlay (internal/runtime livefence.go fenceUnreadableBy); a by starting "tego:" is the launcher's own, and any
// other names the person who asked.
const FenceByOverlay = "tego: the live overlay could not be read"

// FenceRows is run's fence as its launcher applied it, as of now: nil for a Locked run (no live_fence). A lifted row
// whose limit has passed by now shows as refused, since every match checks the limit (ADR 0125 decision 4) and the
// launcher's expiry line may still be on its way.
func FenceRows(run *Run, now time.Time) []FenceRow {
	if run == nil {
		return nil
	}
	var rows []FenceRow
	at := map[string]int{}
	for _, e := range run.AllEvents() {
		switch {
		case e.Kind == string(record.KindRunStart):
			var p struct {
				LiveMode  string            `json:"live_mode"`
				LiveFence *record.LiveFence `json:"live_fence"`
			}
			if json.Unmarshal([]byte(e.Raw), &p) != nil || p.LiveMode != record.LiveModeAdjustable || p.LiveFence == nil {
				return nil
			}
			rows = make([]FenceRow, 0, len(p.LiveFence.Entries))
			for _, f := range p.LiveFence.Entries {
				at[f.Kind+":"+f.Value] = len(rows)
				rows = append(rows, FenceRow{Kind: f.Kind, Value: f.Value, Source: f.Source, Rule: f.Rule, State: FenceRefused})
			}
		case e.Kind == string(record.KindGap) && fenceGapWhy(e.Target) != "":
			var p record.GapPayload
			if json.Unmarshal([]byte(e.Raw), &p) != nil || p.LiveBlock == nil {
				continue
			}
			c := p.LiveBlock
			i, ok := at[c.Kind+":"+c.Value]
			if !ok {
				continue // a refused lift outside the fence: no row to fold it into
			}
			r := &rows[i]
			switch p.Why {
			case record.GapLiveRuleLifted:
				r.State, r.Until, r.At, r.By, r.Note = FenceLifted, c.Until, e.TS, c.By, ""
			case record.GapLiveRuleRestored:
				r.State, r.Until, r.At, r.By, r.Note = FenceRefused, time.Time{}, e.TS, c.By, ""
				switch { // the launcher's own restore: no person asked for it
				case c.By == FenceByOverlay:
					r.Note = FenceNoteUnreadable
				case strings.HasPrefix(c.By, "tego:"):
					r.Note = FenceNoteByTegoPrefix + strings.TrimSpace(strings.TrimPrefix(c.By, "tego:")) + "."
				}
			case record.GapLiveLiftExpired:
				// At and By stay the lift's: the time limit ended it, no person did ("last changed by" on the page).
				r.State, r.Until, r.Note = FenceRefused, time.Time{}, FenceNoteExpired
			case record.GapLiveLiftRefused:
				r.Note = FenceNoteRefusedPrefix + fenceRefusedWords(c.Refused) + "."
			}
		}
	}
	for i := range rows {
		if r := &rows[i]; r.State == FenceLifted && !r.Until.IsZero() && !now.Before(r.Until) {
			r.State, r.Note = FenceRefused, FenceNoteExpired
		}
	}
	return rows
}

// fenceGapWhy is a gap line's why when its target ("<what> <why>") is one of the launcher's fence lines, else "".
func fenceGapWhy(t string) string {
	what, why, _ := strings.Cut(t, " ")
	if what != record.GapEnforce {
		return ""
	}
	switch why {
	case record.GapLiveRuleLifted, record.GapLiveRuleRestored, record.GapLiveLiftExpired, record.GapLiveLiftRefused:
		return why
	}
	return ""
}

// fenceRefusedWords is a live-lift-refused line's reason in words.
func fenceRefusedWords(refused string) string {
	switch refused {
	case record.LiveRefusedMAC:
		return "its signature did not check (a forged or replayed lift)"
	case record.LiveRefusedOutsideFence:
		return "the entry is outside this run's fence"
	case record.LiveRefusedLocked:
		return "the run's launcher holds no fence"
	case record.LiveRefusedUntil:
		return "its time limit had already passed"
	}
	return "the launcher did not apply it"
}
