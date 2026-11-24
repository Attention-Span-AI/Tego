// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// Undo and live blocks: every Undo form of a change that placed live blocks on runs still running
// carries a "lift" box, ticked, that also lifts those blocks (rules.RevertReq.Lift); the rule service lifts only the
// ones the change placed that still hold, and wants the Undo's acknowledgement with it (lift.go). This file holds the
// words both Undo answers (the event page's and POST /rules/revert's) say about them; it decides nothing.

// liftOut is a lift option in words, for a page: the run, the block in short words and its key.
type liftOut struct {
	Run, Words, Block string
}

// liftOuts is opts in words, each Value said under its run's folder and the home; nil for none.
func liftOuts(opts []rules.LiftOption) []liftOut {
	if len(opts) == 0 {
		return nil
	}
	home := homeDir()
	out := make([]liftOut, 0, len(opts))
	for _, o := range opts {
		out = append(out, liftOut{Run: o.Run, Block: o.Block, Words: liveWords(o.Block, shortener{cwd: o.Cwd, home: home})})
	}
	return out
}

// undoLiveLine is the sentence an Undo answer ends with about the live blocks the undone change had placed: lifted,
// not lifted (with why), or kept because the Undo's box was not ticked; "" when the change placed none that still
// held. It never says a block is lifted that the launcher has not been asked to lift.
func undoLiveLine(rv *rules.Reverted) string {
	lifted, failed := 0, ""
	for _, l := range rv.Lifted {
		if l.OK {
			lifted++
		} else if failed == "" {
			failed = l.Err
		}
	}
	var parts []string
	switch {
	case lifted == 1:
		parts = append(parts, "The live block it placed is being lifted: within about a second its run may do that again.")
	case lifted > 1:
		parts = append(parts, "The "+plural4(lifted, "live block", "live blocks")+" it placed are being lifted: within about a second their runs may do that again.")
	}
	if failed != "" {
		parts = append(parts, "A live block it placed was "+strings.TrimSuffix(failed, ".")+"; remove it on the run's page.")
	}
	// A Redo (this answer undoes an Undo) puts back the live blocks that Undo had lifted.
	put, already := 0, 0
	var notPut []string
	for _, l := range rv.Restored {
		switch {
		case l.OK:
			put++
		case l.Held:
			already++
		default:
			who := "A live block the Undo had lifted"
			if l.Block != "" {
				who = "The live block " + l.Block
			}
			notPut = append(notPut, who+" was "+strings.TrimSuffix(l.Err, ".")+"; place it again on the run's page.")
		}
	}
	switch {
	case put == 1:
		parts = append(parts, "The live block the Undo had lifted is back on its run, as it was.")
	case put > 1:
		parts = append(parts, "The "+plural4(put, "live block", "live blocks")+" the Undo had lifted are back on their runs, as they were.")
	}
	if already > 0 {
		if already == 1 {
			parts = append(parts, "A live block it would put back was on its run already, so it was left as it was.")
		} else {
			parts = append(parts, "The "+strconv.Itoa(already)+" live blocks it would put back were on their runs already, so they were left as they were.")
		}
	}
	parts = append(parts, notPut...)
	own, other := 0, 0
	for _, k := range rv.Kept {
		if k.Mine {
			own++
		} else {
			other++
		}
	}
	switch n := own; {
	case n == 1:
		parts = append(parts, "The live block it placed stays on its run until the run ends or you remove it on the run's page.")
	case n > 1:
		parts = append(parts, "The "+plural4(n, "live block", "live blocks")+" it placed stay on their runs until they end or you remove them on the run's page.")
	}
	// A block the journal says the change placed, but that Tego cannot show is the change's own now (it may be yours, put
	// back by hand, or placed before the journal kept who made a block), is never lifted by an Undo.
	switch {
	case other == 1:
		parts = append(parts, "A live block on its run was left in place: Tego cannot show this change made it (it may be yours), so remove it on the run's page if you want it gone.")
	case other > 1:
		parts = append(parts, "The "+plural4(other, "live block", "live blocks")+" on their runs were left in place: Tego cannot show this change made them (they may be yours), so remove them on the run's page if you want them gone.")
	}
	return strings.Join(parts, " ")
}
