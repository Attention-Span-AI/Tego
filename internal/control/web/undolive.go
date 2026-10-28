// SPDX-License-Identifier: Apache-2.0

package web

import (
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
	switch n := len(rv.Kept); {
	case n == 1:
		parts = append(parts, "The live block it placed stays on its run until the run ends or you remove it on the run's page.")
	case n > 1:
		parts = append(parts, "The "+plural4(n, "live block", "live blocks")+" it placed stay on their runs until they end or you remove them on the run's page.")
	}
	return strings.Join(parts, " ")
}
