// SPDX-License-Identifier: Apache-2.0

package web

import "github.com/attention-span-ai/tego/internal/control/ledgerview"

// lineWords is what Logs says of one line in words: its verdict chip, the action, what it acted on and the reason. The
// page's rows (rowViews) and the CSV download (logsCSV) both take their words from lineWordsOf, so the two cannot say
// different things of the same line; TestCSVAndPageSayTheSameWords reads both for every kind of line. The page adds
// only how it shows What (the paths shortened to the run's home, pathWordsIn).
type lineWords struct {
	// Verdict is the chip's word (pageVerdict), Action the operation (shownOp), What the object, masked, and for a
	// command the whole command (shown; a launcher in front of a shell script is not elided), and Why the reason in
	// words (reasonWords), "" when the line gives none.
	Verdict, Action, What, Why string
}

// lineWordsOf is e in words; reads is the run's read context (readContextOf) or nil.
func lineWordsOf(e ledgerview.Event, reads *readContext) lineWords {
	_, _, verdict := pageVerdict(e, reads)
	what := shown(e)
	if e.Kind == "exec" {
		what = mask(e.Target)
	}
	return lineWords{Verdict: verdict, Action: shownOp(e), What: what, Why: reasonWords(e)}
}
