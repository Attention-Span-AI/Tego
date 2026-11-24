// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"

	"github.com/attention-span-ai/tego/internal/check/mirror"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A refused action is two ledger lines: the action itself with verdict refused, and a kind=refused line that mirrors
// it (internal/runtime pipeline.go mirrorRefusals; the DNS broker writes the same pair). A person counts one refusal,
// so every count the dashboard shows (the run's Refused, the Overview tile, Logs' rows and headline, the Refusals
// tab, the line page's Similar) counts the pair once: the mirror is marked here, as the read model takes each line
// (runState.take), and left out wherever the action line is shown. A refused line with no action next to it (a
// first write the relay reset, an older ledger) is a refusal of its own and stays. This is the package's one
// counting rule (Event.Refusal). The pairing itself is internal/check/mirror's, the one implementation `tego measure`
// (R19), drift, learn and the receipt use too: the same window, envelope, rule and reason, and the same fallback, so
// a count cannot differ between them. TestReceiptAgreesWithDashboardAndMeasure holds the counts to one over every
// record fixture, mirror-split.jsonl among them, whose mirrors do not each follow their action.

// markMirror sets ev.Mirror when ev is a kind=refused line that mirrors a refused action no earlier mirror took
// (internal/check/mirror, Pairs.Fold), and notes which action it took. Every line of the run goes through it, in order,
// as Fold's window counts lines; ev is the line about to be added to st.b.Events, whose last line is the one just before
// it.
//
// Which actions a mirror took is the builder's own state (st.pairs), never a mark on the lines: a published Run shares
// its lines with every request holding it, so a line is not written once it is taken.
func (st *runState) markMirror(ev *Event) {
	ev.Mirror = false
	back, mirrors := st.foldMirror(ev)
	if !mirrors {
		return
	}
	ev.Mirror = true
	// A mirror carries no open flags and a reason such as fs-gate says nothing of the access, so whether it would have
	// changed a file is its action's to say (fsOp). So is what a rename or a link would have replaced: a mirror names one
	// path, the first, and an atomic write is a rename onto the file it writes.
	i := len(st.b.Events) - 1 - back
	if i < 0 {
		return // the action fell out of the retained window
	}
	a := &st.b.Events[i]
	ev.write = a.Kind == string(record.KindFS) && a.Op != "read"
	if ev.write && (a.Op == record.FSRename || a.Op == record.FSLink) {
		_, ev.to, _ = strings.Cut(a.Target, " → ")
	}
}

// foldMirror takes ev, the run's next line, through the pairing window: whether it mirrors a refused action, and how many
// lines before it that action is.
func (st *runState) foldMirror(ev *Event) (back int, mirrors bool) {
	return st.pairs.Fold(mirror.Fields{Kind: record.Kind(ev.Kind), Verdict: record.Verdict(ev.Verdict), Rule: ev.Rule,
		Reason: record.Reason(ev.Reason), PID: ev.pid, MonoNS: ev.mono})
}

// Refusal reports whether the line is one refusal as a person counts it: a refused action, or a refused line that
// mirrors no action (Mirror unset). Event.Refused also matches a mirror.
func (e *Event) Refusal() bool {
	if e.Kind == string(record.KindRefused) {
		return !e.Mirror
	}
	return e.Verdict == string(record.VerdictRefused) && record.Kind(e.Kind).IsAction()
}

// Actions is evs without the mirrors of refused actions: one line per thing the agent did. evs is not changed.
func Actions(evs []*Event) []*Event {
	out := make([]*Event, 0, len(evs))
	for _, e := range evs {
		if !e.Mirror {
			out = append(out, e)
		}
	}
	return out
}
