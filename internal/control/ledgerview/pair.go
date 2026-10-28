// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A refused action is two ledger lines: the action itself with verdict refused, and a kind=refused line that mirrors
// it (internal/runtime pipeline.go mirrorRefusals; the DNS broker writes the same pair). A person counts one refusal,
// so every count the dashboard shows (the run's Refused, the Overview tile, Logs' rows and headline, the Refusals
// tab, the line page's Similar) counts the pair once: the mirror is marked here, as the read model takes each line
// (runState.take), and left out wherever the action line is shown. A refused line with no action next to it (a
// first write the relay reset, an older ledger) is a refusal of its own and stays. This is the package's one
// counting rule (Event.Refusal). It is measure's (R19, internal/check/internal/mirror), which pairs a mirror only
// with the line just before it, widened to a mirror that another writer's line slipped in front of.

// mirrorWindow is how many lines back a mirror's action may be. The writer appends the mirror right after its action,
// so it is the line before; the window only absorbs a line another writer slipped in between.
const mirrorWindow = 4

// markMirror sets ev.Mirror when ev is a kind=refused line that mirrors a refused action no earlier mirror took,
// with the same rule and reason. The mirror is a copy of its action's envelope, so the action is first looked for by
// pid and monotonic clock among the run's last mirrorWindow lines: that passes over a line slipped in between, and
// pairs each mirror with its own action when two refusals were written before either mirror. Failing that (a line
// with no monotonic clock, an older ledger), the line just before it is its action.
//
// Which actions a mirror took is the builder's own state (st.paired), never a mark on the lines: a published Run
// shares its lines with every request holding it, so a line is not written once it is taken.
func (st *runState) markMirror(ev *Event) {
	ev.Mirror = false
	if ev.Kind != string(record.KindRefused) {
		return
	}
	evs := st.b.Events
	// Only the window's lines can still be taken.
	st.paired = slices.DeleteFunc(st.paired, func(i int) bool { return i < len(evs)-mirrorWindow })
	prev := -1
	for i, n := len(evs)-1, 0; i >= 0 && n < mirrorWindow; i, n = i-1, n+1 {
		a := &evs[i]
		if !record.Kind(a.Kind).IsAction() || a.Verdict != string(record.VerdictRefused) || slices.Contains(st.paired, i) {
			continue
		}
		if a.Rule != ev.Rule || a.Reason != ev.Reason {
			continue
		}
		if ev.mono != 0 && a.mono == ev.mono && a.pid == ev.pid {
			st.pair(ev, i)
			return
		}
		if n == 0 {
			prev = i
		}
	}
	if prev >= 0 {
		st.pair(ev, prev)
	}
}

// pair marks ev as the mirror of line i. A mirror carries no open flags and a reason such as fs-gate says nothing of
// the access, so whether it would have changed a file is its action's to say (fsOp). So is what a rename or a link
// would have replaced: a mirror names one path, the first, and an atomic write is a rename onto the file it writes.
func (st *runState) pair(ev *Event, i int) {
	st.paired, ev.Mirror = append(st.paired, i), true
	a := &st.b.Events[i]
	ev.write = a.Kind == string(record.KindFS) && a.Op != "read"
	if ev.write && (a.Op == record.FSRename || a.Op == record.FSLink) {
		_, ev.to, _ = strings.Cut(a.Target, " → ")
	}
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
