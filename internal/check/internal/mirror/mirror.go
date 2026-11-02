// SPDX-License-Identifier: Apache-2.0

// Package mirror recognises a refused line that mirrors a refused action line before it, the one rule drift (R13),
// measure (R19), learn and the receipt need to count a refusal once. It lives in one place so those views cannot count
// refusals differently. The dashboard pairs by the same rule (internal/control/ledgerview, pair.go), which cannot
// import this package; ledgerview's TestReceiptAgreesWithDashboardAndMeasure holds the two to one count over every
// record v1 fixture, mirror-split.jsonl among them, whose mirrors do not each follow their action.
package mirror

import "github.com/attention-span-ai/tego/pkg/spec/record"

// window is how many lines back a mirror's action may be, as ledgerview's mirrorWindow. The pipeline writes a mirror
// right after its action (mirrorRefusals), but other writers append to the same ledger on their own (the DNS broker,
// which writes its own pairs, and the approval broker), so a line of theirs can come between the two, and two
// refusals can both be written before either mirror.
const window = 4

// Pairs pairs each refused line of one run with the refused action it mirrors. A mirror is a copy of its action's
// envelope, rule and reason, so its action is the nearest of the window lines before it that is a refused action under
// the same rule and reason, with the same pid and monotonic clock, that no earlier mirror took. Failing that (a mirror
// with no monotonic clock, or one whose writer stamped a clock of its own), it is the line just before it, when that
// line is such an action in all but the envelope. A refused line that pairs with nothing is a refusal of its own (a
// keyring or mount-family refusal, a first write the relay reset). The zero Pairs has seen no line.
type Pairs struct {
	back [window]line // the last window lines, the newest first; a slot no line filled is no action
}

// line is what Pairs keeps of one line: whether it is a refused action no mirror took yet, and what a mirror copies.
type line struct {
	open   bool
	rule   string
	reason record.Reason
	pid    int
	mono   uint64
}

// Take takes e, the run's next line, and reports whether it is a refused line that mirrors a refused action before it.
// Every line of the run goes through Take once, in ledger order, whatever its kind and whatever the caller does with
// it: the window counts lines.
func (p *Pairs) Take(e *record.Event) bool {
	mirrors := e.Kind == record.KindRefused && p.pair(e)
	copy(p.back[1:], p.back[:window-1])
	p.back[0] = line{open: e.Kind.IsAction() && e.Verdict == record.VerdictRefused, rule: e.Rule, reason: e.Reason,
		pid: e.PID, mono: e.MonoNS}
	return mirrors
}

// pair takes the refused action the refused line e mirrors, and reports whether there was one.
func (p *Pairs) pair(e *record.Event) bool {
	for i := range p.back {
		if a := &p.back[i]; a.awaits(e) && e.MonoNS != 0 && a.mono == e.MonoNS && a.pid == e.PID {
			a.open = false
			return true
		}
	}
	if a := &p.back[0]; a.awaits(e) {
		a.open = false
		return true
	}
	return false
}

// awaits reports whether l is a refused action no mirror took yet, under e's rule and reason.
func (l *line) awaits(e *record.Event) bool {
	return l.open && l.rule == e.Rule && l.reason == e.Reason
}
