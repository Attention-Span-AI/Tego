// SPDX-License-Identifier: Apache-2.0

// Package mirror recognises a refused line that mirrors a refused action line before it, the one rule drift (R13),
// measure (R19), learn and the receipt need to count a refusal once. It lives in one place so those views cannot count
// refusals differently. The dashboard pairs by it too (internal/control/ledgerview, pair.go, through Fold, which also
// says which line each mirror took), so there is one implementation of the rule; ledgerview's
// TestReceiptAgreesWithDashboardAndMeasure holds the counts to one over every record v1 fixture, mirror-split.jsonl
// among them, whose mirrors do not each follow their action.
package mirror

import "github.com/attention-span-ai/tego/pkg/spec/record"

// window is how many lines back a mirror's action may be. The pipeline writes a mirror
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

// Fields are what pairing reads of one line: its kind, verdict, rule and reason, and the envelope a mirror copies from
// its action (the process and the monotonic clock). A reader that holds its lines in a form of its own passes them so.
type Fields struct {
	Kind    record.Kind
	Verdict record.Verdict
	Rule    string
	Reason  record.Reason
	PID     int
	MonoNS  uint64
}

// FieldsOf is e's Fields.
func FieldsOf(e *record.Event) Fields {
	return Fields{Kind: e.Kind, Verdict: e.Verdict, Rule: e.Rule, Reason: e.Reason, PID: e.PID, MonoNS: e.MonoNS}
}

// Take takes e, the run's next line, and reports whether it is a refused line that mirrors a refused action before it.
// Every line of the run goes through Take once, in ledger order, whatever its kind and whatever the caller does with
// it: the window counts lines.
func (p *Pairs) Take(e *record.Event) bool {
	_, mirrors := p.Fold(FieldsOf(e))
	return mirrors
}

// Fold is Take for a line given as its Fields. When the line mirrors a refused action it also says which: back is how
// many lines before this one the action is (0 is the line just before it).
func (p *Pairs) Fold(f Fields) (back int, mirrors bool) {
	if f.Kind == record.KindRefused {
		back, mirrors = p.pair(&f)
	}
	copy(p.back[1:], p.back[:window-1])
	p.back[0] = line{open: f.Kind.IsAction() && f.Verdict == record.VerdictRefused, rule: f.Rule, reason: f.Reason,
		pid: f.PID, mono: f.MonoNS}
	return back, mirrors
}

// pair takes the refused action the refused line f mirrors, and reports how far back it is, and whether there was one.
func (p *Pairs) pair(f *Fields) (int, bool) {
	for i := range p.back {
		if a := &p.back[i]; a.awaits(f) && f.MonoNS != 0 && a.mono == f.MonoNS && a.pid == f.PID {
			a.open = false
			return i, true
		}
	}
	if a := &p.back[0]; a.awaits(f) {
		a.open = false
		return 0, true
	}
	return 0, false
}

// awaits reports whether l is a refused action no mirror took yet, under f's rule and reason.
func (l *line) awaits(f *Fields) bool {
	return l.open && l.rule == f.Rule && l.reason == f.Reason
}
