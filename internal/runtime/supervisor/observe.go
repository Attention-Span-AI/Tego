// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import "github.com/attention-span-ai/tego/pkg/spec/record"

// observing reports whether the policy in force is an observe run's (R30), read off the loop's table like
// every other field a decision reads.
func (l *Loop) observing() bool {
	c := l.table.Load()
	return c != nil && c.pol.Observe
}

// stampObserved turns an action event into the observe run's record of it (R30): verdict observed, with
// no reason, because nothing was decided. The rule stays: it is the entry the contract would have
// matched, or unmatched, which is what a learn or drift pass over an observe run reads.
//
// Only action kinds carry a verdict (record §2.1 R8); a gap is left as it is.
func stampObserved(ev *record.Event) {
	switch ev.Kind {
	case record.KindExec, record.KindFS, record.KindNet, record.KindMCP:
		ev.Verdict = record.VerdictObserved
		ev.Reason = ""
	}
}
