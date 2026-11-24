// SPDX-License-Identifier: Apache-2.0

package web

import "github.com/attention-span-ai/tego/internal/control/ledgerview"

import "strings"

// The Receipt tab's activity sections (UX-FINISH): where the run connected, the programs it ran and the
// secret-looking files it read, from the receipt's own lists (internal/check/receipt through ledgerview), so
// recorded totals agree with `tego receipt`; the dashboard also classifies custom protected paths from the
// run's contract copy. A watched run refuses nothing; without these its tab said "Nothing was
// refused" about a run that read a key and connected out. Nothing here counts: each method shapes a list or a count
// the receipt already holds.

// receiptSensShown bounds the sensitive files the tab names before "and N more".
const receiptSensShown = 20

// verdictChip is one count of a try's outcome, said as a badge.
type verdictChip struct {
	Class, Icon, Text string
	N                 int
}

// Chips says what happened to an action's tries (a receipt Verdicts' counts), one badge per outcome that
// happened, in the terminal receipt's words: refused, allowed, recorded (a watched run decides nothing).
func (v *receiptView) Chips(observed, allowed, refused int) []verdictChip {
	var out []verdictChip
	if refused > 0 {
		out = append(out, verdictChip{Class: "b-refused", Icon: "i-ban", Text: "Refused", N: refused})
	}
	if allowed > 0 {
		out = append(out, verdictChip{Class: "b-neutral", Icon: "i-check", Text: "Allowed", N: allowed})
	}
	if observed > 0 {
		out = append(out, verdictChip{Class: "b-observed", Icon: "i-eye", Text: "Recorded, not refused", N: observed})
	}
	return out
}

// SensChips is Chips for a secret-looking file at path: a read that went through is the thing to look at (red whether
// observed or allowed by a rule). An allowed read of the agent's own login is grey; an observed read keeps the
// went-through colour. A blocked read is the protection working.
func (v *receiptView) SensChips(path string, observed, allowed, refused int) []verdictChip {
	var out []verdictChip
	own := ledgerview.AgentOwn(ledgerview.CommandAgent(v.R.Command), path)
	for _, v := range []struct {
		verdict string
		n       int
	}{{"observed", observed}, {"allow", allowed}} {
		if v.n > 0 {
			c := protectedReadChip(v.verdict, own, false)
			c.N = v.n
			out = append(out, c)
		}
	}

	if refused > 0 {
		out = append(out, verdictChip{Class: "b-refused", Icon: "i-ban", Text: "Refused", N: refused})
	}
	return out
}

// Places is how many destinations the receipt explicitly lists. Overflow counts
// include attempts to identities outside the builder cap, not distinct places.
func (v *receiptView) Places() int { return len(v.R.Connections) }

// ProgramStarts is how many times the listed programs were started.
func (v *receiptView) ProgramStarts() int {
	n := 0
	for _, p := range v.R.Programs {
		n += p.Count
	}
	return n
}

// SensShown is how many sensitive files the tab names.
func (v *receiptView) SensShown() int { return receiptSensShown }

// MoreSensitive is how many sensitive files the tab leaves out.
func (v *receiptView) MoreSensitive() int { return max(len(v.R.SensitiveReads)-receiptSensShown, 0) }

// ConnNote is what the connections list cannot hold, as a sentence; "" when it holds everything.
func (v *receiptView) ConnNote() string { return sentence(v.R.ConnectionsNote) }

// SensNote is what the sensitive files list cannot hold, as a sentence; "" when it holds everything.
func (v *receiptView) SensNote() string { return sentence(v.R.SensitiveReadsNote) }

// sentence is s with a capital first letter and a full stop, "" for "".
func sentence(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}
