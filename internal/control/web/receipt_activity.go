// SPDX-License-Identifier: Apache-2.0

package web

import "github.com/attention-span-ai/tego/internal/control/ledgerview"

import "strings"

// The Receipt tab's activity sections (UX-FINISH): where the run connected, the programs it ran and the
// secret-looking files it read, from the receipt's own lists (internal/check/receipt through ledgerview), so
// the page says what `tego receipt` prints. A watched run refuses nothing; without these its tab said "Nothing was
// refused" about a run that read a key and connected out. Nothing here counts: each method shapes a list or a count
// the receipt already holds.

// receiptSensShown bounds the sensitive files the tab names before "and N more".
const receiptSensShown = 20

// verdictChip is one count of a try's outcome, said as a badge.
type verdictChip struct {
	Class, Text string
	N           int
}

// Chips says what happened to an action's tries (a receipt Verdicts' counts), one badge per outcome that
// happened, in the terminal receipt's words: refused, allowed, recorded (a watched run decides nothing).
func (v *receiptView) Chips(observed, allowed, refused int) []verdictChip {
	var out []verdictChip
	if refused > 0 {
		out = append(out, verdictChip{Class: "b-refused", Text: "Blocked", N: refused})
	}
	if allowed > 0 {
		out = append(out, verdictChip{Class: "b-neutral", Text: "Allowed", N: allowed})
	}
	if observed > 0 {
		out = append(out, verdictChip{Class: "b-observed", Text: "Recorded, not blocked", N: observed})
	}
	return out
}

// SensChips is Chips for a secret-looking file at path: a read that went through is the thing to look at (red when
// nothing blocked it, amber when a rule allowed it), unless it is the agent's own file (its login: grey, Low); a
// blocked one is the protection working.
func (v *receiptView) SensChips(path string, observed, allowed, refused int) []verdictChip {
	var out []verdictChip
	own := ledgerview.AgentOwn(ledgerview.CommandAgent(strings.Join(v.R.Command, " ")), path)
	if observed > 0 {
		out = append(out, verdictChip{Class: "b-leak", Text: "Read, not blocked", N: observed})
	}
	if allowed > 0 && own {
		out = append(out, verdictChip{Class: "b-neutral", Text: "Allowed", N: allowed})
	} else if allowed > 0 {
		out = append(out, verdictChip{Class: "b-asked", Text: "Read, allowed", N: allowed})
	}
	if refused > 0 {
		out = append(out, verdictChip{Class: "b-refused", Text: "Blocked", N: refused})
	}
	return out
}

// Places is how many destinations the run connected to, listed or not.
func (v *receiptView) Places() int { return len(v.R.Connections) + v.R.ConnectionsMore }

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
