// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestShownOpLiveModeWhys: ADR 0125's live whys (record minor 26) read as what happened to the run's live rules, never
// as a "block" (the live-block- prefix) or "Not enforced: ..." (a gap with no words); an add and a remove still read
// block and unblock.
func TestShownOpLiveModeWhys(t *testing.T) {
	gap := func(why string) ledgerview.Event {
		return ledgerview.Event{Kind: "gap", Target: "enforce " + why, Raw: `{"what":"enforce","why":"` + why + `"}`}
	}
	for why, want := range map[string]string{
		"live-block-added":     "block",
		"live-block-removed":   "unblock",
		"live-block-expired":   "Live block ended: its time ran out",
		"live-unblock-expired": "Live block back: its time off ran out",
		"live-rule-lifted":     "Rule in the fence allowed",
		"live-rule-restored":   "Rule in the fence refuses again",
		"live-lift-expired":    "Allowed rule ended: its time ran out",
		"live-lift-refused":    "Request to allow a rule refused: nothing was loosened",
	} {
		if got := shownOp(gap(why)); got != want {
			t.Errorf("shownOp(%s) = %q, want %q", why, got, want)
		}
	}
}

// TestShownLiveModeOps: a fence line's text says what it did and who asked, never "blocked live" (review r12: a lift
// read "…datasets, blocked live by somebody" on Logs): a lift allowed it, a restore refused it again, an expiry names
// no person (its time limit ended it), a refused lift was asked for; a block and an unblock read as before.
func TestShownLiveModeOps(t *testing.T) {
	gap := func(why, op, refused string) ledgerview.Event {
		extra := ""
		if refused != "" {
			extra = `,"refused":"` + refused + `"`
		}
		return ledgerview.Event{Kind: "gap", Target: "enforce " + why, Raw: `{"what":"enforce","why":"` + why +
			`","live_block":{"op":"` + op + `","kind":"exec","value":"psql","by":"uid:4000000000 pid:9 dashboard"` + extra + `}}`}
	}
	for _, c := range []struct{ why, op, refused, want string }{
		{"live-rule-lifted", "lift", "", "psql, allowed live by user 4000000000, from the dashboard"},
		{"live-rule-restored", "restore", "", "psql, refused again by user 4000000000, from the dashboard"},
		{"live-lift-expired", "expire", "", "psql"},
		{"live-block-expired", "expire", "", "psql"},
		{"live-lift-refused", "lift", "mac", "psql, asked by user 4000000000, from the dashboard"},
		{"live-block-added", "add", "", "psql, blocked live by user 4000000000, from the dashboard"},
		{"live-block-removed", "remove", "", "block on psql removed by user 4000000000, from the dashboard"},
	} {
		if got := shown(gap(c.why, c.op, c.refused)); got != c.want {
			t.Errorf("shown(%s %s) = %q, want %q", c.why, c.op, got, c.want)
		}
	}
}
