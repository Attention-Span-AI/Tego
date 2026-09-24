// SPDX-License-Identifier: Apache-2.0

package status

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveCarriesTheGapLine is R34 for status: every gap event the run recorded reaches the
// snapshot, grouped by what and why, and the state is decided exactly as it would be without them.
// (limits-check-doctor-cli.md R34.)
func TestDeriveCarriesTheGapLine(t *testing.T) {
	dir := write(t, false, func(w *ledger.Writer) {
		runStart("")(w)
		appendEvent(w, record.KindGap, record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"})
		appendEvent(w, record.KindGap, record.GapPayload{What: "record", Why: "channel-full", Count: 7})
		appendEvent(w, record.KindGap, record.GapPayload{What: "record", Why: "channel-full", Count: 5})
	}, &record.RunEndPayload{Reason: record.RunEndExit})
	s := derive(t, dir, false, base, 0)
	if s.St != Done {
		t.Fatalf("state = %s, want done: a gap qualifies the state, never changes it", s.St)
	}
	want := []gaps.Count{
		{What: "capture", Why: "no-openssl", Events: 1, Binaries: []string{"/usr/bin/gh"}},
		{What: "record", Why: "channel-full", Events: 2, Lost: 12},
	}
	if !reflect.DeepEqual(s.Gaps, want) {
		t.Fatalf("gaps = %+v\nwant %+v", s.Gaps, want)
	}
}

// TestDeriveNoGaps: a run that recorded no gap has an empty gap tally.
func TestDeriveNoGaps(t *testing.T) {
	dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit})
	if s := derive(t, dir, false, base, 0); len(s.Gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", s.Gaps)
	}
}

// A run with no cost_usd budget has nothing the missing price table would break: status leaves the no-price-table
// gap out of the gap line (it stays in the ledger and in tego measure) and keeps every other gap, and keeps that
// gap too for a run that declared a cost_usd budget (G10).
func TestDeriveGapLineOmitsNoPriceTableWithoutACostBudget(t *testing.T) {
	cost := 5.0
	tokens := int64(100)
	other := gaps.Count{What: "record", Why: "channel-full", Events: 1, Lost: 3}
	for _, tc := range []struct {
		name   string
		limits *record.Limits
		want   []gaps.Count
	}{
		{"no limits", nil, []gaps.Count{other}},
		{"tokens only", &record.Limits{Tokens: &tokens}, []gaps.Count{other}},
		{"cost budget", &record.Limits{CostUSD: &cost}, []gaps.Count{other, {What: "record", Why: "no-price-table", Events: 1}}},
	} {
		dir := write(t, false, func(w *ledger.Writer) {
			if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock", Limits: tc.limits}); err != nil {
				t.Fatal(err)
			}
			appendEvent(w, record.KindGap, record.GapPayload{What: "record", Why: "no-price-table"})
			appendEvent(w, record.KindGap, record.GapPayload{What: "record", Why: "channel-full", Count: 3})
		}, &record.RunEndPayload{Reason: record.RunEndExit})
		if s := derive(t, dir, false, base, 0); !reflect.DeepEqual(s.Gaps, tc.want) {
			t.Errorf("%s: gaps = %+v\nwant %+v", tc.name, s.Gaps, tc.want)
		}
	}
}
