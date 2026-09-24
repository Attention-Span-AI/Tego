// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestMeasureReadsUsageAsTheWatcherDoes is R20 over the decode it shares with limits.Watcher
// (ledger.Usage, §4, I5): measure's totals are the sums of what ledger.Usage reads off each response,
// negative counts included — clamped to 0, never wrapped to 1.8e19 — so the two can never disagree
// about a response the budget already judged.
func TestMeasureReadsUsageAsTheWatcherDoes(t *testing.T) {
	const model = "claude-sonnet-4-5-20250929"
	events := []event{
		{kind: record.KindRunStart, mono: 1},
		{kind: record.KindSSLResponse, mono: 2, model: model, usage: &record.Usage{Input: 100, Output: -7, CacheRead: -1, CacheWrite: 4}},
		{kind: record.KindSSLResponse, mono: 3, model: model, usage: &record.Usage{Input: -3, Output: 50}},
		{kind: record.KindSSLResponse, mono: 4, model: model},
		{kind: record.KindRunEnd, mono: 5, reason: record.RunEndExit},
	}
	rep, err := Compute(ledgerOf(t, events), fixturePrices())
	if err != nil {
		t.Fatal(err)
	}
	var want ledger.TokenUsage
	responses := 0
	for e, err := range ledgerOf(t, events).Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if u, ok := ledger.Usage(e); ok {
			responses++
			want.In += u.In
			want.Out += u.Out
			want.CacheRead += u.CacheRead
			want.CacheWrite += u.CacheWrite
		}
	}
	if rep.TokensIn != want.In || rep.TokensOut != want.Out || rep.CacheRead != want.CacheRead ||
		rep.CacheWrite != want.CacheWrite || rep.Responses != responses {
		t.Fatalf("measure %d/%d/%d/%d over %d responses, ledger.Usage %+v over %d",
			rep.TokensIn, rep.TokensOut, rep.CacheRead, rep.CacheWrite, rep.Responses, want, responses)
	}
	if rep.TokensIn != 100 || rep.TokensOut != 50 || rep.CacheRead != 0 || rep.CacheWrite != 4 {
		t.Fatalf("negative counts were not read as 0: %d/%d/%d/%d", rep.TokensIn, rep.TokensOut, rep.CacheRead, rep.CacheWrite)
	}
}
