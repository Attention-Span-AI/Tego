// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type agreeClock struct{}

func (agreeClock) Now() time.Time { return time.Unix(0, 0) }
func (agreeClock) MonoNS() uint64 { return 1 }

type agreeSink struct{}

func (agreeSink) Emit(*record.Event) {}

type agreeKiller struct{ kills int }

func (k *agreeKiller) Kill(cgroup.Cgroup) error { k.kills++; return nil }

// TestMeasureAndTheWatcherAgreeOnSpend is limits-check-doctor-cli.md I5: measure.Compute and a limits.Watcher fed
// the same completed ledger agree on tokens and cost to the cent. The ledger covers every counter either side
// prices: two models at different rates, 5-minute and 1-hour cache writes (the 1-hour ones on the model the
// table gives a 1-hour rate), cache reads, a priced server-tool fee, a cut stream charged its max_tokens bound
// (output_bound), a model the table does not name (unpriced on both sides), a response with no usage, and a
// negative count (clamped to 0 by the one decode both share, ledger.Usage).
func TestMeasureAndTheWatcherAgreeOnSpend(t *testing.T) {
	const runID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	prices, err := limits.Load(filepath.Join("..", "runtime", "limits", "testdata", "prices.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const sonnet, haiku = "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"
	responses := []record.SSLResponsePayload{
		{Model: sonnet, Usage: &record.Usage{Input: 1200, Output: 340, CacheRead: 90000, CacheWrite: 4000, CacheWrite1h: 1500}},
		{Model: haiku, Usage: &record.Usage{Input: 800, Output: 120, CacheWrite: 2500}},
		{Model: sonnet, Usage: &record.Usage{Input: 50, Output: 2048, OutputBound: true}},
		{Model: sonnet, Usage: &record.Usage{Input: 10, Output: 5, ServerTool: map[string]int{"web_search_requests": 7}}},
		{Model: "claude-unknown-9", Usage: &record.Usage{Input: 999, Output: 111}},
		{Model: haiku},
		{Model: haiku, Usage: &record.Usage{Input: -40, Output: 33, CacheRead: 7}},
		{Model: sonnet, Usage: &record.Usage{Input: 3, Output: 1, CacheWrite: 1, CacheWrite1h: 900}},
	}
	root := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, runID)
	w, err := ledger.Open(dir, record.RunRef{ID: runID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	for i, p := range responses {
		p.Status, p.ParserVersion = 200, "1"
		ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, PID: 7, TID: 7,
			MonoNS: uint64(i+2) * 1e9}
		if err := ev.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}

	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rep, err := measure.ComputeAt(t.Context(), r, prices, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The watcher as a run builds it, with token and cost budgets far above this run's spend.
	lim := agent.ResolvedLimits{Tokens: 1 << 40, CostUSD: 1e9, Set: agent.BudgetTokens | agent.BudgetCostUSD}
	killer := &agreeKiller{}
	watcher := limits.NewWatcher(lim, prices, killer, cgroup.Cgroup{}, agreeClock{}, agreeSink{})
	r2, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	for ev, err := range r2.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		watcher.Observe(ev)
	}
	if b, tripped := watcher.Tripped(); tripped || killer.kills != 0 {
		t.Fatalf("the watcher tripped (%v) on a run far under its budgets", b)
	}
	s := watcher.Snapshot()

	if rep.TokensIn != s.TokensIn || rep.TokensOut != s.TokensOut || rep.Tokens() != s.Tokens() {
		t.Errorf("tokens: measure in=%d out=%d, watcher in=%d out=%d", rep.TokensIn, rep.TokensOut, s.TokensIn, s.TokensOut)
	}
	if rep.CacheRead != s.CacheRead || rep.CacheWrite != s.CacheWrite {
		t.Errorf("cache: measure read=%d write=%d, watcher read=%d write=%d", rep.CacheRead, rep.CacheWrite, s.CacheRead, s.CacheWrite)
	}
	if uint64(rep.Responses) != s.Responses || uint64(rep.Unpriced) != s.Unpriced {
		t.Errorf("responses: measure %d (%d unpriced), watcher %d (%d unpriced)", rep.Responses, rep.Unpriced, s.Responses, s.Unpriced)
	}
	if math.Round(rep.EstCostUSD*100) != math.Round(s.CostUSD*100) {
		t.Errorf("cost: measure $%.6f, watcher $%.6f: not the same cent", rep.EstCostUSD, s.CostUSD)
	}
	// The fixture must exercise what it claims: every counter non-zero, one response unpriced, one without usage.
	if rep.TokensIn == 0 || rep.TokensOut == 0 || rep.CacheRead == 0 || rep.CacheWrite == 0 || rep.EstCostUSD == 0 ||
		rep.Unpriced != 1 || rep.Responses != len(responses)-1 {
		t.Fatalf("the fixture does not exercise every counter: %+v", rep)
	}
	// And the sum is the one a reader works out by hand from the price table, so the two cannot agree on a
	// shared mistake in what they read.
	want := (1200*3.0+340*15+90000*0.30+2500*3.75+1500*6.0+ // sonnet, 1h cache writes at their own rate
		800*1.0+120*5+2500*1.25+ // haiku
		50*3.0+2048*15+ // the cut stream's bound
		10*3.0+5*15+ // + 7 web searches below
		0*1.0+33*5+7*0.10+ // the clamped negative input
		3*3.0+1*15+900*6.0)/1e6 + 7*0.01 // cache_write 1 raised to its 900 1-hour tokens
	if math.Round(rep.EstCostUSD*1e6) != math.Round(want*1e6) {
		t.Errorf("cost $%.6f, want $%.6f by hand", rep.EstCostUSD, want)
	}
}
