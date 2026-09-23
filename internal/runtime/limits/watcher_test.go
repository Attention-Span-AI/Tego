// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeSink collects what the watcher emitted, in order.
type fakeSink struct {
	mu     sync.Mutex
	events []*record.Event
}

func (s *fakeSink) Emit(ev *record.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *fakeSink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.events...)
}

func (s *fakeSink) kinds(k record.Kind) []*record.Event {
	var out []*record.Event
	for _, e := range s.all() {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// fakeKiller records the kills and can fail them.
type fakeKiller struct {
	kills atomic.Int64
	err   error
}

func (k *fakeKiller) Kill(cgroup.Cgroup) error {
	k.kills.Add(1)
	return k.err
}

// fakeClock is a monotonic clock a test advances by hand.
type fakeClock struct {
	mono atomic.Uint64
}

func (c *fakeClock) Now() time.Time      { return time.Unix(0, int64(c.mono.Load())).UTC() }
func (c *fakeClock) MonoNS() uint64      { return c.mono.Load() }
func (c *fakeClock) set(ns uint64)       { c.mono.Store(ns) }
func (c *fakeClock) add(d time.Duration) { c.mono.Add(uint64(d.Nanoseconds())) }

// testTable is the price table every cost test uses: $3/MTok in, $15/MTok out, $0.30 cache read,
// $3.75 cache write — the shape of a real frontier-model price row.
func testTable() *PriceTable {
	return &PriceTable{
		Version: PriceVersion,
		Models: map[string]ModelPrice{
			"claude-sonnet-4-5-20250929": {
				InputPerMTok: 3, OutputPerMTok: 15, CacheReadPerMTok: 0.30, CacheWritePerMTok: 3.75,
			},
		},
	}
}

// response builds one ssl_response event with a usage object.
func response(mono uint64, model string, in, out, cacheRead, cacheWrite int) *record.Event {
	ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, MonoNS: mono}
	must(ev.SetPayload(record.SSLResponsePayload{
		Model:         model,
		Status:        200,
		ParserVersion: "1",
		Usage:         &record.Usage{Input: in, Output: out, CacheRead: cacheRead, CacheWrite: cacheWrite},
	}))
	return ev
}

// decision builds one decision event for a tool call.
func decision(mono uint64, step int, tool, hash string) *record.Event {
	ev := &record.Event{Kind: record.KindDecision, Source: record.SourceForwarder, MonoNS: mono}
	must(ev.SetPayload(record.DecisionPayload{Step: step, Tool: tool, InputHash: hash}))
	return ev
}

// runStart builds the run_start that gives a run its monotonic origin.
func runStart(mono uint64) *record.Event {
	ev := &record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor, MonoNS: mono}
	must(ev.SetPayload(record.RunStartPayload{Tier: "landlock", Capture: "forwarder"}))
	return ev
}

// gapEvent builds a gap, which R4 must not count as activity.
func gapEvent(mono uint64) *record.Event {
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, MonoNS: mono}
	must(ev.SetPayload(record.GapPayload{What: record.GapRecord, Why: "channel-full"}))
	return ev
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// newTestWatcher wires a watcher to fakes and returns it with them.
func newTestWatcher(t *testing.T, ceiling agent.ResolvedLimits, prices *PriceTable) (*Watcher, *fakeSink, *fakeKiller, *fakeClock, *[]Breach) {
	t.Helper()
	sink, killer, clk := &fakeSink{}, &fakeKiller{}, &fakeClock{}
	var breaches []Breach
	w := NewWatcher(ceiling, prices, killer, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithOnBreach(func(b Breach) { breaches = append(breaches, b) }))
	return w, sink, killer, clk, &breaches
}

// TestObserveAccumulates covers R1 and R2: every usage counter sums, cache tokens are priced but
// never counted toward the token ceiling, and a response with no usage contributes nothing (E14).
func TestObserveAccumulates(t *testing.T) {
	w, _, killer, _, _ := newTestWatcher(t, agent.ResolvedLimits{}, testTable())
	w.Observe(runStart(1_000))
	w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 1_000_000, 100_000, 500_000, 200_000))
	unparsed := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, MonoNS: 3_000}
	must(unparsed.SetPayload(record.SSLResponsePayload{Status: 500, ParserVersion: "1"}))
	w.Observe(unparsed)

	got := w.Snapshot()
	if got.TokensIn != 1_000_000 || got.TokensOut != 100_000 {
		t.Errorf("tokens in/out = %d/%d, want 1000000/100000", got.TokensIn, got.TokensOut)
	}
	if got.CacheRead != 500_000 || got.CacheWrite != 200_000 {
		t.Errorf("cache read/write = %d/%d, want 500000/200000", got.CacheRead, got.CacheWrite)
	}
	if got.Tokens() != 1_100_000 {
		t.Errorf("R1 ceiling quantity = %d, want 1100000 (cache excluded)", got.Tokens())
	}
	// 1.0*3 + 0.1*15 + 0.5*0.30 + 0.2*3.75 = 3 + 1.5 + 0.15 + 0.75
	if want := 5.40; !nearly(got.CostUSD, want) {
		t.Errorf("cost = %.4f, want %.2f", got.CostUSD, want)
	}
	if got.Responses != 1 {
		t.Errorf("responses with usage = %d, want 1", got.Responses)
	}
	if killer.kills.Load() != 0 {
		t.Errorf("an unbounded run was killed %d times", killer.kills.Load())
	}
}

// TestEventBreaches is the table of every ceiling an event can cross (limits-check-doctor-cli.md R1, R2, R5, and E13:
// a repeat streak over an empty input_hash still counts): the stream is fed in order and the watcher must trip
// exactly once, on the event named.
func TestEventBreaches(t *testing.T) {
	model := "claude-sonnet-4-5-20250929"
	tests := []struct {
		name    string
		ceiling agent.ResolvedLimits
		stream  []*record.Event
		want    *Breach
	}{
		{
			name:    "tokens over ceiling",
			ceiling: agent.ResolvedLimits{Tokens: 1_000},
			stream: []*record.Event{
				runStart(1_000),
				response(2_000, model, 600, 200, 0, 0),
				response(3_000, model, 300, 100, 0, 0), // 1200 > 1000
			},
			want: &Breach{Which: record.LimitTokens, Value: 1_200, Ceiling: 1_000},
		},
		{
			name:    "tokens exactly at the ceiling do not breach",
			ceiling: agent.ResolvedLimits{Tokens: 1_000},
			stream:  []*record.Event{runStart(1_000), response(2_000, model, 900, 100, 0, 0)},
			want:    nil,
		},
		{
			name:    "cache tokens never breach the token ceiling",
			ceiling: agent.ResolvedLimits{Tokens: 1_000},
			stream:  []*record.Event{runStart(1_000), response(2_000, model, 100, 100, 900_000, 900_000)},
			want:    nil,
		},
		{
			name:    "an unbounded token ceiling never breaches",
			ceiling: agent.ResolvedLimits{},
			stream:  []*record.Event{runStart(1_000), response(2_000, model, 9_000_000, 9_000_000, 0, 0)},
			want:    nil,
		},
		{
			name:    "cost over ceiling",
			ceiling: agent.ResolvedLimits{CostUSD: 1},
			// 400k in at $3/MTok = $1.20
			stream: []*record.Event{runStart(1_000), response(2_000, model, 400_000, 0, 0, 0)},
			want:   &Breach{Which: record.LimitCostUSD, Value: 1.20, Ceiling: 1},
		},
		{
			// Amended 2026-09-24: an unpriced model is charged toward the
			// ceiling at the table's highest prices; it used to be free spend under a cost budget.
			name:    "an unpriced model is charged at the table's top price",
			ceiling: agent.ResolvedLimits{CostUSD: 1},
			stream:  []*record.Event{runStart(1_000), response(2_000, "some-other-model", 9_000_000, 9_000_000, 0, 0)},
			want:    &Breach{Which: record.LimitCostUSD, Value: 162, Ceiling: 1},
		},
		{
			name:    "repeats: three identical calls in a row",
			ceiling: agent.ResolvedLimits{Repeats: 3},
			stream: []*record.Event{
				runStart(1_000),
				decision(2_000, 1, "bash", "aaaa"),
				decision(3_000, 2, "bash", "aaaa"),
				decision(4_000, 3, "bash", "aaaa"),
			},
			want: &Breach{Which: record.LimitRepeats, Value: 3, Ceiling: 3},
		},
		{
			name:    "repeats: a different input hash resets the streak",
			ceiling: agent.ResolvedLimits{Repeats: 3},
			stream: []*record.Event{
				runStart(1_000),
				decision(2_000, 1, "bash", "aaaa"),
				decision(3_000, 2, "bash", "bbbb"),
				decision(4_000, 3, "bash", "aaaa"),
			},
			want: nil,
		},
		{
			name:    "repeats: a different tool resets the streak",
			ceiling: agent.ResolvedLimits{Repeats: 3},
			stream: []*record.Event{
				runStart(1_000),
				decision(2_000, 1, "bash", "aaaa"),
				decision(3_000, 2, "read_file", "aaaa"),
				decision(4_000, 3, "bash", "aaaa"),
			},
			want: nil,
		},
		{
			name:    "repeats: an empty input hash is a value like any other (E13)",
			ceiling: agent.ResolvedLimits{Repeats: 2},
			stream: []*record.Event{
				runStart(1_000),
				decision(2_000, 1, "now", ""),
				decision(3_000, 2, "now", ""),
			},
			want: &Breach{Which: record.LimitRepeats, Value: 2, Ceiling: 2},
		},
		{
			name:    "a text-only decision does not break the streak",
			ceiling: agent.ResolvedLimits{Repeats: 2},
			stream: []*record.Event{
				runStart(1_000),
				decision(2_000, 1, "bash", "aaaa"),
				{Kind: record.KindDecision, Source: record.SourceForwarder, MonoNS: 3_000},
				decision(4_000, 2, "bash", "aaaa"),
			},
			want: &Breach{Which: record.LimitRepeats, Value: 2, Ceiling: 2},
		},
		// E16. Every case below carries the presence bit with a value of 0: the operator
		// asked for the tightest budget there is. Read as a number alone each of these is
		// indistinguishable from the unbounded rows above, which is how the tightest request
		// produced no budget at all.
		{
			name:    "an explicit token budget of 0 breaches on the first response (E16)",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetTokens},
			stream:  []*record.Event{runStart(1_000), response(2_000, model, 40, 20, 0, 0)},
			want:    &Breach{Which: record.LimitTokens, Value: 60, Ceiling: 0},
		},
		{
			name:    "an explicit cost budget of 0 breaches on the first priced response",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetCostUSD},
			stream:  []*record.Event{runStart(1_000), response(2_000, model, 1_000, 0, 0, 0)},
			want:    &Breach{Which: record.LimitCostUSD, Value: 0.003, Ceiling: 0},
		},
		{
			name:    "an explicit repeats budget of 0 breaches on the first tool call",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetRepeats},
			stream:  []*record.Event{runStart(1_000), decision(2_000, 1, "bash", "aaaa")},
			want:    &Breach{Which: record.LimitRepeats, Value: 1, Ceiling: 0},
		},
		{
			name:    "a repeats budget of 0 still needs a tool call to judge",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetRepeats},
			stream: []*record.Event{
				runStart(1_000),
				{Kind: record.KindDecision, Source: record.SourceForwarder, MonoNS: 2_000},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, sink, killer, _, breaches := newTestWatcher(t, tc.ceiling, testTable())
			for _, ev := range tc.stream {
				w.Observe(ev)
			}
			got, tripped := w.Tripped()
			if tc.want == nil {
				if tripped {
					t.Fatalf("tripped on %+v, want no breach", got)
				}
				if n := len(sink.kinds(record.KindLimit)); n != 0 {
					t.Fatalf("%d limit events, want 0", n)
				}
				if killer.kills.Load() != 0 {
					t.Fatalf("%d kills, want 0", killer.kills.Load())
				}
				return
			}
			if !tripped {
				t.Fatalf("no breach, want %+v", *tc.want)
			}
			if got.Which != tc.want.Which || !nearly(got.Value, tc.want.Value) || !nearly(got.Ceiling, tc.want.Ceiling) {
				t.Fatalf("breach %+v, want %+v", got, *tc.want)
			}
			limits := sink.kinds(record.KindLimit)
			if len(limits) != 1 {
				t.Fatalf("%d limit events, want exactly 1 (I1)", len(limits))
			}
			assertLimitEvent(t, limits[0], *tc.want)
			if killer.kills.Load() != 1 {
				t.Fatalf("%d kills, want 1", killer.kills.Load())
			}
			if len(*breaches) != 1 {
				t.Fatalf("%d facade callbacks, want 1", len(*breaches))
			}
		})
	}
}

// assertLimitEvent checks the wire shape of the limit event: kind, source, the limit-* reason of I2
// and the which/value/ceiling payload.
func assertLimitEvent(t *testing.T, ev *record.Event, want Breach) {
	t.Helper()
	if ev.Kind != record.KindLimit || ev.Source != record.SourceSupervisor {
		t.Errorf("limit event kind/source = %s/%s", ev.Kind, ev.Source)
	}
	if ev.Reason != want.Reason() {
		t.Errorf("limit event reason = %q, want %q (I2)", ev.Reason, want.Reason())
	}
	var p record.LimitPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("decode limit payload: %v", err)
	}
	if p.Which != want.Which || !nearly(p.Value, want.Value) || !nearly(p.Ceiling, want.Ceiling) {
		t.Errorf("limit payload %+v, want %+v", p, want)
	}
	// The event a run appends must satisfy the frozen schema; the ledger stamps the rest.
	ev.V, ev.Seq, ev.Run, ev.Agent, ev.PID, ev.TID = record.Version, 1, "r-3f9c2a1b-0dllq06ts7400-k7m2pq", "retriever", 1, 1
	ev.ID, ev.Prev = record.ZeroID, record.ZeroID
	ev.TS, ev.MonoNS = time.Unix(0, 0).UTC(), 1
	if err := ev.Validate(); err != nil {
		t.Errorf("limit event does not validate: %v", err)
	}
}

// TestLoopingAgentStoppedByRepeats is acceptance §12.4's first half: an agent that calls the same
// tool with the same input forever is stopped by limits.repeats, with the limit event, the kill,
// and the terminal reason the facade turns into exit 124.
func TestLoopingAgentStoppedByRepeats(t *testing.T) {
	ceiling := agent.ResolvedLimits{Repeats: 5}
	w, sink, killer, _, breaches := newTestWatcher(t, ceiling, testTable())
	w.Observe(runStart(1_000))

	// The loop: one model turn and one identical tool call, twenty times over.
	mono := uint64(1_000)
	for step := 1; step <= 20; step++ {
		mono += 1_000_000
		w.Observe(response(mono, "claude-sonnet-4-5-20250929", 100, 10, 0, 0))
		mono += 1_000_000
		w.Observe(decision(mono, step, "bash", "same-input-hash"))
	}

	b, tripped := w.Tripped()
	if !tripped {
		t.Fatal("a looping agent was not stopped")
	}
	if b.Which != record.LimitRepeats {
		t.Fatalf("stopped by %q, want %q", b.Which, record.LimitRepeats)
	}
	if b.Value != 5 || b.Ceiling != 5 {
		t.Fatalf("breach %+v, want the streak and ceiling at 5", b)
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want exactly 1 however long the loop runs (I1)", n)
	}
	if n := killer.kills.Load(); n != 1 {
		t.Fatalf("%d kills, want exactly 1", n)
	}
	if len(*breaches) != 1 {
		t.Fatalf("%d terminal-reason callbacks, want 1", len(*breaches))
	}
	if code := identity.ExitCode(identity.ReasonLimit, syscall.WaitStatus(0), false, identity.ExecFailureNone); code != identity.ExitLimit {
		t.Fatalf("a limit run exits %d, want 124", code)
	}
	// The streak keeps counting after the trip, but nothing else happens.
	w.Observe(decision(mono+1_000_000, 21, "bash", "same-input-hash"))
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events after the trip, want 1", n)
	}
}

// TestCostCeilingStopsRun is acceptance §12.4's second half: a $25 budget stops the run, the limit
// event names cost_usd with the estimate and the ceiling, and the exit code is 124.
func TestCostCeilingStopsRun(t *testing.T) {
	const model = "claude-sonnet-4-5-20250929"
	ceiling := agent.ResolvedLimits{CostUSD: 25}
	w, sink, killer, _, _ := newTestWatcher(t, ceiling, testTable())
	w.Observe(runStart(1_000))

	// $3/MTok in: one million input tokens per turn is $3, so the ninth turn crosses $25.
	mono := uint64(1_000)
	turns := 0
	for range 20 {
		mono += 1_000_000
		w.Observe(response(mono, model, 1_000_000, 0, 0, 0))
		turns++
		if _, tripped := w.Tripped(); tripped {
			break
		}
	}
	b, tripped := w.Tripped()
	if !tripped {
		t.Fatalf("a $25 budget did not stop the run after %d turns costing $%.2f", turns, w.Snapshot().CostUSD)
	}
	if turns != 9 {
		t.Errorf("stopped after %d turns, want 9 ($27 is the first estimate over $25)", turns)
	}
	if b.Which != record.LimitCostUSD || !nearly(b.Value, 27) || !nearly(b.Ceiling, 25) {
		t.Fatalf("breach %+v, want cost_usd 27 over 25", b)
	}
	limits := sink.kinds(record.KindLimit)
	if len(limits) != 1 {
		t.Fatalf("%d limit events, want 1", len(limits))
	}
	assertLimitEvent(t, limits[0], b)
	if killer.kills.Load() != 1 {
		t.Fatalf("%d kills, want 1", killer.kills.Load())
	}
	if code := identity.ExitCode(identity.ReasonLimit, syscall.WaitStatus(0), false, identity.ExecFailureNone); code != identity.ExitLimit {
		t.Fatalf("a limit run exits %d, want 124", code)
	}
}

// TestTickBreaches covers R3 and R4 (and E17, a stall_after shorter than the model's latency): only the clock crosses wall and stall, a gap is not activity,
// and the first crossing wins.
func TestTickBreaches(t *testing.T) {
	tests := []struct {
		name    string
		ceiling agent.ResolvedLimits
		stream  []*record.Event
		at      uint64 // clock reading when Tick runs
		want    *Breach
	}{
		{
			name:    "wall over ceiling",
			ceiling: agent.ResolvedLimits{Wall: 10 * time.Second},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1_000_000_000 + 11*uint64(time.Second),
			want:    &Breach{Which: record.LimitWall, Value: 11, Ceiling: 10},
		},
		{
			name:    "wall exactly at the ceiling does not breach",
			ceiling: agent.ResolvedLimits{Wall: 10 * time.Second},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1_000_000_000 + 10*uint64(time.Second),
			want:    nil,
		},
		{
			name:    "stall over ceiling",
			ceiling: agent.ResolvedLimits{StallAfter: 5 * time.Second},
			stream: []*record.Event{
				runStart(1_000_000_000),
				decision(2_000_000_000, 1, "bash", "aaaa"),
			},
			at:   2_000_000_000 + 6*uint64(time.Second),
			want: &Breach{Which: record.LimitStallAfter, Value: 6, Ceiling: 5},
		},
		{
			// R4: the breach is stall > stall_after, strictly.
			name:    "stall exactly at the ceiling does not breach",
			ceiling: agent.ResolvedLimits{StallAfter: 5 * time.Second},
			stream: []*record.Event{
				runStart(1_000_000_000),
				decision(2_000_000_000, 1, "bash", "aaaa"),
			},
			at:   2_000_000_000 + 5*uint64(time.Second),
			want: nil,
		},
		{
			name:    "a gap does not count as activity (R4)",
			ceiling: agent.ResolvedLimits{StallAfter: 5 * time.Second},
			stream: []*record.Event{
				runStart(1_000_000_000),
				decision(2_000_000_000, 1, "bash", "aaaa"),
				gapEvent(2_000_000_000 + 5*uint64(time.Second)),
			},
			at:   2_000_000_000 + 6*uint64(time.Second),
			want: &Breach{Which: record.LimitStallAfter, Value: 6, Ceiling: 5},
		},
		{
			name:    "an event resets the stall window",
			ceiling: agent.ResolvedLimits{StallAfter: 5 * time.Second},
			stream: []*record.Event{
				runStart(1_000_000_000),
				decision(2_000_000_000, 1, "bash", "aaaa"),
				decision(2_000_000_000+5*uint64(time.Second), 2, "bash", "bbbb"),
			},
			at:   2_000_000_000 + 6*uint64(time.Second),
			want: nil,
		},
		{
			name:    "wall wins when both are crossed on the same tick",
			ceiling: agent.ResolvedLimits{Wall: 10 * time.Second, StallAfter: 5 * time.Second},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1_000_000_000 + 11*uint64(time.Second),
			want:    &Breach{Which: record.LimitWall, Value: 11, Ceiling: 10},
		},
		{
			name:    "no run_start, no monotonic origin, no breach",
			ceiling: agent.ResolvedLimits{Wall: time.Nanosecond},
			stream:  nil,
			at:      1 << 40,
			want:    nil,
		},
		{
			name:    "unbounded wall and stall never breach",
			ceiling: agent.ResolvedLimits{},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1 << 50,
			want:    nil,
		},
		{
			// limits-check-doctor-cli.md E17: a stall_after shorter than the model's own latency breaches on the
			// first tick after the first call, legitimately, and nothing cross-checks it against live latency.
			name:    "a stall_after shorter than the model's latency breaches on the first tick (E17)",
			ceiling: agent.ResolvedLimits{StallAfter: 50 * time.Millisecond, Set: agent.BudgetStallAfter},
			stream: []*record.Event{
				runStart(1_000_000_000),
				decision(2_000_000_000, 1, "bash", "aaaa"),
			},
			at:   2_000_000_000 + uint64(time.Second),
			want: &Breach{Which: record.LimitStallAfter, Value: 1, Ceiling: 0.05},
		},
		// The clock half: the same zero, asked for. Compare with the row above, whose
		// numbers are identical and whose meaning is the opposite.
		{
			name:    "an explicit wall budget of 0 breaches on the first tick (E16)",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetWall},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1_000_000_000 + uint64(time.Second),
			want:    &Breach{Which: record.LimitWall, Value: 1, Ceiling: 0},
		},
		{
			name:    "an explicit stall budget of 0 breaches on the first tick",
			ceiling: agent.ResolvedLimits{Set: agent.BudgetStallAfter},
			stream:  []*record.Event{runStart(1_000_000_000)},
			at:      1_000_000_000 + uint64(time.Second),
			want:    &Breach{Which: record.LimitStallAfter, Value: 1, Ceiling: 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, sink, killer, clk, _ := newTestWatcher(t, tc.ceiling, testTable())
			for _, ev := range tc.stream {
				w.Observe(ev)
			}
			clk.set(tc.at)
			got, err := w.Tick(t.Context())
			if err != nil {
				t.Fatalf("Tick: %v", err)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("Tick breached %+v, want nil", *got)
				}
				if killer.kills.Load() != 0 {
					t.Fatalf("%d kills, want 0", killer.kills.Load())
				}
				return
			}
			if got == nil {
				t.Fatalf("Tick returned no breach, want %+v", *tc.want)
			}
			if got.Which != tc.want.Which || !nearly(got.Value, tc.want.Value) || !nearly(got.Ceiling, tc.want.Ceiling) {
				t.Fatalf("breach %+v, want %+v", *got, *tc.want)
			}
			assertLimitEvent(t, sink.kinds(record.KindLimit)[0], *tc.want)

			// R6/I1: a later tick past the same ceiling is idempotent.
			clk.add(time.Hour)
			again, err := w.Tick(t.Context())
			if err != nil || again != nil {
				t.Fatalf("second Tick = %v, %v; want nil, nil", again, err)
			}
			if n := len(sink.kinds(record.KindLimit)); n != 1 {
				t.Fatalf("%d limit events, want 1 (I1)", n)
			}
			if n := killer.kills.Load(); n != 1 {
				t.Fatalf("%d kills, want 1", n)
			}
		})
	}
}

// TestRunTicksUntilBreach drives the ticker goroutine the facade's worker group owns.
func TestRunTicksUntilBreach(t *testing.T) {
	w, sink, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{Wall: time.Second}, nil)
	w.Observe(runStart(1_000))
	clk.set(1_000 + 2*uint64(time.Second))

	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { done <- w.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the wall ceiling was crossed")
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want 1", n)
	}
	if killer.kills.Load() != 1 {
		t.Fatalf("%d kills, want 1", killer.kills.Load())
	}
}

// TestRunStopsOnContext proves the ticker goroutine is owned: a cancelled context ends it.
func TestRunStopsOnContext(t *testing.T) {
	w, _, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{Wall: time.Hour}, nil)
	w.Observe(runStart(1_000))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on cancel")
	}
}

// TestKillFailureIsReported covers §7: a kill that fails is wrapped and returned, and the limit
// event is appended all the same, because the ceiling was in fact crossed.
func TestKillFailureIsReported(t *testing.T) {
	sink, clk := &fakeSink{}, &fakeClock{}
	boom := errors.New("cgroup is gone")
	killer := &fakeKiller{err: boom}
	w := NewWatcher(agent.ResolvedLimits{Wall: time.Second}, nil, killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink)
	w.Observe(runStart(1_000))
	clk.set(1_000 + 2*uint64(time.Second))

	b, err := w.Tick(t.Context())
	if b == nil {
		t.Fatal("no breach")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("Tick error = %v, want it to wrap %v", err, boom)
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want 1 even when the kill failed", n)
	}
	if err := w.Run(t.Context()); err != nil {
		t.Fatalf("Run after a trip = %v, want nil", err)
	}
}

// TestPriceGapsOncePerRun covers R2 and E15: the missing-table gap is recorded once for the run and
// the unpriced-model gap once per model, and tokens are unaffected either way.
func TestPriceGapsOncePerRun(t *testing.T) {
	t.Run("no price table", func(t *testing.T) {
		w, sink, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{}, nil)
		w.Observe(runStart(1_000))
		for i := range 3 {
			w.Observe(response(uint64(2_000+i), "claude-sonnet-4-5-20250929", 100, 10, 0, 0))
		}
		gaps := sink.kinds(record.KindGap)
		if len(gaps) != 1 {
			t.Fatalf("%d gap events, want 1", len(gaps))
		}
		var p record.GapPayload
		if err := gaps[0].DecodePayload(&p); err != nil {
			t.Fatalf("decode gap: %v", err)
		}
		if p.What != record.GapRecord || p.Why != GapNoPriceTable {
			t.Errorf("gap %+v, want what=record why=%s", p, GapNoPriceTable)
		}
		if s := w.Snapshot(); s.Tokens() != 330 || s.CostUSD != 0 || s.Unpriced != 3 {
			t.Errorf("state %+v: tokens still count, cost does not", s)
		}
	})

	t.Run("unpriced model", func(t *testing.T) {
		w, sink, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{}, testTable())
		w.Observe(runStart(1_000))
		w.Observe(response(2_000, "mystery-model", 100, 10, 0, 0))
		w.Observe(response(3_000, "mystery-model", 100, 10, 0, 0))
		w.Observe(response(4_000, "other-mystery", 100, 10, 0, 0))
		w.Observe(response(5_000, "claude-sonnet-4-5-20250929", 100, 10, 0, 0))

		gaps := sink.kinds(record.KindGap)
		if len(gaps) != 2 {
			t.Fatalf("%d gap events, want one per unpriced model", len(gaps))
		}
		for i, wantModel := range []string{"mystery-model", "other-mystery"} {
			var p record.GapPayload
			if err := gaps[i].DecodePayload(&p); err != nil {
				t.Fatalf("decode gap: %v", err)
			}
			if p.Why != GapUnpricedModel || p.Binary != wantModel {
				t.Errorf("gap %d = %+v, want why=%s model=%s", i, p, GapUnpricedModel, wantModel)
			}
		}
	})

	// The agent chooses usage.model, and each distinct unpriced name was a map entry and a gap line without
	// end: past maxUnpricedModels one line without a model stands for the rest.
	t.Run("unpriced models past the bound", func(t *testing.T) {
		w, sink, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{}, testTable())
		w.Observe(runStart(1_000))
		for i := range maxUnpricedModels + 50 {
			w.Observe(response(uint64(2_000+i), fmt.Sprintf("made-up-%d", i), 1, 1, 0, 0))
		}
		gaps := sink.kinds(record.KindGap)
		if len(gaps) != maxUnpricedModels+1 {
			t.Fatalf("%d gap events, want %d named and one for the rest", len(gaps), maxUnpricedModels)
		}
		var last record.GapPayload
		if err := gaps[len(gaps)-1].DecodePayload(&last); err != nil {
			t.Fatal(err)
		}
		if last.Why != GapUnpricedModel || last.Binary != "" {
			t.Errorf("the last gap %+v, want why=%s with no model", last, GapUnpricedModel)
		}
		if s := w.Snapshot(); s.Unpriced != maxUnpricedModels+50 {
			t.Errorf("unpriced %d, every response still counts", s.Unpriced)
		}
	})
}

// TestObserveTickRace is limits-check-doctor-cli.md R6 and I1 under the race detector: a near-ceiling state hammered from both
// directions produces exactly one limit event and one kill.
func TestObserveTickRace(t *testing.T) {
	const model = "claude-sonnet-4-5-20250929"
	sink, clk := &fakeSink{}, &fakeClock{}
	killer := &fakeKiller{}
	w := NewWatcher(agent.ResolvedLimits{Tokens: 1_000, Wall: time.Second}, testTable(), killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink)
	w.Observe(runStart(0))

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range 200 {
				w.Observe(response(uint64(i+1), model, 10, 1, 0, 0))
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				clk.add(10 * time.Millisecond)
				if _, err := w.Tick(t.Context()); err != nil {
					t.Errorf("Tick: %v", err)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want exactly 1 (I1)", n)
	}
	if n := killer.kills.Load(); n != 1 {
		t.Fatalf("%d kills, want exactly 1 (I1)", n)
	}
}

// TestBreachReasonIsExhaustive is I2: every Which maps to a limit-* code of the closed set, and an
// unknown one maps to no code rather than an invented one.
func TestBreachReasonIsExhaustive(t *testing.T) {
	want := map[string]record.Reason{
		record.LimitTokens:     record.ReasonLimitTokens,
		record.LimitCostUSD:    record.ReasonLimitCost,
		record.LimitWall:       record.ReasonLimitWall,
		record.LimitStallAfter: record.ReasonLimitStall,
		record.LimitRepeats:    record.ReasonLimitRepeats,
	}
	for which, reason := range want {
		got := Breach{Which: which}.Reason()
		if got != reason {
			t.Errorf("%s -> %q, want %q", which, got, reason)
		}
		if !got.IsLimit() {
			t.Errorf("%q is not in the closed limit set", got)
		}
	}
	if got := (Breach{Which: "invented"}).Reason(); got != "" {
		t.Errorf("unknown which -> %q, want the empty reason", got)
	}
}

// TestNilInputsAreSafe covers the quality bar: no panic on input a producer could hand over.
func TestNilInputsAreSafe(t *testing.T) {
	w := NewWatcher(agent.ResolvedLimits{Tokens: 1}, nil, nil, cgroup.Cgroup{}, &fakeClock{}, nil)
	w.Observe(nil)
	w.Observe(&record.Event{Kind: record.KindSSLResponse})
	w.Observe(&record.Event{Kind: record.KindDecision})
	w.Observe(response(1, "m", 10, 10, 0, 0)) // trips, with no sink and no killer
	if _, tripped := w.Tripped(); !tripped {
		t.Fatal("a watcher with no sink and no killer still trips")
	}
	if _, err := w.Tick(t.Context()); err != nil {
		t.Fatalf("Tick after trip: %v", err)
	}
}

// TestBreachString renders the way the CLI reports a breach.
func TestBreachString(t *testing.T) {
	tests := []struct {
		b    Breach
		want string
	}{
		{Breach{Which: record.LimitTokens, Value: 60420, Ceiling: 60000}, "tokens 60420 over ceiling 60000"},
		{Breach{Which: record.LimitCostUSD, Value: 27.5, Ceiling: 25}, "cost_usd 27.50 over ceiling 25"},
	}
	for _, tc := range tests {
		if got := tc.b.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

// BenchmarkObserve guards the budgeted path: Observe runs on the pipeline goroutine, once per
// event, so its cost is paid by every event the run records.
func BenchmarkObserve(b *testing.B) {
	w := NewWatcher(agent.ResolvedLimits{Tokens: 1 << 40}, testTable(), &fakeKiller{},
		cgroup.Cgroup{}, &fakeClock{}, &fakeSink{})
	ev := response(1_000, "claude-sonnet-4-5-20250929", 1_000, 100, 10, 10)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		ev.MonoNS = uint64(i + 1)
		w.Observe(ev)
	}
}

// BenchmarkTick guards the 1 Hz path, which every run pays for its whole life.
func BenchmarkTick(b *testing.B) {
	clk := &fakeClock{}
	w := NewWatcher(agent.ResolvedLimits{Wall: time.Hour, StallAfter: time.Hour}, nil, &fakeKiller{},
		cgroup.Cgroup{}, clk, &fakeSink{})
	w.Observe(runStart(1))
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		clk.add(time.Millisecond)
		if _, err := w.Tick(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// nearly compares two estimates to the cent, which is the precision every cost surface renders.
func nearly(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// TestTouchIsActivityForTheStallCheck is limits-check-doctor-cli.md R4's record: off half at the watcher: Touch is
// activity the ledger does not carry, so it resets the stall window as an event does; a reading older than the
// last activity never moves the window back; and a Touch before run_start gives the run its origin. A gap still
// never resets the window a Touch set.
func TestTouchIsActivityForTheStallCheck(t *testing.T) {
	const s = uint64(time.Second)
	t.Run("a touch resets the stall window", func(t *testing.T) {
		w, _, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
		w.Observe(runStart(1 * s))
		for at := 2 * s; at <= 30*s; at += 4 * s {
			w.Touch(at)
			clk.set(at + 4*s)
			if b, _ := w.Tick(t.Context()); b != nil {
				t.Fatalf("stalled at %ds with a touch every 4s under a 5s stall_after: %+v", (at+4*s)/s, *b)
			}
		}
		if killer.kills.Load() != 0 {
			t.Fatal("a touched run was killed")
		}
		clk.set(30*s + 6*s)
		if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitStallAfter {
			t.Fatalf("6s after the last touch, Tick = %v, want a stall", b)
		}
	})
	t.Run("an older reading does not move the window back", func(t *testing.T) {
		w, _, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
		w.Observe(runStart(1 * s))
		w.Touch(10 * s)
		w.Touch(3 * s)
		w.Observe(gapEvent(12 * s))
		if got := w.Snapshot().LastEventMonoNS; got != 10*s {
			t.Fatalf("LastEventMonoNS = %d, want the newest touch's %d (a gap and an older touch move nothing)", got, 10*s)
		}
	})
	t.Run("a touch before run_start is the origin", func(t *testing.T) {
		w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{Wall: 5 * time.Second}, nil)
		w.Touch(2 * s)
		if got := w.Snapshot().StartMonoNS; got != 2*s {
			t.Fatalf("StartMonoNS = %d, want the touch's %d", got, 2*s)
		}
		clk.set(8 * s)
		if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitWall {
			t.Fatalf("Tick = %v, want a wall breach measured from the touch", b)
		}
	})
}
