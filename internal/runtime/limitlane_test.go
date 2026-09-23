// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// laneCapacity is the queue depth these tests fill: small, so a full queue is a few events away.
const laneCapacity = 8

// laneRunner is a runner wired the way startWorkers wires one — newBudget over the run's queue, then
// the pipeline with the watcher as its budget stage — with deps as the caller gives them.
func laneRunner(t *testing.T, l agent.ResolvedLimits, deps Deps) (*runner, *collectSink, *stepClock) {
	t.Helper()
	clk := &stepClock{}
	clk.advance(time.Second)
	deps.Clock = clk
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log:   slog.New(slog.DiscardHandler),
		rt:    &agent.RuleTable{Contract: &agent.Contract{Name: "lane"}, Limits: l},
		deps:  deps,
		cgm:   cgroups,
		cg:    cgroup.Cgroup{Path: cgroups.root, ID: 4242},
		queue: NewQueue(laneCapacity),
	}
	r.newBudget()
	sink := &collectSink{}
	r.pipe = newPipeline(r.queue, sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 11, TID: 12, Cgroup: 4242}, nil, budgets(r.budget, clk), slog.New(slog.DiscardHandler))
	r.startBudgetClock()
	return r, sink, clk
}

// fillQueue emits one more exec event than the queue holds, so it is full and has dropped one: the
// state of a pipeline that has fallen behind its producers.
func fillQueue(t *testing.T, q *Queue) {
	t.Helper()
	for range laneCapacity + 1 {
		ev := &record.Event{Kind: record.KindExec, Source: record.SourceSeccomp}
		if err := ev.SetPayload(record.ExecPayload{Path: "/bin/true", Argv: []string{"true"}}); err != nil {
			t.Fatal(err)
		}
		q.Emit(ev)
	}
}

// limitIndex is the position of the one limit event in what reached the ledger, or -1.
func limitIndex(t *testing.T, evs []*record.Event) int {
	t.Helper()
	at := -1
	for i, ev := range evs {
		if ev.Kind != record.KindLimit {
			continue
		}
		if at >= 0 {
			t.Fatal("two limit events for one run (I1)")
		}
		at = i
	}
	return at
}

// TestALimitEventSurvivesAFullQueue is the event-path half of the fix. The watcher runs as a stage on
// the pipeline goroutine, and the queue it used to emit into is full precisely when the pipeline is
// behind — so a busy run crossing its token budget ended with run_end reason=limit and exit 124 and no
// line saying which ceiling, because Queue.Emit dropped the limit event and counted it as one more
// channel-full loss. The event now takes a slot of its own and is written straight after the response
// that crossed the ceiling, ahead of the backlog.
func TestALimitEventSurvivesAFullQueue(t *testing.T) {
	// A table that prices the response, so the watcher raises no unpriced gap into the full queue and
	// the only loss the run can report is the filler.
	priced := &limits.PriceTable{Version: limits.PriceVersion, Models: map[string]limits.ModelPrice{
		"claude-sonnet-4-5-20250929": {InputPerMTok: 3, OutputPerMTok: 15},
	}}
	r, sink, _ := laneRunner(t, agent.ResolvedLimits{Tokens: 100}, Deps{Prices: priced})
	fillQueue(t, r.queue)

	r.pipe.handle(sslResponse(t, 200, 0)) // crosses R1 on the pipeline goroutine, as a real run does
	if r.terminal != identity.ReasonLimit {
		t.Fatalf("terminal reason %q, want limit", r.terminal)
	}
	r.pipe.drain()

	evs := sink.all()
	at := limitIndex(t, evs)
	if at < 0 {
		t.Fatalf("no limit event reached the ledger from a full queue: %v", laneKinds(evs))
	}
	if at != 1 || evs[0].Kind != record.KindSSLResponse {
		t.Fatalf("limit event at %d of %v, want right after the response that crossed the ceiling", at, laneKinds(evs))
	}
	var p record.LimitPayload
	if err := evs[at].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Which != record.LimitTokens || p.Ceiling != 100 || p.Value != 200 {
		t.Fatalf("limit payload %+v, want tokens 200 over 100", p)
	}
	// The one filler the full queue refused is still reported, and nothing else is: the limit event
	// is not among the losses.
	if n := channelFullCount(t, evs); n != 1 {
		t.Fatalf("channel-full count %d, want the one filler the queue refused", n)
	}
}

// TestATickedLimitEventSurvivesAFullQueue is the clock half: the wall ceiling trips on the watcher's own
// goroutine, which the same full queue would have refused just the same. The pipeline writes the limit
// event before the backlog it has not reached yet.
func TestATickedLimitEventSurvivesAFullQueue(t *testing.T) {
	r, sink, clk := laneRunner(t, agent.ResolvedLimits{Wall: 30 * time.Second}, Deps{})
	fillQueue(t, r.queue)
	clk.advance(31 * time.Second)
	if b, err := r.budget.Tick(t.Context()); err != nil || b == nil {
		t.Fatalf("Tick = %v, %v; want the wall breach", b, err)
	}
	r.pipe.drain()

	evs := sink.all()
	if at := limitIndex(t, evs); at != 0 {
		t.Fatalf("limit event at %d of %v, want it first, ahead of the backlog", at, laneKinds(evs))
	}
	reason, code, _, _ := r.ending()
	if reason != identity.ReasonLimit || code != identity.ExitLimit {
		t.Fatalf("the run ended %q/%d, want limit/124", reason, code)
	}
}

// TestThePipelineLoopReadsTheLimitSlotFirst covers the live loop rather than the drain: with a backlog
// already queued and the limit event waiting in its slot, the first line the running pipeline writes
// is the limit event.
func TestThePipelineLoopReadsTheLimitSlotFirst(t *testing.T) {
	r, sink, clk := laneRunner(t, agent.ResolvedLimits{Wall: time.Second}, Deps{})
	fillQueue(t, r.queue)
	clk.advance(2 * time.Second)
	if b, err := r.budget.Tick(t.Context()); err != nil || b == nil {
		t.Fatalf("Tick = %v, %v; want the wall breach", b, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	close(started)
	done := make(chan error, 1)
	go func() { done <- r.pipe.run(ctx, started) }()
	deadline := time.Now().Add(5 * time.Second)
	for sink.count() < laneCapacity+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	evs := sink.all()
	if len(evs) == 0 || evs[0].Kind != record.KindLimit {
		t.Fatalf("the running pipeline wrote %v first, want the limit event", laneKinds(evs))
	}
}

// TestARunWithoutAPriceTableRecordsOneTableGap is E15's "once" at the facade (R32): emitPriceGap writes
// the reason the CLI gave right after run_start, and the watcher, told the same reason, adds nothing
// when the first response cannot be priced. Before, a version-mismatch run also carried a
// no-price-table gap, two lines naming two causes for one missing table.
func TestARunWithoutAPriceTableRecordsOneTableGap(t *testing.T) {
	for _, why := range []string{limits.GapNoPriceTable, limits.GapVersionMismatch} {
		t.Run(why, func(t *testing.T) {
			r, sink, _ := laneRunner(t, agent.ResolvedLimits{}, Deps{PriceGap: why})
			r.emitPriceGap()
			r.pipe.handle(sslResponse(t, 10, 5))
			r.pipe.handle(sslResponse(t, 10, 5))
			r.pipe.drain()

			var got []string
			for _, ev := range sink.all() {
				if ev.Kind != record.KindGap {
					continue
				}
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Why == limits.GapNoPriceTable || p.Why == limits.GapVersionMismatch {
					got = append(got, p.Why)
				}
			}
			if len(got) != 1 || got[0] != why {
				t.Fatalf("price-table gaps %v, want exactly [%s]", got, why)
			}
		})
	}
}

// channelFullCount sums the counts of the channel-full gaps among evs.
func channelFullCount(t *testing.T, evs []*record.Event) int {
	t.Helper()
	n := 0
	for _, ev := range evs {
		if ev.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Why == GapChannelFull {
			n += p.Count
		}
	}
	return n
}

// laneKinds lists the kinds of evs in order, for failure messages.
func laneKinds(evs []*record.Event) []record.Kind {
	out := make([]record.Kind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}
