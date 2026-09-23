// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestComposeOrder(t *testing.T) {
	var order []string
	mk := func(name string) Stage {
		return func(next func(*record.Event)) func(*record.Event) {
			return func(ev *record.Event) { order = append(order, name); next(ev) }
		}
	}
	h := Compose(func(*record.Event) { order = append(order, "write") }, mk("a"), mk("b"), mk("c"))
	h(&record.Event{})
	want := []string{"a", "b", "c", "write"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
}

func TestQueueDropsWhenFull(t *testing.T) {
	q := NewQueue(2)
	for i := 0; i < 5; i++ {
		q.Emit(&record.Event{Seq: uint64(i)})
	}
	if got := q.Dropped(); got != 3 {
		t.Fatalf("dropped %d, want 3", got)
	}
	if got := q.Dropped(); got != 0 {
		t.Fatalf("dropped after reset %d, want 0", got)
	}
}

// collectSink records the events a pipeline terminal receives. It is written by the pipeline
// goroutine and read by the test, so it carries its own lock.
type collectSink struct {
	mu     sync.Mutex
	events []*record.Event
	err    error
}

func (c *collectSink) append(e *record.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	clone := *e
	c.events = append(c.events, &clone)
	return nil
}

// all returns a snapshot of what the terminal has received.
func (c *collectSink) all() []*record.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.events)
}

// count is how many events reached the terminal.
func (c *collectSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// testPipeline builds a pipeline over a collecting terminal and the ledger's real stages, with no
// budget watcher: the stages below are the ones every run has whether or not it has a budget.
func testPipeline(t *testing.T, q *Queue, sink *collectSink) *pipeline {
	t.Helper()
	return newPipeline(q, sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 11, TID: 12, Cgroup: 99}, nil, nil, slog.New(slog.DiscardHandler))
}

// passthroughStage stands in for the blob split, which needs a live writer.
func passthroughStage(next ledger.Sink) ledger.Sink { return next }

func TestPipelineStampsAndAttributes(t *testing.T) {
	q := NewQueue(4)
	sink := &collectSink{}
	p := testPipeline(t, q, sink)

	fs := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp}
	p.handle(fs)
	gap := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	p.handle(gap)

	if sink.count() != 2 {
		t.Fatalf("wrote %d events, want 2", sink.count())
	}
	got := sink.all()[0]
	if got.Rule != UnmatchedRule || got.Verdict != record.VerdictObserved {
		t.Fatalf("an action with no decision must read as unmatched/observed: %+v", got)
	}
	if got.Attr == nil || got.Attr.Method != record.MethodNone || got.Attr.Confidence != record.ConfidenceUnattributed {
		t.Fatalf("attribution %+v, want unattributed/none", got.Attr)
	}
	if got.PID != 11 || got.TID != 12 || got.Cgroup != 99 {
		t.Fatalf("stamp %+v", got)
	}
	if sink.all()[1].Attr != nil {
		t.Fatal("a gap event carries no attribution (spec/record/v1 R8)")
	}
}

func TestPipelineKeepsAProducersDecision(t *testing.T) {
	sink := &collectSink{}
	p := testPipeline(t, NewQueue(4), sink)
	p.handle(&record.Event{Kind: record.KindExec, Source: record.SourceSeccomp, Rule: "exec[sh]",
		Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonExecNotAllowed})
	got := sink.all()[0]
	if got.Rule != "exec[sh]" || got.Verdict != record.VerdictRefused || got.Reason != record.ReasonExecNotAllowed {
		t.Fatalf("the stage overwrote a real decision: %+v", got)
	}
}

func TestPipelineRedactsHeaders(t *testing.T) {
	sink := &collectSink{}
	p := testPipeline(t, NewQueue(4), sink)
	ev := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder}
	if err := ev.SetPayload(record.SSLRequestPayload{Host: "api", Headers: map[string]string{
		"x-api-key": "secret", "content-type": "application/json"}}); err != nil {
		t.Fatal(err)
	}
	p.handle(ev)
	if got := string(sink.all()[0].Payload); strings.Contains(got, "secret") {
		t.Fatalf("a credential reached the terminal: %s", got)
	}
}

func TestPipelineDropCountBecomesAGap(t *testing.T) {
	q := NewQueue(1)
	sink := &collectSink{}
	p := testPipeline(t, q, sink)
	for i := 0; i < 4; i++ { // one fits, three are dropped
		q.Emit(&record.Event{Kind: record.KindFS, Source: record.SourceSeccomp})
	}
	p.drain()
	if sink.count() != 2 {
		t.Fatalf("wrote %d events, want the buffered one plus a gap", sink.count())
	}
	gap := sink.all()[1]
	if gap.Kind != record.KindGap {
		t.Fatalf("last event is %s, want gap", gap.Kind)
	}
	var p0 record.GapPayload
	if err := gap.DecodePayload(&p0); err != nil {
		t.Fatal(err)
	}
	if p0.What != record.GapRecord || p0.Why != GapChannelFull || p0.Count != 3 {
		t.Fatalf("gap %+v, want record/channel-full/3", p0)
	}
	// The counter resets, so the next drain reports nothing.
	p.drain()
	if sink.count() != 2 {
		t.Fatalf("a second drain wrote %d events", sink.count())
	}
}

// TestPipelineWaitsForRunStart runs in a synctest bubble so its negative half is a proof rather than a
// guess: synctest.Wait returns only once the pipeline goroutine is durably blocked, so an event it could
// have written before run_start has been written by then. A 20 ms sleep only said the goroutine had not
// got round to it yet, and passed on a loaded machine whether or not run waited for started.
func TestPipelineWaitsForRunStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(4)
		sink := &collectSink{}
		p := testPipeline(t, q, sink)
		started := make(chan struct{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.run(ctx, started) }()
		q.Emit(&record.Event{Kind: record.KindFS, Source: record.SourceSeccomp})
		synctest.Wait()
		if sink.count() != 0 {
			t.Fatal("the pipeline wrote before run_start was on disk")
		}
		close(started)
		synctest.Wait()
		if sink.count() != 1 {
			t.Fatalf("wrote %d events once run_start was on disk, want the buffered one", sink.count())
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("pipeline: %v", err)
		}
		if sink.count() != 1 {
			t.Fatalf("wrote %d events after run_start", sink.count())
		}
	})
}

func TestPipelineCountsATerminalFailure(t *testing.T) {
	sink := &collectSink{err: errors.New("disk full")}
	p := testPipeline(t, NewQueue(4), sink)
	p.handle(&record.Event{Kind: record.KindFS, Source: record.SourceSeccomp})
	if p.failed.Load() != 1 || p.written.Load() != 0 {
		t.Fatalf("failed=%d written=%d, want 1/0", p.failed.Load(), p.written.Load())
	}
}

func BenchmarkPipelineEvent(b *testing.B) {
	p := newPipeline(NewQueue(4), func(*record.Event) error { return nil }, ledger.RedactStage,
		passthroughStage, runStamp{PID: 1, TID: 1, Cgroup: 2}, nil, nil, slog.New(slog.DiscardHandler))
	ev := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp}
	if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/out/a"}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		e := *ev
		p.handle(&e)
	}
}

func BenchmarkQueueEmit(b *testing.B) {
	q := NewQueue(QueueCapacity)
	ev := &record.Event{Kind: record.KindFS}
	b.ReportAllocs()
	for b.Loop() {
		q.Emit(ev)
		select {
		case <-q.C():
		default:
		}
	}
}

// TestIdlePumpReportsDrops: drops were reported only after a handled event, so a burst that overfilled a lane
// and then stopped left its channel-full gap unwritten while the run went on, until the drain at shutdown.
func TestIdlePumpReportsDrops(t *testing.T) {
	sink := &collectSink{}
	q := NewQueue(4)
	p := newPipeline(q, sink.append, ledger.RedactStage, passthroughStage, runStamp{PID: 1, TID: 1, Cgroup: 2}, nil, nil,
		slog.New(slog.DiscardHandler))
	now := time.Now()
	for range 12 {
		q.Lane(LaneDefault).Emit(execAt(t, now))
	}
	p.lastDropReport = time.Now() // a report just made: handling the events adds none
	until := make(chan struct{})
	done := make(chan struct{})
	go func() { p.pump(until); close(done) }()
	defer func() { close(until); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range sink.all() {
			if ev.Kind == record.KindGap {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("an idle pump left the drops unreported")
}
