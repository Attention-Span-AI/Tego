// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLedgerCeilingEndsTheRun: a run whose events.jsonl reaches the machine's record.max_run_bytes is ended as a
// limit by the next Tick (MinorLedgerCap): one limit line which=ledger_bytes with the size and the ceiling, no reason
// (the closed reason set has none for it), the facade told, the cgroup killed, and nothing below the ceiling trips.
func TestLedgerCeilingEndsTheRun(t *testing.T) {
	sink, killer, clk := &fakeSink{}, &fakeKiller{}, &fakeClock{}
	var size atomic.Int64
	var breaches []Breach
	w := NewWatcher(agent.ResolvedLimits{}, nil, killer, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithOnBreach(func(b Breach) { breaches = append(breaches, b) }),
		WithLedgerCeiling(64<<10, size.Load))
	clk.set(1_000)
	w.Observe(runStart(1_000))

	size.Store(64<<10 - 1)
	if b, err := w.Tick(context.Background()); b != nil || err != nil {
		t.Fatalf("a ledger under its ceiling tripped: %+v %v", b, err)
	}
	size.Store(70_000)
	b, err := w.Tick(context.Background())
	if err != nil || b == nil || b.Which != record.LimitLedgerBytes || b.Value != 70_000 || b.Ceiling != 64<<10 {
		t.Fatalf("Tick = %+v, %v; want a ledger_bytes breach of 70000 over 65536", b, err)
	}
	if b.Reason() != "" {
		t.Errorf("reason %q: ledger_bytes has no code in the closed set", b.Reason())
	}
	limitsSeen := sink.kinds(record.KindLimit)
	if len(limitsSeen) != 1 || limitsSeen[0].Reason != "" {
		t.Fatalf("limit lines %+v", limitsSeen)
	}
	var p record.LimitPayload
	if err := limitsSeen[0].DecodePayload(&p); err != nil || p.Which != record.LimitLedgerBytes || p.Value != 70_000 || p.Ceiling != 65536 {
		t.Fatalf("limit payload %+v (%v)", p, err)
	}
	if len(breaches) != 1 || killer.kills.Load() != 1 {
		t.Errorf("breaches %d, kills %d; want 1 and 1", len(breaches), killer.kills.Load())
	}
	if b, _ := w.Tick(context.Background()); b != nil {
		t.Errorf("a second breach after the first: %+v", b)
	}
}

// TestLedgerCeilingTripsOnAnEvent: a busy run is ended by the event that finds its ledger at the ceiling, not a
// second later at the next Tick: a run writing thousands of lines a second passed a 64 KiB ceiling by 3 MiB.
func TestLedgerCeilingTripsOnAnEvent(t *testing.T) {
	sink, killer, clk := &fakeSink{}, &fakeKiller{}, &fakeClock{}
	var size atomic.Int64
	w := NewWatcher(agent.ResolvedLimits{}, nil, killer, cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithLedgerCeiling(64<<10, size.Load))
	w.Observe(runStart(1_000))
	exec := &record.Event{Kind: record.KindExec, Source: record.SourceSeccomp, MonoNS: 2_000}
	w.Observe(exec)
	if _, tripped := w.Tripped(); tripped {
		t.Fatal("tripped under the ceiling")
	}
	size.Store(64 << 10)
	w.Observe(exec)
	if b, tripped := w.Tripped(); !tripped || b.Which != record.LimitLedgerBytes || killer.kills.Load() != 1 {
		t.Fatalf("breach %+v tripped %v kills %d; want ledger_bytes, one kill", b, tripped, killer.kills.Load())
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit lines", n)
	}
}

// TestNoLedgerCeilingNeverReadsTheSize: without the option, or with a ceiling of 0, the size is never asked for.
func TestNoLedgerCeilingNeverReadsTheSize(t *testing.T) {
	for _, ceiling := range []int64{0, -1} {
		sink, clk := &fakeSink{}, &fakeClock{}
		read := false
		w := NewWatcher(agent.ResolvedLimits{}, nil, &fakeKiller{}, cgroup.Cgroup{}, clk, sink,
			WithLedgerCeiling(ceiling, func() int64 { read = true; return 1 << 40 }))
		clk.set(1_000)
		w.Observe(runStart(1_000))
		if b, _ := w.Tick(context.Background()); b != nil || read {
			t.Errorf("ceiling %d: breach %+v, size read %v", ceiling, b, read)
		}
	}
}
