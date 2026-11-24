// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ceilingRun is TestTheLedgerCeilingIsPassedByTheLinesInFlightAndNoMore's rig: the run's real watcher, queue,
// pipeline and a real ledger writer, with backlog lines queued ahead of the drain and ceiling bytes allowed (0: none).
func ceilingRun(t *testing.T, ceiling int64, backlog int) (*runner, *ledger.Writer, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runs", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	w, err := ledger.Open(dir, record.RunRef{ID: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "a"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(t.TempDir(), "chain.log"))), ledger.WithFreshRunDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	clk := &stepClock{}
	clk.advance(time.Second)
	cgroups := &fakeCgroups{root: t.TempDir()}
	machine := &config.Machine{}
	if ceiling > 0 {
		machine.Record.MaxRunBytes = config.Ceiling[config.ByteSize]{Value: config.ByteSize(ceiling), Bounded: true}
	}
	r := &runner{
		log:    slog.New(slog.DiscardHandler),
		rt:     &agent.RuleTable{Contract: &agent.Contract{Name: "cap"}},
		deps:   Deps{Clock: clk, Config: machine},
		cgm:    cgroups,
		cg:     cgroup.Cgroup{Path: cgroups.root, ID: 4242},
		queue:  NewQueue(2 * backlog),
		writer: w,
		dir:    dir,
	}
	r.newBudget()
	t.Cleanup(r.closeActivity)
	r.pipe = newPipeline(r.queue, w.Append, w.RedactStage, w.SplitBlobsStage, runStamp{PID: 11, TID: 12, Cgroup: 4242},
		nil, budgets(r.budget, clk), slog.New(slog.DiscardHandler), w.AppendBatch)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Command: []string{"agent"}, Cwd: "/p"}); err != nil {
		t.Fatal(err)
	}
	r.startBudgetClock()
	for i := range backlog {
		ev := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp, Verdict: record.VerdictAllow, Rule: "fs.implicit[/p]"}
		if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/p/file-" + strconv.Itoa(i), Flags: 0}); err != nil {
			t.Fatal(err)
		}
		r.queue.Emit(ev)
	}
	return r, w, dir
}

// TestTheLedgerCeilingOvershootIsRecordedAsAGap pins its choice: the lines in flight when the ceiling trips are
// all written (a verdict line is never dropped or held back), so the overshoot is stated instead of bounded: one
// gap what=limits why=ledger-ceiling-overshoot, count the bytes past the ceiling when the pipeline drained, written
// once after the limit line and before run_end. A run under its ceiling writes none.
func TestTheLedgerCeilingOvershootIsRecordedAsAGap(t *testing.T) {
	const ceiling, backlog = 64 << 10, 600
	r, w, dir := ceilingRun(t, ceiling, backlog)
	r.pipe.drain()
	size := w.LedgerBytes()
	r.emitLedgerOvershootGap()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndLimit, ExitCode: identity.ExitLimit}); err != nil {
		t.Fatal(err)
	}
	var gaps []record.GapPayload
	var limitAt, gapAt, last = -1, -1, 0
	for i, e := range events(t, dir) {
		last = i
		switch e.Kind {
		case record.KindLimit:
			limitAt = i
		case record.KindGap:
			var g record.GapPayload
			if err := e.DecodePayload(&g); err != nil {
				t.Fatal(err)
			}
			gaps, gapAt = append(gaps, g), i
		}
	}
	if len(gaps) != 1 || gaps[0].What != record.GapLimits || gaps[0].Why != GapLedgerCeilingOvershoot {
		t.Fatalf("gap lines %+v, want one what=limits why=%s", gaps, GapLedgerCeilingOvershoot)
	}
	if want := int(size - ceiling); gaps[0].Count != want || want < 1 {
		t.Errorf("the gap counts %d bytes past the ceiling, the ledger held %d bytes of %d: want %d", gaps[0].Count, size, ceiling, want)
	}
	if !(limitAt > 0 && gapAt > limitAt && gapAt == last-1) {
		t.Errorf("limit line at %d, gap at %d, last line %d: want the gap after the limit line and just before run_end", limitAt, gapAt, last)
	}
}

func TestNoOvershootGapUnderTheCeiling(t *testing.T) {
	r, w, dir := ceilingRun(t, 1<<30, 20)
	r.pipe.drain()
	r.emitLedgerOvershootGap()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	for _, e := range events(t, dir) {
		if e.Kind == record.KindGap {
			t.Fatalf("a gap line in a run under its ceiling: %s", e.Kind)
		}
	}
}
