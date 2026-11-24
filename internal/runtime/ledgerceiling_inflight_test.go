// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
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

// TestTheLedgerCeilingIsPassedByTheLinesInFlightAndNoMore pins the ledger ceiling on the run's real
// wiring (watcher, queue, shutdown drain and a real ledger writer, no child process). record.max_run_bytes is read
// before the pipeline writes each line (limits.WithLedgerCeiling), so the first line that finds the ledger at the
// ceiling trips it, and the ledger holds at most one line more than the ceiling at that moment. A known backlog is
// queued ahead of the pipeline: after the trip every queued line is still written (the watcher drops none), the
// limit line is written once, right after the line that tripped it, and the file on disk shows all of it.
func TestTheLedgerCeilingIsPassedByTheLinesInFlightAndNoMore(t *testing.T) {
	const ceiling, backlog = 64 << 10, 600
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
	machine.Record.MaxRunBytes = config.Ceiling[config.ByteSize]{Value: ceiling, Bounded: true}
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

	// Queue the whole backlog before the production shutdown drain reads any of it.
	for i := range backlog {
		ev := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp, Verdict: record.VerdictAllow, Rule: "fs.implicit[/p]"}
		if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/p/file-" + strconv.Itoa(i), Flags: 0}); err != nil {
			t.Fatal(err)
		}
		r.queue.Emit(ev)
	}
	r.pipe.drain()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndLimit, ExitCode: identity.ExitLimit}); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int64 // the size of the file after each line
	var kinds []string
	var limit record.LimitPayload
	var total int64
	for _, ln := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
		total += int64(len(ln)) + 1
		var e struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(ln, &e); err != nil {
			t.Fatalf("a ledger line does not decode: %v", err)
		}
		if e.Kind == string(record.KindLimit) {
			if err := json.Unmarshal(ln, &limit); err != nil { // a line holds its payload's keys beside the common ones
				t.Fatal(err)
			}
		}
		sizes, kinds = append(sizes, total), append(kinds, e.Kind)
	}
	at := -1
	for i, k := range kinds {
		if k == string(record.KindLimit) {
			if at >= 0 {
				t.Fatalf("two limit lines, at %d and %d", at, i)
			}
			at = i
		}
	}
	if at < 3 {
		t.Fatalf("limit line at %d in a ledger of %d lines, want at least three preceding lines", at, len(kinds))
	}
	if limit.Which != record.LimitLedgerBytes || limit.Ceiling != ceiling {
		t.Errorf("limit %+v, want ledger_bytes at %d", limit, ceiling)
	}
	// The limit line follows the line that found the ledger at the ceiling; the size it read is the file's before that
	// line, which is at least the ceiling and under it plus the line before (the one whose write crossed it).
	before := sizes[at-2] // the file when the tripping line was observed
	if before < ceiling || before >= ceiling+(sizes[at-2]-sizes[at-3]) {
		t.Errorf("the ledger held %d bytes when the ceiling tripped: want at least %d and under it plus one line", before, ceiling)
	}
	if int64(limit.Value) != before {
		t.Errorf("the limit line says it read %v bytes, the file held %d", limit.Value, before)
	}
	// Everything queued behind the trip was written, none dropped; Close added the final run_end.
	if len(kinds) != backlog+3 {
		t.Errorf("%d lines on disk, want %d: run_start, %d queued lines, one limit line and run_end", len(kinds), backlog+3, backlog)
	}
	if kinds[len(kinds)-1] != string(record.KindRunEnd) {
		t.Errorf("last line %q, want run_end", kinds[len(kinds)-1])
	}
	// The final overshoot is bounded by one crossing line, the tripping line, the single limit line, the
	// remaining known backlog and run_end. No event not accounted for by that bound reached disk.
	crossing := sizes[at-2] - sizes[at-3]
	tripping := sizes[at-1] - sizes[at-2]
	limitSize := sizes[at] - sizes[at-1]
	tail := total - sizes[at]
	if got, upper := total-ceiling, crossing+tripping+limitSize+tail; got < tripping+limitSize+tail || got >= upper {
		t.Errorf("final overshoot %d, want at least %d and less than %d", got, tripping+limitSize+tail, upper)
	}
	if inFlight := len(kinds) - 2 - at; inFlight < 100 {
		t.Errorf("only %d lines were behind the limit line: the backlog did not outrun the trip", inFlight)
	}
	if total != int64(len(b)) || total != w.Size() {
		t.Errorf("on-disk size %d, line sizes %d, writer size %d must agree", len(b), total, w.Size())
	}
	for i, e := range events(t, dir) {
		if i == 0 || i == at || i == len(kinds)-1 {
			continue
		}
		var p record.FSPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		want := i - 1
		if i > at {
			want--
		}
		if e.Kind != record.KindFS || p.Path != "/p/file-"+strconv.Itoa(want) {
			t.Errorf("line %d: kind=%s path=%q, want queued file %d", i, e.Kind, p.Path, want)
		}
	}
	if r.terminal != identity.ReasonLimit {
		t.Errorf("terminal reason %q, want limit", r.terminal)
	}
}
