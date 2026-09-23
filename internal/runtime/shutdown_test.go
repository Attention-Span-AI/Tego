// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// hasRunEndOnDisk reports whether a run's ledger already carries run_end as its last line. It reads
// the file directly rather than through the package's own reader so it can be called from any
// goroutine, including from inside a fake's method, without touching *testing.T off the test
// goroutine (forbidden for Fatal-family calls).
func hasRunEndOnDisk(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		return false
	}
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	if len(lines) == 0 {
		return false
	}
	var last struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		return false
	}
	return last.Kind == string(record.KindRunEnd)
}

// orderCheckingHandle is an api.Handle that records, at the exact moment Detach and Close are
// called, whether the run's ledger already has run_end on disk. Reading the fact the runtime itself
// just wrote is a direct, non-racy way to prove ordering — no clock, no sleep, no assumption about
// scheduling, just "was the line there when I was called".
type orderCheckingHandle struct {
	dir                             string
	detached, closed                int
	detachSawRunEnd, closeSawRunEnd bool
}

func (h *orderCheckingHandle) LandlockRuleset() (int, bool)                { return -1, false }
func (h *orderCheckingHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (h *orderCheckingHandle) Attach(uint64) error                         { return nil }

func (h *orderCheckingHandle) Detach() error {
	h.detached++
	h.detachSawRunEnd = hasRunEndOnDisk(h.dir)
	return nil
}

func (h *orderCheckingHandle) Close() error {
	h.closed++
	h.closeSawRunEnd = hasRunEndOnDisk(h.dir)
	return nil
}

// orderCheckingCgroups wraps fakeCgroups and, on Remove, records the same two facts: whether
// run_end was already on disk and whether the handle had already been detached.
type orderCheckingCgroups struct {
	*fakeCgroups
	dir                              string
	handle                           *orderCheckingHandle
	removeSawRunEnd, removeSawDetach bool
}

func (c *orderCheckingCgroups) Remove(ctx context.Context, cg cgroup.Cgroup) error {
	c.removeSawRunEnd = hasRunEndOnDisk(c.dir)
	c.removeSawDetach = c.handle.detached > 0
	return c.fakeCgroups.Remove(ctx, cg)
}

// TestShutdownJoinsWorkersAndDrainsBeforeClosingTheLedger pins the load-bearing half of R8's order —
// "cancel → errgroup.Wait() → drain the queue → ... → ledger.Close(reason) → Detach/Close() →
// cgroup.Manager.Remove ... → remove $XDG_RUNTIME_DIR/tego/<run>/" — at the facade's own level,
// with no root and no real child process.
//
// A worker held open on a channel stands in for a source still finishing up: it enqueues one more
// event only when released. Because group.Wait cannot return while that worker is still running (Go's
// own WaitGroup semantics, not a race), shutdown() is provably still inside Wait at the moment the
// test's own "not yet done" check runs — no timing assumption needed for that part. Once released,
// the worker's event must survive: it can only reach the ledger if drain() runs after Wait() returns,
// which is exactly R8's claim. The two order-checking fakes then confirm the tail: ledger.Close
// before Detach/Close, and Detach before cgroup.Remove.
// supervisor.md E25: the supervisor loop runs in the same group (run.go "supervisor"), so this join before the drain, Metrics and ledger.Close is the facade waiting for Loop.Run to return.
func TestShutdownJoinsWorkersAndDrainsBeforeClosingTheLedger(t *testing.T) {
	const runID = "r-00000000-000000000000a-order0"
	runDir := filepath.Join(t.TempDir(), runID)
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-order"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}

	handle := &orderCheckingHandle{dir: runDir}
	cgroups := &orderCheckingCgroups{fakeCgroups: &fakeCgroups{root: t.TempDir()}, dir: runDir, handle: handle}

	queue := NewQueue(8)
	pipe := newPipeline(queue, ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))

	g, _ := newGroup(context.Background())
	release := make(chan struct{})
	worked := make(chan struct{})
	g.Go("late-source", func() error {
		<-release
		// A source's last act before it fully stops: one more event that must not be lost to a
		// drain that ran ahead of the group's own join.
		queue.Emit(gapEvent(source.Gap{What: record.GapRecord, Why: "late-worker-marker"}))
		close(worked)
		return nil
	})

	runtimeDir := t.TempDir()
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w, handle: handle,
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
		queue: queue, pipe: pipe, runtimeDir: runtimeDir,
	}

	done := make(chan Result, 1)
	go func() { done <- r.shutdown(context.Background()) }()

	// The worker is still blocked on release, so group.Wait cannot have returned yet — shutdown
	// cannot possibly be past its own Wait() call, let alone finished. This can never flake false:
	// it would only ever fail by shutdown finishing too early, which is exactly the violation R8
	// forbids.
	select {
	case <-done:
		t.Fatal("shutdown returned before its own worker was released: the join-before-drain order is broken")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-worked

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown never returned once its worker finished")
	}

	evs := events(t, runDir)
	if len(evs) < 3 {
		t.Fatalf("run has %d events, want at least run_start, the late fs event and run_end", len(evs))
	}
	last, prev := evs[len(evs)-1], evs[len(evs)-2]
	if last.Kind != record.KindRunEnd {
		t.Fatalf("last event is %s, want run_end", last.Kind)
	}
	if prev.Kind != record.KindGap {
		t.Fatalf("the event the late worker emitted never reached the ledger before run_end (want gap, got %s): "+
			"drain must run after the workers are joined, not before", prev.Kind)
	}

	if !handle.detachSawRunEnd {
		t.Fatal("Handle.Detach ran before ledger.Close wrote run_end (R8 order broken)")
	}
	if !handle.closeSawRunEnd {
		t.Fatal("Handle.Close ran before ledger.Close wrote run_end (R8 order broken)")
	}
	if !cgroups.removeSawRunEnd {
		t.Fatal("cgroup.Remove ran before ledger.Close wrote run_end (R8 order broken)")
	}
	if !cgroups.removeSawDetach {
		t.Fatal("cgroup.Remove ran before Handle.Detach (R8's release order: Detach/Close, then Remove)")
	}
	if _, err := os.Stat(runtimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the run's tmpfs directory must be removed by shutdown (R8)")
	}
}

// failingAnchor always refuses to record a run's head. ledger.Writer.Close still writes run_end to
// events.jsonl before it ever calls the anchor (finish's own ordering), so this reproduces exactly
// the shape R18 names — "disk full, fsync EIO, chain.log append failure" — a Close that fails after
// the data everyone actually reads is already durable.
type failingAnchor struct{ calls int }

func (a *failingAnchor) Append(string, string) error {
	a.calls++
	return errors.New("anchor: disk full")
}
func (a *failingAnchor) Head(string) (string, bool, error) { return "", false, nil }

// TestShutdownContinuesPastALedgerCloseFailure pins R18: "If ledger.Close itself fails ... the
// shutdown sequence still proceeds through Detach/Close → cgroup.Manager.Remove → socket cleanup ...
// every step runs unconditionally." Without this, a single anchor write failure — an operational
// hiccup, not a run failure — would leak the backend's kernel state, the run's cgroup and its tmpfs
// directory on every affected run, which is strictly worse than the logged, durable-data write
// failure R18 accepts instead.
//
// Also pins runtime-launch.md R18: a failing ledger Close does not stop the rest of shutdown.
func TestShutdownContinuesPastALedgerCloseFailure(t *testing.T) {
	const runID = "r-00000000-000000000000b-r18000"
	runDir := filepath.Join(t.TempDir(), runID)
	anchor := &failingAnchor{}
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-r18"}, ledger.WithAnchor(anchor))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}

	handle := &orderCheckingHandle{dir: runDir}
	cgroups := &orderCheckingCgroups{fakeCgroups: &fakeCgroups{root: t.TempDir()}, dir: runDir, handle: handle}
	runtimeDir := t.TempDir()

	g, _ := newGroup(context.Background())
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w, handle: handle,
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
		runtimeDir: runtimeDir,
	}
	_ = r.shutdown(context.Background())

	if anchor.calls == 0 {
		t.Fatal("the failing anchor was never reached: this test proves nothing about R18")
	}
	if !hasRunEndOnDisk(runDir) {
		t.Fatal("run_end must still be on disk even though the anchor write failed (finish writes the line first)")
	}
	if handle.detached != 1 || handle.closed != 1 {
		t.Fatalf("handle detached=%d closed=%d, want 1/1: shutdown must not abort after ledger.Close fails (R18)",
			handle.detached, handle.closed)
	}
	if cgroups.removed != 1 {
		t.Fatalf("cgroup removed %d times, want 1: shutdown must not abort after ledger.Close fails (R18)",
			cgroups.removed)
	}
	if _, err := os.Stat(runtimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the run's tmpfs directory must still be removed after a ledger.Close failure (R18)")
	}
}
