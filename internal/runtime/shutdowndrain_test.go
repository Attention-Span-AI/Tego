// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// finalDrainSource stands in for the kernel recorder or the uprobe source at Stop: its final drain puts the
// samples its ring still holds into the run's queue, each after the work one sample costs, which here is a
// wait for room in the queue. The wait is bounded by budget, as StopDrain bounds the real drain, so a queue
// nothing reads costs the test that long and then drops the rest, as Queue.Emit does.
type finalDrainSource struct {
	q      *Queue
	n      int
	budget time.Duration
}

const finalDrainMarker = "final-drain-marker"

func (s *finalDrainSource) Name() string                                            { return "final-drain" }
func (s *finalDrainSource) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (s *finalDrainSource) Gaps() []source.Gap                                      { return nil }

func (s *finalDrainSource) Stop() error {
	deadline := time.Now().Add(s.budget)
	for range s.n {
		for len(s.q.C()) == cap(s.q.C()) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Microsecond)
		}
		s.q.Emit(gapEvent(source.Gap{What: record.GapRecord, Why: finalDrainMarker}))
	}
	return nil
}

// TestShutdownReadsTheQueueWhileSourcesStop: step 13 cancels the workers, which ends the pipeline goroutine,
// before it stops the sources, and a source's Stop is where the recorder and the uprobe source drain what their
// ring still holds (edge case #28). Nothing read the queue then, so a final drain past the queue's depth lost
// the rest as channel-full however far within its StopDrain it was. Here a source's Stop emits more than
// QueueCapacity events, and every one must reach the ledger. The second case is a run whose pipeline goroutine
// was still running when shutdown began after a worker failed and cancelled the group: the group's
// cancellation no longer ends it (runPipeline), only shutdown does.
func TestShutdownReadsTheQueueWhileSourcesStop(t *testing.T) {
	for _, tc := range []struct {
		name            string
		cancelledBefore bool
	}{
		{"pipeline still running", false},
		{"a failed worker cancelled the group first", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const runID = "r-00000000-000000000000c-drain0"
			runDir := filepath.Join(t.TempDir(), runID)
			w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-drain"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatalf("ledger.Open: %v", err)
			}
			if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup"}); err != nil {
				t.Fatalf("WriteRunStart: %v", err)
			}
			queue := NewQueue(QueueCapacity)
			pipe := newPipeline(queue, ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
				runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
			g, gctx := newGroup(context.Background())
			started := make(chan struct{})
			close(started)
			src := &finalDrainSource{q: queue, n: QueueCapacity + 1000, budget: 3 * time.Second}
			cgroups := &fakeCgroups{root: t.TempDir()}
			r := &runner{
				log: slog.New(slog.DiscardHandler), group: g, writer: w,
				cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
				queue: queue, pipe: pipe, started: started, sources: []source.Source{src},
			}
			r.runPipeline(gctx)
			if tc.cancelledBefore {
				g.Cancel()
				select {
				case <-r.pipeDone:
					t.Fatal("the group's cancellation ended the pipeline")
				case <-time.After(100 * time.Millisecond):
				}
			}
			_ = r.shutdown(context.Background())

			var markers, full int
			for _, ev := range events(t, runDir) {
				if ev.Kind != record.KindGap {
					continue
				}
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				switch p.Why {
				case finalDrainMarker:
					markers++
				case GapChannelFull:
					full += p.Count
				}
			}
			if markers != src.n || full != 0 {
				t.Fatalf("%d of the %d events a source emitted at Stop reached the ledger, %d were channel-full",
					markers, src.n, full)
			}
		})
	}
}

// releaseSource is a source whose Stop lets a waiting worker go on, so the worker's emits begin inside
// shutdown, after the pump has started and before the workers are joined.
type releaseSource struct{ release chan struct{} }

func (s *releaseSource) Name() string                                            { return "release" }
func (s *releaseSource) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (s *releaseSource) Stop() error                                             { close(s.release); return nil }
func (s *releaseSource) Gaps() []source.Gap                                      { return nil }

// TestShutdownJoinsWaitingSupervisorWorkersWhileReading is CI run #33's TestAFloodOfRefusalsLosesNoLines loss
// (4 channel-full, one per supervisor worker): a supervisor worker records a notification after answering it,
// so an agent that exits mid-flood leaves the workers waiting for room in a full supervisor lane. Shutdown
// released every waiter (Queue.stopWaiting) right after the sources stopped and before it joined the workers,
// and each waiter dropped its line. The worker here holds a full lane, as a ledger that is the bottleneck
// leaves it, and records its remaining lines once shutdown is under way; every one must reach the ledger.
func TestShutdownJoinsWaitingSupervisorWorkersWhileReading(t *testing.T) {
	const runID = "r-00000000-000000000000c-drain1"
	runDir := filepath.Join(t.TempDir(), runID)
	w, err := ledger.Open(runDir, record.RunRef{ID: runID, Agent: "shutdown-drain"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "cgroup"}); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}
	queue := NewQueue(QueueCapacity)
	pipe := newPipeline(queue, ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
	g, gctx := newGroup(context.Background())
	started := make(chan struct{})
	close(started)
	src := &releaseSource{release: make(chan struct{})}
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g, writer: w,
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
		queue: queue, pipe: pipe, started: started, sources: []source.Source{src},
	}
	r.runPipeline(gctx)
	// The pipeline goroutine ends first, as shutdown's cancel ends it, so the lane fills with nothing reading.
	g.Cancel()
	r.stopPipeline()
	<-r.pipeDone
	const late = 1000
	lane := queue.Lane(LaneSupervisor)
	full := make(chan struct{})
	g.Go("supervisor", func() error {
		for range QueueCapacity {
			lane.Emit(gapEvent(source.Gap{What: record.GapRecord, Why: finalDrainMarker}))
		}
		close(full)
		<-src.release
		for range late {
			lane.Emit(gapEvent(source.Gap{What: record.GapRecord, Why: finalDrainMarker}))
		}
		return nil
	})
	<-full
	_ = r.shutdown(context.Background())

	var markers, dropped int
	for _, ev := range events(t, runDir) {
		if ev.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		switch p.Why {
		case finalDrainMarker:
			markers++
		case GapChannelFull:
			dropped += p.Count
		}
	}
	if want := QueueCapacity + late; markers != want || dropped != 0 {
		t.Fatalf("%d of the %d lines a supervisor worker recorded reached the ledger, %d were channel-full",
			markers, want, dropped)
	}
}

// emptyingCgroups is a run cgroup whose processes die some time after cgroup.kill, as SIGKILL is delivered
// asynchronously: WaitEmpty returns once they have, or when its ctx ends with the tree still populated, as
// cgroup.FS.WaitEmpty does. A negative emptyAfter is a tree the kill never empties.
type emptyingCgroups struct {
	*fakeCgroups
	emptyAfter time.Duration

	mu    sync.Mutex
	kills int
	empty chan struct{}
}

func newEmptyingCgroups(t *testing.T, after time.Duration) *emptyingCgroups {
	return &emptyingCgroups{fakeCgroups: &fakeCgroups{root: t.TempDir()}, emptyAfter: after, empty: make(chan struct{})}
}

func (c *emptyingCgroups) Kill(cgroup.Cgroup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kills++
	if c.kills == 1 && c.emptyAfter >= 0 {
		time.AfterFunc(c.emptyAfter, func() { close(c.empty) })
	}
	return nil
}

func (c *emptyingCgroups) WaitEmpty(ctx context.Context, _ cgroup.Cgroup) error {
	select {
	case <-c.empty:
		return nil
	default:
	}
	select {
	case <-c.empty:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("cgroup: wait empty: %w", ctx.Err())
	}
}

func (c *emptyingCgroups) emptied() bool {
	select {
	case <-c.empty:
		return true
	default:
		return false
	}
}

// TestAwaitEmptyOutlivesTheRunContext: step 12's wait for the cgroup to empty is what lets step 13's final
// drains read every sample of the run, because nothing of the run is left to produce one. On the cancellation
// path (a failed worker, a cancelling caller) that wait used the run's own ctx, already cancelled, so it
// returned at once while the processes cgroup.kill had signalled were still exiting, and their exits reached
// the ring after the drain had measured it. The wait now runs on a context of its own, bounded by killTimeout;
// a tree that outlasts even that is a ringbuf-undrained gap with no count, for a run whose kernel record reads.
func TestAwaitEmptyOutlivesTheRunContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	newRunner := func(cg *emptyingCgroups) *runner {
		return &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root},
			queue: NewQueue(8), kernelRecord: &plainSource{name: "observe"}}
	}
	queued := func(r *runner) []record.GapPayload {
		var out []record.GapPayload
		for {
			select {
			case ev := <-r.queue.C():
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				out = append(out, p)
			default:
				return out
			}
		}
	}

	t.Run("killed by awaitExit, still exiting", func(t *testing.T) {
		cg := newEmptyingCgroups(t, 100*time.Millisecond)
		r := newRunner(cg)
		_ = cg.Kill(r.cg) // awaitExit's own kill on the cancellation branch
		r.awaitEmpty(cancelled, true)
		if !cg.emptied() {
			t.Fatal("awaitEmpty returned with the killed tree still in the cgroup: the final drains would miss its exits")
		}
		if cg.kills != 1 {
			t.Errorf("%d kills, want awaitExit's one", cg.kills)
		}
		if gaps := queued(r); len(gaps) != 0 {
			t.Errorf("gaps %v for a tree that emptied", gaps)
		}
	})
	t.Run("the run context ended while a descendant lived on", func(t *testing.T) {
		cg := newEmptyingCgroups(t, 100*time.Millisecond)
		r := newRunner(cg)
		r.awaitEmpty(cancelled, false)
		if cg.kills != 1 || !cg.emptied() {
			t.Fatalf("%d kills, emptied %v: want the tree killed and waited for", cg.kills, cg.emptied())
		}
	})
	t.Run("a tree the kill does not empty is bounded and said", func(t *testing.T) {
		cg := newEmptyingCgroups(t, -1)
		r := newRunner(cg)
		r.killWait = 50 * time.Millisecond
		start := time.Now()
		r.awaitEmpty(cancelled, true)
		if d := time.Since(start); d < r.killWait || d > 5*time.Second {
			t.Errorf("awaitEmpty took %s, want its bound of %s", d, r.killWait)
		}
		gaps := queued(r)
		if len(gaps) != 1 || gaps[0].What != record.GapRecord || gaps[0].Why != GapRingbufUndrained || gaps[0].Count != 0 {
			t.Fatalf("gaps %+v, want one what=record why=ringbuf-undrained with no count", gaps)
		}
	})
	t.Run("a recorder that reads nothing has no drain to miss", func(t *testing.T) {
		cg := newEmptyingCgroups(t, -1)
		r := newRunner(cg)
		r.kernelRecord = &inertRecorder{}
		r.killWait = 10 * time.Millisecond
		r.awaitEmpty(cancelled, true)
		if gaps := queued(r); len(gaps) != 0 {
			t.Fatalf("gaps %+v beside the recorder's own kernel-record-unavailable", gaps)
		}
	})
	t.Run("a live context waits as before", func(t *testing.T) {
		cg := newEmptyingCgroups(t, 0)
		r := newRunner(cg)
		_ = cg.Kill(r.cg)
		r.awaitEmpty(context.Background(), false)
		if cg.kills != 1 || !cg.emptied() {
			t.Fatalf("%d kills, emptied %v", cg.kills, cg.emptied())
		}
	})
}

// failingWaitCgroups is a cgroup whose events file cannot be read: WaitEmpty fails with a plain error.
type failingWaitCgroups struct{ *emptyingCgroups }

func (c *failingWaitCgroups) WaitEmpty(context.Context, cgroup.Cgroup) error {
	return errors.New("cgroup: read cgroup.events: permission denied")
}

// TestAwaitEmptyKillsOnAPlainWaitError: a WaitEmpty failure that is not the run context ending (an agent
// that chmod'd its own cgroup.events) used to return with the tree alive, and shutdown then released
// enforcement over it under a clean run_end.
func TestAwaitEmptyKillsOnAPlainWaitError(t *testing.T) {
	cg := &failingWaitCgroups{newEmptyingCgroups(t, 0)}
	r := &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root},
		queue: NewQueue(8), kernelRecord: &plainSource{name: "observe"}, killWait: 10 * time.Millisecond}
	r.awaitEmpty(context.Background(), false)
	if cg.kills != 1 {
		t.Fatalf("%d kills, want the tree killed", cg.kills)
	}
	if !r.quiesced.Load() {
		t.Error("not quiesced")
	}
	if r.detail == "" {
		t.Error("run_end has no detail for the kill after an unreadable cgroup.events")
	}
	select {
	case ev := <-r.queue.C():
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.What != record.GapRecord || p.Why != GapRingbufUndrained {
			t.Fatalf("gap %+v", p)
		}
	default:
		t.Fatal("no gap for a tree that could not be shown empty")
	}
}

// inertRecorder is a kernel recorder whose Start found it could not read for this run.
type inertRecorder struct{ plainSource }

func (*inertRecorder) Gaps() []source.Gap {
	return []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}
}
