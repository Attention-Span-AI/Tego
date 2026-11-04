// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// quietRing is a ring buffer whose samples arrived without waking the reader, as *ringbuf.Reader behaves: a
// read blocked on an empty wait stays blocked until a Flush, a Close or its deadline, and after a Flush it
// hands out what the ring holds and then ringbuf.ErrFlushed. A deadline in the past hands out what the ring
// holds and then os.ErrDeadlineExceeded. AvailableBytes is the bytes the samples take on the ring. produce,
// when set, puts one more sample on the ring each time one is read: another run's producers, which can keep a
// ring from ever being empty.
type quietRing struct {
	mu       sync.Mutex
	cond     *sync.Cond
	samples  [][]byte
	deadline time.Time
	flushed  bool
	closed   bool
	produce  func() []byte
	reads    int
}

func newQuietRing(samples ...[]byte) *quietRing {
	q := &quietRing{samples: samples}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *quietRing) push(samples ...[]byte) {
	q.mu.Lock()
	q.samples = append(q.samples, samples...) // no wake-up: the reader does not see them until it is woken
	q.mu.Unlock()
}

func (q *quietRing) ReadInto(rec *ringbuf.Record) error { return readInto(rec, q.next) }

func (q *quietRing) next() (ringbuf.Record, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.closed {
			return ringbuf.Record{}, ringbuf.ErrClosed
		}
		past := !q.deadline.IsZero() && !time.Now().Before(q.deadline)
		if q.flushed || past {
			if len(q.samples) > 0 {
				s := q.samples[0]
				q.samples = q.samples[1:]
				q.reads++
				if q.produce != nil {
					q.samples = append(q.samples, q.produce())
				}
				return ringbuf.Record{RawSample: s, Remaining: len(q.samples)}, nil
			}
			if q.flushed {
				q.flushed = false
				return ringbuf.Record{}, ringbuf.ErrFlushed
			}
			return ringbuf.Record{}, os.ErrDeadlineExceeded
		}
		if !q.deadline.IsZero() {
			t := time.AfterFunc(time.Until(q.deadline), func() { q.mu.Lock(); q.cond.Broadcast(); q.mu.Unlock() })
			q.cond.Wait()
			t.Stop()
			continue
		}
		q.cond.Wait()
	}
}

func (q *quietRing) SetDeadline(t time.Time) {
	q.mu.Lock()
	q.deadline = t
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *quietRing) Close() error {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
	return nil
}

func (q *quietRing) Flush() error {
	q.mu.Lock()
	q.flushed = true
	q.cond.Broadcast()
	q.mu.Unlock()
	return nil
}

func (q *quietRing) AvailableBytes() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, s := range q.samples {
		n += ringRecordBytes(len(s))
	}
	return n
}

// endOfRun is a run's last samples: one process's exec, an open, and its exit.
func endOfRun(pid uint32, mono uint64) [][]byte {
	h := sample{MonoNS: mono, CgroupID: 77, PID: pid, TID: pid, PPID: 1}
	open, exit := h, h
	open.Kind, open.MonoNS = KindOpen, mono+100
	exit.Kind, exit.MonoNS = KindExit, mono+200
	return [][]byte{
		execSample(h, 900*proc.NanosPerTick, "python3", "/usr/bin/python3.13", []string{"python3", "app.py"}, false),
		fsSample(open, 0, 1, 2049, "/usr/lib/x86_64-linux-gnu/libssl.so.3", ""),
		exitSample(exit, 0, 0),
	}
}

// startQuiet starts a recorder over q with a hook, as run r-1.
func startQuiet(t *testing.T, ctx context.Context, q *quietRing, opts Options) (*Recorder, *fakeSink, *hookLog) {
	t.Helper()
	f := newFixture(t)
	opts.Rules, opts.Reader, opts.Proc = f.rules, q, f.procFS
	if opts.FlushInterval == 0 {
		opts.FlushInterval = time.Hour
	}
	// These tests are about what Stop reads, so the drain's own timed reads are kept out of their way unless
	// a test asks for them (TestSamplesWithNoWakeupAreReadOnTheReadInterval).
	if opts.ReadInterval == 0 {
		opts.ReadInterval = time.Hour
	}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	hook := &hookLog{}
	if err := r.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(ctx, source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	return r, sink, hook
}

// stopWithin runs Stop and fails the test if it does not return in time: runner.shutdown calls it before
// run_end is written, so a Stop that hangs is a launcher that never ends its ledger.
func stopWithin(t *testing.T, r *Recorder, d time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- r.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(d):
		t.Fatalf("Stop did not return within %s", d)
	}
}

// TestStopDrainsWhatTheRingStillHolds is edge case #28's final drain for the kernel record: the exec, the open
// and the exit that end a run are on the ring when Stop runs, not yet read. Stop used to close the reader
// first, and every one of them was lost with no gap: the ledger missed the run's last actions and the uprobe
// source missed the exit that settles a process.
func TestStopDrainsWhatTheRingStillHolds(t *testing.T) {
	q := newQuietRing()
	r, sink, hook := startQuiet(t, context.Background(), q, Options{})
	q.push(endOfRun(50, 1000)...)
	stopWithin(t, r, 5*time.Second)
	if n := len(sink.byKind(record.KindExec)); n != 1 {
		t.Errorf("%d exec events, want the one still on the ring at Stop", n)
	}
	want := []string{"exec 50 77 /usr/bin/python3.13", "open 50 77 /usr/lib/x86_64-linux-gnu/libssl.so.3", "exit 50"}
	if got := hook.all(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("hook saw %q, want %q", got, want)
	}
	if len(r.Gaps()) != 0 {
		t.Errorf("gaps = %v for a ring Stop drained whole", r.Gaps())
	}
}

// TestCancelLeavesTheRestToStop: the run cancels its workers before it knows its processes are gone, and a
// process can still act between the two (a worker failed, and the cgroup is killed after). Cancellation ends
// the drain goroutine promptly, and what reaches the ring after it is read by Stop, which the run calls once
// the cgroup is empty.
func TestCancelLeavesTheRestToStop(t *testing.T) {
	q := newQuietRing()
	ctx, cancel := context.WithCancel(context.Background())
	r, sink, _ := startQuiet(t, ctx, q, Options{})
	cancel()
	waitFor(t, func() bool {
		select {
		case <-r.done:
			return true
		default:
			return false
		}
	}, "the drain goroutine outlived its context")
	q.push(endOfRun(51, 2000)...)
	stopWithin(t, r, 5*time.Second)
	if n := len(sink.byKind(record.KindExec)); n != 1 {
		t.Errorf("%d exec events, want the one that reached the ring after the cancellation", n)
	}
}

// TestStopDrainIsBoundedByWhatTheRingHeld: the ring is every run's of the build, and another run's producers
// can keep it from ever being empty, so a drain to empty never ends and Stop never returns. The final drain
// reads the bytes the ring held when it began, which hold every sample of this run, and stops there.
func TestStopDrainIsBoundedByWhatTheRingHeld(t *testing.T) {
	q := newQuietRing()
	other := sample{MonoNS: 5000, CgroupID: 99, PID: 60, TID: 60, PPID: 1, Kind: KindExit}
	r, sink, _ := startQuiet(t, context.Background(), q, Options{})
	q.push(endOfRun(52, 3000)...)
	q.mu.Lock()
	q.produce = func() []byte { return exitSample(other, 0, 0) }
	q.mu.Unlock()
	stopWithin(t, r, 5*time.Second)
	if n := len(sink.byKind(record.KindExec)); n != 1 {
		t.Errorf("%d exec events, want this run's one", n)
	}
	q.mu.Lock()
	reads := q.reads
	q.mu.Unlock()
	if reads > 10 {
		t.Errorf("the final drain read %d samples of a ring that held 3 when it began", reads)
	}
}

// TestStopDrainPastItsBudgetCountsWhatIsLeft: the drain's work is bounded too. Past StopDrain the samples still
// on the ring are counted, not recorded, and what this run lost that way is gap why=ringbuf-undrained with its
// count, never a silent absence (I7, capture-derive I4).
func TestStopDrainPastItsBudgetCountsWhatIsLeft(t *testing.T) {
	q := newQuietRing()
	r, sink, _ := startQuiet(t, context.Background(), q, Options{StopDrain: time.Nanosecond})
	var all [][]byte
	for i := range 5 {
		all = append(all, endOfRun(uint32(60+i), uint64(1000*(i+1)))...)
	}
	q.push(all...)
	stopWithin(t, r, 5*time.Second)
	// The drain goroutine, woken by Stop, records the one sample in its hands (the first exec) and returns; the
	// final drain is past its budget from the start, so the other 14 are counted.
	recorded := len(sink.byKind(record.KindExec))
	undrained := gapCount(r.Gaps())[GapRingbufUndrained]
	if recorded != 1 || undrained != 14 {
		t.Errorf("%d exec events recorded and %d samples counted undrained, want 1 and the other 14 of 15; gaps %v",
			recorded, undrained, r.Gaps())
	}
}

// heldFollower is a capture source whose OnExec does not return until release is closed: one attaching at a
// file a traced process chose, which is how long the kernel record waited on it.
type heldFollower struct{ entered, release chan struct{} }

func (h heldFollower) OnExec(int, uint64, string) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
}
func (heldFollower) OnOpen(int, uint64, string) {}
func (heldFollower) OnExit(int)                 {}

// TestAFollowerHeldInOneCallDoesNotHoldStop: the runtime feeds a follower through a queue, and a full queue made the
// recorder's drain wait for room. A follower held in one OnExec behind a burst of libssl opens therefore held Stop's
// final drain, and run_end behind it. The queue drops and counts past its capacity now, and Stop returns within its
// StopDrain.
func TestAFollowerHeldInOneCallDoesNotHoldStop(t *testing.T) {
	f := newFixture(t)
	follower := heldFollower{entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { close(follower.release) })
	hook, closeQueue, dropped := runtime.NewHookQueue(follower)
	t.Cleanup(func() { closeQueue(0) })
	// Establish the blocked follower and full queue before starting the stop clock. Decoding
	// 5,000 samples within StopDrain is a throughput assumption, especially under -race.
	hook.OnExec(50, 77, "/usr/bin/python3.13")
	select {
	case <-follower.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the follower never entered OnExec")
	}
	filled := make(chan struct{})
	go func() {
		defer close(filled)
		for range 5000 {
			hook.OnOpen(50, 77, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
			if dropped() != 0 {
				return
			}
		}
	}()
	select {
	case <-filled:
	case <-time.After(5 * time.Second):
		t.Fatal("filling the hook queue blocked")
	}
	before := dropped()
	if before == 0 {
		t.Fatal("the fixture did not fill the hook queue")
	}
	q := newQuietRing()
	const stopDrain = 2 * time.Second
	r, err := New(Options{Rules: f.rules, Reader: q, Proc: f.procFS, FlushInterval: time.Hour, ReadInterval: time.Hour,
		StopDrain: stopDrain})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	q.push(endOfRun(50, 1000)...)
	stopWithin(t, r, stopDrain+3*time.Second)
	if delta := dropped() - before; delta != 2 {
		t.Errorf("Stop dropped %d hooks, want its exec and libssl open to encounter the full queue", delta)
	}
}
