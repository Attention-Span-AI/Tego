// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// quietRing is a capture ring whose chunks arrived without waking the reader, as *ringbuf.Reader behaves: a
// read blocked on an empty wait stays blocked until a Flush, a Close or its deadline; after a Flush it hands
// out what the ring holds and then ringbuf.ErrFlushed, and past its deadline what the ring holds and then
// os.ErrDeadlineExceeded. produce, when set, puts one more chunk on the ring each time one is read: another
// run's probes, which can keep the ring from ever being empty.
type quietRing struct {
	mu       sync.Mutex
	cond     *sync.Cond
	records  [][]byte
	deadline time.Time
	flushed  bool
	closed   bool
	produce  func() []byte
	reads    int
}

func newQuietRing() *quietRing {
	q := &quietRing{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *quietRing) push(records ...[]byte) {
	q.mu.Lock()
	q.records = append(q.records, records...)
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
			if len(q.records) > 0 {
				r := q.records[0]
				q.records = q.records[1:]
				q.reads++
				if q.produce != nil {
					q.records = append(q.records, q.produce())
				}
				return ringbuf.Record{RawSample: r}, nil
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
	for _, r := range q.records {
		n += ringRecordBytes(len(r))
	}
	return n
}

// startQuiet starts a source over q as run r-1 in cgroup 41, under ctx. PollInterval is long, so the drain
// goroutine waits on the ring rather than waking to poll.
func startQuiet(t *testing.T, ctx context.Context, q *quietRing, opts Options) (*Uprobe, *fakeSink) {
	t.Helper()
	opts.Reader = q
	if opts.PollInterval == 0 {
		opts.PollInterval = time.Hour
	}
	u, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := u.Start(ctx, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	return u, sink
}

// stopWithin runs Stop and fails the test if it does not return in time: runner.shutdown calls it before
// run_end is written.
func stopWithin(t *testing.T, u *Uprobe, d time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- u.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(d):
		t.Fatalf("Stop did not return within %s", d)
	}
}

// exchangeChunks is one request and its response as the probes put them on the ring.
func exchangeChunks(pid uint32, ssl uint64, mono uint64) [][]byte {
	return [][]byte{
		chunkRecord(41, pid, pid+1, ssl, bpf.SSLWrite, mono, []byte(exchangeRequest), false),
		chunkRecord(41, pid, pid+1, ssl, bpf.SSLRead, mono+8_000_000, []byte(exchangeResponse), false),
	}
}

// TestStopDrainsTheCaptureRing is capture-derive.md E28 (edge case #28), the one final ring-buffer drain: a run's last response is on the
// ring when the run ends. Stop used to close the reader first, which dropped it and turned the request it
// answered into a malformed gap, and a request still on the ring vanished with no gap at all.
func TestStopDrainsTheCaptureRing(t *testing.T) {
	q := newQuietRing()
	u, sink := startQuiet(t, context.Background(), q, Options{})
	q.push(exchangeChunks(100, 0xabc, 1_000_000)...)
	stopWithin(t, u, 5*time.Second)
	evs := sink.events()
	if len(evs) != 2 || evs[0].Kind != record.KindSSLRequest || evs[1].Kind != record.KindSSLResponse {
		t.Fatalf("events %v, want the ssl_request and ssl_response still on the ring at Stop", evs)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v for a ring Stop drained whole", gaps)
	}
}

// TestStopDrainOfTheCaptureRingIsBounded: another run's probes can keep the ring from ever being empty, so the
// final drain reads the bytes the ring held when it began and no further, and Stop returns.
func TestStopDrainOfTheCaptureRingIsBounded(t *testing.T) {
	q := newQuietRing()
	u, sink := startQuiet(t, context.Background(), q, Options{})
	q.push(exchangeChunks(100, 0xabc, 1_000_000)...)
	q.mu.Lock()
	q.produce = func() []byte { return chunkRecord(99, 700, 701, 0xdef, bpf.SSLWrite, 2_000_000, []byte("x"), false) }
	q.mu.Unlock()
	stopWithin(t, u, 5*time.Second)
	if n := len(sink.events()); n != 2 {
		t.Errorf("%d events, want this run's request and response", n)
	}
	q.mu.Lock()
	reads := q.reads
	q.mu.Unlock()
	if reads > 10 {
		t.Errorf("the final drain read %d chunks of a ring that held 2 when it began", reads)
	}
}

// TestStopDrainPastItsBudgetIsARingBufferDrop: past StopDrain the chunks of this run still on the ring are
// counted, not reassembled, into ring-buffer-drop, so every chunk that never became an event is explained (I4).
// The chunks of another run are not this run's to count.
func TestStopDrainPastItsBudgetIsARingBufferDrop(t *testing.T) {
	q := newQuietRing()
	u, _ := startQuiet(t, context.Background(), q, Options{StopDrain: time.Nanosecond})
	var all [][]byte
	for i := range 4 {
		all = append(all, exchangeChunks(uint32(100+10*i), uint64(0xa00+i), uint64(1_000_000*(i+1)))...)
	}
	all = append(all, chunkRecord(99, 700, 701, 0xdef, bpf.SSLWrite, 9_000_000, []byte("x"), false))
	q.push(all...)
	stopWithin(t, u, 5*time.Second)
	// The drain goroutine, woken by Stop, reassembles the first chunk and returns; the final drain is past
	// its budget from the start, so the next 7 of this run are counted and cgroup 99's is not.
	var drops int64
	for _, g := range u.Gaps() {
		if g.Why == GapRingBufferDrop {
			drops += g.Count
		}
	}
	if drops != 7 {
		t.Errorf("ring-buffer-drop %d, want the 7 chunks of this run past the budget; gaps %v", drops, u.Gaps())
	}
}

// TestCancelLeavesTheRestToStop is the order every production run stops in: runner.shutdown cancels the run's
// workers before it calls any source's Stop, so the final drain is always reached through a cancellation first.
// Cancellation ends the drain goroutine and leaves the ring open, and Stop's final drain reads what it holds
// (edge case #28): the exchange on the ring when the run was cancelled, and one its processes finished after,
// since the run cancels before it knows its cgroup is empty. A cancellation that closed the reader, as Stop
// once did, left the final drain nothing to read, and the run's last request and response were lost with no gap.
func TestCancelLeavesTheRestToStop(t *testing.T) {
	q := newQuietRing()
	ctx, cancel := context.WithCancel(context.Background())
	u, sink := startQuiet(t, ctx, q, Options{})
	q.push(exchangeChunks(100, 0xabc, 1_000_000)...)
	cancel()
	u.mu.Lock()
	done := u.done
	u.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain goroutine outlived its context")
	}
	q.push(exchangeChunks(200, 0xdef, 3_000_000)...)
	stopWithin(t, u, 5*time.Second)
	var kinds []record.Kind
	for _, ev := range sink.events() {
		kinds = append(kinds, ev.Kind)
	}
	want := []record.Kind{record.KindSSLRequest, record.KindSSLResponse, record.KindSSLRequest, record.KindSSLResponse}
	if !slices.Equal(kinds, want) {
		t.Fatalf("events %v, gaps %v: want both exchanges, the one on the ring at the cancellation and the one after it",
			kinds, u.Gaps())
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v for a ring Stop drained whole", gaps)
	}
}
