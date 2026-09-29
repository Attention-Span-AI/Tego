// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stalledSink is a run's pipeline that has stopped reading: every Emit waits until release, as the capture
// lane's bounded wait does while the ledger is behind.
type stalledSink struct {
	*meteredSink
	gate    chan struct{}
	release func()
}

func newStalledSink(h *harness) *stalledSink {
	gate := make(chan struct{})
	var once sync.Once
	return &stalledSink{meteredSink: &meteredSink{fakeSink: h.sink}, gate: gate,
		release: func() { once.Do(func() { close(gate) }) }}
}

func (s *stalledSink) Emit(ev *record.Event) {
	<-s.gate
	s.meteredSink.Emit(ev)
}

// I1 (capture-derive.md): the client's request path never waits on the ledger. With the sink stalled, every
// request is still forwarded and answered at once; the events reach the sink, in order, once it reads again.
func TestStalledSinkDoesNotDelayTheClient(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, Options{})
	s := newStalledSink(h)
	t.Cleanup(s.release)
	h.listener.Bind(h.listener.runRef(), s)
	const n = 4
	for i := range n {
		start := time.Now()
		resp := h.post("/v1/messages", []byte(`{"i":`+itoa(i)+`}`), nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if d := time.Since(start); d > time.Second {
			t.Fatalf("request %d took %v with the sink stalled: the client waited on the ledger", i, d)
		}
	}
	if got := len(h.sink.all()); got != 0 {
		t.Fatalf("%d events reached a stalled sink", got)
	}
	s.release()
	evs := h.sink.waitFor(t, record.KindSSLResponse, n)
	_ = evs
	// Within each exchange the request line precedes its response, and exchanges keep the order they ran in.
	var kinds []string
	for _, ev := range h.sink.all() {
		kinds = append(kinds, string(ev.Kind))
	}
	want := strings.Repeat("ssl_request ssl_response ", n)
	if got := strings.Join(kinds, " ") + " "; got != want {
		t.Errorf("events = %q, want %q", got, want)
	}
	if gaps := h.listener.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: nothing overflowed", gaps)
	}
}

// I1: past its bound the listener's emit queue drops rather than grow or wait; each drop is counted in the
// run's gap report (gap what=capture why=emit-queue-full) and the first is reported unmetered, which ends a
// run with a token or cost budget (limits-check-doctor-cli.md R1 (s)).
func TestEmitQueueOverflowIsAGapAndUnmetered(t *testing.T) {
	orig := emitQueueSize
	emitQueueSize = 2
	t.Cleanup(func() { emitQueueSize = orig })
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-5",` +
			`"usage":{"input_tokens":10,"output_tokens":5}}`))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	s := newStalledSink(h)
	t.Cleanup(s.release)
	h.listener.Bind(h.listener.runRef(), s)
	const n = 6
	for i := range n {
		start := time.Now()
		resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if d := time.Since(start); d > time.Second {
			t.Fatalf("request %d took %v with the queue full", i, d)
		}
	}
	// The last exchange's response is emitted after the client's read returns; wait for the drops to land.
	deadline := time.Now().Add(5 * time.Second)
	var dropped int64
	for time.Now().Before(deadline) {
		dropped = 0
		for _, g := range h.listener.Gaps() {
			if g.What == record.GapCapture && g.Why == GapEmitQueueFull {
				dropped = g.Count
			}
		}
		if len(s.reported()) > 0 && dropped > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if dropped == 0 {
		t.Fatalf("gaps = %+v, want a capture gap why=%s", h.listener.Gaps(), GapEmitQueueFull)
	}
	got := s.reported()
	if len(got) != 1 || !strings.Contains(got[0], "emit queue full") {
		t.Errorf("reported %q, want one unmetered report naming the full queue", got)
	}
	s.release()
	if err := h.listener.Close(); err != nil {
		t.Fatal(err)
	}
	// Everything the queue took was written; with the drops that is every event the exchanges produced. The
	// count is read again now: the last exchange may have dropped more since the loop above.
	for _, g := range h.listener.Gaps() {
		if g.What == record.GapCapture && g.Why == GapEmitQueueFull {
			dropped = g.Count
		}
	}
	if written := int64(len(h.sink.all())); written+dropped < 2*n {
		t.Errorf("written %d + dropped %d < %d events", written, dropped, 2*n)
	}
}

// The gap why the emit queue writes is one of R37's closed set (derive.CaptureWhys).
func TestEmitQueueFullIsACaptureWhy(t *testing.T) {
	if !derive.IsCaptureWhy(GapEmitQueueFull) {
		t.Fatalf("%q is not in derive.CaptureWhys %v", GapEmitQueueFull, derive.CaptureWhys)
	}
}
