// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// slowGapSink holds each gap it is handed for a while, outside every lock of the listener: Close's derive of an
// unanswered exchange emits its gap and only then reads x.neverSent, so the handler's write lands in between.
type slowGapSink struct{ *meteredSink }

func (s slowGapSink) Emit(ev *record.Event) {
	if ev.Kind == record.KindGap {
		time.Sleep(50 * time.Millisecond)
	}
	s.meteredSink.Emit(ev)
}

// closeTakenTransport holds a round trip until Close has taken the listener's in-flight set, ignoring the
// request's context as a handler that outlasts closeDrain does, then fails it as a dial that never connected.
type closeTakenTransport struct {
	l       atomic.Pointer[Listener]
	entered chan struct{}
}

func (c *closeTakenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	close(c.entered)
	for {
		l := c.l.Load()
		l.mu.Lock()
		n := len(l.inflight)
		l.mu.Unlock()
		if n == 0 {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}
		time.Sleep(time.Millisecond)
	}
}

// A handler still in its round trip when Close gives up waiting (closeDrain) wrote x.neverSent after Close had
// taken x and while Close's derive read it: a data race -race reports. The write is made under the in-flight
// lock, and only while x is still the handler's.
func TestNeverSentIsNotWrittenUnderClose(t *testing.T) {
	orig := closeDrain
	closeDrain = 20 * time.Millisecond
	t.Cleanup(func() { closeDrain = orig })
	tr := &closeTakenTransport{entered: make(chan struct{})}
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{Transport: tr})
	tr.l.Store(h.listener)
	m := &meteredSink{fakeSink: h.sink}
	h.listener.Bind(h.listener.runRef(), slowGapSink{m})
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", bytes.NewReader([]byte(`{}`)))
		if err != nil {
			return
		}
		if resp, err := h.client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-tr.entered
	if err := h.listener.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	// Close derived the exchange with no answer before the dial failed: it counts as sent, which fails closed.
	if got := waitReported(m, 1); len(got) != 1 {
		t.Errorf("reported %q, want the one exchange Close derived unanswered", got)
	}
}
