// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// deadlineRecorder is a ResponseWriter that takes read deadlines, as net/http's own does, and counts the
// calls that arrive once the handler has returned.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	returned atomic.Bool
	late     atomic.Int32
}

func (d *deadlineRecorder) SetReadDeadline(time.Time) error {
	if d.returned.Load() {
		d.late.Add(1)
	}
	return nil
}

// endedReader signals entry into the read beyond its prefix, then signals when a read fails.
type endedReader struct {
	r         io.Reader
	remaining int
	started   chan struct{}
	startOnce sync.Once
	once      sync.Once
	done      chan struct{}
}

func (e *endedReader) Read(p []byte) (int, error) {
	if e.remaining == 0 {
		e.startOnce.Do(func() { close(e.started) })
	}
	n, err := e.r.Read(p)
	e.remaining -= n
	if err != nil {
		e.once.Do(func() { close(e.done) })
	}
	return n, err
}

// A request body the upstream leg is still reading when the handler returns never touches the
// connection again. The upstream answers before the body has ended, so the handler returns while its
// transport's writeLoop is still blocked reading the rest; the body then fails. Its read used to set the
// connection's read deadline through a ResponseWriter net/http had taken back, which on a kept-alive
// connection cleared the idle deadline net/http had set for the next request.
func TestABodyReadAfterItsHandlerReturnedLeavesTheConnectionAlone(t *testing.T) {
	const maxBody = 1024
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	body := &endedReader{
		r:         io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("x"), 2*maxBody)), pr),
		remaining: 2 * maxBody,
		started:   make(chan struct{}),
		done:      make(chan struct{}),
	}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		// The transport must already be inside idleBody.Read when the upstream replies. A read
		// started after retirement correctly refuses before touching body and cannot close done.
		select {
		case <-body.started:
		case <-time.After(5 * time.Second):
			t.Error("the upstream leg never started the remainder read")
		}
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	}, Options{MaxBody: maxBody})
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.ContentLength = 1 << 20
	req.Header.Set("Content-Type", "application/json")
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	serveDirect(h.listener, w, req)
	w.returned.Store(true)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want the upstream's 413", w.Code)
	}
	_ = pw.CloseWithError(io.ErrUnexpectedEOF)
	select {
	case <-body.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream leg never read the rest of the body")
	}
	time.Sleep(200 * time.Millisecond) // the deadline call, if any, follows the failed read at once
	if n := w.late.Load(); n != 0 {
		t.Errorf("%d read deadline calls reached the connection after the handler returned", n)
	}
}

// A read begun after retirement refuses before reading the body or setting a connection deadline.
func TestABodyReadStartedAfterRetirementIsRefused(t *testing.T) {
	underlying := bytes.NewReader([]byte("unread"))
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	b := &idleBody{r: underlying, rc: http.NewResponseController(w), idle: time.Second}
	b.retire()
	w.returned.Store(true)
	n, err := b.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, errBodyRetired) {
		t.Fatalf("read after retirement = %d, %v, want 0, errBodyRetired", n, err)
	}
	if left := underlying.Len(); left != len("unread") {
		t.Errorf("read after retirement consumed %d underlying bytes", len("unread")-left)
	}
	if n := w.late.Load(); n != 0 {
		t.Errorf("%d read deadline calls reached the connection after retirement", n)
	}
}
