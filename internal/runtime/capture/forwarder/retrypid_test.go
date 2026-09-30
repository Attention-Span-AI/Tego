// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A retry is a repeat by the same caller. Two processes of one run on one credential that send
// byte-identical requests (a fixed warmup or probe body) are two requests: the second was tagged retry_of the
// first, and R33 folded it into its own thread's previous step. The SDK counter's fallback names the retrying
// process's own most recent request, never another process's.
func TestRetryIsRecognizedOnlyWithinItsProcess(t *testing.T) {
	const keep = 64
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{MaxBody: keep})
	read := func(pid int, body []byte, header http.Header) *exchange {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range header {
			req.Header[http.CanonicalHeaderKey(k)] = v
		}
		x, err := h.listener.readRequest(httptest.NewRecorder(), req, pid)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		h.listener.budget.give(x.held)
		return x
	}
	body := []byte(`{"model":"claude-opus-5","max_tokens":8}`)
	a := read(100, body, nil)
	if b := read(200, body, nil); b.retryOf != "" {
		t.Errorf("process 200's identical request was tagged retry_of process 100's %q", b.retryOf)
	}
	if again := read(100, body, nil); again.retryOf != a.id {
		t.Errorf("process 100's repeat: retry_of %q, want its own original %q", again.retryOf, a.id)
	}
	c := read(300, []byte(`{"other":1}`), nil)
	if d := read(400, []byte(`{"changed":1}`), http.Header{RetryHeader: {"1"}}); d.retryOf != "" {
		t.Errorf("a counted retry from a process with no request of its own named %q", d.retryOf)
	}
	if e := read(300, []byte(`{"changed":2}`), http.Header{RetryHeader: {"1"}}); e.retryOf != c.id {
		t.Errorf("a counted retry: retry_of %q, want its process's latest %q", e.retryOf, c.id)
	}
	long := bytes.Repeat([]byte("x"), 2*keep)
	f := read(500, long, nil)
	if g := read(600, long, http.Header{RetryHeader: {"1"}}); g.retryOf != "" {
		t.Errorf("a truncated counted retry named another process's request %q", g.retryOf)
	}
	if g := read(500, long, http.Header{RetryHeader: {"1"}}); g.retryOf != f.id {
		t.Errorf("a truncated counted retry: retry_of %q, want %q", g.retryOf, f.id)
	}
}

// The per-process fallback holds at most the cache's size of processes, forgetting the one idle longest.
func TestRetryLatestIsBounded(t *testing.T) {
	c := newRetryCache(2, time.Minute)
	c.rememberLatest(1, "fx-1", 1)
	c.rememberLatest(2, "fx-2", 2)
	c.rememberLatest(3, "fx-3", 3)
	if len(c.latest) != 2 {
		t.Fatalf("%d processes held, want 2", len(c.latest))
	}
	if _, ok := c.recent(1, 3); ok {
		t.Error("the oldest process was not the one forgotten")
	}
	if id, ok := c.recent(3, 3); !ok || id != "fx-3" {
		t.Errorf("recent(3) = (%q, %v)", id, ok)
	}
}
