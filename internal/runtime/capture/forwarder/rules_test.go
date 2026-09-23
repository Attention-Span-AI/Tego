// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// timeoutError is a net.Error whose Timeout() is scripted, so statusFor's branching can be exercised
// without a real dial or a real clock wait.
type timeoutError struct{ timeout bool }

func (e timeoutError) Error() string   { return "scripted net error" }
func (e timeoutError) Timeout() bool   { return e.timeout }
func (e timeoutError) Temporary() bool { return e.timeout }

// Capture-derive.md R26's error-to-status mapping. A dial/TLS failure (any non-timeout error) is 502; a
// timeout — whether reported through net.Error, or through one of the two sentinel values RoundTrip can
// return for a context/deadline expiry — is 504. This is the only place the distinction lives, so a
// regression here changes what the agent sees without changing anything visible elsewhere.
func TestStatusForMapsUpstreamErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"a plain dial failure is bad gateway", errors.New("dial tcp: connection refused"), http.StatusBadGateway},
		{"a net.Error that is not a timeout is bad gateway", timeoutError{timeout: false}, http.StatusBadGateway},
		{"a net.Error timeout is gateway timeout", timeoutError{timeout: true}, http.StatusGatewayTimeout},
		{"context.DeadlineExceeded is gateway timeout", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"os.ErrDeadlineExceeded is gateway timeout", os.ErrDeadlineExceeded, http.StatusGatewayTimeout},
		{"a wrapped timeout is still gateway timeout", errWrap{context.DeadlineExceeded}, http.StatusGatewayTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusFor(tc.err); got != tc.want {
				t.Errorf("statusFor(%v) = %d, want %d (R26)", tc.err, got, tc.want)
			}
		})
	}
}

// errWrap wraps an error with %w semantics without pulling in fmt.Errorf's formatting, so the wrapped
// case above tests unwrapping alone.
type errWrap struct{ err error }

func (e errWrap) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

// erroringBody is a request body that fails mid-read, the way a client that resets the connection while
// still sending would look from the server's side.
type erroringBody struct{}

func (erroringBody) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

// R26's third bucket — a request rejected before the Transport is ever reached is a
// 400, never forwarded, and (like every mapped error, R26's last sentence) always an event, not only a
// status code. Two distinct triggers reach this bucket by different paths through ServeHTTP/forward, so
// each gets its own subtest rather than one assertion standing in for both.
func TestRequestsRejectedBeforeTransport(t *testing.T) {
	cases := []struct {
		name string
		req  func() *http.Request
	}{
		{
			name: "a body that fails mid-read never reaches outbound (readRequest, R26)",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/v1/messages", erroringBody{})
			},
		},
		{
			name: "CONNECT has no upstream mapping and is refused, not tunneled (R26, ServeHTTP)",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodConnect, "/", nil)
				r.Method = http.MethodConnect
				r.Host = "api.anthropic.com:443"
				return r
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := newHarness(t, func(http.ResponseWriter, *http.Request) { reached = true }, Options{})
			rec := httptest.NewRecorder()
			serveDirect(h.listener, rec, tc.req())
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if reached {
				t.Error("the request reached the upstream despite being rejected before the Transport")
			}
			gaps := h.sink.of(record.KindGap)
			if len(gaps) != 1 {
				t.Fatalf("%d gap events, want exactly one — a mapped error is always an event too (R26)", len(gaps))
			}
			if g := payloadOf[record.GapPayload](t, gaps[0]); g.Why != GapMalformed {
				t.Errorf("gap = %+v, want why=malformed", g)
			}
			if len(h.sink.of(record.KindSSLRequest)) != 0 {
				t.Error("a request rejected before the Transport was still recorded as one sent")
			}
		})
	}
}

// Capture-derive.md E34 — a retry-cache entry is not invalidated by the gap of the request it names.
// Close() races the response (#28) and gaps the in-flight original, but R24's cache is a separate,
// TTL-scoped structure; a same-key request arriving inside the TTL must still find it and extend the
// original, exactly as it would have had the response arrived normally. If Close ever started clearing
// the cache to "clean up" a gapped exchange, a legitimate retry of that exchange would silently stop
// being recognised as one and open a fresh step instead (R23).
func TestRetryCacheOutlivesTheOriginalsGap(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}, Options{})
	// Registered after the harness so it runs first: a Fatal before the release below would otherwise
	// leave the upstream handler blocked, and httptest.Server.Close waits for it forever.
	var clients sync.WaitGroup
	unblock := releaseOnCleanup(t, release, &clients)
	body := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`)

	clients.Add(1)
	go func() {
		defer clients.Done()
		req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			return
		}
		resp, err := h.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	if err := h.listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	unblock()

	h.sink.waitFor(t, record.KindGap, 1)
	reqs := h.sink.of(record.KindSSLRequest)
	if len(reqs) != 1 {
		t.Fatalf("%d ssl_request events, want 1", len(reqs))
	}
	original := payloadOf[record.SSLRequestPayload](t, reqs[0])

	key := ComputeRetryKey(http.MethodPost, "/v1/messages", body, credential(http.Header{}))
	id, ok := h.listener.retries.lookup(reqs[0].PID, key, h.listener.opts.Clock.Mono())
	if !ok {
		t.Fatal("the retry-cache entry for the gapped original is gone; #34 requires the gap not to purge it")
	}
	if id != original.RequestID {
		t.Errorf("cached retry target = %q, want the gapped original's id %q", id, original.RequestID)
	}
}

// RFC 9110 §7.2's Host rule (R20) — the TLS default port is omitted, any other port is kept,
// because a virtual-hosted upstream routes on the literal header value. T-fwd-1 exercises this code path
// only by comparing its output against itself re-invoked, which cannot catch a change to the rule itself;
// this pins the two branches against literal expected strings instead.
func TestHostHeaderOmitsTheDefaultPortOnly(t *testing.T) {
	cases := []struct {
		name string
		port int
		want string
	}{
		{"an unset port is treated as the TLS default and omitted", 0, "api.anthropic.com"},
		{"the explicit TLS default port is omitted", 443, "api.anthropic.com"},
		{"a non-default port is kept", 8443, "api.anthropic.com:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Listener{model: agent.ModelEndpoint{Host: "api.anthropic.com", Port: tc.port}}
			if got := l.hostHeader(); got != tc.want {
				t.Errorf("hostHeader() = %q, want %q (R20, RFC 9110 §7.2)", got, tc.want)
			}
		})
	}
}
