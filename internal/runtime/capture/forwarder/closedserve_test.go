// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAHandlerDispatchedAfterCloseIsTurnedAway: srv.Close does not stop a connection goroutine that has
// already read a request from dispatching its handler. That handler counted itself into handlers with
// nothing ordering it before Close's Wait, then forwarded and emitted after Close's flush, a line behind
// the run's drain (R8, I4). A handler that starts once Close has begun is now served a 503 and emits
// nothing.
func TestAHandlerDispatchedAfterCloseIsTurnedAway(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, Options{})
	if err := h.listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	h.listener.peers = anyPeer
	emitted := len(h.sink.all())
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}))
	rec := httptest.NewRecorder()
	h.listener.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d for a request dispatched after Close, want 503", rec.Code)
	}
	if n := len(h.sink.all()); n != emitted {
		t.Errorf("%d events reached the sink after Close returned", n-emitted)
	}
}
