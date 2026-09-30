// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// abortAfter is an upstream that sends the headers and part of a body, then aborts the connection.
func abortAfter(contentType string, part []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(part)
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}
}

// An upstream that fails once streaming has started closes the agent's connection. Returning normally
// from the handler made net/http write the terminating chunk, so the agent read a truncated turn as a whole one.
func TestUpstreamAbortMidStreamAbortsTheClient(t *testing.T) {
	h := newHarness(t, abortAfter("text/event-stream",
		[]byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")), Options{})
	resp := h.post("/v1/messages", []byte(`{"model":"m","stream":true}`), nil)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err == nil {
		t.Fatalf("the client read %q and a clean end of stream; want an error for the upstream's abort", body)
	}
	// The exchange is still recorded, with the malformed gap, before the connection is dropped.
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if n := gapCount(h.listener, GapMalformed); n != 1 {
		t.Errorf("malformed = %d, want 1", n)
	}
}
