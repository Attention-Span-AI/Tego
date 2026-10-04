// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"net/http"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestForwardPreservesExplicitEmptyQuery(t *testing.T) {
	target := make(chan string, 1)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		target <- r.RequestURI
		_, _ = w.Write([]byte(`{"type":"error"}`))
	}, Options{})
	resp := h.post("/v1/messages?", []byte(`{"model":"m","messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := <-target; got != "/v1/messages?" {
		t.Fatalf("upstream request target = %q, want the client's explicit empty query", got)
	}
	reqs := h.sink.waitFor(t, record.KindSSLRequest, 1)
	if got := payloadOf[record.SSLRequestPayload](t, reqs[0]).Path; got != "/v1/messages?" {
		t.Fatalf("recorded target = %q, want the forwarded target", got)
	}
}
