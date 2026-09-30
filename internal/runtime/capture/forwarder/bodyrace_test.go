// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A body larger than MaxBody is read past its captured prefix by the upstream transport's
// own goroutine. When that read fails — here the client stalls past BodyIdleTimeout after the upstream has already
// answered 401 — the failure must not touch the reply's header map, which the handler goroutine and net/http's
// finishRequest read and write concurrently. Under -race the old fail(), a header.Set from the transport's
// goroutine, is reported as a data race; in production it could be a fatal "concurrent map read and map write".
func TestRestReadFailureOffTheHandlerDoesNotTouchTheReplyHeader(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		// An upstream that answers before it has read the body, as one refusing an upload does.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error"}`))
		http.NewResponseController(w).Flush()
	}, Options{MaxBody: 1024, BodyIdleTimeout: 200 * time.Millisecond, BodyTimeout: 5 * time.Second})
	c, err := net.Dial("tcp", strings.TrimPrefix(h.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Past MaxBody, so the rest is forwarded through the transport's writeLoop, then the client stalls.
	fmt.Fprintf(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", 1<<20)
	_, _ = c.Write([]byte(strings.Repeat("x", 4096)))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want the upstream's 401", resp.StatusCode)
	}
	// Past the idle deadline, so the transport's read of the rest fails while the exchange winds down.
	time.Sleep(4 * 200 * time.Millisecond)
}
