// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/http"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime"
)

// The runtime finds the held-request hook by this interface; a renamed method would wire nothing silently.
var _ runtime.RequestHolder = (*Manager)(nil)

// slowStart is an upstream leg whose connection is slow to come up for a reason of Tego's own (loading its trust roots
// from a busy disk, a stalled resolver): the request waits inside RoundTrip until the test lets the connection go, then
// the real transport connects and sends it.
type slowStart struct {
	next    http.RoundTripper
	entered chan struct{}
	release chan struct{}
}

func (s *slowStart) RoundTrip(r *http.Request) (*http.Response, error) {
	close(s.entered)
	<-s.release
	return s.next.RoundTrip(r)
}

// TestARequestTegoHoldsIsHeldUntilItsConnectionIsReady is the forwarder's half of the stall clock's rule that Tego's own
// latency is not the agent's silence: from Tego's receipt of a request until its upstream connection is ready the
// listener reports a held request (Manager.HoldingRequest, which the runtime hands the budget watcher as its held
// hook), and from the moment the request is sent it does not, so a model that then goes silent still stalls the run
// (TestASilentUpstreamIsNoActivity and the integration test of a silent model).
func TestARequestTegoHoldsIsHeldUntilItsConnectionIsReady(t *testing.T) {
	answered := make(chan struct{})
	finish := make(chan struct{})
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(answered)
		<-finish // a silent model: headers, then nothing
	}, Options{Transport: nil})
	t.Cleanup(func() { close(finish) })
	slow := &slowStart{next: h.upstream.Client().Transport, entered: make(chan struct{}), release: make(chan struct{})}
	h.listener.transport = slow

	m := &Manager{listeners: []*Listener{h.listener}}
	if m.HoldingRequest() {
		t.Fatal("a listener with no request reports one held")
	}
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", nil)
		if err != nil {
			done <- result{err: err}
			return
		}
		resp, err := h.client.Do(req)
		done <- result{resp, err}
	}()
	select {
	case <-slow.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the request never reached the upstream leg")
	}
	if !m.HoldingRequest() {
		t.Fatal("a request waiting for its upstream connection is not reported held: the stall clock would count Tego's own wait as the agent's silence")
	}
	close(slow.release)
	select {
	case <-answered:
	case <-time.After(30 * time.Second):
		t.Fatal("the upstream never answered")
	}
	// The upstream has answered its headers and is silent: nothing of Tego's is in the way any more.
	deadline := time.Now().Add(30 * time.Second)
	for m.HoldingRequest() {
		if time.Now().After(deadline) {
			t.Fatal("a request already sent on is still reported held: a silent model would never stall")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	_ = r.resp.Body.Close()
}

// TestAHeldRequestEndsWithItsExchange: a request that fails before its connection is ready, here one the upstream leg
// refuses, is not held forever.
func TestAHeldRequestEndsWithItsExchange(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {}, Options{})
	h.listener.transport = failingLeg{}
	m := &Manager{listeners: []*Listener{h.listener}}
	resp := h.post("/v1/messages", []byte(`{"model":"claude-test-1"}`), nil)
	_ = resp.Body.Close()
	deadline := time.Now().Add(30 * time.Second)
	for m.HoldingRequest() {
		if time.Now().After(deadline) {
			t.Fatal("a request whose upstream leg failed is still reported held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type failingLeg struct{}

func (failingLeg) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrHandlerTimeout
}
