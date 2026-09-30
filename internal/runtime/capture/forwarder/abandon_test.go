// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// abandonSink is a sink that listens for source.ReportAbandoned, as the run's capture lane does.
type abandonSink struct {
	*fakeSink
	mu    sync.Mutex
	pairs []uint64
}

func (s *abandonSink) Abandoned(pair uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pairs = append(s.pairs, pair)
}

// waitAbandoned is the pairs the sink was told of once there are n, or after two seconds.
func (s *abandonSink) waitAbandoned(n int) []uint64 {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := append([]uint64(nil), s.pairs...)
		s.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.pairs...)
}

// hangUp is an upstream that reads the request and drops the connection without a byte of an answer.
func hangUp(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	if c, _, err := http.NewResponseController(w).Hijack(); err == nil {
		_ = c.Close()
	}
}

// A request the forwarder gives up on, with no response to end its step, is reported abandoned under the
// pair its ssl_request carries, whatever its path, as the uprobe path reports one (unanswered). Without it the
// step tracker kept the thread in flight until its next request and unattributed other threads' actions.
func TestUnansweredRequestIsAbandoned(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		path string
	}{
		{"dropped connection", Options{}, "/v1/messages"},
		{"dropped connection, silent path", Options{}, "/v1/messages/count_tokens"},
		{"upstream leg failed", Options{Transport: failDial{}}, "/v1/messages"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.opts.Deriver = derive.NewDispatcher([]derive.Parser{anthropic.New()})
			h := newHarness(t, hangUp, c.opts)
			s := &abandonSink{fakeSink: h.sink}
			h.listener.Bind(h.listener.runRef(), s)
			resp := h.post(c.path, []byte(`{"model":"claude-opus-5","max_tokens":8,"messages":[]}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			req := h.sink.waitFor(t, record.KindSSLRequest, 1)[0]
			if got := s.waitAbandoned(1); len(got) != 1 || got[0] != req.Pair || req.Pair == 0 {
				t.Errorf("abandoned %v, want the request's pair %d once", got, req.Pair)
			}
		})
	}
}

// An answered request is not abandoned: its ssl_response ends its step.
func TestAnsweredRequestIsNotAbandoned(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) },
		Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	s := &abandonSink{fakeSink: h.sink}
	h.listener.Bind(h.listener.runRef(), s)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":8,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	time.Sleep(50 * time.Millisecond)
	if got := s.waitAbandoned(0); len(got) != 0 {
		t.Errorf("abandoned %v, want none for an answered request", got)
	}
}

// An exchange Close claims before its answer came is abandoned too.
func TestCloseClaimedRequestIsAbandoned(t *testing.T) {
	orig := closeDrain
	closeDrain = 20 * time.Millisecond
	t.Cleanup(func() { closeDrain = orig })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(entered) })
		<-release
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	t.Cleanup(func() { close(release) })
	s := &abandonSink{fakeSink: h.sink}
	h.listener.Bind(h.listener.runRef(), s)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages",
			bytes.NewReader([]byte(`{"model":"claude-opus-5","max_tokens":8,"messages":[]}`)))
		if err != nil {
			return
		}
		if resp, err := h.client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	if err := h.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.waitAbandoned(1); len(got) != 1 || got[0] == 0 {
		t.Errorf("abandoned %v, want the one exchange Close claimed", got)
	}
	var pair uint64
	for _, ev := range h.sink.of(record.KindSSLRequest) {
		pair = ev.Pair
	}
	if got := s.waitAbandoned(1); len(got) == 1 && pair != 0 && got[0] != pair {
		t.Errorf("abandoned pair %d, want the request's %d", got[0], pair)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
