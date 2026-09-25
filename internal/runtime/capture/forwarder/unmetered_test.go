// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type r2clock struct{ mono uint64 }

func (c *r2clock) Now() time.Time { return time.Now() }
func (c *r2clock) MonoNS() uint64 { return c.mono }

type r2sink struct{ evs []*record.Event }

func (s *r2sink) Emit(ev *record.Event) { s.evs = append(s.evs, ev) }

// feedWatcher runs every captured event through a watcher with a 1000-token budget and reports the breach.
func feedWatcher(t *testing.T, evs []*record.Event) (limits.State, bool) {
	t.Helper()
	lim := agent.ResolvedLimits{Tokens: 1000, Set: agent.BudgetTokens}
	w := limits.NewWatcher(lim, nil, nil, cgroup.Cgroup{}, &r2clock{mono: 1}, &r2sink{})
	for _, ev := range evs {
		w.Observe(ev)
	}
	_, tripped := w.Tripped()
	return w.Snapshot(), tripped
}

// Anthropic's OpenAI-compatible endpoint on the declared host spends tokens that no line counts.
func TestChatCompletionsOnDeclaredHostIsUnbudgeted(t *testing.T) {
	const body = `{"id":"chatcmpl-1","object":"chat.completion","model":"claude-opus-5",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":150000,"completion_tokens":5000,"total_tokens":155000}}`
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	for _, p := range []string{"/v1/chat/completions", "/v1/messages/batches"} {
		resp := h.post(p, []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"x"}]}`), nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	h.sink.waitFor(t, record.KindSSLResponse, 2)
	time.Sleep(50 * time.Millisecond)
	evs := h.sink.all()
	var kinds []string
	for _, ev := range evs {
		kinds = append(kinds, string(ev.Kind))
	}
	st, tripped := feedWatcher(t, evs)
	t.Logf("events: %v; watcher tokens=%d responses=%d tripped=%v", kinds, st.Tokens(), st.Responses, tripped)
	if !tripped {
		t.Errorf("155000 tokens spent twice under a 1000-token budget, and the watcher counted %d: no usage, "+
			"no unparsed decision, no gap", st.Tokens())
	}
}

// An agent that opens a few uploads it never finishes holds the whole capture budget, and every later
// model call's usage is lost; the run is not ended the way a capture-lane drop ends it.
func TestStalledUploadsBlindTheTokenBudget(t *testing.T) {
	const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":150000,\"output_tokens\":1}}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":900}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})

	// Eight uploads that declare MaxBody and never send it: each reserves 8 MiB of the 64 MiB budget.
	addr := strings.TrimPrefix(h.listener.BaseURL(), "http://")
	var stalls []net.Conn
	for i := 0; i < 8; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		stalls = append(stalls, c)
		fmt.Fprintf(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n{", DefaultMaxBody)
	}
	defer func() {
		for _, c := range stalls {
			c.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	used := h.listener.budget.used.Load()
	t.Logf("budget used %d of %d", used, h.listener.budget.limit)
	// A body's array is reserved as its bytes arrive, so a stalled upload holds what it sent.
	if used > 8*requestChunk {
		t.Errorf("8 uploads that sent one byte each hold %d bytes of the capture budget", used)
	}

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","stream":true,"messages":[]}`),
		http.Header{"Content-Type": {"application/json"}})
	got, _ := io.ReadAll(bufio.NewReader(resp.Body))
	resp.Body.Close()
	if !strings.Contains(string(got), "message_stop") {
		t.Fatalf("agent did not get its answer: %q", got)
	}
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	time.Sleep(50 * time.Millisecond)
	evs := h.sink.all()
	for _, ev := range evs {
		t.Logf("%s %s", ev.Kind, ev.Payload)
	}
	st, tripped := feedWatcher(t, evs)
	if !tripped {
		t.Errorf("a 150900-token call under a 1000-token budget counted %d tokens once 8 stalled uploads held "+
			"the capture budget", st.Tokens())
	}
}

// meteredSink is a fakeSink that also collects what the listener reports unmetered (source.MeteredSink).
type meteredSink struct {
	*fakeSink
	mu   sync.Mutex
	whys []string
}

func (s *meteredSink) Unmetered(_ int64, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.whys = append(s.whys, why)
}

func (s *meteredSink) reported() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.whys...)
}

// meter rebinds a harness's listener to a metered sink over its own.
func meter(h *harness) *meteredSink {
	m := &meteredSink{fakeSink: h.sink}
	h.listener.Bind(h.listener.runRef(), m)
	return m
}

// TestBatchCreationIsReportedUnmetered: a message batch spends later, where no exchange shows it, so its
// creation is reported to the run, which ends a budgeted one.
func TestBatchCreationIsReportedUnmetered(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msgbatch_1","type":"message_batch","processing_status":"in_progress"}`))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages/batches?beta=true", []byte(`{"requests":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	deadline := time.Now().Add(2 * time.Second)
	for len(m.reported()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := m.reported()
	if len(got) != 1 || !strings.Contains(got[0], "POST /v1/messages/batches") || strings.Contains(got[0], "beta") {
		t.Fatalf("reported %q, want one report naming the route without its query", got)
	}
}

// TestUsageIsReadPastTheCaptureCap: the usage of a stream is read off every byte relayed, so a body the
// capture cap cut before its message_delta still counts its whole spend, and nothing is reported unmetered.
func TestUsageIsReadPastTheCaptureCap(t *testing.T) {
	pad := strings.Repeat("x", 4096)
	var sse strings.Builder
	sse.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":150000,\"output_tokens\":1}}}\n\n")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&sse, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"%s\"}}\n\n", pad)
	}
	sse.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":900}}\n\n")
	sse.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse.String()))
	}, Options{MaxBody: 16 << 10, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","stream":true,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	evs := h.sink.waitFor(t, record.KindSSLResponse, 1)
	p := payloadOf[record.SSLResponsePayload](t, evs[0])
	if p.Usage == nil || p.Usage.Input != 150000 || p.Usage.Output != 900 {
		t.Fatalf("usage = %+v, want the stream's whole report though capture kept 16 KiB of it", p.Usage)
	}
	if got := m.reported(); len(got) != 0 {
		t.Errorf("a stream whose usage was read was reported unmetered: %q", got)
	}
}

// TestCutJSONResponseIsReportedUnmetered: a successful answer whose body capture cut before its usage, and
// which no stream reported, is spend nothing read: it is reported, and a budgeted run ends.
func TestCutJSONResponseIsReportedUnmetered(t *testing.T) {
	body := `{"id":"msg_1","type":"message","model":"claude-opus-5","content":[{"type":"text","text":"` +
		strings.Repeat("y", 64<<10) + `"}],"usage":{"input_tokens":150000,"output_tokens":900}}`
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}, Options{MaxBody: 16 << 10, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	deadline := time.Now().Add(2 * time.Second)
	for len(m.reported()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.reported(); len(got) != 1 {
		t.Fatalf("reported %q, want the cut response once", got)
	}
}

// TestStalledBodyTimesOut: a request body that stops arriving is abandoned after BodyIdleTimeout, and what it
// held of the capture budget goes back.
func TestStalledBodyTimesOut(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}, Options{BodyIdleTimeout: 100 * time.Millisecond})
	c, err := net.Dial("tcp", strings.TrimPrefix(h.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n{", 1<<20)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	deadline := time.Now().Add(time.Second)
	for h.listener.budget.used.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if used := h.listener.budget.used.Load(); used != 0 {
		t.Errorf("the abandoned upload still holds %d bytes", used)
	}
}

// A small upload that stops arriving is answered too: net/http drains an unread body under 256 KiB before it
// writes the reply, with no deadline of its own, so the refusal has to close the connection instead (R27a).
func TestStalledSmallBodyIsAnswered(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}, Options{BodyIdleTimeout: 100 * time.Millisecond})
	c, err := net.Dial("tcp", strings.TrimPrefix(h.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled small upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if !resp.Close {
		t.Error("the connection is kept after a body that never ended")
	}
}

// A health check whose body stops arriving is under the same deadlines as any other body (R27a): the drain
// ends at BodyIdleTimeout and the handler answers, rather than holding its goroutine and connection until the
// peer hangs up.
func TestStalledHelloBodyTimesOut(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{BodyIdleTimeout: 100 * time.Millisecond})
	c, err := net.Dial("tcp", strings.TrimPrefix(h.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "HEAD %s HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{", HelloPath)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodHead})
	if err != nil {
		t.Fatalf("no answer to a health check whose body stalled: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200: the answer depends on the method and the path alone (#30)", resp.StatusCode)
	}
}
