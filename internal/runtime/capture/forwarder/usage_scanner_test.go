// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const r4Stream = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5","usage":{"input_tokens":1200,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}` + "\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// waitReported polls a metered sink until it has n reports or a second has passed.
func waitReported(m *meteredSink, n int) []string {
	deadline := time.Now().Add(2 * time.Second)
	for len(m.reported()) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return m.reported()
}

// Finding 3 (ADR 0037): a request the upstream read and then dropped without a byte of an answer may have been
// spent; the uprobe path reports it unmetered (closePending), and the forwarder recorded a gap only.
func TestUnansweredRequestIsReportedUnmetered(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		c, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = c.Close()
		}
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindGap, 1)
	if got := waitReported(m, 1); len(got) != 1 || !strings.Contains(got[0], "no response") {
		t.Errorf("reported %q; want the unanswered model request reported unmetered once, as uprobe does", got)
	}
}

// failDial is an upstream leg whose dial fails: no byte of the request leaves.
type failDial struct{}

func (failDial) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
}

// Finding 3's one exemption: a leg that never connected sent nothing the upstream could spend on.
func TestDialFailureIsNotReported(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {},
		Options{Transport: failDial{}, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":8,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindGap, 1)
	time.Sleep(50 * time.Millisecond)
	if got := m.reported(); len(got) != 0 {
		t.Errorf("a request that never left was reported unmetered: %q", got)
	}
}

// sseHandler answers every request with body as an event stream, after reading the request whole.
func sseHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body))
	}
}

// Finding 2: derive stops reading a stream at its first line it cannot parse, so a whole, untruncated copy can
// leave it short of the message_delta the scanner read on the wire. That count replaces derive's bound.
func TestScannedDeltaReplacesTheBoundOnAWholeCopy(t *testing.T) {
	stream := strings.Replace(r4Stream, `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`,
		`data: {"type":"content_block_delta",`, 1)
	h := newHarness(t, sseHandler(stream), Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if p.Usage == nil || p.Usage.Output != 7 || p.Usage.OutputBound {
		t.Fatalf("usage = %+v, want the wire's output count 7, not the 4096 bound", p.Usage)
	}
	if got := m.reported(); len(got) != 0 {
		t.Errorf("reported %q", got)
	}
}

// largeRequest is a streamed Messages request of about n bytes whose max_tokens comes after its messages.
func largeRequest(n, maxTokens int) []byte {
	return []byte(`{"model":"claude-opus-5","stream":true,"messages":[{"role":"user","content":"` +
		strings.Repeat("x", n) + `"}],"max_tokens":` + strconv.Itoa(maxTokens) + `}`)
}

// Finding 4: a request body larger than capture keeps does not parse, so derive had no max_tokens to bound a
// cut stream by and reported every interrupted large-context stream unmetered. The bound is read off every
// byte relayed.
func TestLargeRequestCutStreamIsBounded(t *testing.T) {
	cut := r4Stream[:strings.Index(r4Stream, "event: message_delta")]
	h := newHarness(t, sseHandler(cut), Options{MaxBody: 16 << 10,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", largeRequest(64<<10, 2048), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if p.Usage == nil || p.Usage.Output != 2048 || !p.Usage.OutputBound {
		t.Fatalf("usage = %+v, want output 2048 marked a bound", p.Usage)
	}
	if got := m.reported(); len(got) != 0 {
		t.Errorf("a cut stream with a max_tokens on the wire was reported unmetered: %q", got)
	}
}

// Finding 4's rules: a max_tokens that is only a case variant of the key gives no bound, so the cut stream is
// still unmetered.
func TestLargeRequestCaseVariantGivesNoBound(t *testing.T) {
	cut := r4Stream[:strings.Index(r4Stream, "event: message_delta")]
	h := newHarness(t, sseHandler(cut), Options{MaxBody: 16 << 10,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	body := largeRequest(64<<10, 2048)
	body = []byte(strings.Replace(string(body), `"max_tokens":2048}`, `"max_tokens":2048,"MAX_TOKENS":9}`, 1))
	resp := h.post("/v1/messages", body, nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if got := waitReported(m, 1); len(got) != 1 {
		t.Errorf("reported %q, want the unbounded cut stream reported unmetered once", got)
	}
}

// The forwarder's wire usage scanner decoded with encoding/json v1, which folds key case and lets
// the last match win, while derive reads usage keys exactly as written (capture-derive.md R29). The scanner's
// reading is merged as the larger of the two, so a case variant of a usage key was charged on the forwarder path
// only. It is now derive's own scanner: a case variant is ignored here as on the uprobe path, whose stream derive
// reads.
func TestCaseVariantUsageKeyIsNotCharged(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5",` +
		`"usage":{"input_tokens":1200,"INPUT_TOKENS":999999,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` +
		strings.Repeat("x", 32<<10) + `"}}` + "\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},` +
		`"usage":{"output_tokens":7,"Output_Tokens":888888}}` + "\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	// The uprobe path's reading: derive over the whole stream.
	resp, _, err := anthropic.ParseStream([]byte(stream))
	if err != nil || resp.Usage.InputTokens != 1200 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("derive read %+v, %v; want input 1200, output 7", resp, err)
	}

	// The forwarder's: a record copy MaxBody cut, so the usage comes from the wire scanner.
	h := newHarness(t, sseHandler(stream), Options{MaxBody: 16 << 10,
		Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	r := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, r.Body)
	r.Body.Close()
	p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if p.Usage == nil || p.Usage.Input != 1200 || p.Usage.Output != 7 || p.Usage.OutputBound {
		t.Fatalf("usage = %+v; want input 1200 and output 7, the keys spelled as the API spells them", p.Usage)
	}
}

// A proxy may add extension fields or use any SSE line ending. The relayed response and recorded final
// usage must agree, including when capture retains only a prefix and the wire scanner supplies the total.
func TestSSELineEndingsAndExtensionsKeepFinalUsage(t *testing.T) {
	base := "\xef\xbb\xbfevent: unused\n\nx-proxy: trace\n" + r4Stream
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		for _, cap := range []int{256, 8192} {
			t.Run(strconv.Quote(ending)+"/"+strconv.Itoa(cap), func(t *testing.T) {
				stream := strings.ReplaceAll(base, "\n", ending)
				h := newHarness(t, sseHandler(stream), Options{MaxBody: cap,
					Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
				m := meter(h)
				resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != stream {
					t.Fatalf("relayed body differs: %v", err)
				}
				p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
				if p.Usage == nil || p.Usage.Input != 1200 || p.Usage.Output != 7 || p.Usage.OutputBound {
					t.Fatalf("usage %+v; want input 1200, final output 7", p.Usage)
				}
				if got := m.reported(); len(got) != 0 {
					t.Errorf("valid stream reported unmetered: %v", got)
				}
			})
		}
	}
}

// The wire usage scanner reads Anthropic's stream framing, so its incomplete verdict belongs to an exchange
// the Anthropic parser reads. An OpenAI Responses stream whose response.completed frame echoes more than the
// scanner's 64 KiB line bound (instructions, tools) was marked incomplete and counted a malformed capture gap
// on every such turn, although the exchange was captured whole. The same frame on an Anthropic listener keeps
// the verdict: an oversized frame of a type it cannot vouch for is missing accounting there.
func TestWireUsageVerdictIsTheAnthropicParsersOnly(t *testing.T) {
	frame := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"instructions":"` + strings.Repeat("x", 70<<10) +
		`","usage":{"input_tokens":5,"output_tokens":2}}}` + "\n\n"
	for _, tc := range []struct {
		provider string
		gaps     int64
	}{{"openai", 0}, {"anthropic", 1}} {
		t.Run(tc.provider, func(t *testing.T) {
			h := newProviderHarness(t, tc.provider, sseHandler(frame),
				Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			resp := h.post("/v1/responses", []byte(`{"model":"gpt-5","stream":true}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			h.sink.waitFor(t, record.KindSSLResponse, 1)
			var got int64
			for _, g := range h.listener.Gaps() {
				if g.Why == GapMalformed {
					got += g.Count
				}
			}
			if got != tc.gaps {
				t.Fatalf("malformed gaps %d, want %d (%v)", got, tc.gaps, h.listener.Gaps())
			}
		})
	}
}
