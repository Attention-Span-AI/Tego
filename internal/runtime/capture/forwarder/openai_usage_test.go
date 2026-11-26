// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/derive/openai"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// OpenAI-style usage through the forwarder (public issue 99, ADR 0037, amended 2026-11-26): a models[] entry that declares provider openai
// has its chat completions and responses counted from the usage each answer states, and Tego sends the request on
// exactly as the agent wrote it.

const oaiChatRequest = `{"model":"gpt-x","messages":[{"role":"user","content":"Say ok."}]}`

// oaiChatAnswer is a chat completion that spent 120 prompt tokens (20 of them cached) and 30 completion tokens.
const oaiChatAnswer = `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-x-2026","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],` +
	`"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150,"prompt_tokens_details":{"cached_tokens":20}}}`

func oaiDeriver() *derive.Dispatcher {
	return derive.NewDispatcher([]derive.Parser{anthropic.New(), openai.New()})
}

func jsonHandler(body string, seen *[][]byte, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if seen != nil {
			mu.Lock()
			*seen = append(*seen, got)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// The budget stops the run at the limit it crosses with OpenAI-style answers counted: each answer is 130 tokens (100
// input plus 30 output; the 20 cached tokens are excluded from the budget, as its definition says), so a 300-token
// budget is crossed by the third. The request reaches the upstream untouched.
func TestOpenAIChatAnswersAreCountedAndTheBudgetTrips(t *testing.T) {
	var seen [][]byte
	var mu sync.Mutex
	h := newProviderHarness(t, "openai", jsonHandler(oaiChatAnswer, &seen, &mu), Options{Deriver: oaiDeriver()})
	m := meter(h)
	for i := 0; i < 3; i++ {
		drain(h.post("/v1/chat/completions", []byte(oaiChatRequest), http.Header{"Content-Type": {"application/json"}}))
	}
	evs := h.sink.waitFor(t, record.KindSSLResponse, 3)
	p := payloadOf[record.SSLResponsePayload](t, evs[0])
	if p.Usage == nil || p.Usage.Input != 100 || p.Usage.Output != 30 || p.Usage.CacheRead != 20 || p.Model != "gpt-x-2026" ||
		p.ResponseID != "chatcmpl-1" || p.ParserVersion != openai.ParserVersion {
		t.Fatalf("ssl_response = %+v usage %+v", p, p.Usage)
	}
	if got := m.reported(); len(got) != 0 {
		t.Fatalf("an answer that stated its usage was reported unmetered: %q", got)
	}
	// The request was never changed.
	mu.Lock()
	defer mu.Unlock()
	for _, b := range seen {
		if !bytes.Equal(b, []byte(oaiChatRequest)) {
			t.Fatalf("the upstream got %q, want the agent's request byte for byte", b)
		}
	}
	w := limits.NewWatcher(agent.ResolvedLimits{Tokens: 300, Set: agent.BudgetTokens}, nil, nil, cgroup.Cgroup{}, &r2clock{mono: 1}, &r2sink{})
	for _, ev := range h.sink.all() {
		w.Observe(ev)
	}
	st := w.Snapshot()
	if _, ok := w.Tripped(); !ok || st.Tokens() != 390 {
		t.Fatalf("watcher: tripped=%v tokens=%d, want tripped at 390 (3 x (100 input + 30 output), cache excluded)", ok, st.Tokens())
	}
}

// A streamed answer that states usage (the client asked for it) is counted; one that does not is reported unmetered
// with the note a person is told, and the request is still not changed.
func TestOpenAIStreamedChatAnswers(t *testing.T) {
	const chunk = `data: {"id":"c","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{"content":"ok"}}],"usage":null}` + "\n\n"
	withUsage := chunk + `data: {"id":"c","object":"chat.completion.chunk","model":"gpt-x","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":7,"total_tokens":19}}` + "\n\ndata: [DONE]\n\n"
	without := chunk + "data: [DONE]\n\n"
	const asked = `{"model":"gpt-x","stream":true,"stream_options":{"include_usage":true},"messages":[]}`
	const notAsked = `{"model":"gpt-x","stream":true,"messages":[]}`

	h := newProviderHarness(t, "openai", sseHandler(withUsage), Options{Deriver: oaiDeriver()})
	m := meter(h)
	drain(h.post("/v1/chat/completions", []byte(asked), nil))
	p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if p.Usage == nil || p.Usage.Input != 12 || p.Usage.Output != 7 {
		t.Fatalf("a stream with usage: %+v", p.Usage)
	}
	if got := m.reported(); len(got) != 0 {
		t.Fatalf("a stream with usage reported unmetered: %q", got)
	}

	h = newProviderHarness(t, "openai", sseHandler(without), Options{Deriver: oaiDeriver()})
	m = meter(h)
	drain(h.post("/v1/chat/completions", []byte(notAsked), nil))
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	got := waitReported(m, 1)
	if len(got) != 1 || got[0] != "POST /v1/chat/completions: usage unreadable (stream without usage)" {
		t.Fatalf("reported %q, want the stream-without-usage account", got)
	}
}

// The Responses API: a whole answer's usage object and a stream's response.completed event are counted.
func TestOpenAIResponsesAnswers(t *testing.T) {
	const whole = `{"id":"resp_1","object":"response","status":"completed","model":"gpt-x","output":[],` +
		`"usage":{"input_tokens":50,"input_tokens_details":{"cached_tokens":20},"output_tokens":9,"output_tokens_details":{"reasoning_tokens":4},"total_tokens":59}}`
	stream := "event: response.created\ndata: " + `{"type":"response.created","response":{"id":"resp_1","status":"in_progress","usage":null}}` + "\n\n" +
		"event: response.completed\ndata: " + `{"type":"response.completed","response":` + whole + `}` + "\n\n"
	for name, h := range map[string]*harness{
		"whole":  newProviderHarness(t, "openai", jsonHandler(whole, nil, nil), Options{Deriver: oaiDeriver()}),
		"stream": newProviderHarness(t, "openai", sseHandler(stream), Options{Deriver: oaiDeriver()}),
	} {
		m := meter(h)
		drain(h.post("/v1/responses", []byte(`{"model":"gpt-x","input":"hi"}`), nil))
		p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
		if p.Usage == nil || p.Usage.Input != 30 || p.Usage.Output != 9 || p.Usage.CacheRead != 20 {
			t.Errorf("%s: usage %+v", name, p.Usage)
		}
		if got := m.reported(); len(got) != 0 {
			t.Errorf("%s: reported unmetered %q", name, got)
		}
	}
}

// What stays unreadable stays fail closed: an OpenAI-style answer on an entry that does not declare provider openai
// (a contract's word is what Tego goes by, never the bytes), a path the parser does not read, and an answer a capture
// cap cut short.
func TestOpenAIStyleAnswersTheContractDidNotDeclareStayUnreadable(t *testing.T) {
	// Another declared provider: no parser, today's rule.
	h := newProviderHarness(t, "acme-llm", jsonHandler(oaiChatAnswer, nil, nil), Options{Deriver: oaiDeriver()})
	m := meter(h)
	drain(h.post("/v1/chat/completions", []byte(oaiChatRequest), nil))
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if got := waitReported(m, 1); len(got) != 1 || got[0] != "POST /v1/chat/completions: usage unreadable" {
		t.Errorf("an undeclared provider: reported %q", got)
	}
	// A declared openai entry, a path that is not read (embeddings).
	h = newProviderHarness(t, "openai", jsonHandler(`{"object":"list","data":[],"usage":{"prompt_tokens":5,"total_tokens":5}}`, nil, nil), Options{Deriver: oaiDeriver()})
	m = meter(h)
	drain(h.post("/v1/embeddings", []byte(`{"model":"e","input":"x"}`), nil))
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if got := waitReported(m, 1); len(got) != 1 || got[0] != "POST /v1/embeddings: usage unreadable" {
		t.Errorf("embeddings: reported %q", got)
	}
	// A streamed answer the capture budget cut before its usage chunk.
	big := strings.Repeat(`data: {"id":"c","model":"m","choices":[{"delta":{"content":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}],"usage":null}`+"\n\n", 2000) +
		`data: {"id":"c","model":"m","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":5}}` + "\n\ndata: [DONE]\n\n"
	h = newProviderHarness(t, "openai", sseHandler(big), Options{MaxBody: 16 << 10, Deriver: oaiDeriver()})
	m = meter(h)
	drain(h.post("/v1/chat/completions", []byte(`{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[]}`), nil))
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if got := waitReported(m, 1); len(got) != 1 || !strings.Contains(got[0], "usage unreadable") {
		t.Errorf("a cut stream: reported %q", got)
	}
}

// An Anthropic-style run is recorded exactly as it was: the same exchange through a dispatcher that links only the
// Anthropic parser and through the one that also links the OpenAI parser writes the same events, field for field
// (the time-dependent ones aside).
func TestAnAnthropicRunIsRecordedAsBefore(t *testing.T) {
	run := func(d *derive.Dispatcher) []string {
		h := newHarness(t, sseHandler(r4Stream), Options{Deriver: d})
		m := meter(h)
		drain(h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":64,"stream":true,"messages":[]}`), nil))
		h.sink.waitFor(t, record.KindSSLResponse, 1)
		if got := m.reported(); len(got) != 0 {
			t.Fatalf("reported %q", got)
		}
		var out []string
		for _, ev := range h.sink.all() {
			var raw map[string]any
			if err := json.Unmarshal(ev.Payload, &raw); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"latency_ms", "request_id", "blob", "sha256", "request_seq", "wire_size", "headers"} {
				delete(raw, k)
			}
			b, _ := json.Marshal(raw)
			out = append(out, string(ev.Kind)+" "+string(b))
		}
		return out
	}
	before := run(derive.NewDispatcher([]derive.Parser{anthropic.New()}))
	after := run(oaiDeriver())
	if len(before) == 0 || strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("the record changed:\nbefore:\n%s\nafter:\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// A cost budget prices OpenAI-style answers by the model the answer names, through the price table the machine
// installs, with the cached part at the cache-read price. A model the table does not name is the unknown-price rule of
// every other model: never $0, charged at the table's dearest rates and recorded unpriced.
func TestOpenAIAnswersArePricedByTheTable(t *testing.T) {
	h := newProviderHarness(t, "openai", jsonHandler(oaiChatAnswer, nil, nil), Options{Deriver: oaiDeriver()})
	for i := 0; i < 2; i++ {
		drain(h.post("/v1/chat/completions", []byte(oaiChatRequest), nil))
	}
	evs := h.sink.waitFor(t, record.KindSSLResponse, 2)
	table := &limits.PriceTable{Version: limits.PriceVersion, Models: map[string]limits.ModelPrice{
		// $2 in, $10 out, $0.5 cached input and $2.5 cache write per million tokens.
		"gpt-x-2026": {InputPerMTok: 2, OutputPerMTok: 10, CacheReadPerMTok: 0.5, CacheWritePerMTok: 2.5, CacheWrite1hPerMTok: new(4.0)},
	}}
	run := func(table *limits.PriceTable) limits.State {
		w := limits.NewWatcher(agent.ResolvedLimits{CostUSD: 1, Set: agent.BudgetCostUSD}, table, nil, cgroup.Cgroup{}, &r2clock{mono: 1}, &r2sink{})
		for _, ev := range evs {
			w.Observe(ev)
		}
		return w.Snapshot()
	}
	st := run(table)
	want := 2 * (100*2.0 + 30*10.0 + 20*0.5) / 1e6
	if st.Unpriced != 0 || st.CostUSD < want-1e-12 || st.CostUSD > want+1e-12 {
		t.Fatalf("priced: cost %.9f unpriced %d, want %.9f and none unpriced", st.CostUSD, st.Unpriced, want)
	}
	other := &limits.PriceTable{Version: limits.PriceVersion, Models: map[string]limits.ModelPrice{
		"another-model": {InputPerMTok: 2, OutputPerMTok: 10, CacheReadPerMTok: 0.5, CacheWritePerMTok: 2.5, CacheWrite1hPerMTok: new(4.0)},
	}}
	st = run(other)
	if st.Unpriced != 2 || st.CostUSD != 0 || st.UnpricedMaxUSD <= 0 {
		t.Fatalf("a model the table does not name: %+v, want both answers unpriced and charged at the dearest rates", st)
	}
}

// A gateway or local server that answers inference at its root: POST / with usage is not a health check. It is reported
// unmetered, so the run ends, where it counted nothing and let the run go on; a GET of the root stays silent.
func TestOpenAIPostToTheRootIsUnreadableAndGetIsSilent(t *testing.T) {
	h := newProviderHarness(t, "openai", jsonHandler(oaiChatAnswer, nil, nil), Options{Deriver: oaiDeriver()})
	m := meter(h)
	drain(h.post("/?x=1", []byte(oaiChatRequest), nil))
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if got := waitReported(m, 1); len(got) != 1 || got[0] != "POST /: usage unreadable" {
		t.Fatalf("POST /?x=1 with usage: reported %q, want the unreadable account", got)
	}
	req, err := http.NewRequest(http.MethodGet, h.listener.BaseURL()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	drain(h.do(req))
	h.sink.waitFor(t, record.KindSSLResponse, 2)
	if got := m.reported(); len(got) != 1 {
		t.Fatalf("GET / was reported unmetered: %q", got)
	}
}

// A client that leaves in the middle of a stream ends a budgeted run: the forwarder stops reading, derive is handed a
// prefix flagged cut short, and a prefix holding a usage chunk (a server may state usage in every chunk) is not the
// answer's usage. The exchange is reported unmetered, never counted as the prefix's tokens or as zero.
func TestAClientThatLeavesMidStreamEndsABudgetedRun(t *testing.T) {
	const pad = "data: " + `{"id":"c","object":"chat.completion.chunk","model":"gpt-x","choices":[{"index":0,"delta":{"content":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}],"usage":{"prompt_tokens":12,"completion_tokens":1}}` + "\n\n"
	const responsesPad = "event: response.output_text.delta\ndata: " + `{"type":"response.output_text.delta","delta":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}` + "\n\n"
	for _, tc := range []struct{ name, path, req, first, more string }{
		{"chat", "/v1/chat/completions", `{"model":"gpt-x","stream":true,"messages":[]}`, pad, pad},
		{"responses", "/v1/responses", `{"model":"gpt-x","stream":true,"input":"hi"}`, "event: response.created\ndata: " +
			`{"type":"response.created","response":{"id":"r","status":"in_progress","usage":null}}` + "\n\n", responsesPad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proceed := make(chan struct{})
			h := newProviderHarness(t, "openai", func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				rc := http.NewResponseController(w)
				_, _ = w.Write([]byte(tc.first))
				_ = rc.Flush()
				<-proceed
				for i := 0; i < 400; i++ {
					if _, err := w.Write([]byte(strings.Repeat(tc.more, 200))); err != nil {
						return
					}
					if rc.Flush() != nil {
						return
					}
				}
			}, Options{Deriver: oaiDeriver()})
			m := meter(h)
			ctx, cancel := context.WithCancel(context.Background())
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.listener.BaseURL()+tc.path, strings.NewReader(tc.req))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			if _, err := resp.Body.Read(buf); err != nil {
				t.Fatalf("the first chunk did not arrive: %v", err)
			}
			cancel()
			resp.Body.Close()
			close(proceed)
			p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
			if p.Usage != nil {
				t.Fatalf("a cut stream was counted: usage %+v", p.Usage)
			}
			got := waitReported(m, 1)
			if len(got) != 1 || got[0] != "POST "+tc.path+": usage unreadable (answer cut off)" {
				t.Fatalf("reported %q, want the cut stream reported unmetered once", got)
			}
		})
	}
}
