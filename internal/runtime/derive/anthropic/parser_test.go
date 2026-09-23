// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// readFile loads one testdata body.
func readFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", name))
}

// read loads one testdata body or fails the test.
func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := readFile(name)
	if err != nil {
		t.Fatalf("testdata %s: %v", name, err)
	}
	return b
}

// request is a /v1/messages request message carrying body.
func request(body []byte) *derive.Message {
	return &derive.Message{
		Method: http.MethodPost,
		Path:   MessagesPath,
		Proto:  "HTTP/1.1",
		Header: http.Header{"Content-Type": {"application/json"}},
		Body:   body,
	}
}

// response is a 200 response message carrying body with the given content type.
func response(body []byte, contentType string) *derive.Message {
	return &derive.Message{
		Status: http.StatusOK,
		Header: http.Header{"Content-Type": {contentType}},
		Body:   body,
	}
}

// A non-streaming response yields model, id, stop reason, usage and one decision per
// tool_use block, in wire order, with no decision for the text block (capture-derive.md R28, R30).
func TestParseNonStreaming(t *testing.T) {
	p := New()
	facts, err := p.Parse(request(read(t, "messages-request.json")), response(read(t, "messages-response.json"), "application/json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if facts.ParserVersion != ParserVersion {
		t.Errorf("parser_version = %q, want %q", facts.ParserVersion, ParserVersion)
	}
	if facts.Model != "claude-opus-5" || facts.ResponseID != "msg_01Xq0001Z" || facts.StopReason != "tool_use" {
		t.Errorf("facts = %+v", facts)
	}
	if facts.Stream {
		t.Error("stream = true on a JSON body")
	}
	if facts.Usage == nil || facts.Usage.Input != 1000 || facts.Usage.Output != 102 ||
		facts.Usage.CacheRead != 0 || facts.Usage.CacheWrite != 512 {
		t.Errorf("usage = %+v", facts.Usage)
	}
	if len(facts.Decisions) != 2 {
		t.Fatalf("%d decisions, want 2 (one per tool_use, none for text)", len(facts.Decisions))
	}
	if got := facts.Decisions[0]; got.Tool != "bash" || got.ToolUseID != "toolu_010001A" || got.Text || got.Unparsed {
		t.Errorf("decision 0 = %+v", got)
	}
	if got := facts.Decisions[1]; got.Tool != "read_file" || got.ToolUseID != "toolu_010001B" {
		t.Errorf("decision 1 = %+v", got)
	}
	// The hash is over the exact wire bytes of the input object.
	want := sha256.Sum256([]byte(`{"command":"rg -n TODO"}`))
	if facts.Decisions[0].InputHash != hex.EncodeToString(want[:]) {
		t.Errorf("input_hash = %s, want sha256 of the wire bytes", facts.Decisions[0].InputHash)
	}
}

// The event sequence assembles to the same shape, with the tool input rebuilt from its
// input_json_delta fragments and usage folded without double-counting (R29).
func TestParseStreaming(t *testing.T) {
	p := New()
	resp := response(read(t, "messages-stream.sse"), "text/event-stream")
	resp.SSE = true
	facts, err := p.Parse(request(read(t, "messages-request.json")), resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !facts.Stream {
		t.Error("stream = false on an event stream")
	}
	if facts.Model != "claude-opus-5" || facts.ResponseID != "msg_01Xq0002Z" || facts.StopReason != "tool_use" {
		t.Errorf("facts = %+v", facts)
	}
	// message_start seeds input and cache, message_delta reports the message's totals: output is 104,
	// never 1+104, and cache_read stays 512 rather than doubling.
	if facts.Usage == nil || facts.Usage.Input != 1200 || facts.Usage.Output != 104 ||
		facts.Usage.CacheRead != 512 || facts.Usage.CacheWrite != 0 {
		t.Errorf("usage = %+v", facts.Usage)
	}
	if len(facts.Decisions) != 1 {
		t.Fatalf("%d decisions, want 1", len(facts.Decisions))
	}
	d := facts.Decisions[0]
	if d.Tool != "read_file" || d.ToolUseID != "toolu_010002A" {
		t.Errorf("decision = %+v", d)
	}
	want := sha256.Sum256([]byte(`{"path":"README.md"}`))
	if d.InputHash != hex.EncodeToString(want[:]) {
		t.Errorf("input_hash = %s, want the sha256 of the joined fragments", d.InputHash)
	}
}

// Every shape that is not a model turn, and every response body that should have been one
// and was not, maps onto exactly one sentinel — and never onto a panic (R29). Failures of the request
// half are T-anthropic-9's subject: they no longer void the pair.
func TestParseTable(t *testing.T) {
	req := read(t, "messages-request.json")
	stream := read(t, "messages-stream.sse")
	cases := []struct {
		name     string
		req      *derive.Message
		resp     *derive.Message
		wantErr  error
		wantNone bool // parsed, but nothing to derive
		// wantPartial: a stream that failed after message_start keeps what it reported (its model and
		// usage) and records the failure as an unparsed schema decision, instead of an error that dropped
		// the usage the budgets need.
		wantPartial bool
	}{
		{
			name: "a path that carries no model turn derives nothing",
			req:  &derive.Message{Method: "GET", Path: "/v1/models", Header: http.Header{}},
			resp: response([]byte(`{"data":[]}`), "application/json"), wantNone: true,
		},
		{
			name: "a body-less HEAD answer to /v1/messages spent nothing",
			req:  &derive.Message{Method: "HEAD", Path: "/v1/messages", Header: http.Header{}},
			resp: response(nil, "application/json"), wantNone: true,
		},
		{
			name: "a body-less OPTIONS answer to /v1/messages spent nothing",
			req:  &derive.Message{Method: "OPTIONS", Path: "/v1/messages", Header: http.Header{}},
			resp: response(nil, "application/json"), wantNone: true,
		},
		{
			name: "a body-less GET answer to /v1/messages spent nothing",
			req:  &derive.Message{Method: "GET", Path: "/v1/messages", Header: http.Header{}},
			resp: response(nil, "application/json"), wantNone: true,
		},
		{
			name: "the local health check derives nothing",
			req:  &derive.Message{Method: "HEAD", Path: "/api/hello", Header: http.Header{}},
			resp: response(nil, ""), wantNone: true,
		},
		{
			name: "an undecodable content encoding is an encoding failure",
			req:  request(req),
			resp: func() *derive.Message {
				m := response([]byte{0x1f, 0x8b, 0x08}, "application/json")
				m.ContentEncoding = "br"
				return m
			}(),
			wantErr: derive.ErrEncoding,
		},
		{name: "a response that is not JSON", req: request(req),
			resp: response([]byte("<html>502</html>"), "text/html"), wantErr: derive.ErrSchema},
		{name: "an empty response body", req: request(req),
			resp: response(nil, "application/json"), wantErr: derive.ErrSchema},
		{name: "a response that is neither a message nor an error", req: request(req),
			resp: response([]byte(`{"ok":true}`), "application/json"), wantErr: derive.ErrSchema},
		{name: "a negative usage count", req: request(req),
			resp:    response([]byte(`{"id":"m","type":"message","model":"claude-opus-5","content":[],"usage":{"input_tokens":-1}}`), "application/json"),
			wantErr: derive.ErrSchema},
		{name: "a stream truncated mid-message", req: request(req),
			resp: response(stream[:len(stream)/2], "text/event-stream"), wantPartial: true},
		{name: "a stream that never started", req: request(req),
			resp:    response([]byte("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"), "text/event-stream"),
			wantErr: derive.ErrSchema},
		{name: "an unknown stream event", req: request(req),
			resp: response([]byte("event: wat\ndata: {\"type\":\"wat\"}\n\n"), "text/event-stream"), wantErr: derive.ErrSchema},
		{name: "a delta for a block that never opened", req: request(req),
			resp: response([]byte(`event: message_start
data: {"type":"message_start","message":{"id":"m","model":"claude-opus-5"}}

event: content_block_delta
data: {"type":"content_block_delta","index":3,"delta":{"type":"text_delta","text":"x"}}

`), "text/event-stream"), wantPartial: true},
		{name: "a tool input the fragments never completed", req: request(req),
			resp: response([]byte(`event: message_start
data: {"type":"message_start","message":{"id":"m","model":"claude-opus-5"}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_stop
data: {"type":"message_stop"}

`), "text/event-stream"), wantPartial: true},
		{name: "a stream that carried an error event", req: request(req),
			resp: response([]byte(`event: message_start
data: {"type":"message_start","message":{"id":"m","model":"claude-opus-5"}}

event: error
data: {"type":"error","error":{"type":"overloaded_error"}}

`), "text/event-stream"), wantPartial: true},
	}
	p := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts, err := p.Parse(tc.req, tc.resp)
			if facts.ParserVersion != ParserVersion {
				t.Errorf("parser_version = %q, want it stamped on every outcome (I6)", facts.ParserVersion)
			}
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantPartial:
				if err != nil {
					t.Fatalf("err = %v, want the partial facts and an unparsed decision", err)
				}
				if facts.Usage == nil || facts.Model == "" {
					t.Errorf("facts = %+v, want the model and the usage message_start reported", facts)
				}
				if n := len(facts.Decisions); n == 0 || !facts.Decisions[n-1].Unparsed || facts.Decisions[n-1].Why != derive.WhySchema {
					t.Errorf("decisions = %+v, want an unparsed schema decision last", facts.Decisions)
				}
			case tc.wantNone:
				if err != nil {
					t.Fatalf("err = %v, want a clean parse with nothing to derive", err)
				}
				if len(facts.Decisions) != 0 || facts.Model != "" {
					t.Errorf("facts = %+v, want empty", facts)
				}
			default:
				if err != nil {
					t.Fatalf("err = %v", err)
				}
			}
		})
	}
}

// An API error body parses, because a 429 is a fact about the call and not an unreadable
// body; the status carries the meaning and no decision is derived.
func TestParseErrorBody(t *testing.T) {
	p := New()
	resp := response([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`), "application/json")
	resp.Status = http.StatusTooManyRequests
	facts, err := p.Parse(request(read(t, "messages-request.json")), resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(facts.Decisions) != 0 {
		t.Errorf("%d decisions on an error body, want none", len(facts.Decisions))
	}
	if facts.Model != "claude-opus-5" {
		t.Errorf("model = %q, want the request's model as the fallback", facts.Model)
	}
}

// Input_hash is byte identity, not JSON equality (capture-derive.md R31): the same object written two ways
// hashes differently, so limits.repeats only ever matches a true repeat.
func TestInputHashByteIdentity(t *testing.T) {
	a := InputHash([]byte(`{"a":1,"b":2}`))
	b := InputHash([]byte(`{"b":2,"a":1}`))
	c := InputHash([]byte(`{"a":1, "b":2}`))
	if a == b || a == c {
		t.Error("input_hash collapsed two distinct byte strings; it must hash the wire, not a re-marshaling")
	}
	if a != InputHash([]byte(`{"a":1,"b":2}`)) {
		t.Error("input_hash is not deterministic")
	}
}

// The collected stream form httpstream produces — one data payload per line, framing
// already stripped — assembles to the same response as the wire form (R16).
func TestParseStreamCollectedForm(t *testing.T) {
	wire := read(t, "messages-stream.sse")
	var collected []string
	for _, line := range strings.Split(string(wire), "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			collected = append(collected, data)
		}
	}
	got, _, err := ParseStream([]byte(strings.Join(collected, "\n") + "\n"))
	if err != nil {
		t.Fatalf("collected form: %v", err)
	}
	want, _, err := ParseStream(wire)
	if err != nil {
		t.Fatalf("wire form: %v", err)
	}
	if got.ID != want.ID || got.StopReason != want.StopReason || len(got.Content) != len(want.Content) ||
		!reflect.DeepEqual(got.Usage, want.Usage) {
		t.Errorf("collected = %+v\nwire = %+v", got, want)
	}
}

// A parser handed half an exchange says so rather than dereferencing nil.
func TestParseHalfExchange(t *testing.T) {
	p := New()
	if _, err := p.Parse(nil, response(nil, "")); !errors.Is(err, derive.ErrSchema) {
		t.Errorf("err = %v, want a schema error", err)
	}
	if _, err := p.Parse(request(nil), nil); !errors.Is(err, derive.ErrSchema) {
		t.Errorf("err = %v, want a schema error", err)
	}
}

// A request half this parser could not read reports itself and nothing more — the facts of
// a response that parsed reach the ssl_response intact (R29 is body-scoped, R30 keeps the tool_use order).
//
// The first two shapes were rows of T-anthropic-3 asserting the opposite: Parse returned ErrSchema and the
// Dispatcher collapsed the whole exchange to one unparsed decision, so usage, model, stop_reason and every
// tool_use went to nothing. usage is the only input limits' token and cost ceilings have, and the request
// is the half the agent writes: padding a body past capture's cap (forwarder DefaultMaxBody, R6/R14) would
// have silenced those ceilings for every turn of the conversation.
func TestParseRequestHalfNeverVoidsResponse(t *testing.T) {
	reqBody := read(t, "messages-request.json")
	cases := []struct {
		name    string
		req     *derive.Message
		wantWhy string
	}{
		{name: "a request body a capture cap cut short", req: request(reqBody[:len(reqBody)/2]), wantWhy: derive.WhySchema},
		{name: "a request without a model", req: request([]byte(`{"messages":[]}`)), wantWhy: derive.WhySchema},
		{name: "an empty request body", req: request(nil), wantWhy: derive.WhySchema},
		{
			name: "a request capture never decoded is an encoding failure, not a syntax error",
			req: func() *derive.Message {
				m := request([]byte{0x1f, 0x8b, 0x08, 0x00})
				m.ContentEncoding = "gzip"
				return m
			}(),
			wantWhy: derive.WhyEncoding,
		},
	}
	p := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts, err := p.Parse(tc.req, response(read(t, "messages-response.json"), "application/json"))
			if err != nil {
				t.Fatalf("err = %v, want the response's own facts to survive the request half", err)
			}
			if facts.Usage == nil || facts.Usage.Input != 1000 || facts.Usage.Output != 102 ||
				facts.Usage.CacheWrite != 512 {
				t.Errorf("usage = %+v, want the response's counters: limits has no other source", facts.Usage)
			}
			if facts.Model != "claude-opus-5" || facts.ResponseID != "msg_01Xq0001Z" || facts.StopReason != "tool_use" {
				t.Errorf("facts = %+v", facts)
			}
			if len(facts.Decisions) != 3 {
				t.Fatalf("%d decisions, want the request's unparsed marker and one per tool_use", len(facts.Decisions))
			}
			if got := facts.Decisions[0]; !got.Unparsed || got.Why != tc.wantWhy || got.Tool != "" {
				t.Errorf("decision 0 = %+v, want unparsed why=%s for the request half", got, tc.wantWhy)
			}
			if got := facts.Decisions[1]; got.Tool != "bash" || got.ToolUseID != "toolu_010001A" || got.Unparsed {
				t.Errorf("decision 1 = %+v, want the first tool_use in wire order", got)
			}
			if got := facts.Decisions[2]; got.Tool != "read_file" || got.ToolUseID != "toolu_010001B" {
				t.Errorf("decision 2 = %+v, want the second tool_use in wire order", got)
			}
		})
	}
}

// The assembled event stream is read the same way — a request the parser could not read
// costs the stream neither its usage nor its decision.
func TestParseStreamSurvivesUnreadableRequest(t *testing.T) {
	resp := response(read(t, "messages-stream.sse"), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(`{"messages":`)), resp)
	if err != nil {
		t.Fatalf("err = %v, want the stream's facts", err)
	}
	if facts.Usage == nil || facts.Usage.Input != 1200 || facts.Usage.Output != 104 {
		t.Errorf("usage = %+v", facts.Usage)
	}
	if !facts.Stream || facts.Model != "claude-opus-5" {
		t.Errorf("facts = %+v", facts)
	}
	if len(facts.Decisions) != 2 || !facts.Decisions[0].Unparsed || facts.Decisions[1].Tool != "read_file" {
		t.Errorf("decisions = %+v", facts.Decisions)
	}
}

// When the response half is unreadable too, Parse still returns the error and derives no
// decision of its own — the Dispatcher owns the single unparsed marker R29 requires, and a second one from
// the request half would make two for one exchange.
func TestParseBothHalvesUnreadable(t *testing.T) {
	reqBody := read(t, "messages-request.json")
	facts, err := New().Parse(request(reqBody[:len(reqBody)/2]), response([]byte("<html>502</html>"), "text/html"))
	if !errors.Is(err, derive.ErrSchema) {
		t.Fatalf("err = %v, want a schema error", err)
	}
	if len(facts.Decisions) != 0 || facts.Usage != nil {
		t.Errorf("facts = %+v, want nothing derived from an exchange neither half of which parsed", facts)
	}
}

// The parser claims its provider and the hosts a run declared for it.
func TestClaims(t *testing.T) {
	p := New("api.anthropic.test", "API.ANTHROPIC.COM")
	if p.Provider() != Provider || p.Version() != ParserVersion {
		t.Errorf("provider/version = %s/%s", p.Provider(), p.Version())
	}
	hosts := p.Hosts()
	if len(hosts) != 2 || hosts[0] != "api.anthropic.com" || hosts[1] != "api.anthropic.test" {
		t.Errorf("hosts = %v", hosts)
	}
}
