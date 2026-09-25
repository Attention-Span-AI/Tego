// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// wholeStreamTail ends cutStream as the API ends a message: its message_delta with the real output count, then
// message_stop.
const wholeStreamTail = "event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}` + "\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// parseCut parses cutStream answered to reqBody.
func parseCut(t *testing.T, reqBody string) derive.Facts {
	t.Helper()
	resp := response([]byte(cutStream), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(reqBody)), resp)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

// TestMaxTokensIsReadAsWritten: encoding/json folds key case and takes the last match, so
// {"max_tokens":64000,...,"MAX_TOKENS":1} bounded a cut stream by 1 while the API let the model write 64000.
// max_tokens is the one key spelled exactly so; a body that names it twice or only in another spelling has no bound,
// and the cut stream is unmetered.
func TestMaxTokensIsReadAsWritten(t *testing.T) {
	cases := []struct {
		name      string
		req       string
		wantOut   int
		unmetered bool
	}{
		{"case variant after", `{"model":"m","max_tokens":64000,"stream":true,"messages":[],"MAX_TOKENS":1}`, 0, true},
		{"case variant before", `{"model":"m","Max_Tokens":1,"max_tokens":64000,"messages":[]}`, 0, true},
		{"unicode fold", `{"model":"m","max_tokens":64000,"max_tokenſ":1,"messages":[]}`, 0, true},
		{"exact duplicate", `{"model":"m","max_tokens":64000,"max_tokens":1,"messages":[]}`, 0, true},
		{"only another spelling", `{"model":"m","MAX_TOKENS":64000,"messages":[]}`, 0, true},
		{"not an integer", `{"model":"m","max_tokens":6.4e4,"messages":[]}`, 0, true},
		{"nested variant is not top level", `{"model":"m","max_tokens":4096,"metadata":{"MAX_TOKENS":1}}`, 4096, false},
		{"escaped exact spelling", `{"model":"m","max_tokens":4096,"messages":[]}`, 4096, false},
		{"exact", `{"model":"m","max_tokens":4096,"messages":[{"role":"user","content":"\"max_tokens\":1"}]}`, 4096, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := parseCut(t, tc.req)
			if facts.Unmetered != tc.unmetered {
				t.Fatalf("Unmetered = %v, want %v (usage %+v)", facts.Unmetered, tc.unmetered, facts.Usage)
			}
			if !tc.unmetered && (facts.Usage.Output != tc.wantOut || !facts.Usage.OutputBound) {
				t.Errorf("usage %+v, want output %d bound", facts.Usage, tc.wantOut)
			}
		})
	}
}

// TestModelIsReadAsWritten: where the request's model prices an exchange (the response names none), it is the
// key spelled exactly model, not the spelling encoding/json kept last; a request naming no exact model, or any
// key twice, has none, and is unparsed.
func TestModelIsReadAsWritten(t *testing.T) {
	noModel := &derive.Message{Status: 200, Body: []byte(`{"id":"msg_1","type":"message",` +
		`"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":1,"output_tokens":1}}`)}
	cases := []struct{ body, want string }{
		{`{"model":"claude-haiku-4","MODEL":"claude-opus-5","messages":[]}`, "claude-haiku-4"},
		{`{"Model":"claude-opus-5","messages":[]}`, ""},
		{`{"model":"claude-haiku-4","model":"claude-opus-5","messages":[]}`, ""},
		{`{"model":"claude-opus-5","messages":[]}`, "claude-opus-5"},
	}
	for _, tc := range cases {
		facts, err := New().Parse(request([]byte(tc.body)), noModel)
		if err != nil {
			t.Fatal(err)
		}
		unparsed := len(facts.Decisions) == 1 && facts.Decisions[0].Unparsed
		if facts.Model != tc.want || unparsed != (tc.want == "") {
			t.Errorf("%s: model %q decisions %+v, want model %q", tc.body, facts.Model, facts.Decisions, tc.want)
		}
	}
}

// TestResponseUsageIsReadAsWritten: the usage a charge is made of is read only from its exact keys, in a JSON
// body and in a stream's message_start and message_delta; encoding/json v1 kept whichever spelling came last.
func TestResponseUsageIsReadAsWritten(t *testing.T) {
	for _, body := range []string{
		`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":0,"output_tokens":900},"USAGE":{"output_tokens":1}}`,
		`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":0,"output_tokens":900,"OUTPUT_TOKENS":1}}`,
		`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":0,"output_tokens":900,"output_tokenſ":1}}`,
		`{"id":"m","type":"message","TYPE":"error","model":"x","content":[],"usage":{"input_tokens":0,"output_tokens":900}}`,
	} {
		resp, err := ParseResponse(200, []byte(body))
		if err != nil || resp.Usage.OutputTokens != 900 {
			t.Errorf("ParseResponse(%s) = %+v, %v; want output 900", body, resp, err)
		}
	}

	body := strings.Replace(cutStream, `"usage":{"input_tokens":1200`, `"USAGE":{"input_tokens":1},"usage":{"input_tokens":1200`, 1) +
		"event: message_delta\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":900},"Usage":{"output_tokens":1}}` + "\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	resp := response([]byte(body), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(`{"model":"m","max_tokens":4096,"messages":[]}`)), resp)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Usage.Input != 1200 || facts.Usage.Output != 900 || facts.Usage.OutputBound {
		t.Errorf("usage %+v, want input 1200 and output 900 as written", facts.Usage)
	}
}

// TestAssemblyErrorKeepsMessageDelta: a complete stream whose assembly fails before its message_delta (a tool_use
// input that is not valid JSON, which fine-grained tool streaming allows) was charged max_tokens though the wire
// carried the real count. The frames after the failure are read for usage.
func TestAssemblyErrorKeepsMessageDelta(t *testing.T) {
	body := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5","usage":{"input_tokens":1200,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"ls"}}` + "\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":9,\"delta\":{}}\n\n" +
		wholeStreamTail
	resp := response([]byte(body), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(`{"model":"claude-opus-5","max_tokens":64000,"stream":true,"messages":[]}`)), resp)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Unmetered || facts.Usage.OutputBound || facts.Usage.Output != 7 || facts.Usage.Input != 1200 {
		t.Errorf("usage %+v unmetered %v, want the reported output 7", facts.Usage, facts.Unmetered)
	}
	last := facts.Decisions[len(facts.Decisions)-1]
	if !last.Unparsed || last.Why != derive.WhySchema {
		t.Errorf("decisions %+v, want the assembly failure as one unparsed why=schema", facts.Decisions)
	}
}

// TestErrorEventBeforeMessageStart: an error event on a 200 before any message_start (an overloaded_error) is an
// error answer. It spent nothing; it was unparsed, and so unmetered, and a budgeted run ended on a transient
// overload. After message_start an error event still leaves the max_tokens bound (ADR 0036).
func TestErrorEventBeforeMessageStart(t *testing.T) {
	const errEvent = "event: error\n" +
		`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}` + "\n\n"
	req := `{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`

	resp := response([]byte("event: ping\ndata: {\"type\":\"ping\"}\n\n"+errEvent), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(req)), resp)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Unmetered || facts.Usage == nil || facts.Usage.Output != 0 || facts.Usage.OutputBound ||
		len(facts.Decisions) != 0 || facts.Model != "claude-opus-5" {
		t.Errorf("facts %+v usage %+v, want an error answer: nothing spent, no decision", facts, facts.Usage)
	}

	resp = response([]byte(cutStream+errEvent), "text/event-stream")
	resp.SSE = true
	if facts, err = New().Parse(request([]byte(req)), resp); err != nil {
		t.Fatal(err)
	}
	if facts.Unmetered || facts.Usage.Output != 4096 || !facts.Usage.OutputBound {
		t.Errorf("usage %+v, want the bound 4096 after message_start", facts.Usage)
	}
}

// TestPathCaseAndParams: "outside /v1" compared the path as written, so /V1/messages and /v1;x/messages were silent.
// The first segment is lowercased with its ;params cut, and what is ambiguous is a path this parser does not read.
func TestPathCaseAndParams(t *testing.T) {
	for _, p := range []string{"/V1/messages", "/v1;x/messages", "/V1/MESSAGES", "/v1;/models", "/;x/v1/messages",
		"/v1%3bx/messages", `/v1\messages`, "/v1 /messages", "/V1", "/v1./messages", "https://api.anthropic.com/V1/messages",
		"/%2576%2531/messages", "/%2576%2531/models"} {
		if got := classifyPath("POST", p); got != pathOther {
			t.Errorf("classifyPath(%q) = %v, want a path it does not read", p, got)
		}
	}
	for _, p := range []string{"/", "/api/hello", "/API/event_logging/batch", "/health;x"} {
		if got := classifyPath("POST", p); got != pathSilent {
			t.Errorf("classifyPath(%q) = %v, want silent", p, got)
		}
	}
}

// TestMaxTokensScanPieces: the forwarder's scan reads the same max_tokens from a body in any pieces as from the
// whole, reports none before the object closes, and loses it to a duplicate in a later piece.
func TestMaxTokensScanPieces(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"a \"quoted\\\\\" max_tokens: 1 {"}],` +
		`"max_tokens" : 8192 ,"stream":true}`)
	if n, ok := RequestMaxTokens(body); !ok || n != 8192 {
		t.Fatalf("whole: %d %v", n, ok)
	}
	for size := 1; size <= len(body); size++ {
		var s MaxTokensScanner
		for i := 0; i < len(body); i += size {
			if n, ok := s.Result(); ok {
				t.Fatalf("size %d: max_tokens %d before the object closed", size, n)
			}
			_, _ = s.Write(body[i:min(i+size, len(body))])
		}
		if n, ok := s.Result(); !ok || n != 8192 {
			t.Fatalf("size %d: %d %v", size, n, ok)
		}
	}
	var s MaxTokensScanner
	_, _ = s.Write(body[:len(body)-1])
	_, _ = s.Write([]byte(`,"MAX_TOKENS":1}`))
	if n, ok := s.Result(); ok {
		t.Errorf("a later case variant left max_tokens %d", n)
	}
}

// FuzzMaxTokensScan: whenever the scan reads a max_tokens, encoding/json reads the same one (there is only one
// spelling to fold), and the reading does not depend on how the body was split.
func FuzzMaxTokensScan(f *testing.F) {
	seed(f, "messages-request.json")
	for _, s := range []string{
		`{"model":"m","max_tokens":64000,"MAX_TOKENS":1}`,
		`{"max_tokens":5}`,
		`{"a":"\\","max_tokens":3}`,
		`{"a":{"max_tokens":[1,"}"]},"max_tokens":7}`,
		`{"max_tokens":12`,
		` {"max_tokens" : 1 } `,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		n, ok := RequestMaxTokens(body)
		for _, size := range []int{1, 2, 7} {
			var s MaxTokensScanner
			for i := 0; i < len(body); i += size {
				_, _ = s.Write(body[i:min(i+size, len(body))])
			}
			if m, mok := s.Result(); m != n || mok != ok {
				t.Fatalf("pieces of %d read %d %v, whole %d %v", size, m, mok, n, ok)
			}
		}
		if !ok {
			return
		}
		if n <= 0 {
			t.Fatalf("max_tokens %d read as a bound", n)
		}
		var folded struct {
			MaxTokens *int `json:"max_tokens"`
		}
		if json.Unmarshal(body, &folded) == nil && (folded.MaxTokens == nil || *folded.MaxTokens != n) {
			t.Fatalf("scan read %d, encoding/json %v", n, folded.MaxTokens)
		}
	})
}

// FuzzCutStreamNeverUndercounts: a stream cut anywhere is charged what its message_delta reported (only when a
// message_delta with usage is in what was kept) or at least max_tokens, or is unmetered.
func FuzzCutStreamNeverUndercounts(f *testing.F) {
	full := cutStream + wholeStreamTail
	for i := 0; i <= len(full); i += 13 {
		f.Add([]byte(full[:i]), true)
		f.Add([]byte(full[:i]), false)
	}
	f.Fuzz(func(t *testing.T, body []byte, sse bool) {
		const maxTok = 4096
		resp := response(body, "text/event-stream")
		resp.SSE = sse
		facts, err := New().Parse(request([]byte(`{"model":"m","max_tokens":4096,"stream":true,"messages":[]}`)), resp)
		if err != nil || facts.Unmetered || facts.Usage == nil || !facts.Stream {
			return
		}
		if facts.Usage.Output >= maxTok || facts.Usage.OutputBound {
			if facts.Usage.OutputBound && facts.Usage.Output < maxTok {
				t.Fatalf("bound below max_tokens: %+v", facts.Usage)
			}
			return
		}
		lb := bytes.ToLower(body)
		if i := bytes.Index(lb, []byte("message_delta")); i >= 0 && bytes.Contains(lb[i:], []byte("usage")) {
			return
		}
		if bytes.Contains(lb, []byte("error")) && !bytes.Contains(lb, []byte("message_start")) {
			return // an error answer: nothing began, nothing spent
		}
		t.Fatalf("stream with no message_delta usage charged %+v unbounded; body %q", facts.Usage, body)
	})
}

// FuzzClassifyTargetForms: an absolute-form target never classifies as spending nothing where its origin-form
// spelling spends, and a path whose first segment names v1 in any case or with ;params is never silent unless it
// is on the allow-list as written.
func FuzzClassifyTargetForms(f *testing.F) {
	for _, s := range []string{"/v1/messages", "/v1/%6Dessages", "//v1/messages", "/x/../v1/messages", "/v1/messages?x",
		"/V1/messages", "/v1;x/messages", "/%2e%2e/v1/messages", "/v1/messages#x", "*", "/v1%2fmessages",
		"/v1/messages/batches", "/api/hello", "/;x/v1/models"} {
		f.Add(s, "POST")
	}
	f.Fuzz(func(t *testing.T, target, method string) {
		a, p, ok := derive.SplitTarget(target)
		if ok && a == "" && p != target {
			t.Fatalf("origin-form rewritten: %q -> %q", target, p)
		}
		if ok && !(strings.HasPrefix(p, "/") || p == "*") {
			t.Fatalf("ok target %q gives non-origin path %q", target, p)
		}
		if !strings.HasPrefix(target, "/") {
			return
		}
		origin := classifyPath(method, target)
		abs := classifyPath(method, "https://api.anthropic.com"+target)
		if abs == pathSilent && origin != pathSilent {
			t.Fatalf("%q: origin-form %v, absolute-form silent", target, origin)
		}
		n := normalizePath(target)
		first := strings.TrimPrefix(n, "/")
		if i := strings.IndexAny(first, "/;"); i >= 0 {
			first = first[:i]
		}
		if origin == pathSilent && strings.HasPrefix(strings.ToLower(first), "v1") && !strings.HasPrefix(n, "/v1/") {
			t.Fatalf("%q (normalized %q) names v1 and is silent", target, n)
		}
	})
}

// The OpenAI-compatible endpoint's usage and model are read as written, as the Messages API's are (R29 (l)): a
// case variant of a key is an unknown member, never what is charged, whole or streamed.
func TestChatKeysAreReadAsWritten(t *testing.T) {
	chat := func(body, contentType string) derive.Facts {
		t.Helper()
		req := &derive.Message{Method: "POST", Path: "/v1/chat/completions",
			Body: []byte(`{"model":"claude-opus-5","messages":[]}`)}
		f, err := New().Parse(req, response([]byte(body), contentType))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return f
	}
	whole := chat(`{"id":"c1","model":"claude-opus-5","Model":"cheap","usage":{"prompt_tokens":100,"completion_tokens":5},`+
		`"USAGE":{"prompt_tokens":1,"completion_tokens":1},"Usage":{"prompt_tokens":2}}`, "application/json")
	if whole.Model != "claude-opus-5" || whole.Usage == nil || whole.Usage.Input != 100 || whole.Usage.Output != 5 {
		t.Errorf("whole: model %q usage %+v; want claude-opus-5, 100 in, 5 out", whole.Model, whole.Usage)
	}
	variantOnly := chat(`{"id":"c1","MODEL":"cheap","usage":{"Prompt_Tokens":1,"prompt_tokens":100,"COMPLETION_TOKENS":1,`+
		`"completion_tokens":5}}`, "application/json")
	if variantOnly.Model != "claude-opus-5" || variantOnly.Usage == nil || variantOnly.Usage.Input != 100 ||
		variantOnly.Usage.Output != 5 {
		t.Errorf("variants: model %q usage %+v; want the request's model and 100 in, 5 out", variantOnly.Model,
			variantOnly.Usage)
	}
	stream := chat("data: {\"id\":\"c1\",\"model\":\"claude-opus-5\",\"choices\":[]}\n\n"+
		"data: {\"id\":\"c1\",\"model\":\"claude-opus-5\",\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":5},"+
		"\"USAGE\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n", "text/event-stream")
	if stream.Usage == nil || stream.Usage.Input != 100 || stream.Usage.Output != 5 {
		t.Errorf("stream: usage %+v; want 100 in, 5 out", stream.Usage)
	}
	if _, err := New().Parse(&derive.Message{Method: "POST", Path: "/v1/chat/completions"},
		response([]byte(`{"id":"c1","model":"m","USAGE":{"prompt_tokens":1}}`), "application/json")); err == nil {
		t.Error("a completion whose only usage is a case variant parsed as metered; want no usage, unparsed")
	}
}

// TestRequestMaxTokensRules is the rule table capture/maxtokens pinned before it was folded into this package:
// the scanner and the whole-body reading agree, and each rule leaves no bound where the upstream could read
// another.
func TestRequestMaxTokensRules(t *testing.T) {
	long := `"messages":[{"role":"user","content":"` + strings.Repeat(`x\"{[`, 1000) + `"}]`
	for _, tc := range []struct {
		name string
		body string
		want int
		ok   bool
	}{
		{"plain", `{"model":"m","max_tokens":4096,"stream":true}`, 4096, true},
		{"first", `{"max_tokens":8,` + long + `}`, 8, true},
		{"after a long nested value", `{` + long + `,"max_tokens":16}`, 16, true},
		{"whitespace", "{ \"max_tokens\" :\n 32 \n}", 32, true},
		{"escaped key", `{"max_tokens":64}`, 64, true},
		{"nested only", `{"metadata":{"max_tokens":5},"messages":[]}`, 0, false},
		{"case variant alone", `{"MAX_TOKENS":5}`, 0, false},
		{"case variant beside exact", `{"max_tokens":5,"Max_Tokens":50000}`, 0, false},
		{"kelvin sign variant", "{\"max_tokens\":5,\"max_toKens\":9}", 0, false},
		{"exact duplicate", `{"max_tokens":5,"max_tokens":6}`, 0, false},
		{"string value", `{"max_tokens":"5"}`, 0, false},
		{"fraction", `{"max_tokens":5.0}`, 0, false},
		{"exponent", `{"max_tokens":5e3}`, 0, false},
		{"negative", `{"max_tokens":-5}`, 0, false},
		{"zero", `{"max_tokens":0}`, 0, false},
		{"leading zero", `{"max_tokens":05}`, 0, false},
		{"null", `{"max_tokens":null}`, 0, false},
		{"huge", `{"max_tokens":99999999999999999999999}`, 0, false},
		{"unended", `{"max_tokens":5,"messages":[`, 0, false},
		{"not an object", `[{"max_tokens":5}]`, 0, false},
		{"trailing bytes", `{"max_tokens":5}x`, 0, false},
		{"none", `{"model":"m"}`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RequestMaxTokens([]byte(tc.body))
			if got != tc.want || ok != tc.ok {
				t.Errorf("RequestMaxTokens(%.80q) = %d, %v; want %d, %v", tc.body, got, ok, tc.want, tc.ok)
			}
			var s MaxTokensScanner
			for i := range len(tc.body) {
				_, _ = s.Write([]byte{tc.body[i]})
			}
			if g, o := s.Result(); g != got || o != ok {
				t.Errorf("byte by byte: %d, %v; whole: %d, %v", g, o, got, ok)
			}
		})
	}
}

// TestBoundCutStream: the bound a capture source read is charged only to the one verdict derive reached for want
// of it, an unmetered 2xx Anthropic stream; every other exchange is left as it is.
func TestBoundCutStream(t *testing.T) {
	cut := func() *derive.Facts {
		return &derive.Facts{ParserVersion: ParserVersion, Stream: true, Unmetered: true,
			Usage: &record.Usage{Input: 100, Output: 1}}
	}
	f := cut()
	if !BoundCutStream(f, 2048, true, 200) || f.Unmetered || f.Usage.Output != 2048 || !f.Usage.OutputBound {
		t.Fatalf("cut stream: %+v %+v; want output 2048, a bound, metered", f, f.Usage)
	}
	for name, tc := range map[string]struct {
		mod    func(*derive.Facts)
		max    int
		ok     bool
		status int
	}{
		"unknown":      {nil, 2048, false, 200},
		"zero":         {nil, 0, true, 200},
		"refused":      {nil, 2048, true, 429},
		"metered":      {func(f *derive.Facts) { f.Unmetered = false }, 2048, true, 200},
		"no usage":     {func(f *derive.Facts) { f.Usage = nil }, 2048, true, 200},
		"not a stream": {func(f *derive.Facts) { f.Stream = false }, 2048, true, 200},
		"bounded":      {func(f *derive.Facts) { f.Usage.OutputBound = true }, 2048, true, 200},
		"other parser": {func(f *derive.Facts) { f.ParserVersion = "openai-x" }, 2048, true, 200},
	} {
		f := cut()
		if tc.mod != nil {
			tc.mod(f)
		}
		if BoundCutStream(f, tc.max, tc.ok, tc.status) {
			t.Errorf("%s: bounded %+v", name, f)
		}
	}
	if BoundCutStream(nil, 1, true, 200) {
		t.Error("nil facts bounded")
	}
}

// A stream's content block is read as written, like a non-stream response's: a case-variant key is an unknown
// member, so it cannot turn a text block into a tool_use decision.
func TestStreamBlockKeysAreReadAsWritten(t *testing.T) {
	sse := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"TYPE\":\"tool_use\",\"NAME\":\"x\",\"ID\":\"toolu_1\",\"text\":\"\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"STOP_REASON\":\"tool_use\"},\"usage\":{\"output_tokens\":2}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	resp := response([]byte(sse), "text/event-stream")
	resp.SSE = true
	facts, err := New().Parse(request([]byte(`{"model":"claude-opus-5","stream":true,"max_tokens":8}`)), resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, d := range facts.Decisions {
		if d.Tool != "" || d.ToolUseID != "" {
			t.Errorf("decision %+v: a case-variant key made a tool_use", d)
		}
	}
	if facts.StopReason != "end_turn" {
		t.Errorf("stop_reason = %q, want end_turn", facts.StopReason)
	}
}
