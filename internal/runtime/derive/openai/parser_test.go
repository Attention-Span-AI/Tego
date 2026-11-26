// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func request(path, body string) *derive.Message {
	return &derive.Message{Method: "POST", Path: path, Body: []byte(body), Decoded: true, Header: http.Header{}}
}

func answer(status int, contentType, body string) *derive.Message {
	h := http.Header{}
	h.Set("Content-Type", contentType)
	return &derive.Message{Status: status, Header: h, Body: []byte(body), Decoded: true, WireSSE: strings.HasPrefix(contentType, "text/event-stream"),
		SSE: strings.HasPrefix(contentType, "text/event-stream")}
}

func sameUsage(got *record.Usage, want record.Usage) bool {
	return got != nil && reflect.DeepEqual(*got, want)
}

// noteOf is the note a parser error carries for the person told of the unmetered exchange it causes.
func noteOf(err error) string {
	var n derive.UnmeteredNoter
	if errors.As(err, &n) {
		return n.UnmeteredNote()
	}
	return ""
}

func parse(t *testing.T, path, reqBody string, resp *derive.Message) (derive.Facts, error) {
	t.Helper()
	return New().Parse(request(path, reqBody), resp)
}

const chatReq = `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`

// A non-streamed chat completion states its usage: the prompt minus its cached part is the input, the cached part
// the cache read, and the completion count (reasoning tokens inside it) the output, which is the mapping ADR 0037, amended 2026-11-26
// writes down and the one the Anthropic chat reading uses.
func TestChatCompletionUsage(t *testing.T) {
	body := `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-x-2026","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],
"usage":{"prompt_tokens":12,"completion_tokens":7,"total_tokens":19,
"prompt_tokens_details":{"cached_tokens":4,"audio_tokens":0},"completion_tokens_details":{"reasoning_tokens":5}}}`
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", body))
	if err != nil {
		t.Fatal(err)
	}
	want := record.Usage{Input: 8, Output: 7, CacheRead: 4}
	if !sameUsage(f.Usage, want) {
		t.Fatalf("usage = %+v, want %+v (output counts the reasoning tokens once, inside completion_tokens)", f.Usage, want)
	}
	if f.Model != "gpt-x-2026" || f.ResponseID != "chatcmpl-1" || f.ParserVersion != ParserVersion || f.Stream || f.Unmetered {
		t.Fatalf("facts = %+v", f)
	}
}

func TestChatCompletionWithoutCachedDetails(t *testing.T) {
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json",
		`{"id":"c","model":"gpt-x","usage":{"prompt_tokens":12,"completion_tokens":7,"prompt_tokens_details":null}}`))
	if err != nil || !sameUsage(f.Usage, record.Usage{Input: 12, Output: 7}) {
		t.Fatalf("facts %+v, err %v", f, err)
	}
}

// The model an answer names none of is the request's, read as written.
func TestAnAnswerWithoutAModelTakesTheRequestsModel(t *testing.T) {
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", `{"usage":{"prompt_tokens":1,"completion_tokens":2}}`))
	if err != nil || f.Model != "gpt-x" {
		t.Fatalf("model %q, err %v, want the request's gpt-x", f.Model, err)
	}
	f, err = parse(t, ChatCompletionsPath, `{"model":"a","MODEL":"b"}`, answer(200, "application/json", `{"usage":{"prompt_tokens":1,"completion_tokens":2}}`))
	if err != nil || f.Model != "a" {
		t.Fatalf("a request spelling model in two cases: model %q, err %v (the exact key is read)", f.Model, err)
	}
	f, _ = parse(t, ChatCompletionsPath, `{"model":"a","model":"b"}`, answer(200, "application/json", `{"usage":{"prompt_tokens":1,"completion_tokens":2}}`))
	if f.Model != "" {
		t.Fatalf("a request naming model twice has no model this parser can say: %q", f.Model)
	}
}

const chatStreamTail = "data: [DONE]\n\n"

func chunk(extra string) string {
	return `{"id":"chatcmpl-9","object":"chat.completion.chunk","model":"gpt-x","choices":[` + extra + `]`
}

// A streamed chat completion that was asked for usage ends with a chunk whose choices array is empty and whose usage
// is the whole request's; every earlier chunk says "usage": null.
func TestChatStreamWithUsage(t *testing.T) {
	body := "data: " + chunk(`{"index":0,"delta":{"content":"o"}}`) + `,"usage":null}` + "\n\n" +
		"data: " + chunk(`{"index":0,"delta":{"content":"k"},"finish_reason":"stop"}`) + `,"usage":null}` + "\n\n" +
		"data: " + chunk("") + `,"usage":{"prompt_tokens":12,"completion_tokens":7,"total_tokens":19,"prompt_tokens_details":{"cached_tokens":2}}}` + "\n\n" +
		chatStreamTail
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "text/event-stream", body))
	if err != nil {
		t.Fatal(err)
	}
	if !sameUsage(f.Usage, record.Usage{Input: 10, Output: 7, CacheRead: 2}) || !f.Stream || f.Model != "gpt-x" || f.ResponseID != "chatcmpl-9" {
		t.Fatalf("facts = %+v usage %+v", f, f.Usage)
	}
}

// The usage object spread over several data: lines of one frame (joined by a newline, which JSON allows), a frame
// ended by CR alone, CRLF framing, and a leading byte-order mark all read the same count.
func TestChatStreamUsageSplitAcrossLinesAndFramings(t *testing.T) {
	split := "data: {\"id\":\"c\",\"model\":\"gpt-x\",\"choices\":[],\ndata: \"usage\":{\"prompt_tokens\":12,\ndata: \"completion_tokens\":7}}\n\n" + chatStreamTail
	for name, body := range map[string]string{
		"lines":  split,
		"crlf":   strings.ReplaceAll(split, "\n", "\r\n"),
		"cr":     strings.ReplaceAll(split, "\n", "\r"),
		"bom":    "\xef\xbb\xbf" + split,
		"events": "event: message\n" + split,
		"noted":  ": keep-alive\n\nretry: 100\nid: 4\n" + split,
	} {
		f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "text/event-stream", body))
		if err != nil || !sameUsage(f.Usage, record.Usage{Input: 12, Output: 7}) {
			t.Errorf("%s: facts %+v err %v", name, f, err)
		}
	}
}

// A streamed answer that ends without a usage chunk is an answer whose spend cannot be read: an error that tells a
// person what the client can change, and, through the Dispatcher, an unmetered exchange with that note. A request
// the client sent with stream_options.include_usage is not this case.
func TestChatStreamWithoutUsageIsUnreadableAndSaysWhy(t *testing.T) {
	body := "data: " + chunk(`{"index":0,"delta":{"content":"o"}}`) + `,"usage":null}` + "\n\n" +
		"data: " + chunk(`{"index":0,"delta":{},"finish_reason":"stop"}`) + `,"usage":null}` + "\n\n" + chatStreamTail
	_, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "text/event-stream", body))
	if !errors.Is(err, derive.ErrSchema) || noteOf(err) != derive.NoteStreamWithoutUsage {
		t.Fatalf("err = %v, want the stream-without-usage schema error", err)
	}
	d := derive.NewDispatcher([]derive.Parser{New()})
	res, herr := d.Handle(request(ChatCompletionsPath, chatReq), answer(200, "text/event-stream", body),
		derive.Meta{Provider: "openai", Host: "api.openai.com"})
	if herr != nil || !res.Facts.Unmetered || res.Facts.UnmeteredNote != derive.NoteStreamWithoutUsage {
		t.Fatalf("dispatcher: unmetered %v note %q err %v", res.Facts.Unmetered, res.Facts.UnmeteredNote, herr)
	}
	if got := derive.UnreadableWhy("POST", ChatCompletionsPath, res.Facts.UnmeteredNote); got != "POST /v1/chat/completions: usage unreadable (stream without usage)" {
		t.Fatalf("why = %q", got)
	}
	// Not a stream: the plain account.
	if got := derive.UnreadableWhy("POST", ChatCompletionsPath, ""); got != "POST /v1/chat/completions: usage unreadable" {
		t.Fatalf("why = %q", got)
	}
}

// An error answer states no usage and spent nothing; a successful answer with none spent what nothing here can read.
func TestAnAnswerWithoutUsage(t *testing.T) {
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(429, "application/json", `{"error":{"message":"slow down","type":"rate_limit"}}`))
	if err != nil || f.Usage != nil || f.Unmetered {
		t.Fatalf("a 429: facts %+v err %v, want no usage and no error", f, err)
	}
	for _, body := range []string{`{"id":"c","model":"m","choices":[]}`, `{"id":"c","usage":null}`, `{"error":{"message":"x"}}`, `{}`} {
		_, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", body))
		if !errors.Is(err, ErrSchema) {
			t.Errorf("200 %s: err %v, want ErrSchema", body, err)
		}
	}
	res, _ := derive.NewDispatcher([]derive.Parser{New()}).Handle(request(ChatCompletionsPath, chatReq),
		answer(200, "application/json", `{"id":"c"}`), derive.Meta{Provider: "openai", Host: "h"})
	if !res.Facts.Unmetered || res.Facts.UnmeteredNote != "" {
		t.Fatalf("a 200 with no usage: unmetered %v note %q", res.Facts.Unmetered, res.Facts.UnmeteredNote)
	}
}

// Malformed, ambiguous or incoherent accounting is unreadable, never a smaller count and never a panic.
func TestMalformedAccountingIsUnreadable(t *testing.T) {
	for _, usage := range []string{
		`{}`,
		`{"prompt_tokens":5}`,
		`{"completion_tokens":5}`,
		`{"prompt_tokens":null,"completion_tokens":1}`,
		`{"prompt_tokens":5,"completion_tokens":null}`,
		`{"prompt_tokens":-1,"completion_tokens":1}`,
		`{"prompt_tokens":5,"completion_tokens":-1}`,
		`{"prompt_tokens":"5","completion_tokens":1}`,
		`{"prompt_tokens":5.5,"completion_tokens":1}`,
		`{"prompt_tokens":99999999999999999999999,"completion_tokens":1}`,
		`{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":-1}}`,
		`{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":6}}`,
		`{"prompt_tokens":5,"completion_tokens":500,"completion_tokens":1}`,
		`{"prompt_tokens":5,"completion_tokens":500,"completion_tokens":1}`,
		`{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":0,"cached_tokens":5}}`,
		`[1,2]`,
		`"usage"`,
		`{"prompt_tokens":5,"completion_tokens":1`,
	} {
		for _, shape := range []string{"whole", "stream"} {
			body, ct := `{"id":"c","model":"m","usage":`+usage+`}`, "application/json"
			if shape == "stream" {
				body, ct = "data: "+body+"\n\n"+chatStreamTail, "text/event-stream"
			}
			if _, err := parse(t, ChatCompletionsPath, chatReq, answer(200, ct, body)); !errors.Is(err, derive.ErrSchema) {
				t.Errorf("%s %s: err %v, want a schema error", shape, usage, err)
			}
		}
	}
	// Duplicate and wrong-case members of the envelope.
	for _, body := range []string{
		`{"id":"c","model":"expensive","model":"cheap","usage":{"prompt_tokens":5,"completion_tokens":1}}`,
		`{"id":"c","usage":{"prompt_tokens":5,"completion_tokens":500},"usage":{"prompt_tokens":5,"completion_tokens":1}}`,
		`{"id":"c","usage":{"prompt_tokens":5,"completion_tokens":1},"usage":{"prompt_tokens":5,"completion_tokens":1}}`,
		`{`, ``, `null`, `5`,
	} {
		if _, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", body)); !errors.Is(err, derive.ErrSchema) {
			t.Errorf("%s: err %v, want a schema error", body, err)
		}
	}
	// "USAGE" is not usage: it is an unknown member, so the answer states none.
	if _, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", `{"id":"c","USAGE":{"prompt_tokens":5,"completion_tokens":1}}`)); !errors.Is(err, ErrSchema) {
		t.Errorf("USAGE read as usage: %v", err)
	}
}

// A stream that repeats its usage, changes its model or id, carries a frame that is not an object or is cut
// mid-frame, is unreadable: the count after a frame that could not be read is not known to be the whole.
func TestChatStreamAmbiguityIsUnreadable(t *testing.T) {
	good := "data: " + `{"id":"c","model":"m","usage":{"prompt_tokens":5,"completion_tokens":7}}` + "\n\n"
	for name, body := range map[string]string{
		"repeated usage":    good + good,
		"changed model":     `data: {"id":"c","model":"a"}` + "\n\n" + `data: {"id":"c","model":"b"}` + "\n\n" + good,
		"changed id":        `data: {"id":"a","model":"m"}` + "\n\n" + `data: {"id":"b","model":"m"}` + "\n\n" + good,
		"not an object":     "data: [1]\n\n" + good,
		"a bare word":       "data: nope\n\n" + good,
		"cut mid-frame":     good + `data: {"id":"c","mod`,
		"after the done":    "data: [DONE]\n\ndata: [oops]\n\n" + good,
		"duplicate usage":   `data: {"id":"c","usage":{"prompt_tokens":5,"completion_tokens":7},"usage":null}` + "\n\n",
		"escaped duplicate": `data: {"id":"c","usage":{"prompt_tokens":5,"completion_tokens":7},"\u0075sage":{"prompt_tokens":5,"completion_tokens":1}}` + "\n\n",
	} {
		if _, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "text/event-stream", body)); !errors.Is(err, derive.ErrSchema) {
			t.Errorf("%s: err %v, want a schema error", name, err)
		}
	}
}

// The Responses API's usage is input_tokens, output_tokens and input_tokens_details.cached_tokens.
func TestResponsesUsage(t *testing.T) {
	body := `{"id":"resp_1","object":"response","status":"completed","model":"gpt-x","output":[],
"usage":{"input_tokens":50,"input_tokens_details":{"cached_tokens":20},"output_tokens":9,"output_tokens_details":{"reasoning_tokens":4},"total_tokens":59}}`
	f, err := parse(t, ResponsesPath, `{"model":"gpt-x","input":"hi"}`, answer(200, "application/json", body))
	if err != nil || !sameUsage(f.Usage, record.Usage{Input: 30, Output: 9, CacheRead: 20}) || f.Model != "gpt-x" || f.ResponseID != "resp_1" {
		t.Fatalf("facts %+v usage %+v err %v", f, f.Usage, err)
	}
	for _, bad := range []string{`{"id":"r","usage":null}`, `{"id":"r"}`, `{"id":"r","usage":{"input_tokens":1}}`,
		`{"id":"r","usage":{"input_tokens":5,"output_tokens":1,"input_tokens_details":{"cached_tokens":6}}}`,
		`{"id":"r","usage":{"input_tokens":5,"output_tokens":-1}}`,
		`{"id":"r","usage":{"input_tokens":5,"output_tokens":1,"output_tokens":9}}`} {
		if _, err := parse(t, ResponsesPath, `{"model":"m"}`, answer(200, "application/json", bad)); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: err %v, want ErrSchema", bad, err)
		}
	}
}

func completedEvent(usage string) string {
	return `{"type":"response.completed","sequence_number":9,"response":{"id":"resp_1","object":"response","status":"completed","model":"gpt-x",` + usage + `}}`
}

// A streamed Responses answer states its usage in the response.completed event's response; the events before it
// carry usage null.
func TestResponsesStream(t *testing.T) {
	body := "event: response.created\ndata: " + `{"type":"response.created","response":{"id":"resp_1","status":"in_progress","usage":null}}` + "\n\n" +
		"event: response.output_text.delta\ndata: " + `{"type":"response.output_text.delta","delta":"ok"}` + "\n\n" +
		"event: response.completed\ndata: " + completedEvent(`"usage":{"input_tokens":50,"input_tokens_details":{"cached_tokens":20},"output_tokens":9,"total_tokens":59}`) + "\n\n"
	f, err := parse(t, ResponsesPath, `{"model":"gpt-x","stream":true}`, answer(200, "text/event-stream", body))
	if err != nil || !sameUsage(f.Usage, record.Usage{Input: 30, Output: 9, CacheRead: 20}) || !f.Stream || f.ResponseID != "resp_1" {
		t.Fatalf("facts %+v usage %+v err %v", f, f.Usage, err)
	}
	// The event name alone routes a payload with no type.
	body = "event: response.completed\ndata: " + `{"response":{"id":"r","usage":{"input_tokens":1,"output_tokens":2}}}` + "\n\n"
	if f, err = parse(t, ResponsesPath, `{"model":"m"}`, answer(200, "text/event-stream", body)); err != nil || f.Usage == nil || f.Usage.Output != 2 {
		t.Fatalf("by event name: %+v %v", f, err)
	}
}

// What a Responses stream does not state, it does not count: no completed event (an incomplete or failed one is not
// read), a second one, one without usage or without a response.
func TestResponsesStreamWithoutAUsableCompletedEventIsUnreadable(t *testing.T) {
	ok := "data: " + completedEvent(`"usage":{"input_tokens":5,"output_tokens":1}`) + "\n\n"
	for name, body := range map[string]string{
		"none":        "data: " + `{"type":"response.output_text.delta","delta":"x"}` + "\n\n",
		"incomplete":  "data: " + `{"type":"response.incomplete","response":{"id":"r","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n",
		"failed":      "data: " + `{"type":"response.failed","response":{"id":"r","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n",
		"twice":       ok + ok,
		"no usage":    "data: " + completedEvent(`"usage":null`) + "\n\n",
		"no response": "data: " + `{"type":"response.completed"}` + "\n\n",
		"bad counts":  "data: " + completedEvent(`"usage":{"input_tokens":5}`) + "\n\n",
		"empty":       "",
		"not object":  "data: 5\n\n" + ok,
		"typed twice": "data: " + `{"type":"response.completed","type":"x","response":{"id":"r","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n",
	} {
		_, err := parse(t, ResponsesPath, `{"model":"m"}`, answer(200, "text/event-stream", body))
		if !errors.Is(err, derive.ErrSchema) {
			t.Errorf("%s: err %v, want a schema error", name, err)
		}
		if noteOf(err) != "" {
			t.Errorf("%s: a Responses stream is not told to set a chat option", name)
		}
	}
}

// Only the endpoints read for usage are read; a path that spends nothing is silent; any other is an unparsed answer
// (spend unknown), and a spelling a server may resolve differently is not the endpoint.
func TestPathClassification(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		want           pathKind
	}{
		{"POST", "/v1/chat/completions", pathChat},
		{"POST", "/v1/chat/completions?x=1", pathChat},
		{"POST", "/v1//chat/./completions/", pathChat},
		{"POST", "https://api.openai.com/v1/chat/completions", pathChat},
		{"POST", "/v1/responses", pathResponses},
		{"post", "/v1/responses", pathResponses},
		{"GET", "/v1/chat/completions", pathOther},
		{"POST", "/V1/chat/completions", pathOther},
		{"POST", "/v1/chat/completions;x", pathOther},
		{"POST", "/v1/chat%2Fcompletions", pathChat}, // as the upstream may read it: usage is read, an error answer states none
		{"POST", "/v1/chat%252Fcompletions", pathOther},
		{"POST", "/openai/v1/chat/completions", pathOther},
		{"POST", "/v1/completions", pathOther},
		{"POST", "/v1/embeddings", pathOther},
		{"POST", "/v1/responses/resp_1/cancel", pathOther},
		{"GET", "/v1/responses/resp_1", pathOther},
		{"POST", "/v1/models", pathOther},
		{"GET", "/v1/models", pathSilent},
		{"HEAD", "/v1/models/gpt-x", pathSilent},
		{"GET", "/", pathSilent},
		{"HEAD", "/?x=1", pathSilent},
		{"POST", "/", pathOther},
		{"POST", "/?x", pathOther},
		{"PUT", "", pathOther},
		{"GET", "", pathOther},
		{"CONNECT", "api.openai.com:443", pathOther},
		{"POST", "ftp://x/v1/chat/completions", pathOther},
	} {
		if got := classifyPath(tc.method, tc.target); got != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.target, got, tc.want)
		}
	}
	p := New()
	if !p.Silent("GET", "/v1/models") || p.Silent("POST", "/v1/chat/completions") || p.Silent("POST", "/v1/embeddings") {
		t.Error("Silent does not follow the classification")
	}
	_, err := parse(t, "/v1/embeddings", `{}`, answer(200, "application/json", `{"usage":{"prompt_tokens":3,"total_tokens":3}}`))
	if !errors.Is(err, ErrSchema) {
		t.Errorf("an embeddings answer is read as spend: %v", err)
	}
	// An answer to POST / that states usage is not read as silent: it is unreadable, so a budgeted run ends.
	for _, target := range []string{"/", "/?x"} {
		if _, err := parse(t, target, chatReq, answer(200, "application/json", oaiChatAnswerForPaths)); !errors.Is(err, ErrSchema) {
			t.Errorf("POST %s answered 2xx with usage: err %v, want unreadable (ErrSchema)", target, err)
		}
		if New().Silent("POST", target) || !New().Silent("GET", target) {
			t.Errorf("POST %s is silent, or GET %s is not", target, target)
		}
	}
	listing := &derive.Message{Method: "GET", Path: "/v1/models", Header: http.Header{}}
	if f, err := p.Parse(listing, answer(200, "application/json", `{"data":[]}`)); err != nil || f.Usage != nil || f.ParserVersion != ParserVersion {
		t.Errorf("a model listing: %+v %v", f, err)
	}
}

// A body capture could not decode is an encoding failure, not a schema one.
func TestAnUndecodedBodyIsAnEncodingError(t *testing.T) {
	resp := answer(200, "application/json", "\x1f\x8b")
	resp.ContentEncoding, resp.Decoded = "gzip", false
	if _, err := parse(t, ChatCompletionsPath, chatReq, resp); !errors.Is(err, derive.ErrEncoding) {
		t.Fatalf("err = %v, want an encoding error", err)
	}
}

// Dispatch is by the declared provider and the declared host of an openai entry, and never by a host name of Tego's own.
func TestTheParserClaimsOnlyDeclaredHosts(t *testing.T) {
	if hosts := New().Hosts(); len(hosts) != 0 {
		t.Fatalf("a parser with no declared host claims %v", hosts)
	}
	p := New("LLM.Example.com", " ", "llm.example.com", "other.example")
	if hosts := p.Hosts(); len(hosts) != 2 || hosts[0] != "llm.example.com" || hosts[1] != "other.example" {
		t.Fatalf("hosts = %v", hosts)
	}
	d := derive.NewDispatcher([]derive.Parser{p})
	if _, ok := d.Parser("openai", "anything.example"); !ok {
		t.Error("the declared provider does not reach the parser")
	}
	if _, ok := d.Parser("", "llm.example.com"); !ok {
		t.Error("a declared host does not reach the parser")
	}
	if _, ok := d.Parser("", "api.openai.com"); ok {
		t.Error("a host nothing declared reaches the parser: dispatch guessed from a name")
	}
}

// The body bound: past MaxBody nothing is read, and a long stream of text with its usage at the end reads fine.
func TestHugeAnswers(t *testing.T) {
	big := answer(200, "application/json", `{"id":"c","usage":{"prompt_tokens":1,"completion_tokens":1}}`+strings.Repeat(" ", MaxBody))
	if _, err := parse(t, ChatCompletionsPath, chatReq, big); !errors.Is(err, ErrSchema) {
		t.Fatalf("a body past MaxBody: %v", err)
	}
	delta := "data: " + chunk(`{"index":0,"delta":{"content":"`+strings.Repeat("x", 1000)+`"}}`) + `,"usage":null}` + "\n\n"
	body := strings.Repeat(delta, 6000) + "data: " + chunk("") + `,"usage":{"prompt_tokens":100,"completion_tokens":` + strconv.Itoa(6000) + `}}` + "\n\n" + chatStreamTail
	f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "text/event-stream", body))
	if err != nil || f.Usage == nil || f.Usage.Output != 6000 || f.Usage.Input != 100 {
		t.Fatalf("a %d byte stream: %+v %v", len(body), f.Usage, err)
	}
	// One frame of megabytes of extension members around a small usage still reads the usage.
	fat := `{"id":"c","extra":"` + strings.Repeat("y", 4<<20) + `","usage":{"prompt_tokens":3,"completion_tokens":4}}`
	if f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", fat)); err != nil || f.Usage == nil || f.Usage.Output != 4 {
		t.Fatalf("a fat body: %+v %v", f.Usage, err)
	}
}

func TestEveryNumberFitsOrIsRefused(t *testing.T) {
	for _, n := range []string{"2147483648", "9223372036854775807", "9223372036854775808", "1e3", "1E400", "-0"} {
		body := `{"id":"c","usage":{"prompt_tokens":` + n + `,"completion_tokens":1}}`
		f, err := parse(t, ChatCompletionsPath, chatReq, answer(200, "application/json", body))
		if err == nil && (f.Usage == nil || f.Usage.Input < 0 || f.Usage.Output < 0) {
			t.Errorf("%s: usage %+v with no error", n, f.Usage)
		}
	}
}

const oaiChatAnswerForPaths = `{"id":"c","model":"m","usage":{"prompt_tokens":120,"completion_tokens":30}}`

// A body cut short (the client closed early, or a capture cap) is never read, whatever its prefix holds: a server that
// states usage in every chunk (a request option of some servers) would otherwise have an early chunk's count taken
// for the answer's.
func TestATruncatedAnswerIsNeverReadable(t *testing.T) {
	everyChunk := "data: " + `{"id":"c","model":"m","choices":[{"delta":{"content":"o"}}],"usage":{"prompt_tokens":12,"completion_tokens":1}}` + "\n\n"
	whole := `{"id":"c","model":"m","usage":{"prompt_tokens":12,"completion_tokens":7}}`
	for name, tc := range map[string]struct {
		path, ct, body string
	}{
		"chat stream, one usage chunk kept":     {ChatCompletionsPath, "text/event-stream", everyChunk},
		"chat stream, the done marker kept":     {ChatCompletionsPath, "text/event-stream", everyChunk + "data: [DONE]\n\n"},
		"chat whole":                            {ChatCompletionsPath, "application/json", whole},
		"responses whole":                       {ResponsesPath, "application/json", `{"id":"r","usage":{"input_tokens":1,"output_tokens":2}}`},
		"responses stream, the completed event": {ResponsesPath, "text/event-stream", "data: " + completedEvent(`"usage":{"input_tokens":5,"output_tokens":1}`) + "\n\n"},
	} {
		resp := answer(200, tc.ct, tc.body)
		if _, err := parse(t, tc.path, chatReq, answer(200, tc.ct, tc.body)); err != nil {
			t.Fatalf("%s: the untruncated answer is unreadable: %v", name, err)
		}
		resp.Truncated = true
		f, err := parse(t, tc.path, chatReq, resp)
		if !errors.Is(err, derive.ErrSchema) || f.Usage != nil {
			t.Errorf("%s: truncated: usage %+v err %v, want unreadable", name, f.Usage, err)
		}
		// Its note is the cut-off one, never the advice to ask the API for usage in the stream.
		if got := noteOf(err); got != derive.NoteAnswerCutOff {
			t.Errorf("%s: truncated: note %q, want %q", name, got, derive.NoteAnswerCutOff)
		}
	}
}
