// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// reference is a plain decode of what a body says its usage is, written independently of the parser: encoding/json into
// generic maps (names matched case-sensitively, as the API writes them), the stream read line by line for the lines that
// are a whole `data:` object. It is the yardstick the invariants below hold the parser to.
type reference struct {
	in, out float64 // the largest counts any readable usage stated, and whether any was
	found   bool
}

func (r *reference) add(in, out any) {
	i, ok1 := in.(float64)
	o, ok2 := out.(float64)
	if !ok1 || !ok2 || i < 0 || o < 0 || i >= 1<<53 || o >= 1<<53 {
		return
	}
	r.in, r.out, r.found = max(r.in, i), max(r.out, o), true
}

var lineEnd = regexp.MustCompile(`\r\n|\r|\n`)

func referenceOf(body []byte, path string, stream bool) reference {
	var ref reference
	inKey, outKey := "prompt_tokens", "completion_tokens"
	if path == ResponsesPath {
		inKey, outKey = "input_tokens", "output_tokens"
	}
	usageOf := func(obj map[string]any) {
		if u, ok := obj["usage"].(map[string]any); ok {
			ref.add(u[inKey], u[outKey])
		}
	}
	if !stream {
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			usageOf(obj)
		}
		return ref
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	name := "" // the event: name of the frame in progress, which routes a payload that names no type
	for _, line := range lineEnd.Split(string(body), -1) {
		if line == "" {
			name = ""
			continue
		}
		if v, ok := bytes.CutPrefix([]byte(line), []byte("event:")); ok {
			name = string(bytes.TrimPrefix(v, []byte(" ")))
			continue
		}
		data, ok := bytes.CutPrefix([]byte(line), []byte("data:"))
		if !ok {
			continue
		}
		var obj map[string]any
		if json.Unmarshal(bytes.TrimSpace(bytes.TrimPrefix(data, []byte(" "))), &obj) != nil {
			continue
		}
		if path == ResponsesPath {
			typ, _ := obj["type"].(string)
			if typ == "" {
				typ = name
			}
			if typ != EventResponseCompleted {
				continue
			}
			if resp, ok := obj["response"].(map[string]any); ok {
				usageOf(resp)
			}
			continue
		}
		usageOf(obj)
	}
	return ref
}

// checkFacts holds the properties every reading of network-controlled bytes keeps (§9 Fuzzing):
//   - it returns without panicking, and fails only as a schema or encoding error, with no usage beside the error;
//   - a cut-short answer (Truncated) is never read;
//   - an accepted usage is a plain non-negative reading with no cache write or bound;
//   - against the reference decode of the same bytes, an accepted whole answer states exactly its prompt (Input +
//     CacheRead == prompt_tokens or input_tokens) and its completion, and an accepted stream counts no less than the
//     largest usage any one of its lines states;
//   - its model and id are never longer than the body.
func checkFacts(t *testing.T, path string, body []byte, sseFlag, cut bool, f derive.Facts, err error) {
	t.Helper()
	if err != nil {
		if !errors.Is(err, derive.ErrSchema) && !errors.Is(err, derive.ErrEncoding) {
			t.Fatalf("%s failed with %v, which is neither a schema nor an encoding error", path, err)
		}
		if f.Usage != nil {
			t.Fatalf("%s returned usage %+v beside the error %v", path, f.Usage, err)
		}
		return
	}
	if cut {
		t.Fatalf("%s: a truncated answer was accepted: %+v", path, f)
	}
	if f.ParserVersion != ParserVersion {
		t.Fatalf("%s: parser version %q", path, f.ParserVersion)
	}
	if len(f.Model) > len(body) || len(f.ResponseID) > len(body) {
		t.Fatalf("%s: a model or id longer than the body", path)
	}
	u := f.Usage
	if u == nil {
		return
	}
	if u.Input < 0 || u.Output < 0 || u.CacheRead < 0 || u.CacheWrite != 0 || u.OutputBound || u.Modified {
		t.Fatalf("%s: usage %+v is not a plain non-negative reading", path, *u)
	}
	stream := sseFlag || isStream(false, "", body)
	ref := referenceOf(body, path, stream)
	if !ref.found {
		t.Fatalf("%s: accepted usage %+v the reference decode of the same bytes does not find", path, *u)
	}
	if stream {
		if float64(u.Input+u.CacheRead) < ref.in || float64(u.Output) < ref.out {
			t.Fatalf("%s: stream counted %+v, lower than the reference's %v in and %v out", path, *u, ref.in, ref.out)
		}
		return
	}
	if float64(u.Input+u.CacheRead) != ref.in || float64(u.Output) != ref.out {
		t.Fatalf("%s: counted input+cache %d and output %d, the reference decode says %v and %v", path, u.Input+u.CacheRead, u.Output, ref.in, ref.out)
	}
}

func fuzzSeeds(f *testing.F) {
	for _, s := range []string{
		`{"id":"c","model":"m","usage":{"prompt_tokens":12,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":4}}}`,
		`{"id":"r","model":"m","usage":{"input_tokens":12,"output_tokens":7,"input_tokens_details":{"cached_tokens":4}}}`,
		"data: {\"id\":\"c\",\"usage\":null}\n\ndata: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n",
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n",
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\r\r",
		`{"usage":{"prompt_tokens":-1,"completion_tokens":2}}`,
		`{"usage":{"prompt_tokens":1,"prompt_tokens":2,"completion_tokens":2}}`,
		`{"usage":{"prompt_tokens":3,"completion_tokens":2},"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		"data: \n\n: x\n\nretry: 1\n\ndata:{",
		`{}`, ``, `null`,
	} {
		f.Add([]byte(s), false, false)
		f.Add([]byte(s), true, true)
	}
}

func fuzzParse(t *testing.T, path string, body []byte, sse, cut bool) {
	p := New()
	req := &derive.Message{Method: "POST", Path: path, Body: []byte(`{"model":"m"}`), Header: http.Header{}, Decoded: true}
	resp := &derive.Message{Status: 200, Body: body, Header: http.Header{}, Decoded: true, SSE: sse, WireSSE: true, Truncated: cut}
	facts, err := p.Parse(req, resp)
	checkFacts(t, path, body, sse, cut, facts, err)
}

// FuzzParseChat reads any bytes as a chat completion, whole and as a stream, cut short or not.
func FuzzParseChat(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, body []byte, sse, cut bool) { fuzzParse(t, ChatCompletionsPath, body, sse, cut) })
}

// FuzzParseResponses reads any bytes as a Responses API answer, whole and as a stream, cut short or not.
func FuzzParseResponses(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, body []byte, sse, cut bool) { fuzzParse(t, ResponsesPath, body, sse, cut) })
}

// FuzzClassifyPath: no target panics the classifier, and what it calls silent is also what Silent says.
func FuzzClassifyPath(f *testing.F) {
	for _, s := range []string{"/v1/chat/completions", "/", "https://h/v1/responses", "/v1/models/x", "%", "/v1/chat/completions;x", "\x00"} {
		f.Add("POST", s)
		f.Add("GET", s)
	}
	f.Fuzz(func(t *testing.T, method, target string) {
		if (classifyPath(method, target) == pathSilent) != New().Silent(method, target) {
			t.Fatalf("Silent disagrees with the classification for %q %q", method, target)
		}
		if classifyPath(method, target) == pathSilent && method != "GET" && method != "HEAD" && method != "get" && method != "head" {
			if m := bytes.ToUpper([]byte(method)); string(m) != "GET" && string(m) != "HEAD" {
				t.Fatalf("%q %q is silent, and only a GET or HEAD may be", method, target)
			}
		}
	})
}
