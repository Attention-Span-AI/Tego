// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"net/http"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
)

// TestUnmeteredExchanges (capture-derive.md R40's labeling by shape on a model host): an exchange on a model endpoint whose spend the facts cannot count says so
// (Facts.Unmetered), with one unparsed decision, and one that spends nothing stays silent.
func TestUnmeteredExchanges(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	const host = "api.anthropic.com"
	cases := []struct {
		name, provider, method, path string
		status                       int
		body                         string
		unmetered                    bool
		decisions                    int
		usageIn                      int
	}{
		{"chat completions is read in the OpenAI shape", "anthropic", "POST", "/v1/chat/completions", 200,
			`{"id":"c1","model":"claude-opus-5","usage":{"prompt_tokens":150000,"completion_tokens":5000}}`, false, 0, 150000},
		{"a chat completion with no usage is unmetered", "anthropic", "POST", "/v1/chat/completions", 200,
			`{"id":"c1","model":"claude-opus-5"}`, true, 1, 0},
		// limits-check-doctor-cli.md R1 (a): a 2xx message that reports no usage object spent what nothing read.
		// It was charged zero tokens, so a budget passed it unseen.
		{"a message with no usage is unmetered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[]}`, true, 1, 0},
		{"a message whose usage has no output_tokens is unmetered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"usage":{"input_tokens":5}}`, true, 1, 0},
		{"a message with an empty usage is unmetered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"usage":{}}`, true, 1, 0},
		{"a message with a null usage is unmetered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"usage":null}`, true, 1, 0},
		{"a message whose usage key is misspelt is unmetered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"USAGE":{"input_tokens":9}}`, true, 1, 0},
		{"a message with usage is metered", "anthropic", "POST", "/v1/messages", 200,
			`{"id":"msg_1","type":"message","model":"claude-opus-5","content":[],"usage":{"input_tokens":9,"output_tokens":1}}`,
			false, 0, 9},
		{"batch creation is unmetered", "anthropic", "POST", "/v1/messages/batches", 200,
			`{"id":"msgbatch_1","type":"message_batch"}`, true, 1, 0},
		{"a refused batch creation spent nothing", "anthropic", "POST", "/v1/messages/batches", 400,
			`{"type":"error"}`, false, 0, 0},
		{"a batch's status is silent", "anthropic", "GET", "/v1/messages/batches/msgbatch_1", 200, `{}`, false, 0, 0},
		{"a batch's results are not read", "anthropic", "GET", "/v1/messages/batches/msgbatch_1/results", 200,
			`{}`, true, 1, 0},
		{"model listing is silent", "anthropic", "GET", "/v1/models", 200, `{}`, false, 0, 0},
		{"token counting is silent", "anthropic", "POST", "/v1/messages/count_tokens", 200, `{}`, false, 0, 0},
		{"the Files API is silent", "anthropic", "POST", "/v1/files", 200, `{}`, false, 0, 0},
		{"telemetry outside /v1 is silent", "anthropic", "POST", "/api/event_logging/batch", 200, `{}`, false, 0, 0},
		{"an unknown API path is unmetered", "anthropic", "POST", "/v1/complete", 200, `{"completion":"x"}`, true, 1, 0},
		{"an unknown API path's error spent nothing", "anthropic", "POST", "/v1/complete", 404, `nope`, false, 1, 0},
		{"a declared endpoint with no parser is unmetered", "mistral", "POST", "/v1/chat", 200, `{}`, true, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &derive.Message{Method: tc.method, Path: tc.path, Header: http.Header{},
				Body: []byte(`{"model":"claude-opus-5","messages":[]}`), Decoded: true}
			resp := &derive.Message{Status: tc.status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: []byte(tc.body), Decoded: true}
			h := host
			if tc.provider == "mistral" {
				h = "api.mistral.ai"
			}
			res, err := d.Handle(req, resp, testMeta(tc.provider, h))
			if err != nil {
				t.Fatal(err)
			}
			if res.Facts.Unmetered != tc.unmetered {
				t.Errorf("Unmetered = %v, want %v", res.Facts.Unmetered, tc.unmetered)
			}
			if len(res.Events) != tc.decisions {
				t.Errorf("%d decision events, want %d", len(res.Events), tc.decisions)
			}
			in := 0
			if res.Facts.Usage != nil {
				in = res.Facts.Usage.Input
			}
			if in != tc.usageIn {
				t.Errorf("usage input = %d, want %d", in, tc.usageIn)
			}
		})
	}
}

// TestUndeclaredHostIsNotUnmetered is the uprobe path's other traffic: a TLS peer no models[] entry names is
// not a model call, so its unparsed exchange ends no budgeted run.
func TestUndeclaredHostIsNotUnmetered(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	req, resp := pair()
	res, _ := d.Handle(req, resp, testMeta("", "pypi.org"))
	if res.Facts.Unmetered {
		t.Error("an undeclared host's exchange was reported unmetered")
	}
}

// TestChatCompletionStream reads usage out of the last chunk of a streamed chat completion, and a stream
// that never carried usage is unmetered.
func TestChatCompletionStream(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	req := &derive.Message{Method: "POST", Path: "/v1/chat/completions", Header: http.Header{},
		Body: []byte(`{"model":"claude-opus-5","stream":true}`), Decoded: true}
	stream := func(body string) *derive.Message {
		return &derive.Message{Status: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
			Body: []byte(body), Decoded: true, SSE: true}
	}
	res, _ := d.Handle(req, stream(`{"id":"c","model":"claude-opus-5","choices":[]}`+"\n"+
		`{"id":"c","model":"claude-opus-5","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":7,`+
		`"prompt_tokens_details":{"cached_tokens":4}}}`+"\n[DONE]"), testMeta("anthropic", "api.anthropic.com"))
	if u := res.Facts.Usage; u == nil || u.Input != 6 || u.CacheRead != 4 || u.Output != 7 || res.Facts.Unmetered {
		t.Errorf("facts = %+v usage %+v", res.Facts, res.Facts.Usage)
	}
	res, _ = d.Handle(req, stream(`{"id":"c","model":"claude-opus-5","choices":[]}`), testMeta("anthropic", "api.anthropic.com"))
	if !res.Facts.Unmetered {
		t.Error("a stream with no usage was not unmetered")
	}
}
