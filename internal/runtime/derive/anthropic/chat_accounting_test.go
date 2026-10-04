// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

func TestChatAccountingRequiresUnambiguousExplicitCounters(t *testing.T) {
	for _, body := range []string{
		`{"model":"x","usage":{}}`,
		`{"model":"x","usage":{"prompt_tokens":5}}`,
		`{"model":"x","usage":{"prompt_tokens":null,"completion_tokens":1}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":null}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":500,"completion_tokens":1}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":500,"\u0063ompletion_tokens":1}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":500},"usage":{"prompt_tokens":5,"completion_tokens":1}}`,
		`{"model":"expensive","model":"cheap","usage":{"prompt_tokens":5,"completion_tokens":1}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":-1}}}`,
		`{"model":"x","usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":0,"cached_tokens":5}}}`,
	} {
		for _, stream := range []bool{false, true} {
			wire, ct := body, "application/json"
			if stream {
				wire, ct = "data: "+body+"\n\n"+`data: {"model":"x","usage":{"prompt_tokens":5,"completion_tokens":1}}`+"\n\n", "text/event-stream"
			}
			req := &derive.Message{Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"x","messages":[]}`), Decoded: true}
			if _, err := New().Parse(req, response([]byte(wire), ct)); !errors.Is(err, ErrSchema) {
				t.Errorf("chat accounting %s stream %v: error %v, want ErrSchema", body, stream, err)
			}
		}
	}
}

func TestChatStreamReadsSharedSSEFraming(t *testing.T) {
	body := "\xef\xbb\xbfdata: {\"model\":\"x\",\rdata: \"usage\":{\"prompt_tokens\":5,\"completion_tokens\":7}}\r\rdata: [DONE]\r\r"
	req := &derive.Message{Method: "POST", Path: "/v1/chat/completions", Body: []byte(`{"model":"x","messages":[]}`), Decoded: true}
	facts, err := New().Parse(req, response([]byte(body), "text/event-stream"))
	if err != nil || facts.Usage == nil || facts.Usage.Input != 5 || facts.Usage.Output != 7 {
		t.Fatalf("chat CR-only multiline SSE = %+v, %v", facts, err)
	}
}

func TestChatStreamKeepsResponseIdentityAcrossUsageOnlyChunk(t *testing.T) {
	body := "data: " + `{"id":"expensive-answer","model":"expensive","choices":[]}` + "\n\n" +
		"data: " + `{"usage":{"prompt_tokens":5,"completion_tokens":7}}` + "\n\n" +
		"data: " + `{"id":"expensive-answer","model":"expensive","choices":[]}` + "\n\ndata: [DONE]\n\n"
	req := &derive.Message{Method: "POST", Path: ChatCompletionsPath,
		Body: []byte(`{"model":"cheap","messages":[]}`), Decoded: true}
	facts, err := New().Parse(req, response([]byte(body), "text/event-stream"))
	if err != nil || facts.Model != "expensive" || facts.ResponseID != "expensive-answer" ||
		facts.Usage == nil || facts.Usage.Input != 5 || facts.Usage.Output != 7 {
		t.Fatalf("usage-only final chunk lost response identity: %+v, %v", facts, err)
	}
}

func TestChatStreamRejectsUnreadableOrAmbiguousAccountingSequence(t *testing.T) {
	const initial = "data: " + `{"id":"answer","model":"expensive","choices":[]}` + "\n\n"
	const final = "data: " + `{"usage":{"prompt_tokens":5,"completion_tokens":7}}` + "\n\ndata: [DONE]\n\n"
	for _, bad := range []string{
		"data: null\n\n",
		"data: [garbage]\n\n",
		"data: []\n\n",
		"data: 5\n\n",
		"data: \"ignored\"\n\n",
		"data: " + `{"model":"cheap"}` + "\n\n",
		"data: " + `{"id":"other-answer"}` + "\n\n",
		"data: " + `{"usage":{"prompt_tokens":5000,"completion_tokens":5000}}` + "\n\n",
	} {
		req := &derive.Message{Method: "POST", Path: ChatCompletionsPath,
			Body: []byte(`{"model":"cheap","messages":[]}`), Decoded: true}
		if _, err := New().Parse(req, response([]byte(initial+bad+final), "text/event-stream")); !errors.Is(err, ErrSchema) {
			t.Errorf("chat stream ignored %q: error %v, want ErrSchema", bad, err)
		}
	}
}
