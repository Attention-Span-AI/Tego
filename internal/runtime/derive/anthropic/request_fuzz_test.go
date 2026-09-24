// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// FuzzParseRequest: the request body is written by the agent, so ParseRequest reads bytes another party
// controls (ARCHITECTURE §16), and until this target only the response half had one. The properties are
// R28's and R29's: a body is either a request with a model, taken from valid JSON, or a schema error, never
// a panic or another kind of error; and through Parse the request half can only ever add an unparsed
// decision beside the response's facts (why=schema), never fail the exchange or lose the response, while a
// readable request supplies the model a response without one lacks.
func FuzzParseRequest(f *testing.F) {
	seed(f, "messages-request.json")
	f.Add([]byte(`{"model":"claude-opus-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{"model":"","messages":[]}`))
	f.Add([]byte(`{"model":"m","system":"s","tools":[{"name":"t","input_schema":{}}],"stream":true}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`))
	f.Add([]byte(`{"model":1}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := ParseRequest(body)
		if err != nil {
			if !errors.Is(err, derive.ErrSchema) {
				t.Fatalf("ParseRequest failed with %v, which is not a schema error", err)
			}
		} else {
			if req.Model == "" {
				t.Fatal("a request without a model parsed (R28)")
			}
			if !json.Valid(body) {
				t.Fatal("a body that is not valid JSON parsed as a request")
			}
		}

		// A response with no model of its own, so the model can only come from the request.
		resp := &derive.Message{Status: 200, Body: []byte(`{"id":"msg_1","type":"message",` +
			`"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":1,"output_tokens":1}}`)}
		facts, perr := New().Parse(&derive.Message{Method: "POST", Path: MessagesPath, Body: body}, resp)
		if perr != nil {
			t.Fatalf("the request half failed the exchange: %v", perr)
		}
		if facts.ResponseID != "msg_1" || facts.Usage == nil {
			t.Fatalf("an unreadable request lost the response's facts: %+v", facts)
		}
		unparsed := len(facts.Decisions) > 0 && facts.Decisions[0].Unparsed
		// The model a charge is priced by is the one spelled exactly "model"; a body naming it
		// in another case, or twice, has none, and is unparsed.
		model, modelOK := requestModel(body)
		switch {
		case (err != nil || !modelOK) && (!unparsed || facts.Decisions[0].Why != derive.WhySchema):
			t.Fatalf("an unreadable request left decisions %+v, want one unparsed why=schema first (R29)", facts.Decisions)
		case err == nil && modelOK && unparsed:
			t.Fatalf("a readable request was recorded as unparsed: %+v", facts.Decisions)
		case err == nil && modelOK && facts.Model != model:
			t.Fatalf("model %q, want the request's %q (R28)", facts.Model, model)
		}
	})
}
