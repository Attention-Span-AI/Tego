// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"errors"
	"testing"
)

func TestMessageRejectsAmbiguousAccounting(t *testing.T) {
	for _, body := range []string{
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":500},"usage":{"input_tokens":5,"output_tokens":1}}`,
		`{"id":"m","model":"expensive","model":"cheap","usage":{"input_tokens":5,"output_tokens":1}}`,
		`{"id":"m","type":"message","type":"error","usage":{"input_tokens":5,"output_tokens":500}}`,
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":500,"output_tokens":1}}`,
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":500,"\u006futput_tokens":1}}`,
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1,"cache_creation":{"ephemeral_1h_input_tokens":500,"ephemeral_1h_input_tokens":1}}}`,
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1,"server_tool_use":{"web_search_requests":500,"web_search_requests":1}}}`,
		`{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1,"server_tool_use":{"web_search_requests":9223372036854775808}}}`,
	} {
		if _, err := ParseResponse(200, []byte(body)); !errors.Is(err, ErrSchema) {
			t.Errorf("ambiguous accounting accepted: %s (error %v)", body, err)
		}
	}
}

func TestStreamRejectsAmbiguousAccounting(t *testing.T) {
	const start = `data: {"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const final = `data: {"type":"message_delta","usage":{"output_tokens":1}}` + "\n\n" +
		`data: {"type":"message_stop"}` + "\n\n"
	for _, payload := range []string{
		`{"type":"message_delta","usage":{"output_tokens":500,"output_tokens":1}}`,
		`{"type":"message_delta","usage":{"output_tokens":500},"usage":{"output_tokens":1}}`,
		`{"type":"message_delta","type":"ping","usage":{"output_tokens":500}}`,
		`{"type":"ping","type":"error","error":{}}`,
		`{"type":"message_start","message":{"model":"x","usage":{"input_tokens":500,"output_tokens":1}},"message":{"model":"x","usage":{"input_tokens":1,"output_tokens":1}}}`,
	} {
		body := []byte(start + "data: " + payload + "\n\n" + final)
		var scanner StreamUsageScanner
		_, _ = scanner.Write(body)
		_, _, _ = scanner.Result()
		if !scanner.Incomplete() {
			t.Errorf("ambiguous accounting recovered after a later count: %s", payload)
		}
		resp, _, err := ParseStream(body)
		if !errors.Is(err, ErrSchema) || resp == nil || !resp.incompleteUsage {
			t.Errorf("ParseStream = %+v, %v for %s; want incomplete accounting", resp, err, payload)
		}
	}
}

func TestEmptyNamedAccountingFrameStaysIncomplete(t *testing.T) {
	const start = `data: {"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const final = `data: {"type":"message_delta","usage":{"output_tokens":1}}` + "\n\n" +
		`data: {"type":"message_stop"}` + "\n\n"
	for _, name := range []string{EventMessageStart, EventMessageDelta} {
		body := []byte(start + "event: " + name + "\ndata: \n\n" + final)
		var scanner StreamUsageScanner
		_, _ = scanner.Write(body)
		_, _, _ = scanner.Result()
		if !scanner.Incomplete() {
			t.Errorf("empty %s recovered after a later count", name)
		}
		resp, _, err := ParseStream(body)
		if !errors.Is(err, ErrSchema) || resp == nil || !resp.incompleteUsage {
			t.Errorf("empty %s: ParseStream = %+v, %v, want incomplete accounting", name, resp, err)
		}
	}
}

func TestDuplicateErrorRoutingCannotBeANoSpendAnswer(t *testing.T) {
	body := []byte("data: " + `{"type":"ping","type":"error","error":{}}` + "\n\n")
	var scanner StreamUsageScanner
	_, _ = scanner.Write(body)
	_, _, _ = scanner.Result()
	if !scanner.Incomplete() {
		t.Fatal("ambiguous error routing was not incomplete")
	}
	resp, _, err := ParseStream(body)
	if !errors.Is(err, ErrSchema) || resp != nil && resp.ErrorAnswer {
		t.Fatalf("ambiguous error routing = %+v, %v; want schema failure, not a no-spend answer", resp, err)
	}
}

func TestMessageStillReadsUsageBesideDuplicateToolInput(t *testing.T) {
	body := []byte(`{"id":"m","model":"x","extension":{"x":1,"x":2},"content":[{"type":"tool_use","name":"a","input":{"x":1,"x":2}}],"usage":{"input_tokens":5,"output_tokens":7,"extension":{"x":1,"x":2},"server_tool_use":{"web_search_requests":2,"metadata":{"x":1,"x":2}}}}`)
	resp, err := ParseResponse(200, body)
	if err != nil || resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 7 || resp.Usage.ServerToolUse["web_search_requests"] != 2 {
		t.Fatalf("usage beside tool input = %+v, %v", resp, err)
	}
}
