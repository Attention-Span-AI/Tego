// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// A whole message whose usage carries no output_tokens is unreadable spend, not zero output (R1 (a)).
func TestMessageUsageWithoutOutputIsSchemaError(t *testing.T) {
	for _, u := range []string{`{"input_tokens":5}`, `{}`, `{"input_tokens":5,"output_tokens":null}`} {
		body := []byte(`{"id":"m","type":"message","model":"x","content":[],"usage":` + u + `}`)
		if _, err := ParseResponse(200, body); !errors.Is(err, ErrSchema) {
			t.Errorf("usage %s: err = %v, want ErrSchema", u, err)
		}
	}
	body := []byte(`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":5,"output_tokens":0}}`)
	if _, err := ParseResponse(200, body); err != nil {
		t.Errorf("output_tokens 0 is a reported count: %v", err)
	}
}

// TestSilentSubpathsFailClosedOnAmbiguousSpellings: a silent subpath under /v1 was matched on its prefix alone, so
// a spelling a normalizing server serves as /v1/messages ("..;" as a dot segment, a backslash as a slash) was
// recorded as silent and no budget saw the model turn (R25).
func TestSilentSubpathsFailClosedOnAmbiguousSpellings(t *testing.T) {
	for _, p := range []string{
		"/v1/models/..;/messages", `/v1/models/..\messages`, "/v1/files/x/..;/messages", "/v1/models/%2e%2e;/messages",
		"/v1/messages/batches/x;y", "/v1/models/%252e%252e/messages", "/v1/files/%252e%252e/messages", "/v1/models/%252f..%252fmessages", "/v1/models/a\x01b", "/v1/files/café",
	} {
		for _, m := range []string{"POST", "GET", "DELETE"} {
			if got := classifyPath(m, p); got != pathOther {
				t.Errorf("classifyPath(%s, %q) = %v, want a path it does not read", m, p, got)
			}
		}
	}
	for _, p := range []string{"/v1/models", "/v1/models/claude-opus-5", "/v1/files/file_01", "/v1/messages/count_tokens"} {
		if got := classifyPath("GET", p); got != pathSilent {
			t.Errorf("classifyPath(%q) = %v, want silent", p, got)
		}
	}
}

// TestUsageBillingModifiers: a response billed under a modifier the counters do not show (fast speed, a
// non-standard tier, geo pinning, extra iterations) is marked modified, whole or streamed; plain ones are not.
func TestUsageBillingModifiers(t *testing.T) {
	for _, tc := range []struct {
		usage      string
		want       bool
		incomplete bool
	}{
		{`{"input_tokens":1}`, false, false},
		{`{"input_tokens":1,"speed":"standard","service_tier":"standard","inference_geo":"global"}`, false, false},
		{`{"input_tokens":1,"inference_geo":"not_available","speed":null,"iterations":null}`, false, false},
		{`{"input_tokens":1,"iterations":[{"type":"message","input_tokens":1}]}`, false, false},
		{`{"input_tokens":1,"speed":"fast"}`, true, false},
		{`{"input_tokens":1,"service_tier":"priority"}`, true, false},
		{`{"input_tokens":1,"inference_geo":"us"}`, true, false},
		{`{"input_tokens":1,"iterations":[{"type":"compaction"},{"type":"message"}]}`, true, true},
		{`{"input_tokens":1,"iterations":[{"type":"message"},{"type":"message"}]}`, true, true},
		{`{"input_tokens":1,"speed":7}`, true, false},
	} {
		body := []byte(`{"id":"m","type":"message","model":"m","role":"assistant","content":[],"usage":` + strings.Replace(tc.usage, `{`, `{"output_tokens":1,`, 1) + `}`)
		resp, err := ParseResponse(200, body)
		if err != nil {
			t.Fatalf("%s: %v", tc.usage, err)
		}
		if resp.incompleteUsage != tc.incomplete {
			t.Errorf("whole %s: incomplete = %v, want %v", tc.usage, resp.incompleteUsage, tc.incomplete)
		}
		if got := resp.Usage.Record().Modified; got != tc.want {
			t.Errorf("whole %s: Modified = %v, want %v", tc.usage, got, tc.want)
		}
		stream := []byte("event: message_start\n" +
			`data: {"type":"message_start","message":{"id":"m","type":"message","model":"m","role":"assistant","content":[],"usage":{"input_tokens":1}}}` + "\n\n" +
			"event: message_delta\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":` + tc.usage + `}` + "\n\n" +
			"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n")
		sresp, _, err := ParseStream(stream)
		if tc.incomplete && !errors.Is(err, ErrSchema) || !tc.incomplete && err != nil {
			t.Fatalf("%s: error %v, incomplete %v", tc.usage, err, tc.incomplete)
		}
		if sresp == nil || sresp.incompleteUsage != tc.incomplete {
			t.Fatalf("stream %s: response %+v, want incomplete %v", tc.usage, sresp, tc.incomplete)
		}
		if got := sresp.Usage.Record().Modified; got != tc.want {
			t.Errorf("stream %s: Modified = %v, want %v", tc.usage, got, tc.want)
		}
	}
}

// TestCutStreamWithServerToolsIsUnmetered: server-tool counts and the input the tool loop grows are reported only in
// the message_delta a cut stream lost, so max_tokens as output bounds nothing and the exchange stays unmetered
// (ADR 0036 note 2026-09-30). A request with custom tools only is bounded as before.
func TestCutStreamWithServerToolsIsUnmetered(t *testing.T) {
	for _, tc := range []struct {
		name      string
		req       string
		unmetered bool
	}{
		{"no tools", `{"model":"m","max_tokens":4096,"stream":true,"messages":[]}`, false},
		{"custom tools", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"name":"a","description":"x, y: z","input_schema":{"type":"object","properties":{"type":{"type":"string"}}}},{"type":"custom","name":"b"}],"messages":[]}`, false},
		{"null tools", `{"model":"m","max_tokens":4096,"stream":true,"tools":null,"messages":[]}`, false},
		{"web search", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"name":"a","input_schema":{}},{"type":"web_search_20250305","name":"web_search","max_uses":5}],"messages":[]}`, true},
		{"type after name", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"name":"web_search","type":"web_search_20250305"}],"messages":[]}`, true},
		{"escaped key", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"type":"code_execution_20250522","name":"c"}],"messages":[]}`, true},
		{"escaped value", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"type":"custom","name":"c"}],"messages":[]}`, false},
		{"type not a string", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"type":7,"name":"c"}],"messages":[]}`, true},
		{"type in another case", `{"model":"m","max_tokens":4096,"stream":true,"tools":[{"Type":"web_search_1","name":"c"}],"messages":[]}`, true},
		{"mcp servers", `{"model":"m","max_tokens":4096,"stream":true,"mcp_servers":[{"type":"url","url":"https://x","name":"m"}],"messages":[]}`, true},
		{"mcp servers other case", `{"model":"m","max_tokens":4096,"stream":true,"MCP_Servers":[],"messages":[]}`, true},
		{"mcp servers fully escaped", `{"model":"m","max_tokens":4096,"stream":true,"` + escapeAll("mcp_servers") + `":[],"messages":[]}`, true},
		{"mcp servers ten escaped", `{"model":"m","max_tokens":4096,"stream":true,"` + escapeAll("mcp_server") + `s":[],"messages":[]}`, true},
		{"mcp servers twice", `{"model":"m","max_tokens":4096,"stream":true,"mcp_servers":[],"mcp_servers":[],"messages":[]}`, true},
		{"tools twice", `{"model":"m","max_tokens":4096,"stream":true,"tools":[],"tools":[],"messages":[]}`, true},
		{"tools not an array", `{"model":"m","max_tokens":4096,"stream":true,"tools":{"type":"web_search"},"messages":[]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := response([]byte(cutStream), "text/event-stream")
			resp.SSE = true
			facts, err := New().Parse(request([]byte(tc.req)), resp)
			if err != nil {
				t.Fatal(err)
			}
			if facts.Unmetered != tc.unmetered {
				t.Errorf("Unmetered = %v, want %v (usage %+v)", facts.Unmetered, tc.unmetered, facts.Usage)
			}
			if !tc.unmetered && (facts.Usage == nil || !facts.Usage.OutputBound || facts.Usage.Output != 4096) {
				t.Errorf("usage %+v, want the bound 4096", facts.Usage)
			}
		})
	}
}

// TestMessageDeltaWithoutOutputIsNotFinalUsage: a message_delta whose usage carries no output_tokens holds no
// output count, so a stream cut after it is still charged the max_tokens bound, not message_start's placeholder
// (ADR 0036).
func TestMessageDeltaWithoutOutputIsNotFinalUsage(t *testing.T) {
	for _, usage := range []string{`{}`, `{"input_tokens":1200}`, `{"output_tokens":null}`} {
		body := cutStream + "event: message_delta\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":` + usage + "}\n\n"
		resp := response([]byte(body), "text/event-stream")
		resp.SSE = true
		facts, err := New().Parse(request([]byte(`{"model":"claude-opus-5","max_tokens":4096,"messages":[]}`)), resp)
		if err != nil {
			t.Fatal(err)
		}
		if facts.Usage == nil || facts.Usage.Output != 4096 || !facts.Usage.OutputBound {
			t.Errorf("usage %s: %+v, want the bound 4096", usage, facts.Usage)
		}
		s := &StreamUsageScanner{}
		_, _ = s.Write([]byte(body))
		if _, _, final := s.Result(); final {
			t.Errorf("usage %s: scanner reports a final usage", usage)
		}
	}
}

// escapeAll spells every byte of s as a \u escape.
func escapeAll(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, `\u%04x`, c)
	}
	return b.String()
}

func TestMessageUsageRequiresExplicitInput(t *testing.T) {
	for _, input := range []string{"", `"input_tokens":null,`, `"INPUT_TOKENS":5,`} {
		body := []byte(`{"id":"m","type":"message","model":"x","content":[],"usage":{` + input + `"output_tokens":7}}`)
		if _, err := ParseResponse(200, body); !errors.Is(err, ErrSchema) {
			t.Fatalf("%s: %v", body, err)
		}
	}
	// Usage stores counters as int: the largest accepted explicit count is the platform's maximum.
	for _, input := range []int{0, math.MaxInt} {
		body := []byte(fmt.Sprintf(`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":%d,"output_tokens":7}}`, input))
		resp, err := ParseResponse(200, body)
		if err != nil || resp == nil {
			t.Fatalf("explicit input %d: response %v, error %v", input, resp, err)
		}
		if resp.Usage.InputTokens != input {
			t.Fatalf("explicit input %d was changed to %d", input, resp.Usage.InputTokens)
		}
	}
	for _, input := range []string{strconv.FormatUint(uint64(math.MaxInt)+1, 10), "18446744073709551615"} {
		body := []byte(`{"id":"m","type":"message","model":"x","content":[],"usage":{"input_tokens":` + input + `,"output_tokens":7}}`)
		if resp, err := ParseResponse(200, body); resp != nil || !errors.Is(err, ErrSchema) {
			t.Fatalf("overflow input %s: response %v, error %v; want ErrSchema", input, resp, err)
		}
	}
}

func TestStreamIncompleteUsageCannotBeBoundedOrRecovered(t *testing.T) {
	startEnd := strings.Index(scanStream, "event: content_block_start")
	start, rest := scanStream[:startEnd], scanStream[startEnd:]
	cases := map[string]string{
		"missing input":        strings.Replace(scanStream, `"input_tokens":1200,`, "", 1),
		"null input":           strings.Replace(scanStream, `"input_tokens":1200`, `"input_tokens":null`, 1),
		"invalid start":        strings.Replace(scanStream, `"input_tokens":1200`, `"input_tokens":18446744073709551615`, 1),
		"invalid later delta":  start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":\"unknown\",\"output_tokens\":2}}\n\n" + rest,
		"negative later delta": start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"cache_read_input_tokens\":-1,\"output_tokens\":2}}\n\n" + rest,
		"repeated start":       start + start + rest,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := New()
			facts, err := p.Parse(&derive.Message{Method: "POST", Path: "/v1/messages", Body: []byte(`{"model":"m","max_tokens":7,"messages":[]}`)}, &derive.Message{Status: 200, Body: []byte(body), SSE: true})
			if err != nil {
				if !errors.Is(err, ErrSchema) {
					t.Fatal(err)
				}
				return
			}
			if !facts.Unmetered || !facts.IncompleteUsage {
				t.Fatalf("incomplete accounting became metered: %+v", facts)
			}
			if BoundCutStream(&facts, 7, true, 200) || !facts.Unmetered {
				t.Fatal("max_tokens repaired missing input/cache usage")
			}
		})
	}
}
