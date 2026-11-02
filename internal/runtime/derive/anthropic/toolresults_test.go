// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// TestRequestToolResults reads the tool_use ids the request's last message reports results for (capture-derive
// R42): only the last message, only a user message's tool_result blocks, in wire order; and a body whose reading
// a server could take otherwise is not read at all, which the attribute stage treats as leaving every window of
// the run of unknown state rather than open.
func TestRequestToolResults(t *testing.T) {
	const history = `{"role":"user","content":"find the orders"},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_8811","name":"db_query","input":{}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_8811","content":"old"}]},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_8812","name":"db_query","input":{}},` +
		`{"type":"tool_use","id":"toolu_8813","name":"write","input":{}}]}`
	for _, c := range []struct {
		name string
		body string
		want []string
		ok   bool
	}{
		{"first turn", `{"model":"m","max_tokens":9,"messages":[{"role":"user","content":"hi"}]}`, nil, true},
		{"last message's results only", `{"model":"m","messages":[` + history + `,{"role":"user","content":[` +
			`{"type":"tool_result","tool_use_id":"toolu_8812","content":"rows"},{"type":"text","text":"note"},` +
			`{"type":"tool_result","tool_use_id":"toolu_8813","is_error":true}]}],"max_tokens":9}`,
			[]string{"toolu_8812", "toolu_8813"}, true},
		{"assistant prefill last", `{"model":"m","messages":[` + history + `]}`, nil, true},
		{"string content", `{"messages":[{"role":"user","content":"tool_result toolu_1"}]}`, nil, true},
		{"no messages", `{"model":"m"}`, nil, false},
		{"empty messages", `{"model":"m","messages":[]}`, nil, false},
		{"not an object", `[1,2]`, nil, false},
		{"cut body", `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"`, nil, false},
		{"messages twice", `{"messages":[{"role":"user","content":"a"}],"messages":[{"role":"user","content":"b"}]}`, nil, false},
		{"messages in another case", `{"Messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"role twice", `{"messages":[{"role":"assistant","role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"message not an object", `{"messages":[{"role":"user","content":"a"},null]}`, nil, false},
		{"block not an object", `{"messages":[{"role":"user","content":[null,{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"other keys skipped", `{"messages":[{"role":"user","id":"m","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"r","is_error":false}]}]}`,
			[]string{"toolu_1"}, true},
		{"role in another case", `{"messages":[{"Role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"content in another case", `{"messages":[{"role":"user","Content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"content twice", `{"messages":[{"role":"user","content":[],"content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"type in another case", `{"messages":[{"role":"user","content":[{"Type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"type twice", `{"messages":[{"role":"user","content":[{"type":"text","type":"tool_result","tool_use_id":"toolu_1"}]}]}`, nil, false},
		{"tool_use_id in another case", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"a","Tool_Use_Id":"b"}]}]}`, nil, false},
		{"tool_use_id in a Unicode fold", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"a","tool_u\u017Fe_id":"b"}]}]}`, nil, false},
		{"tool_use_id twice", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"a","tool_use_id":"b"}]}]}`, nil, false},
		{"result without an id", `{"messages":[{"role":"user","content":[{"type":"tool_result"}]}]}`, nil, false},
		{"id not a string", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":7}]}]}`, nil, false},
		{"id too long", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + strings.Repeat("x", 257) + `"}]}]}`, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := RequestToolResults([]byte(c.body))
			if ok != c.ok || !slices.Equal(got, c.want) {
				t.Fatalf("RequestToolResults = %q, %v; want %q, %v", got, ok, c.want, c.ok)
			}
		})
	}
	var many strings.Builder
	many.WriteString(`{"messages":[{"role":"user","content":[`)
	for i := range MaxToolResults + 1 {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"type":"tool_result","tool_use_id":"toolu_x"}`)
	}
	many.WriteString(`]}]}`)
	if got, ok := RequestToolResults([]byte(many.String())); ok {
		t.Fatalf("a message reporting more than %d results was read: %d ids", MaxToolResults, len(got))
	}
}

// TestParserToolResultsReadsModelTurnsAlone: only a Messages API turn whose body capture kept whole and decoded is
// read; any other request is not read, and says so.
func TestParserToolResultsReadsModelTurnsAlone(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`)
	p := New()
	for _, c := range []struct {
		name string
		req  derive.Message
		ok   bool
	}{
		{"messages turn", derive.Message{Method: "POST", Path: "/v1/messages", Body: body}, true},
		{"cut", derive.Message{Method: "POST", Path: "/v1/messages", Body: body, Truncated: true}, false},
		{"coded", derive.Message{Method: "POST", Path: "/v1/messages", Body: body, ContentEncoding: "gzip"}, false},
		{"decoded", derive.Message{Method: "POST", Path: "/v1/messages", Body: body, ContentEncoding: "gzip", Decoded: true}, true},
		{"chat completions", derive.Message{Method: "POST", Path: "/v1/chat/completions", Body: body}, false},
		{"count tokens", derive.Message{Method: "POST", Path: "/v1/messages/count_tokens", Body: body}, false},
		{"a GET", derive.Message{Method: "GET", Path: "/v1/messages", Body: body}, false},
	} {
		ids, ok := p.ToolResults(&c.req)
		if ok != c.ok || (ok && !slices.Equal(ids, []string{"toolu_1"})) {
			t.Errorf("%s: ToolResults = %q, %v; want ok %v", c.name, ids, ok, c.ok)
		}
	}
}

// FuzzRequestToolResults: the reader never panics, and every id it returns is a non-empty string within the bound.
func FuzzRequestToolResults(f *testing.F) {
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`))
	f.Add([]byte(`{"messages":[{"role":"user","content":"x"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		ids, ok := RequestToolResults(body)
		if !ok && ids != nil {
			t.Fatalf("unread body returned ids %q", ids)
		}
		if len(ids) > MaxToolResults {
			t.Fatalf("%d ids", len(ids))
		}
		for _, id := range ids {
			if id == "" || len(id) > MaxToolUseIDLen {
				t.Fatalf("id %q", id)
			}
		}
	})
}
