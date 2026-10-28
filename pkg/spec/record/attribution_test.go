// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAttributionByToolUseLine is the line an action attributed to a reply's tool_use carries (capture-derive
// R42, record_minor 29): tool_use_id sits between step and confidence in the fixed order, and the line decodes
// back to the same attribution.
func TestAttributionByToolUseLine(t *testing.T) {
	e := action(KindNet, `{"dst":"10.0.0.7:5432","op":"connect"}`)
	e.Attr = AttributedByToolUse("t7", 1, "toolu_8812")
	line := mustLine(t, e)
	want := `"attribution":{"thread":"t7","step":1,"tool_use_id":"toolu_8812","confidence":"likely","method":"tool_id"}`
	if !strings.Contains(string(line), want) {
		t.Fatalf("line carries no %s:\n%s", want, line)
	}
	back, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	if *back.Attr != *e.Attr {
		t.Fatalf("decoded attribution %+v, want %+v", *back.Attr, *e.Attr)
	}
	e.Attr = AttributedByTID("t7", 2)
	if line := mustLine(t, e); !strings.Contains(string(line), `"attribution":{"thread":"t7","step":2,"confidence":"likely","method":"tid"}`) {
		t.Fatalf("tid attribution line: %s", line)
	}
}

// TestAttributionToolUseIDGoesWithItsMethod: a tool_use_id names the reply only under method tool_id, so an id under
// any other method is not a valid line; a tool_id attribution with no id stays decodable, as v1 accepted it (R8).
func TestAttributionToolUseIDGoesWithItsMethod(t *testing.T) {
	for _, a := range []*Attribution{
		AttributedByToolUse("t1", 1, "toolu_1"),
		AttributedByTID("t1", 1),
		AttributedByTime("t1", 1),
		Unattributed(),
		{Thread: "t1", Step: 1, Confidence: ConfidenceExact, Method: MethodToolID},
	} {
		if !a.Valid() {
			t.Errorf("%+v is not valid", *a)
		}
	}
	for _, a := range []*Attribution{
		{Thread: "t1", Step: 1, ToolUseID: "toolu_1", Confidence: ConfidenceLikely, Method: MethodTime},
		{ToolUseID: "toolu_1", Confidence: ConfidenceUnattributed, Method: MethodNone},
	} {
		if a.Valid() {
			t.Errorf("%+v is valid", *a)
		}
	}
}

// TestSSLRequestToolResultsSaysWhetherTheRequestWasRead: tool_results is absent when derive did not read the
// request, an empty list when it read it and found no result, and the ids otherwise; side is written only when set.
func TestSSLRequestToolResultsSaysWhetherTheRequestWasRead(t *testing.T) {
	none := []string{}
	two := []string{"toolu_1", "toolu_2"}
	for _, c := range []struct {
		p    SSLRequestPayload
		want string
		not  string
	}{
		{SSLRequestPayload{Path: "/v1/messages"}, "", `"tool_results"`},
		{SSLRequestPayload{Path: "/v1/messages", ToolResults: &none}, `"tool_results":[]`, `"side"`},
		{SSLRequestPayload{Path: "/v1/messages", ToolResults: &two}, `"tool_results":["toolu_1","toolu_2"]`, `"side"`},
		{SSLRequestPayload{Path: "/api/event_logging/batch", Side: true}, `"side":true`, `"tool_results"`},
	} {
		raw, err := json.Marshal(c.p)
		if err != nil {
			t.Fatal(err)
		}
		if c.want != "" && !strings.Contains(string(raw), c.want) {
			t.Errorf("%s has no %s", raw, c.want)
		}
		if strings.Contains(string(raw), c.not) {
			t.Errorf("%s has %s", raw, c.not)
		}
		var back SSLRequestPayload
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if (back.ToolResults == nil) != (c.p.ToolResults == nil) || back.Side != c.p.Side {
			t.Errorf("%s decoded to %+v", raw, back)
		}
	}
}
