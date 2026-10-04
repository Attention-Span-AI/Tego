// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

func TestExtraIterationsKeepKnownUsageButCannotBoundSpend(t *testing.T) {
	for _, iterations := range []string{
		`[{"type":"compaction","input_tokens":1000},{"type":"message","input_tokens":1000}]`,
		`[{"type":"compaction"}]`,
		`[{"type":"message"},{"type":"message"}]`,
		`[{"Type":"message"}]`,
		`[{"type":"compaction","type":"message"}]`,
		`[{"type":"message","\u0074ype":"message"}]`,
		`{"type":"message"}`,
		`"unreadable"`,
	} {
		for _, stream := range []bool{false, true} {
			body := `{"id":"m","type":"message","model":"x","usage":{"input_tokens":5,"output_tokens":7,"iterations":` + iterations + `}}`
			ct := "application/json"
			if stream {
				body = `data: {"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1,"iterations":` + iterations + `}}}` + "\n\n" +
					`data: {"type":"message_delta","usage":{"output_tokens":7}}` + "\n\n" +
					`data: {"type":"message_stop"}` + "\n\n"
				ct = "text/event-stream"
			}
			facts, err := New().Parse(request([]byte(`{"model":"x","max_tokens":7,"messages":[]}`)), response([]byte(body), ct))
			if err != nil || !facts.IncompleteUsage || !facts.Unmetered || facts.Usage == nil ||
				facts.Usage.Input != 5 || facts.Usage.Output != 7 || !facts.Usage.Modified || facts.Usage.OutputBound {
				t.Fatalf("iterations %s stream %v: facts %+v error %v", iterations, stream, facts, err)
			}
			if len(facts.Decisions) == 0 || !facts.Decisions[len(facts.Decisions)-1].Unparsed ||
				facts.Decisions[len(facts.Decisions)-1].Why != derive.WhySchema {
				t.Fatalf("iterations %s stream %v: no unparsed decision: %+v", iterations, stream, facts.Decisions)
			}
			if BoundCutStream(&facts, 7, true, 200) || !facts.Unmetered {
				t.Fatalf("iterations %s stream %v: max_tokens recovered missing iteration spend", iterations, stream)
			}
		}
	}
}

func TestPlainIterationsRemainMetered(t *testing.T) {
	for _, iterations := range []string{`null`, `[]`, `[{"type":"message"}]`, `[{"type":"message","metadata":{"x":1,"x":2}}]`} {
		body := `{"id":"m","type":"message","model":"x","usage":{"input_tokens":5,"output_tokens":7,"iterations":` + iterations + `}}`
		facts, err := New().Parse(request([]byte(`{"model":"x","max_tokens":7,"messages":[]}`)), response([]byte(body), "application/json"))
		if err != nil || facts.Unmetered || facts.IncompleteUsage || facts.Usage == nil || facts.Usage.Modified {
			t.Fatalf("plain iterations %s: facts %+v error %v", iterations, facts, err)
		}
	}
}
