// SPDX-License-Identifier: Apache-2.0

package record

import "testing"

func TestModelStepIsTiedOnlyByAMethodThatNamesAStep(t *testing.T) {
	for _, c := range []struct {
		name string
		attr *Attribution
		step int
		ok   bool
	}{
		{"no attribution", nil, 0, false},
		{"unattributed, none", Unattributed(), 0, false},
		{"unattributed by time (ambiguous or before the first request)", &Attribution{Confidence: ConfidenceUnattributed, Method: MethodTime}, 0, false},
		{"likely, time, step 0", AttributedByTime("t", 0), 0, true},
		{"likely, time, step 4", AttributedByTime("t", 4), 4, true},
		{"likely, tid", AttributedByTID("t", 2), 2, true},
		{"likely, tool_id", AttributedByToolUse("t", 7, "toolu_1"), 7, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := &Event{Attr: c.attr}
			if step, ok := e.ModelStep(); step != c.step || ok != c.ok {
				t.Errorf("ModelStep() = %d, %v; want %d, %v", step, ok, c.step, c.ok)
			}
		})
	}
	var none *Event
	if _, ok := none.ModelStep(); ok {
		t.Error("a nil event is tied to a step")
	}
}
