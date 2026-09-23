// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestReasonTableNamesRealCodes: every index of the table names a v1 reason code, once, and index 0 alone is
// unnamed. Which numbers the table holds is the kernel's to say (TestReasonTableIsEventsH): a v1 code no kernel
// program carries (the gates, asks, limits) has no number.
func TestReasonTableNamesRealCodes(t *testing.T) {
	indexed := map[record.Reason]uint8{}
	for i, code := range reasonByIndex {
		if code == "" {
			if i != int(ReasonNone) {
				t.Errorf("index %d is an unnamed hole in the table", i)
			}
			continue
		}
		if !code.Valid() {
			t.Errorf("index %d names %q, which is not a v1 reason code", i, code)
		}
		if prev, dup := indexed[code]; dup {
			t.Errorf("%q has two indexes, %d and %d", code, prev, i)
		}
		indexed[code] = uint8(i)
	}
}

func TestReasonRoundTrip(t *testing.T) {
	for _, code := range reasonByIndex {
		if code == "" {
			continue
		}
		idx, ok := IndexFor(code)
		if !ok {
			t.Fatalf("IndexFor(%q) missing", code)
		}
		got, ok := ReasonFor(idx)
		if !ok || got != code {
			t.Errorf("ReasonFor(IndexFor(%q)) = %q, %v", code, got, ok)
		}
	}
}

func TestReasonUnknownIndex(t *testing.T) {
	cases := []uint8{ReasonNone, 200, 255, uint8(len(reasonByIndex))}
	for _, idx := range cases {
		if got, ok := ReasonFor(idx); ok || got != "" {
			t.Errorf("ReasonFor(%d) = %q, %v; want the empty, unknown answer", idx, got, ok)
		}
	}
	if _, ok := IndexFor(record.Reason("not-a-code")); ok {
		t.Error("IndexFor invented an index for an unknown code")
	}
	if _, ok := IndexFor(""); ok {
		t.Error("the empty reason must have no index")
	}
}
