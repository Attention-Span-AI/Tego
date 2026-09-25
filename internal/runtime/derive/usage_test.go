// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// TestServerToolUse pins how the upstream's server_tool_use object is read: counts by name, a member that is not a
// count or is zero dropped, and names past the bound or not plain folded into ServerToolOther, so the record never
// grows a key per name the reply invents and no count is lost.
func TestServerToolUse(t *testing.T) {
	var many strings.Builder
	many.WriteString("{")
	for i := range maxServerTools + 3 {
		fmt.Fprintf(&many, `"t%02d_requests":1,`, i)
	}
	many.WriteString(`"Bad Name":2}`)
	tests := []struct {
		in   string
		want ServerToolUse
	}{
		{`{"web_search_requests":3,"web_fetch_requests":0,"note":"x","nested":{"a":1}}`, ServerToolUse{"web_search_requests": 3}},
		{`null`, nil},
		{`{}`, nil},
		{`{"web_search_requests":-2}`, ServerToolUse{"web_search_requests": -2}},
		{fmt.Sprintf(`{"a":%d,"b":%d,"c_":1}`, math.MaxInt, math.MaxInt), nil},
		{many.String(), nil},
	}
	for i, tc := range tests {
		var got ServerToolUse
		if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		switch i {
		case 4:
			// Three plain names under the bound are kept as they are.
			if got["a"] != math.MaxInt || got["b"] != math.MaxInt || got["c_"] != 1 || len(got) != 3 {
				t.Errorf("%d: %v", i, got)
			}
		case 5:
			// No more than the bound by name, one more for the rest, and no count lost: 11 ones and a 2.
			total := 0
			for _, n := range got {
				total += n
			}
			if len(got) > maxServerTools+1 || got[ServerToolOther] == 0 || total != maxServerTools+3+2 {
				t.Errorf("%d: %v", i, got)
			}
		default:
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%d: %v, want %v", i, got, tc.want)
			}
		}
	}
	if got := addCounts(math.MaxInt, 5); got != math.MaxInt {
		t.Errorf("addCounts saturates: %d", got)
	}
	merged := ServerToolUse{"web_search_requests": 2}.Merge(ServerToolUse{"web_search_requests": 5, "web_fetch_requests": 1})
	if !reflect.DeepEqual(merged, ServerToolUse{"web_search_requests": 5, "web_fetch_requests": 1}) {
		t.Errorf("Merge = %v", merged)
	}
}

// TestServerToolMergePastTheCapLosesNoCount covers capture-derive.md R29's "no count is lost" across two reports:
// message_start names b..i once each, and message_delta's cumulative report adds a (5) and raises i to 7, which
// its own decode folds into other_requests as the ninth name. Folded one name at a time by max, the merge kept
// {b..h:1, i:1, other_requests:7}, 15 requests where 19 were reported, and a cost budget charged the difference
// to nobody.
func TestServerToolMergePastTheCapLosesNoCount(t *testing.T) {
	var start, delta ServerToolUse
	if err := json.Unmarshal([]byte(`{"b":1,"c":1,"d":1,"e":1,"f":1,"g":1,"h":1,"i":1}`), &start); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"a":5,"b":1,"c":1,"d":1,"e":1,"f":1,"g":1,"h":1,"i":7}`), &delta); err != nil {
		t.Fatal(err)
	}
	merged := start.Merge(delta)
	total, named := 0, 0
	for name, v := range merged {
		total += v
		if name != ServerToolOther {
			named++
		}
	}
	if total < 19 {
		t.Errorf("Merge = %v: %d requests, want at least the 19 reported", merged, total)
	}
	if named > maxServerTools {
		t.Errorf("Merge = %v: %d names kept, want at most %d", merged, named, maxServerTools)
	}
	if merged["a"] != 5 {
		t.Errorf("Merge = %v: a is %d, want 5", merged, merged["a"])
	}
}

// A name that is not plain sorts before the plain ones and opens the ServerToolOther bucket first; the bucket
// must not take one of the maxServerTools named slots.
func TestServerToolCapIgnoresOtherBucket(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"Zed":1`)
	for i := range maxServerTools {
		fmt.Fprintf(&sb, `,"t%02d":1`, i)
	}
	sb.WriteString("}")
	var got ServerToolUse
	if err := json.Unmarshal([]byte(sb.String()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != maxServerTools+1 || got[ServerToolOther] != 1 {
		t.Errorf("got %d entries, other=%d: %v; want %d names plus other_requests:1", len(got), got[ServerToolOther], got, maxServerTools)
	}
}
