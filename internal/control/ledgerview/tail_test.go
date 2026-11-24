// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strconv"
	"strings"
	"testing"
)

// TestTailTokenRoundTrip: the append cursor a page carries reads back as it was made, and refuses what it did not make.
func TestTailTokenRoundTrip(t *testing.T) {
	in := Tail{Rev: 1760000000123456, Seq: map[string]uint64{"r-a-0000000000001-xxxxxx": 41, "r-b-0000000000002-yyyyyy": 0}}
	got, ok := ParseTail(in.String())
	if !ok || got.Rev != in.Rev || got.Overflow || len(got.Seq) != 2 || got.Seq["r-a-0000000000001-xxxxxx"] != 41 {
		t.Fatalf("round trip: %+v %v from %q", got, ok, in.String())
	}
	if _, ok := ParseTail("1;" + manyRuns(MaxTailRuns)); !ok {
		t.Errorf("a cursor naming %d runs, the most it holds, was refused", MaxTailRuns)
	}
	over := Tail{Rev: 7, Seq: map[string]uint64{}, Overflow: true}
	if got, ok := ParseTail(over.String()); !ok || !got.Overflow || got.Rev != 7 {
		t.Errorf("overflow lost: %+v %v from %q", got, ok, over.String())
	}
	for _, bad := range []string{"", "x", "1", "x;", "1;run", "1;run:x", "1;:3", "-1;r:1", "1;" + manyRuns(MaxTailRuns+1)} {
		if _, ok := ParseTail(bad); ok {
			t.Errorf("%q was taken for an append cursor", bad)
		}
	}
}

// manyRuns is n distinct open runs as a token names them.
func manyRuns(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "run" + strconv.Itoa(i) + ":1"
	}
	return strings.Join(parts, ",")
}
