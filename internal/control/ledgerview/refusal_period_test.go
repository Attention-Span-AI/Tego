// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"
)

func TestRefusalBoundsSurviveClockReorderingAndMirrors(t *testing.T) {
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	r := Run{Kinds: map[string]int{}}
	for _, e := range []Event{
		{Kind: "refused", TS: at},
		{Kind: "refused", TS: at.Add(-24 * time.Hour)},
		{Kind: "refused", TS: at.Add(24 * time.Hour)},
		{Kind: "refused", TS: at.Add(-48 * time.Hour), Mirror: true},
	} {
		r.add(e)
	}
	if r.Refusals != 3 || !r.RefusalFirst.Equal(at.Add(-24*time.Hour)) || !r.RefusalLast.Equal(at.Add(24*time.Hour)) {
		t.Fatalf("count=%d bounds=%s..%s", r.Refusals, r.RefusalFirst, r.RefusalLast)
	}
}
