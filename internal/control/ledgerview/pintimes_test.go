// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"
)

// TestPinTimes: a since or until that goes back from now is written as the time it means; a time, other terms and
// the order stay; the pinned query means the same lines as the relative one did at that moment.
func TestPinTimes(t *testing.T) {
	now := time.Date(2026, 10, 27, 10, 30, 15, 900, time.UTC)
	for q, want := range map[string]string{
		"kind:exec since:1h":                 "kind:exec since:2026-10-27T09:30:15",
		"since:90m until:10m x":              "since:2026-10-27T09:00:15 until:2026-10-27T10:20:15 x",
		"since:1d":                           "since:2026-10-26T10:30:15",
		"since:2026-10-27T01:00 until:01:00": "since:2026-10-27T01:00 until:01:00",
		"kind:exec":                          "kind:exec",
	} {
		_, toks, err := ParseQueryAt(q, now, time.UTC)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		out, span, ok := PinTimes(toks, now, time.UTC)
		if got := FormatQuery(out); got != want {
			t.Errorf("%q pinned to %q, want %q", q, got, want)
		}
		if ok != (FormatQuery(out) != FormatQuery(toks)) {
			t.Errorf("%q: ok %v", q, ok)
		}
		if again, _, ok := PinTimes(out, now.Add(time.Hour), time.UTC); ok || FormatQuery(again) != want {
			t.Errorf("%q: pinning twice moved the window: %q", q, FormatQuery(again))
		}
		if q == "kind:exec since:1h" && span != "1h" {
			t.Errorf("span %q", span)
		}
	}
	f1, _, _ := ParseQueryAt("since:1h", now, time.UTC)
	_, toks, _ := ParseQueryAt("since:1h", now, time.UTC)
	out, _, _ := PinTimes(toks, now, time.UTC)
	f2, _, _ := ParseQueryAt(FormatQuery(out), now.Add(5*time.Minute), time.UTC)
	if d := f1.Since.Sub(f2.Since); d < 0 || d >= time.Second {
		t.Errorf("pinned since %v, relative %v", f2.Since, f1.Since)
	}
}
