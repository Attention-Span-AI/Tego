// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
)

// TestHaystackBufferIsBuiltToSize: a version's haystacks are written into a buffer sized from the fields they hold,
// so building them does not grow it by doubling (GAPS C81: the first search of a 68,000-line ledger allocated 42 MB
// for 6 MB of text). The text is the fields joined by spaces and lower-cased, one line each, as the search reads it.
func TestHaystackBufferIsBuiltToSize(t *testing.T) {
	_, s := queryFixture(t)
	n := 0
	for _, r := range s.Runs {
		m := r.memoOf()
		if m == r.memo {
			evs := r.AllEvents()
			r.textMatches([]byte("chatgpt"))
			if len(m.hay) != cap(m.hay) {
				t.Errorf("run %s: haystack buffer holds %d bytes in %d (grown, not sized)", r.ID, len(m.hay), cap(m.hay))
			}
			lines := strings.Split(strings.TrimSuffix(string(m.hay), "\n"), "\n")
			if len(lines) != len(evs) {
				t.Fatalf("run %s: %d haystack lines for %d events", r.ID, len(lines), len(evs))
			}
			for i := range evs {
				e := &evs[i]
				want := strings.ToLower(strings.Join([]string{e.Op, e.Target, e.Rule, e.Reason, e.Agent, e.Run, e.Kind, e.AskID, e.askTarget}, " "))
				if lines[i] != want {
					t.Errorf("run %s line %d: haystack %q, want %q", r.ID, i, lines[i], want)
				}
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no run with a memo was checked")
	}
}
