// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/linewords"
)

// TestWithdrawnAskWording holds that an ask the broker took back when a live block landed (answered ask-unavailable
// by "cancelled") reads "Withdrawn: a live block now refuses this" in the line words, the Approvals list and
// the run page's Highlights, never "denied by cancelled".
func TestWithdrawnAskWording(t *testing.T) {
	got := capFirst(answerPhrase(false, "ask-unavailable", linewords.WithdrawnBy, 2.5))
	if !strings.HasPrefix(got, linewords.Withdrawn) || strings.Contains(got, "by cancelled") {
		t.Errorf("answerPhrase of a withdrawn ask = %q, want it to start %q", got, linewords.Withdrawn)
	}
	if got := answerPhrase(false, "", "uid:1000 pid:1 dashboard", 1); !strings.HasPrefix(got, "denied by ") {
		t.Errorf("a person's denial changed: %q", got)
	}

	s := newServer(t, storyFixture(t))
	r := &ledgerview.Run{ID: "r-withdrawn"}
	for _, c := range []struct {
		name, by string
		want     []string
		never    []string
	}{
		{"withdrawn", linewords.WithdrawnBy, []string{"Withdrawn", "a live block now refuses this"}, []string{"by cancelled", ">Denied<"}},
		{"denied", "uid:1000 pid:1 dashboard", []string{"Denied", "by "}, []string{"Withdrawn"}},
	} {
		v := ledgerview.Approval{AskID: "q-1", Op: "read", Target: "/w/.env", State: "denied", By: c.by,
			After: 2 * time.Second, TS: time.Unix(1_800_000_000, 0)}
		var b strings.Builder
		row := map[string]any{"Run": r.ID, "R": r, "Home": "", "V": v}
		if err := s.pages["run"].ExecuteTemplate(&b, "hl-ask", row); err != nil {
			t.Fatal(err)
		}
		out := b.String()
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: Highlights row lacks %q: %s", c.name, w, out)
			}
		}
		for _, w := range c.never {
			if strings.Contains(out, w) {
				t.Errorf("%s: Highlights row says %q: %s", c.name, w, out)
			}
		}
	}
}
