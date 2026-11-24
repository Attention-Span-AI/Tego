// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestMalformedAsksAreShownNotResolved: a repeated ask id, an answer before its ask and an answer to an id never asked
// are shown as coverage notes in askpair's words, and are not counted: the first ask opens the question and the answer
// pairs with it; an answer that pairs with no ask never counts as answered; an ask with no answer stays unanswered.
func TestMalformedAsksAreShownNotResolved(t *testing.T) {
	ask := func(id, target string, at time.Duration) line {
		return line{kind: record.KindAsk, at: at, payload: map[string]any{"ask_id": id, "hold": "open", "op": "open", "target": target, "ask_rule": "fs.ask_read[/p/]"}}
	}
	answer := func(id string, approved bool, at time.Duration) line {
		return line{kind: record.KindAnswer, at: at, payload: map[string]any{"ask_id": id, "by": "uid:1000 pid:9", "after_s": 2.0, "approved": approved}}
	}
	for _, c := range []struct {
		name                                        string
		lines                                       []line
		asked, approved, denied, unanswered, listed int
		code, words                                 string
	}{
		{"well formed", []line{ask("q-1", "/p/a", time.Second), answer("q-1", true, 2*time.Second)}, 1, 1, 0, 0, 1, "", ""},
		{"a repeated ask id", []line{ask("q-1", "/p/a", time.Second), ask("q-1", "/p/other", 2*time.Second), answer("q-1", true, 3*time.Second)},
			1, 1, 0, 0, 1, CodeAskRepeated, "an ask was recorded twice"},
		{"a repeat after the answer", []line{ask("q-1", "/p/a", time.Second), answer("q-1", true, 2*time.Second), ask("q-1", "/p/a", 3*time.Second)},
			1, 1, 0, 0, 1, CodeAskRepeated, "an ask was recorded twice"},
		{"an answer before its ask", []line{answer("q-1", true, time.Second), ask("q-1", "/p/a", 2*time.Second)},
			1, 0, 0, 1, 1, CodeAnswerUnpaired, "an answer has no ask before it"},
		{"an answer to an id never asked", []line{ask("q-1", "/p/a", time.Second), answer("q-9", true, 2*time.Second)},
			1, 0, 0, 1, 1, CodeAnswerUnpaired, "an answer has no ask before it"},
		{"a second answer", []line{ask("q-1", "/p/a", time.Second), answer("q-1", true, 2*time.Second), answer("q-1", false, 3*time.Second)},
			1, 1, 0, 0, 1, CodeAnswerUnpaired, "an answer has no ask before it"},
		{"an answer and no ask at all", []line{answer("q-9", true, time.Second)}, 0, 0, 0, 0, 0, CodeAnswerUnpaired, "an answer has no ask before it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc := compute(t, append(append([]line{start("off", true)}, c.lines...), end(10*time.Second, 0)), Options{})
			a := rc.Asks
			if a.Asked != c.asked || a.Approved != c.approved || a.Denied != c.denied || a.Unanswered != c.unanswered || len(a.List) != c.listed {
				t.Errorf("asks: asked %d approved %d denied %d unanswered %d listed %d; want %d %d %d %d %d",
					a.Asked, a.Approved, a.Denied, a.Unanswered, len(a.List), c.asked, c.approved, c.denied, c.unanswered, c.listed)
			}
			found := ""
			for _, g := range rc.Coverage.Gaps {
				if g.Field == "asks" {
					if c.code == "" || g.Code != c.code || !strings.Contains(g.Why, c.words) {
						t.Errorf("unexpected asks note %+v", g)
					}
					found = g.Code
				}
			}
			if found != c.code {
				t.Errorf("asks note %q, want %q (gaps %+v)", found, c.code, rc.Coverage.Gaps)
			}
			if c.name == "an answer before its ask" && len(a.List) == 1 && a.List[0].Answer != "" {
				t.Errorf("the early answer was taken for the answer of its ask: %+v", a.List[0])
			}
			if c.name == "a repeated ask id" && len(a.List) == 1 && a.List[0].Target != "/p/a" {
				t.Errorf("the repeat replaced the first ask: %+v", a.List[0])
			}
		})
	}
}
