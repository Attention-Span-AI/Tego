// SPDX-License-Identifier: Apache-2.0

package runscope_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// TestZeroWordsAreTheTable: with no sentence of its own, a caller reads exactly what Why, PlainFirst and Advice say,
// for every row of the table every caller's test walks.
func TestZeroWordsAreTheTable(t *testing.T) {
	for _, r := range answertest.Rows() {
		if runscope.WhyWith(r.Answer, runscope.Words{}) != runscope.Why(r.Answer) ||
			runscope.AdviceWith(r.Answer, runscope.Words{}) != runscope.Advice(r.Answer) ||
			runscope.PlainFirstWith(r.Answer, runscope.Words{}) != runscope.PlainFirst(r.Answer) {
			t.Errorf("row %q: zero Words differ from the table", r.Name)
		}
	}
}

// TestWordsReplaceOneCauseAndNeverTheVerdict: NotAtTop changes what init-not-at-root says and whether its line comes
// first, and nothing else: every other cause and every verdict read the same.
func TestWordsReplaceOneCauseAndNeverTheVerdict(t *testing.T) {
	words := runscope.Words{NotAtTop: "this is a container"}
	for _, r := range answertest.Rows() {
		same := runscope.WhyWith(r.Answer, words) == runscope.Why(r.Answer) &&
			runscope.AdviceWith(r.Answer, words) == runscope.Advice(r.Answer) &&
			runscope.PlainFirstWith(r.Answer, words) == runscope.PlainFirst(r.Answer)
		if r.Cause == runscope.CauseInitNotAtRoot {
			if same {
				t.Errorf("row %q: init-not-at-root is unchanged by Words", r.Name)
			}
			continue
		}
		if !same {
			t.Errorf("row %q (%q): Words changed a cause it does not name", r.Name, r.Cause)
		}
	}
	a := runscope.Unproven(runscope.CauseInitNotAtRoot, nil)
	if a.Outside() {
		t.Fatalf("an unproven answer is outside")
	}
	if got := runscope.WhyWith(a, words); got != "this is a container" {
		t.Errorf("WhyWith = %q", got)
	}
	if runscope.PlainFirstWith(a, words) || !runscope.PlainFirst(a) {
		t.Errorf("the container words must leave plain-first, and the table's must stay in it")
	}
	if adv := runscope.AdviceWith(a, words); !strings.Contains(adv, "any container") {
		t.Errorf("AdviceWith = %q, want where to run the command instead", adv)
	}
	if runscope.AdviceWith(a, runscope.Words{}) != "" {
		t.Errorf("the table's words give advice after a plain-first line")
	}
}
