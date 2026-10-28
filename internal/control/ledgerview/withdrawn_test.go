// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnswerWordsWithdrawn holds that the line page words an ask the broker took back when a live block landed
// (ask-unavailable by "cancelled") as withdrawn, never as refused or "by cancelled".
func TestAnswerWordsWithdrawn(t *testing.T) {
	no := false
	af := &AskFacts{Answered: true, Approved: &no, By: linewords.WithdrawnBy, ByWords: linewords.WithdrawnBy,
		AnswerReason: string(record.ReasonAskUnavailable), After: "2 s"}
	got := capFirst(answerWords(af))
	if got != linewords.Withdrawn {
		t.Errorf("answerWords = %q, want %q", got, linewords.Withdrawn)
	}
	af.By, af.ByWords, af.AnswerReason = "uid:1000 pid:1", "somebody", ""
	if got := answerWords(af); !strings.HasPrefix(got, "denied by somebody") {
		t.Errorf("a person's denial changed: %q", got)
	}
}
