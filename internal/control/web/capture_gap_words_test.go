// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
)

// TestCaptureGapWords: the Receipt tab's two gap links say the receipt's own sentence, the one `tego receipt` and
// `tego status` say (gaps.CaptureWords, gaps.MissedWords), with its first letter capitalised; no other gap is reworded.
func TestCaptureGapWords(t *testing.T) {
	v := &receiptView{}
	for _, c := range []struct{ code, why, want string }{
		{receiptspec.CodeCaptureGap, gaps.CaptureWords(1), "Token counts may be low (1 capture gap)"},
		{receiptspec.CodeCaptureGap, gaps.CaptureWords(2), "Token counts may be low (2 capture gaps)"},
		{receiptspec.CodeMissedActions, gaps.MissedWords(1, 0), "1 gap in the record (counts are a minimum)"},
		{receiptspec.CodeMissedActions, gaps.MissedWords(3, 0), "3 gaps in the record (counts are a minimum)"},
		{receiptspec.CodeCaptureOff, "capture was off", ""},
		{receiptspec.CodeNoPriceTable, gaps.PriceWords(true), ""},
		{receiptspec.CodeRecordUncertain, "recording coverage is uncertain", ""},
	} {
		if got := v.GapWords(c.code, c.why); got != c.want {
			t.Errorf("GapWords(%s, %q) = %q, want %q", c.code, c.why, got, c.want)
		}
	}
}
