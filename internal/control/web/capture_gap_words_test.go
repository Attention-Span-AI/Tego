// SPDX-License-Identifier: Apache-2.0

package web

import "testing"

// TestCaptureGapWords: the receipt's tokens.capture gap reads as plain words, as the record gap does.
func TestCaptureGapWords(t *testing.T) {
	v := &receiptView{}
	for why, want := range map[string]string{
		"1 capture gap line: model traffic tego could not read, so the token counts are a floor":  "Token counts may be low (1 capture gap)",
		"2 capture gap lines: model traffic tego could not read, so the token counts are a floor": "Token counts may be low (2 capture gaps)",
		"capture was off": "",
	} {
		if got := v.GapWords("tokens.capture", why); got != want {
			t.Errorf("GapWords(tokens.capture, %q) = %q, want %q", why, got, want)
		}
	}
	if got := v.GapWords("record", "1 gap line: tego knows it missed some actions, so the counts are a floor"); got != "1 gap in the record (counts are a minimum)" {
		t.Errorf("the record gap reads %q", got)
	}
	if v.GapWords("tokens.est_cost_usd", "no price table: the cost is not estimated") != "" {
		t.Error("the cost gap was reworded")
	}
}
