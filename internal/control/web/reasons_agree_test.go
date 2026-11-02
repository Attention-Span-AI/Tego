// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEveryReasonCodeHasDashboardWords walks record's closed set (record.Reasons, which the record package holds to
// its Reason constants): every code has a label of its own (reasonText: the run page, the line page, the refusal
// bars) and words under a Logs row (reasonWords: its own phrase, or on purpose the label with a lower-case first
// letter), so a code added to the record without words fails here instead of reaching the dashboard as the bare
// code. Only a code outside the set, a newer ledger's, still shows as written.
func TestEveryReasonCodeHasDashboardWords(t *testing.T) {
	for _, r := range record.Reasons {
		code := string(r)
		if got := reasonText(code); got == "" || got == code {
			t.Errorf("reasonText(%s) = %q, want a label", code, got)
		}
		got := reasonWords(ledgerview.Event{Kind: "refused", Reason: code})
		if got == "" || got == code {
			t.Errorf("reasonWords(%s) = %q, want words", code, got)
			continue
		}
		// The fallback lowers the label's first letter, which breaks a label that opens with an acronym ("mCP tool
		// blocked"): such a code needs a phrase of its own.
		first, n := utf8.DecodeRuneInString(got)
		if next, _ := utf8.DecodeRuneInString(got[n:]); unicode.IsLower(first) && unicode.IsUpper(next) {
			t.Errorf("reasonWords(%s) = %q: the label's acronym was lowered", code, got)
		}
	}
	for code, want := range map[string]string{"": "", "made-up": "made-up"} {
		if got := reasonText(code); got != want {
			t.Errorf("reasonText(%q) = %q, want %q", code, got, want)
		}
	}
}
