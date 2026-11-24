// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"strings"
	"testing"
	"time"
)

func TestReceiptTabExplainsLearnWithholding(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000098-rclear"
	at := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	page, text := receiptAndTab(t, run,
		line(run, "py", 0, at, "run_start", `"tier":"landlock","record_minor":31,"command":["python"],"contract_source":{"path":"/edited.yaml","learn":{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:443"]}}`),
		line(run, "py", 1, at.Add(time.Second), "net", `"rule":"unmatched","reason":"net-not-allowed","verdict":"refused","op":"connect","dst":"203.0.113.9:443","proto":"tcp"`),
		line(run, "py", 2, at.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":1`))
	const sentence = "This run's contract says tego learn withheld this destination"
	if !strings.Contains(text, sentence) {
		t.Fatalf("receipt has no withholding sentence: %s", text)
	}
	start := strings.Index(text, sentence)
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatal("unterminated sentence")
	}
	want := text[start : start+end]
	if !strings.Contains(page, html.EscapeString(want)) {
		t.Fatalf("Receipt tab lacks the receipt's sentence %q", want)
	}
}
