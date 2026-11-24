// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBaselineReceiptTabMatchesTerminalAndEscapes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	p.Baseline.Home = "/home/<script>"
	if err := p.Baseline.SealEvidence(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	const run = "r-aaaaaaaa-0000000000098-rcbase"
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	page, text := receiptAndTab(t, run, line(run, "fixture", 0, at, "run_start", string(raw[1:len(raw)-1])), line(run, "fixture", 1, at.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	sentence := "A machine baseline was in force for this run."
	if !strings.Contains(text, sentence) || !strings.Contains(page, sentence) {
		t.Fatal("baseline claim missing from a receipt surface")
	}
	if !strings.Contains(page, html.EscapeString("/home/<script>")) || strings.Contains(page, "/home/<script>") {
		t.Fatal("baseline owner text not escaped")
	}
	for _, words := range []string{p.ContractHash, p.EffectiveHash, p.Baseline.SHA256, "conditional", "final exec environment delivery", "0 recorded refusals"} {
		if !strings.Contains(page, html.EscapeString(words)) || !strings.Contains(text, words) {
			t.Fatalf("receipt surface lacks %q", words)
		}
	}
}
