// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestReceiptAgreesWithMeasure: over the frozen fixture, the receipt's refusals, tokens and cost estimate are the
// figures `tego measure` prints, from the same price table.
func TestReceiptAgreesWithMeasure(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "receipt", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	var rc struct {
		V        int `json:"receipt_v"`
		Refusals struct {
			Total int `json:"total"`
		} `json:"refusals"`
		Tokens struct {
			In       uint64  `json:"in"`
			Out      uint64  `json:"out"`
			Cost     float64 `json:"est_cost_usd"`
			CostText string  `json:"est_cost"`
		} `json:"tokens"`
		Coverage struct {
			Complete bool `json:"complete"`
			Gaps     []struct {
				Field, Code, Why string
			} `json:"gaps"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal([]byte(out), &rc); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	code, mout, errs := run(t, "measure", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("measure: exit %d (stderr %q)", code, errs)
	}
	var m struct {
		Refused   int     `json:"refused"`
		TokensIn  uint64  `json:"tokens_in"`
		TokensOut uint64  `json:"tokens_out"`
		Cost      float64 `json:"est_cost_usd"`
		CostLabel string  `json:"est_cost"`
	}
	if err := json.Unmarshal([]byte(mout), &m); err != nil {
		t.Fatal(err)
	}
	if rc.V != 1 || rc.Refusals.Total != m.Refused || rc.Tokens.In != m.TokensIn || rc.Tokens.Out != m.TokensOut ||
		rc.Tokens.Cost != m.Cost || rc.Tokens.CostText != m.CostLabel {
		t.Errorf("receipt %+v\nmeasure %+v", rc, m)
	}
	// The fixture holds a capture gap and a record gap: the receipt says its counts are a floor, and names each gap by
	// its code too.
	if rc.Coverage.Complete || !strings.Contains(out, `"field": "record"`) || !strings.Contains(out, `"code": "missed-actions"`) {
		t.Errorf("coverage = %+v", rc.Coverage)
	}
	for _, g := range rc.Coverage.Gaps {
		if g.Code == "" {
			t.Errorf("a coverage gap without its code: %+v", g)
		}
	}

	code, text, errs := run(t, "receipt", dir)
	if code != identity.ExitOK {
		t.Fatalf("text: exit %d (stderr %q)", code, errs)
	}
	for _, want := range []string{"Receipt for run", "Time taken", "\nFiles written\n", "Refused actions", "Tokens and model calls",
		"Coverage", "Cost: "} {
		if !strings.Contains(text, want) {
			t.Errorf("the text receipt has no %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Files changed") {
		t.Errorf("the text receipt still says Files changed, not Files written:\n%s", text)
	}
}

// TestReceiptUsage: two runs, or a run beside --last, are usage errors (R25).
func TestReceiptUsage(t *testing.T) {
	for _, args := range [][]string{{"receipt", "a", "b"}, {"receipt", "a", "--last"}} {
		if code, _, errs := run(t, args...); code != identity.ExitUsage {
			t.Errorf("%v exited %d, want %d (stderr %q)", args, code, identity.ExitUsage, errs)
		}
	}
}

// TestReceiptNewestRunAndVerify: no run means the newest run under the ledger root; --verify exits 0 on a chain
// that verifies against its anchor and 1 once a line is gone.
func TestReceiptNewestRunAndVerify(t *testing.T) {
	id, dir := verifiedRun(t)
	code, out, errs := run(t, "receipt")
	if code != identity.ExitOK || !strings.Contains(out, id) {
		t.Fatalf("no run: exit %d, want the newest run %s\nstdout %s\nstderr %s", code, id, out, errs)
	}
	code, out, errs = run(t, "receipt", id, "--verify")
	if code != identity.ExitOK || !strings.Contains(out, "Chain: ") || !strings.Contains(out, "anchored in") {
		t.Fatalf("--verify: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	code, out, errs = run(t, "receipt", id, "--verify", "--json")
	var obj map[string]any
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &obj) != nil || !strings.Contains(errs, "Chain: ") {
		t.Fatalf("--verify --json: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
	if code, _, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "does not verify") {
		t.Fatalf("a dropped line: exit %d, want 1 (stderr %s)", code, errs)
	}
}
