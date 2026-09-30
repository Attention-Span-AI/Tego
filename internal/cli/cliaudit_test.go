// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestDriftAggregateExcusesAnEmptyLedger is §6 case 8 and case 1: a run whose events.jsonl exists but holds
// no line yet (a launcher killed before run_start, or a run in the instant before it) is younger than its
// ledger, so the sum leaves nothing out and the exit stays that of the sum, not 125.
func TestDriftAggregateExcusesAnEmptyLedger(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	young := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2ps")
	for dir, body := range map[string][]byte{first: fixtureBytes(t), young: {}} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", first, "--aggregate", "--json")
	if code == identity.ExitError || strings.Contains(errs, filepath.Base(young)) || !strings.Contains(out, `"skipped":[]`) {
		t.Errorf("exit %d; an empty ledger was reported skipped\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestCompileTestEscapesTheTableText: compile --test prints a row's name, its resolved paths and the failure
// text to a terminal, and a test table from a cloned repository chooses them, so they are escaped like every
// other human-readable view (limits-check-doctor-cli.md: record.Printable). --json is the byte-exact form.
func TestCompileTestEscapesTheTableText(t *testing.T) {
	table := filepath.Join(t.TempDir(), "table.yaml")
	body := "version: 0\ntests:\n  - name: \"evil \\e[2J\\e[Hforged\"\n    action: fs.write\n    path: out/x\n    expect: refused\n"
	if err := os.WriteFile(table, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--test", table)
	if !strings.Contains(out, "evil ") || strings.ContainsAny(out, "\x1b\a\r") {
		t.Errorf("compile --test wrote control bytes or lost the row:\n%q", out)
	}
}
