// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestDriftAggregateReportsAnUnreadableRun is §6 case 8 for drift --aggregate: a run of the agent whose
// ledger cannot be read is named on stderr and in --json's skipped list, and the exit is 125, because a
// sum that silently leaves a run out reads as the agent's whole total (E26). It was only logged to
// tego.log, and the partial sum could exit 0. A run directory with no events.jsonl yet is a run younger
// than its ledger and changes nothing.
func TestDriftAggregateReportsAnUnreadableRun(t *testing.T) {
	root := t.TempDir()
	data := fixtureBytes(t)
	first := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	torn := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2pr")
	young := filepath.Join(root, "r-3f9c2a1b-0dllq06ts7400-k7m2ps")
	nl := bytes.IndexByte(data, '\n') + 1
	corrupt := append(append(slices.Clone(data[:nl]), []byte("{\"torn\n")...), data[nl:]...)
	for dir, body := range map[string][]byte{first: data, torn: corrupt, young: nil} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if body == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", first, "--aggregate", "--json")
	if code != identity.ExitError {
		t.Fatalf("exit %d, want 125 over an incomplete sum\nstdout %s\nstderr %s", code, out, errs)
	}
	if !strings.Contains(errs, filepath.Base(torn)) {
		t.Errorf("stderr names no skipped run:\n%s", errs)
	}
	if strings.Contains(errs, filepath.Base(young)) {
		t.Errorf("a run with no ledger yet was reported:\n%s", errs)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	skipped, _ := got["skipped"].([]any)
	if got["runs"] != float64(1) || len(skipped) != 1 || skipped[0] != filepath.Base(torn) {
		t.Errorf("runs %v skipped %v, want 1 run and the torn one skipped", got["runs"], got["skipped"])
	}

	// Without --aggregate the key is still there, empty: --json keys never come and go.
	_, out, _ = run(t, "drift", first, "--json")
	if !strings.Contains(out, `"skipped":[]`) {
		t.Errorf("a plain drift --json lacks \"skipped\":[]:\n%s", out)
	}
}
