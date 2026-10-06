// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// bestEffortRun writes a finished run whose run_start lists cells as best_effort (nil for none) and returns its id.
func bestEffortRun(t *testing.T, cells []string) string {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"echo"}, Cwd: "/", Tier: "landlock",
		ContractHash: strings.Repeat("a", 64), RecordMinor: record.MinorBestEffort, BestEffort: cells}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// TestStatusAndEventsShowBestEffortCells is ADR 0041 D7's view half: run_start's best_effort (the gate cells
// decided on copied syscall facts and continued, never counted as enforced) is shown where status and events
// show run_start's details, in text and in status --json, and nothing is said of it for a run with none.
func TestStatusAndEventsShowBestEffortCells(t *testing.T) {
	cells := []string{"gate.fs.read/open", "gate.exec"}
	id := bestEffortRun(t, cells)
	code, out, errs := run(t, "status", id)
	if code != identity.ExitOK {
		t.Fatalf("status: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "\nbest effort: gate.fs.read/open, gate.exec ") {
		t.Errorf("status lacks the best-effort cells:\n%s", out)
	}
	code, out, errs = run(t, "status", "--json", id)
	if code != identity.ExitOK {
		t.Fatalf("status --json: exit %d: %s", code, errs)
	}
	var got struct {
		BestEffort []string `json:"best_effort"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || !slices.Equal(got.BestEffort, cells) {
		t.Errorf("status --json best_effort = %v (%v):\n%s", got.BestEffort, err, out)
	}
	code, out, errs = run(t, "events", id)
	if code != identity.ExitOK {
		t.Fatalf("events: exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "best_effort=gate.fs.read/open,gate.exec") {
		t.Errorf("events' run_start line lacks the best-effort cells:\n%s", out)
	}

	id = bestEffortRun(t, nil)
	_, out, _ = run(t, "status", id)
	_, evs, _ := run(t, "events", id)
	if strings.Contains(out+evs, "best effort") || strings.Contains(out+evs, "best_effort") {
		t.Errorf("a run with no best-effort cell shows one:\n%s\n%s", out, evs)
	}
}
