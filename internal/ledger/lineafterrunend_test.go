// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// appendChainedLine appends one decodable, correctly chained line (seq and prev following run_end) to a
// closed run's events.jsonl, as a same-uid writer of the file could.
func appendChainedLine(t *testing.T, dir string, terminated bool) {
	t.Helper()
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	last, err := record.Decode(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	e.Seq, e.Prev = last.Seq+1, last.ID
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if !terminated {
		line = bytes.TrimSuffix(line, []byte("\n"))
	}
	if err := os.WriteFile(path, append(data, line...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGCAgesOutARunWithALineAfterRunEnd: State reads such a run as lost and sweep cannot end it (resume refuses
// a line after run_end); it used to be kept forever, silently, past any retention.
func TestGCAgesOutARunWithALineAfterRunEnd(t *testing.T) {
	dir, _ := closedRun(t, 1)
	appendChainedLine(t, dir, true)
	root := filepath.Dir(dir)
	rep, err := GC(context.Background(), root, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("run with a line after run_end was kept: %+v", rep)
	}
	if len(rep.Errors) != 1 {
		t.Errorf("Errors = %v, want the damaged run reported", rep.Errors)
	}
}

// TestSweepLiveClearsARunWithALineAfterRunEnd: its entry is reported and cleared, not retried on every run.
func TestSweepLiveClearsARunWithALineAfterRunEnd(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	ref := record.RunRef{ID: runID(fixedStart, "lare01"), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithClock(newStepClock(fixedStart, 1_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	appendChainedLine(t, filepath.Join(root, ref.ID), true)
	rep, err := SweepLive(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors[ref.ID] == nil {
		t.Errorf("Errors = %v, want the damaged run reported", rep.Errors)
	}
	if listed(t, root, ref.ID) {
		t.Error("entry still listed")
	}
}

// TestAgentOfLeavesANewerFirstLineToTheContract: a newer run_start is not skipped in search of a later line of
// this version (which would read the whole ledger); the agent is "" and the contract copy names it.
func TestAgentOfLeavesANewerFirstLineToTheContract(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	spliceVersionLine(t, dir, 0, "2", `"run":"`+testRef.ID+`","kind":"hologram","ts":"2031-01-01T00:00:00Z"`)
	repo := NewRunRepository(filepath.Dir(dir)).(*fsRunRepository)
	if a, err := repo.agentOf(testRef.ID); err != nil || a != "" {
		t.Fatalf("agentOf = %q, %v, want empty", a, err)
	}
}
