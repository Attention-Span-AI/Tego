// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// harnessFixtureRuntime is the runtime directory the harness fixture's run names.
const harnessFixtureRuntime = "/run/user/1000/tego/" + "01J0000000000000000000000A"

// generateHarness writes spec/record/v1/fixtures/harness.jsonl through the real Writer: a run at record_minor 14
// (MinorHarness) whose launcher provisioned Claude Code (agent-contract.md R27, ADR 0062): run_start's harness and its
// fs.harness-state grant, a write the grant allowed in hook-state, a write to the provisioned settings file the
// kernel refused, and run_end.
func generateHarness(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	state := harnessFixtureRuntime + "/hook-state"
	settings := harnessFixtureRuntime + "/claude-settings.json"
	start := startPayload()
	start.Command = []string{"/usr/local/bin/claude", "--settings", settings, "-p", "summarize the repo"}
	start.RecordMinor = record.MinorHarness
	start.RuntimeGrants = []string{"fs.harness-state[" + state + "]"}
	start.Harness = &record.HarnessStart{Name: "claude-code", Provisioned: true, Files: []string{settings},
		ReasonFile: harnessFixtureRuntime + "/last-refusal.json", StateDir: state}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.emit(0, f.action(record.KindFS, record.SourceLandlock, fxTID, "fs.harness-state["+state+"]", record.VerdictAllow, "",
		record.Unattributed(), record.FSPayload{Op: record.FSOpen, Path: state + "/state.json", Flags: 0x241}))
	f.emit(time.Millisecond, f.action(record.KindFS, record.SourceLandlock, fxTID, "unmatched", record.VerdictRefused,
		record.ReasonWriteOutsideContract, record.Unattributed(), record.FSPayload{Op: record.FSOpen, Path: settings, Flags: 0x241}))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 2}}); err != nil {
		t.Fatal(err)
	}
}

// TestHarnessFixtureFrozen regenerates harness.jsonl and compares it byte for byte with the committed file; -update
// rewrites it, as TestFixturesFrozen does for the others.
func TestHarnessFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateHarness(t, filepath.Join(root, testRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, testRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "harness.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("harness.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("harness.jsonl differs from the generator output; run go test ./internal/ledger -run TestHarnessFixtureFrozen -update")
	}
}
