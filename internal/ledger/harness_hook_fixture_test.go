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

// harnessHookTego is the tego binary the harness-hook fixture's run granted.
const harnessHookTego = "/usr/local/bin/tego"

// generateHarnessHook writes spec/record/v1/fixtures/harness-hook.jsonl through the real Writer: a run at record_minor
// 20 (MinorHarnessHook) of an allow-list contract whose launcher provisioned Claude Code and granted its hook's exact
// argv (ADR 0064): run_start's harness with the hook {argv, granted: true} and runtime_grants holding the hook-state
// grant and exec.harness-hook[<tego>], the hook's exec allowed under the grant, an exec of the tego binary with other
// argv refused under it at tier landlock (on the supervisor's copied argv), and run_end. Its run_start carries
// launcher_uid and fs_reads, as every run_start at MinorRunIdentity and MinorHeldReads or later does.
func generateHarnessHook(t *testing.T, dir string, anchor ChainAnchor) {
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
	reason := harnessFixtureRuntime + "/last-refusal.json"
	hook := []string{harnessHookTego, "hook", "claude-code", "--reason", reason, "--mode", "json"}
	grant := "exec.harness-hook[" + harnessHookTego + "]"
	start := startPayload()
	start.Command = []string{"/usr/local/bin/claude", "--settings", settings, "-p", "summarize the repo"}
	start.RecordMinor = record.MinorHarnessHook
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	start.RuntimeGrants = []string{"fs.harness-state[" + state + "]", grant}
	start.BestEffort = []string{"exec.rules/argv"}
	start.Harness = &record.HarnessStart{Name: "claude-code", Provisioned: true, Files: []string{settings},
		ReasonFile: reason, StateDir: state, Hook: &record.HarnessHook{Argv: hook, Granted: true}}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	f.emit(0, f.action(record.KindExec, record.SourceSupervisor, fxTID, grant, record.VerdictAllow, "", record.Unattributed(),
		record.ExecPayload{Path: harnessHookTego, Argv: hook, ExecID: f.execID(48215, 4_990_300_000), CommandRule: harnessHookTego,
			CommandList: "allow", CommandMatch: "definite", CommandVia: "name", ArgvFacts: record.ArgvFactsCopied}))
	f.emit(time.Millisecond, f.action(record.KindExec, record.SourceSupervisor, fxTID, grant, record.VerdictRefused,
		record.ReasonExecNotAllowed, record.Unattributed(), record.ExecPayload{Path: harnessHookTego,
			Argv: []string{harnessHookTego, "run", "inner.yaml"}, Errno: 13, CommandRule: "tego", CommandList: "unlisted", CommandVia: "name"}))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 2}}); err != nil {
		t.Fatal(err)
	}
}

// TestHarnessHookFixtureFrozen regenerates harness-hook.jsonl and compares it byte for byte with the committed file;
// -update rewrites it, as TestFixturesFrozen does for the others.
func TestHarnessHookFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateHarnessHook(t, filepath.Join(root, testRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, testRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "harness-hook.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("harness-hook.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("harness-hook.jsonl differs from the generator output; run go test ./internal/ledger -run TestHarnessHookFixtureFrozen -update")
	}
}
