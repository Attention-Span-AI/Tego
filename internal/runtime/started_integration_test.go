// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const startedContract = "version: 0\nname: istarted\ncommand: [/bin/sh]\ntier: landlock\nfs:\n  write: [./out]\n" +
	"env:\n  pass: [PATH, HOME]\nlimits:\n  pids: 64\n"

// startedScript is the agent: it says it ran, and whether the hook's marker was there when it did.
const startedScript = `if [ -e out/marker ]; then echo released > out/agent; else echo early > out/agent; fi`

// TestIntegrationStartedRunsOnceBetweenRunStartAndTheAgent is ADR 0073 D4 and runtime-launch.md §4.1 step 9a through
// the real runner.run: Started is called once, with the run's id and directory, after run_start is durable (the
// callback reads it from events.jsonl) and after every post-run_start gap (a fake one registered last has run), and
// before the agent is released (the agent finds the callback's marker, and the callback finds no sign of the agent).
func TestIntegrationStartedRunsOnceBetweenRunStartAndTheAgent(t *testing.T) {
	f := newFixture(t, startedContract)
	deps := f.deps(t, nil)
	lastGapRan := false
	saved := postStartGaps
	postStartGaps = append(append([]func(*runner){}, saved...), func(*runner) { lastGapRan = true })
	t.Cleanup(func() { postStartGaps = saved })
	var calls []StartedRun
	var sawRunStart, gapBefore, agentBefore bool
	deps.Started = func(s StartedRun) error {
		calls = append(calls, s)
		gapBefore = lastGapRan
		sawRunStart = firstLineIsRunStart(t, filepath.Join(s.Dir, ledger.EventsFile))
		_, err := os.Stat(filepath.Join(f.out, "agent"))
		agentBefore = err == nil
		return os.WriteFile(filepath.Join(f.out, "marker"), nil, 0o600)
	}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", startedScript}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("Started called %d times, want once", len(calls))
	}
	if string(calls[0].ID) != res.RunID || !calls[0].ID.Valid() || filepath.Base(calls[0].Dir) != res.RunID {
		t.Fatalf("Started told %+v, the run is %s", calls[0], res.RunID)
	}
	if !sawRunStart || !gapBefore || agentBefore {
		t.Fatalf("at the callback: run_start durable %v, the last post-run_start gap ran %v, the agent had run %v",
			sawRunStart, gapBefore, agentBefore)
	}
	if b, _ := os.ReadFile(filepath.Join(f.out, "agent")); res.ExitCode != 0 || strings.TrimSpace(string(b)) != "released" {
		t.Fatalf("exit %d, agent %q: the agent ran before the callback returned", res.ExitCode, b)
	}
}

// TestIntegrationStartedErrorEndsTheRunBeforeTheAgent is ADR 0073 D4's fail-closed rule: an error from Started ends
// the run with run_end reason error and a detail naming the hook, the agent never execs, and tego run's exit is 125.
func TestIntegrationStartedErrorEndsTheRunBeforeTheAgent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hook   func(StartedRun) error
		detail string
	}{
		{"error", func(StartedRun) error { return errors.New("the caller could not note the run") },
			"started hook: the caller could not note the run"},
		// An error longer than a ledger line may be is cut, so run_end is still written (record.CutDetail).
		{"error over a line's bound", func(StartedRun) error { return errors.New(strings.Repeat("x", 3<<20)) },
			record.CutDetail("started hook: " + strings.Repeat("x", 3<<20))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, startedContract)
			deps := f.deps(t, nil)
			calls := 0
			deps.Started = func(s StartedRun) error { calls++; return tc.hook(s) }
			res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", startedScript}, deps)
			if err != nil {
				t.Fatalf("Run: %v (an error after run_start is a run_end, never a return)", err)
			}
			if calls != 1 || res.ExitCode != identity.ExitLauncher || res.Reason != record.RunEndError {
				t.Fatalf("calls %d, result %+v: want one call, exit 125, reason error", calls, res)
			}
			if _, err := os.Stat(filepath.Join(f.out, "agent")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the agent ran (%v)", err)
			}
			evs := events(t, runDirs(t, f.root)[0])
			var end record.RunEndPayload
			if last := evs[len(evs)-1]; last.Kind != record.KindRunEnd || last.DecodePayload(&end) != nil {
				t.Fatalf("the ledger ends with %s", last.Kind)
			}
			if end.Reason != record.RunEndError || end.Detail != tc.detail {
				t.Fatalf("run_end reason %s detail %q, want error and %q", end.Reason, end.Detail, tc.detail)
			}
		})
	}
}

// firstLineIsRunStart reports whether path's first line is a run_start, read from the file itself.
func firstLineIsRunStart(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	return sc.Scan() && strings.Contains(sc.Text(), `"kind":"run_start"`) && bytes.HasSuffix(b, []byte("\n"))
}
