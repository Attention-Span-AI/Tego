// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// leaverAgent writes an agent that starts one process in a session of its own (`setsid sleep`) and one its shell
// child disowns (`sh -c 'sleep &'`), neither of which it waits for, then exits 7: the shape of a crashed agent that
// left a dev server or a watcher behind.
func leaverAgent(t *testing.T, f *fixture) string {
	t.Helper()
	script := filepath.Join(f.dir, "leaver.sh")
	body := "#!/bin/sh\nsetsid sleep 300 &\nsh -c 'sleep 300 &'\nexit 7\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	return script
}

// TestIntegrationARunEndsWithItsMainProcess at tier landlock: an agent that exits 7 while a `setsid` child
// and a disowned grandchild live on ends its run stop_grace (2 s here) after its exit, with its own exit 7 and reason
// exit, and run_end's detail names the two processes the kill ended. Before, `tego run` waited for them for as long as
// they lived (300 s here), so a unit never saw the crash and the exit code was lost to a later `tego stop`.
func TestIntegrationARunEndsWithItsMainProcess(t *testing.T) {
	allow := []string{"/bin/sh", "/bin/sleep", "/usr/bin/sleep", "/usr/bin/setsid"}
	f := newFixture(t, contractFor("imainexit", []string{"/bin/sh"}, allow))
	script := leaverAgent(t, f)
	start := time.Now()
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	took := time.Since(start)
	if res.ExitCode != 7 || res.Reason != record.RunEndExit {
		t.Fatalf("result %+v, want the main process's exit 7, reason exit", res)
	}
	if grace := f.machine.StopGrace.Value; took < grace || took > grace+10*time.Second {
		t.Errorf("the run took %s, want stop_grace (%s) after the main process's exit and little more", took, grace)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	end := runEndOf(t, dirs[0])
	if end.ExitCode != 7 || end.Escalated {
		t.Errorf("run_end %+v, want exit_code 7 and no escalation", end)
	}
	if !strings.Contains(end.Detail, "the main process exited") || !strings.Contains(end.Detail, "2 processes:") ||
		strings.Count(end.Detail, " sleep") != 2 {
		t.Errorf("run_end detail %q, want the two sleeps the kill ended named", end.Detail)
	}
}

// TestIntegrationKeepDescendantsWaitsForTheTree is the opt-out: with keep_descendants: true the same agent's run goes
// on past stop_grace while its two sleeps live, as every run once did, and a stop still ends it.
func TestIntegrationKeepDescendantsWaitsForTheTree(t *testing.T) {
	allow := []string{"/bin/sh", "/bin/sleep", "/usr/bin/sleep", "/usr/bin/setsid"}
	f := newFixture(t, contractFor("ikeepdesc", []string{"/bin/sh"}, allow)+"keep_descendants: true\n")
	script := leaverAgent(t, f)
	signals := make(chan os.Signal, 1)
	done := make(chan Result, 1)
	go func() {
		res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script}, f.deps(t, signals))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	select {
	case res := <-done:
		t.Fatalf("the run ended with its main process under keep_descendants: %+v", res)
	case <-time.After(2*f.machine.StopGrace.Value + time.Second):
	}
	signals <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a SIGTERM did not end the run its descendants kept going")
	}
}
