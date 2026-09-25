// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationConcurrentSweepersEndAnOrphanOnce is runtime-launch.md §6 case 10: sweepers racing for one
// orphan each probe its lock with flock(LOCK_EX|LOCK_NB), exactly one wins it, and the others read the run as
// not orphaned and move on (R12) — one run_end, never two, and one sweeper reporting the orphan. Every sweeper
// opens the lock file itself, so each holds its own open file description and the flocks conflict as they do
// between processes.
//
// Also pins runtime-launch.md E10: racing sweepers end an orphan once.
//
// Also pins runtime-launch.md R20: the per-run flock probe alone arbitrates racing sweepers.
func TestIntegrationConcurrentSweepersEndAnOrphanOnce(t *testing.T) {
	const sweepers = 16
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("isweeprace", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	cfg := writeMachineConfig(t, f)

	for round := 1; round <= 3; round++ {
		cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sleep", "120")
		cmd.Dir = f.dir
		cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start launcher: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		dir := waitForStartedRunNot(t, f.root, 20*time.Second, round-1)
		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatalf("kill launcher: %v", err)
		}
		_ = cmd.Wait()
		waitLockFree(t, dir)

		start := make(chan struct{})
		results := make([]SweepResult, sweepers)
		errs := make([]error, sweepers)
		var wg sync.WaitGroup
		for i := range sweepers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = Sweep(context.Background(), f.root, KeepForever)
			}()
		}
		close(start)
		wg.Wait()

		orphaned := 0
		for i := range sweepers {
			if errs[i] != nil {
				t.Errorf("round %d: sweeper %d: %v", round, i, errs[i])
			}
			orphaned += results[i].Orphaned
		}
		if orphaned != 1 {
			t.Errorf("round %d: %d sweepers reported the orphan, want exactly one", round, orphaned)
		}
		ends := 0
		for _, e := range events(t, dir) {
			if e.Kind == record.KindRunEnd {
				ends++
			}
		}
		if ends != 1 {
			t.Fatalf("round %d: %d run_end lines, want one", round, ends)
		}
		if got := lastReason(t, dir); got != record.RunEndOrphaned {
			t.Fatalf("round %d: run ended with %q, want orphaned", round, got)
		}
		assertCgroupRemoved(t, f, filepath.Base(dir), "isweeprace")
	}
}

// waitForStartedRunNot waits for a started run directory under root other than the seen ones (the earlier
// rounds' runs, of which there are n), and returns it.
func waitForStartedRunNot(t *testing.T, root string, d time.Duration, n int) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		dirs := runDirs(t, root)
		if len(dirs) > n {
			for _, dir := range dirs {
				if hasRunStart(dir) && lastReason(t, dir) == "" {
					return dir
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no new started run under %s within %v", root, d)
	return ""
}
