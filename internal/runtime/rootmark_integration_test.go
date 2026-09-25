// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// plantedUID is the uid whose ledger root the planted run is in: nobody, neither root nor the invoking user
// whose root-launched run it names.
const plantedUID = 65534

// TestIntegrationRootSweepLeavesAnotherUsersRootRunAlone: under `sudo tego run` the sweep looked for a run's scope
// under the cgroup mount root for any run directory, and a run's id, agent and cgroup id are ledger data its owner
// writes. A user who planted, in a ledger root of their own, a lost run named after another user's live root-launched
// run — its run_start naming that run's scope by cgroup id, its live index entry listing it — had root's sweep write
// cgroup.kill into the other user's run. The victim runs on: a run directory the sweeper does not own names a scope
// under the mount root only when root's record says root launched that very directory.
func TestIntegrationRootSweepLeavesAnotherUsersRootRunAlone(t *testing.T) {
	c := newCrossOwner(t, "ixvictim")
	launcher := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"), "--", "/bin/sh", "-c", daemonizing)
	if err := launcher.Start(); err != nil {
		t.Fatalf("start the victim's root launcher: %v", err)
	}
	t.Cleanup(func() {
		_ = launcher.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = launcher.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = launcher.Process.Kill()
		}
	})
	pid := c.daemonPID(t, launcher)
	victim := waitForStartedRun(t, c.f.root, 20*time.Second)
	id := filepath.Base(victim)
	scopeID := runCgroupID(pathDir(victim))
	if scopeID == 0 {
		t.Fatalf("the victim's run_start recorded no cgroup id; the test proves nothing")
	}

	root := filepath.Join(t.TempDir(), "runs")
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "ixvictim"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStartIn(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}, scopeID); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	truncateRunEnd(t, filepath.Join(root, id))
	if err := ledger.MarkLive(root, id); err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, plantedUID, plantedUID)
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := SweepLive(context.Background(), root)
	t.Logf("the root sweep of the planted ledger root: %+v %v", res, err)
	time.Sleep(200 * time.Millisecond) // a kill already written takes effect at once; give it room to show
	if !alive(pid) {
		t.Fatalf("the root sweep of a planted run killed another user's root-launched run (descendant %d)", pid)
	}
	if lastKind(t, victim) == record.KindRunEnd {
		t.Fatal("the victim's run ended under the root sweep of a planted run")
	}
}
