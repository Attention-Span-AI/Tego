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

// TestIntegrationRootSweepLeavesAnotherUsersRootRunForARenamedRootOwnedRun: a
// root-owned run directory that never started (its root launcher killed between MakeRunDir and run_start:
// Ctrl-\ under sudo) sits in a ledger root its user owns. The user renames it (same parent, so no write on the
// root-owned directory is needed) to the id of another user's live root-launched run and lists it. orphanRoots
// trusted the mount root for any directory the sweeper owns, the record was never consulted, and an empty
// ledger has no cgroup id to check: the sweep took the first candidate of that name and killed the other run.
// The victim runs on: a root sweeper searches the mount root only on a record naming that very directory.
func TestIntegrationRootSweepLeavesAnotherUsersRootRunForARenamedRootOwnedRun(t *testing.T) {
	if os.Geteuid() != 0 {
		// Here, not in each subtest: the skip list names the test, and a subtest's skip is its own.
		t.Skip("root only: a sweep of another account's run, and a launcher of another uid, need root")
	}
	for _, mode := range []string{"live", "gc"} {
		t.Run(mode, func(t *testing.T) {
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

			root := filepath.Join(t.TempDir(), "runs")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			// What a root launcher killed after Open leaves: a root-owned run directory, a contract copy, a free
			// lock, no ledger line. Made under another name, then renamed as its user can.
			own := filepath.Join(root, "own-killed-run")
			if err := os.Mkdir(own, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(own, ledger.ContractFile), []byte("version: 0\nname: ixvictim\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(own, ledger.LockFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(own, "events.jsonl"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(root, plantedUID, plantedUID); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(own, filepath.Join(root, id)); err != nil { // the user's rename
				t.Fatal(err)
			}
			if mode == "live" {
				if err := ledger.MarkLive(root, id); err != nil {
					t.Fatal(err)
				}
				if err := os.Lchown(filepath.Join(root, ledger.LiveDir), plantedUID, plantedUID); err != nil {
					t.Fatal(err)
				}
				if err := os.Lchown(filepath.Join(root, ledger.LiveDir, id), plantedUID, plantedUID); err != nil {
					t.Fatal(err)
				}
				res, err := SweepLive(context.Background(), root)
				t.Logf("root SweepLive: %+v %v", res, err)
			} else {
				res, err := Sweep(context.Background(), root, KeepForever)
				t.Logf("root Sweep: %+v %v", res, err)
			}
			time.Sleep(200 * time.Millisecond)
			if !alive(pid) {
				t.Fatalf("the root sweep of a renamed root-owned empty run killed another user's root-launched run (descendant %d)", pid)
			}
			if lastKind(t, victim) == record.KindRunEnd {
				t.Fatal("the victim's run ended")
			}
		})
	}
}

// TestIntegrationRootSweepLeavesAnotherUsersRootRunForAPlantedEndedRun pins a path the case above leaves untested:
// a planted ENDED run (user-owned, named after the victim's id, run_start naming the victim's scope by cgroup
// id, a lock line naming a dead pid, listed) under a root SweepLive, which reaches the scope through the
// ended-run hook rather than the lost-run sweep. The victim runs on.
func TestIntegrationRootSweepLeavesAnotherUsersRootRunForAPlantedEndedRun(t *testing.T) {
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
		t.Fatal("no cgroup id")
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
	if err := os.WriteFile(filepath.Join(root, id, ledger.LockFile), []byte("4194000 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ledger.MarkLive(root, id); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, plantedUID, plantedUID)
	}); err != nil {
		t.Fatal(err)
	}
	res, err := SweepLive(context.Background(), root)
	t.Logf("root SweepLive of a planted ended run: %+v %v", res, err)
	time.Sleep(200 * time.Millisecond)
	if !alive(pid) {
		t.Fatalf("killed the victim (descendant %d)", pid)
	}
	if lastKind(t, victim) == record.KindRunEnd {
		t.Fatal("the victim's run ended")
	}
}
