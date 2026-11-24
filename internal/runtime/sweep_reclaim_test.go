// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A launcher that releases the run's lock and exits while reclaimHeld proves it is not a holder of a dead launcher's
// lock: the lock is free by the second look, and nothing of the run is killed (review F3).
func TestReclaimHeldLeavesALauncherThatEndedDuringItsProof(t *testing.T) {
	const id = "r-00000000-000000000000b-orphan"
	root, m, _ := orphanFixture(t, id)
	looks := 0
	oldProbe, oldOpen := probeLock, openStopTarget
	t.Cleanup(func() { probeLock, openStopTarget = oldProbe, oldOpen })
	probeLock = func(runDir) (bool, LockInfo, error) {
		looks++
		return looks == 1, LockInfo{PID: 4242, StartBootNS: 99}, nil
	}
	openStopTarget = func(runDir, LockInfo) (*StopTarget, error) { return nil, ErrStale }
	ref := record.RunRef{ID: id, Agent: "tester"}
	if !reclaimHeld(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, id)), ref) {
		t.Fatal("a lock freed during the proof is a run to read again")
	}
	if len(m.killed) != 0 || looks != 2 {
		t.Fatalf("killed %v after %d looks at the lock", m.killed, looks)
	}
}

// A lock still held after the launcher's proof fails stale is still a dead launcher's, and its tree is killed (R20).
func TestReclaimHeldStillKillsAHolderOfADeadLaunchersLock(t *testing.T) {
	const id = "r-00000000-000000000000c-orphan"
	root, m, _ := orphanFixture(t, id)
	oldProbe, oldOpen := probeLock, openStopTarget
	t.Cleanup(func() { probeLock, openStopTarget = oldProbe, oldOpen })
	looks := 0
	probeLock = func(runDir) (bool, LockInfo, error) { // held at the first two looks, and freed once the tree is killed
		looks++
		return looks <= 2, LockInfo{PID: 4242, StartBootNS: 99}, nil
	}
	openStopTarget = func(runDir, LockInfo) (*StopTarget, error) { return nil, ErrStale }
	ref := record.RunRef{ID: id, Agent: "tester"}
	if !reclaimHeld(context.Background(), testSweepOptions(m), pathDir(filepath.Join(root, id)), ref) {
		t.Fatal("the run's lock is free once its tree is killed")
	}
	if len(m.killed) == 0 {
		t.Fatal("the tree of a run whose lock is held by a holder of a dead launcher's must be killed")
	}
}
