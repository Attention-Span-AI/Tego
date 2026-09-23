// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestStopLeavesAnotherRunsAttachAlone pins R8 and edge case #26 across the seam Options.Cache opens. The
// attach cache is host-wide and outlives a single run on purpose (ARCHITECTURE §9 "resource lifetimes"):
// two concurrent runs whose processes map one system libssl share one attach and one RefCount, and the
// per-cgroup filter in the kernel keeps their plaintext apart (R9). R8 then says a binary still mapped by
// another run's process is never detached while that run's contribution to RefCount stands, and I9 bounds
// the leak in the other direction: no RefCount==0 entry keeps live links past the next Stop.
//
// A Stop that closes every link in the cache satisfies I9 by breaking R8. The second run keeps running,
// its probes are gone, and every request it makes after that is captured by nothing and reported as
// nothing — the silent absence I4 forbids, because no gap is raised for a binary the cache still believes
// is attached.
func TestStopLeavesAnotherRunsAttachAlone(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{111, 112}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	one, sinkOne := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	two, sinkTwo := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	if err := one.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sinkOne); err != nil {
		t.Fatalf("Start r-1: %v", err)
	}
	if err := two.Start(context.Background(), source.RunRef{ID: "r-2", Agent: "b", CgroupID: 42}, sinkTwo); err != nil {
		t.Fatalf("Start r-2: %v", err)
	}
	one.OnExec(111, 41, "")
	two.OnExec(112, 42, "")
	// SSL_write is one probe and SSL_read needs an entry and a return (R1, R3), placed once for both
	// runs: no (dev,ino) is ever double-attached (I8).
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes for two runs on one libssl, want 3 (I8)", got)
	}

	if err := one.Stop(); err != nil {
		t.Fatalf("Stop r-1: %v", err)
	}
	if got := att.openLinks(); got != 3 {
		t.Errorf("%d links open after the first run stopped, want 3: it detached a binary run r-2's process still maps (R8, edge case #26)",
			got)
	}
	if got := shared.size(); got != 1 {
		t.Errorf("attach cache holds %d binaries after the first run stopped, want 1", got)
	}

	if err := two.Stop(); err != nil {
		t.Fatalf("Stop r-2: %v", err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after the last interested run stopped (I9)", got)
	}
}

// TestStopReleasesAProcessWhoseExitWasNeverSeen is the other half: the sweep Stop runs exists because an
// exit event can be missed, so a process this source attached for and never saw exit must still give its
// reference back at Stop, or its links outlive every run that wanted them (I9).
func TestStopReleasesAProcessWhoseExitWasNeverSeen(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{121}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(121, 41, "")
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes, want 3", got)
	}
	// No OnExit for pid 121: the exit event never arrived.
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after the last interested run stopped (I9)", got)
	}
	if got := shared.size(); got != 0 {
		t.Errorf("attach cache holds %d binaries after the last interested run stopped, want 0", got)
	}
}

// TestAReusedPidKeepsAnotherRunsReference pins that a reference in the shared attach cache belongs to the
// source that took it, not to the pid number alone. Run r-1 attaches for pid 131 and never sees it exit;
// the pid is reused by a process of run r-2 that maps the same libssl. Keyed by pid, r-2's attach folds
// into r-1's stale reference and adds nothing, so r-1's Stop gives back the only reference there is and
// closes links r-2's live process still maps (R8, edge case #26) with no gap to say so (I4).
func TestAReusedPidKeepsAnotherRunsReference(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{131}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	one, sinkOne := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	two, sinkTwo := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	if err := one.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sinkOne); err != nil {
		t.Fatalf("Start r-1: %v", err)
	}
	if err := two.Start(context.Background(), source.RunRef{ID: "r-2", Agent: "b", CgroupID: 42}, sinkTwo); err != nil {
		t.Fatalf("Start r-2: %v", err)
	}
	one.OnExec(131, 41, "")
	// No OnExit for r-1's pid 131: the event was missed and the pid went back to the kernel.
	two.OnExec(131, 42, "")
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes, want 3: one attach for both runs (I8)", got)
	}

	if err := one.Stop(); err != nil {
		t.Fatalf("Stop r-1: %v", err)
	}
	if got := att.openLinks(); got != 3 {
		t.Errorf("%d links open after r-1 stopped, want 3: its stale pid gave back r-2's reference (R8, edge case #26)", got)
	}
	if err := two.Stop(); err != nil {
		t.Fatalf("Stop r-2: %v", err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after the last interested run stopped (I9)", got)
	}
}

// TestAnExitDropsOnlyTheSourcesOwnReference is the same seam from OnExit. An exit event names a pid, and a
// source can be told about a pid it never attached for — another run's process, or a reused pid. Only its
// own reference is its to give back: releasing the pid's references wholesale detaches the other run.
func TestAnExitDropsOnlyTheSourcesOwnReference(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{141}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	one, sinkOne := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	two, sinkTwo := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	if err := one.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sinkOne); err != nil {
		t.Fatalf("Start r-1: %v", err)
	}
	if err := two.Start(context.Background(), source.RunRef{ID: "r-2", Agent: "b", CgroupID: 42}, sinkTwo); err != nil {
		t.Fatalf("Start r-2: %v", err)
	}
	two.OnExec(141, 42, "")
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes, want 3", got)
	}

	one.OnExit(141)
	if got := att.openLinks(); got != 3 {
		t.Errorf("%d links open after r-1 was told pid 141 exited, want 3: it dropped r-2's reference (R8)", got)
	}
	two.OnExit(141)
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after the process that held them exited (I9)", got)
	}
	for _, u := range []*Uprobe{one, two} {
		if err := u.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}
}
