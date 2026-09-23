// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// hookedAttacher is fakeAttacher with a hook run once, before the first probe is placed and outside the
// fake's lock, so the hook can Stop the source and let Stop close links without deadlocking on it.
type hookedAttacher struct {
	fakeAttacher
	hook  func()
	fired atomic.Bool
}

func (a *hookedAttacher) Attach(path string, p Probe) (io.Closer, error) {
	if a.hook != nil && a.fired.CompareAndSwap(false, true) {
		a.hook()
	}
	return a.fakeAttacher.Attach(path, p)
}

// startIdle starts a source over an empty ring and waits for its drain to end, so nothing but the test
// itself calls into the source afterwards.
func startIdle(t *testing.T, u *Uprobe, sink *fakeSink, run source.RunRef) {
	t.Helper()
	if err := u.Start(context.Background(), run, sink); err != nil {
		t.Fatalf("Start %s: %v", run.ID, err)
	}
	<-u.done
}

// TestStopDuringAnAttachLeavesNoLinks pins I9 against an exec still being handled when the run tears down.
// The attach cache takes the reference first and the source records it second, and Stop's sweep reads
// only what was recorded, so a Stop that lands in between sweeps without it. Recorded afterwards, the
// reference outlives the only sweep that will ever run, and the binary's links stay open past the run
// with nothing left to close them. An exec that arrives once Stop has returned places no probe at all:
// there is no run left to capture for.
func TestStopDuringAnAttachLeavesNoLinks(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{151, 152}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	att := &hookedAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	startIdle(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	att.hook = func() {
		if err := u.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}

	u.OnExec(151, 41, "")
	if !att.fired.Load() {
		t.Fatal("the attach never reached the attacher, so Stop never overlapped it")
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links open after an attach that finished under Stop, want 0 (I9)", got)
	}
	if got := u.cache.size(); got != 0 {
		t.Errorf("attach cache holds %d binaries after the only run stopped, want 0", got)
	}

	placed := att.count()
	u.OnExec(152, 41, "")
	if got := att.count(); got != placed {
		t.Errorf("%d probes placed by an exec after Stop, want none", got-placed)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links open after an exec that arrived after Stop, want 0 (I9)", got)
	}
}

// TestStopBeforeAReferenceLeavesTheOtherRunAlone is the fast path of the same race, on a cache two runs
// share: r-2's exec finds the binary r-1 already attached and only adds a reference, after r-2's Stop has
// swept. That reference has to be given back too, or r-1's Stop leaves RefCount at one and the links open
// for good; and giving it back must not take r-1's with it (R8, edge case #26). An exec that arrives
// after Stop has returned must leave no reference behind either.
func TestStopBeforeAReferenceLeavesTheOtherRunAlone(t *testing.T) {
	tree := newProcTree(t)
	sharedRootTree(t, tree, []int{161, 162, 163}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	shared := newCache()
	att := &fakeAttacher{}
	one, sinkOne := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared})
	var two *Uprobe
	var stopNow atomic.Bool
	now := func() time.Time {
		// The first clock read of an OnExec is its attach budget, after its entry check and before
		// the cache is consulted: Stop landing here is Stop landing mid-exec.
		if stopNow.CompareAndSwap(true, false) {
			if err := two.Stop(); err != nil {
				t.Errorf("Stop r-2: %v", err)
			}
		}
		return time.Now()
	}
	two, sinkTwo := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att, Cache: shared, Now: now})
	startIdle(t, one, sinkOne, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	startIdle(t, two, sinkTwo, source.RunRef{ID: "r-2", Agent: "b", CgroupID: 42})

	one.OnExec(161, 41, "")
	if got := att.count(); got != 3 {
		t.Fatalf("%d probes, want 3", got)
	}
	stopNow.Store(true)
	two.OnExec(162, 42, "")
	if stopNow.Load() {
		t.Fatal("r-2's exec never read the clock, so Stop never overlapped it")
	}
	if got := att.openLinks(); got != 3 {
		t.Errorf("%d links open after r-2 stopped mid-exec, want 3: r-1's process still maps the binary (R8)", got)
	}
	two.OnExec(163, 42, "")

	if err := one.Stop(); err != nil {
		t.Fatalf("Stop r-1: %v", err)
	}
	if got := att.openLinks(); got != 0 {
		t.Errorf("%d links still open after every run stopped: a reference r-2 took at or after its Stop was never given back (I9)", got)
	}
	if got := shared.size(); got != 0 {
		t.Errorf("attach cache holds %d binaries after every run stopped, want 0", got)
	}
}
