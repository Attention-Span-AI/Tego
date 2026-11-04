// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// holdOnce makes the first lock-file open of a run take a shared flock, as a status probe would, and returns
// its release and a signal that the probe has acquired the lock.
func holdOnce(t *testing.T) (release func(), acquired <-chan struct{}) {
	t.Helper()
	ready := make(chan struct{})
	var mu sync.Mutex // the hook runs in the sweep's goroutine, release in the test's or a timer's
	var held *os.File
	done := false
	prev := lockOpened
	lockOpened = func(path string) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		done = true
		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			t.Error(err)
		}
		held = f
		close(ready)
	}
	release = func() {
		mu.Lock()
		defer mu.Unlock()
		if held != nil {
			_ = held.Close()
			held = nil
		}
	}
	t.Cleanup(func() { lockOpened = prev; release() })
	return release, ready
}

// TestGCKeepsALostRunItsSweepDidNotEnd: a probe holding the lock when the sweep opens it made the sweep return
// "not mine" without running the hook, and gc then aged the run out and deleted it, orphan tree unkilled.
func TestGCKeepsALostRunItsSweepDidNotEnd(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	lost := makeRun(t, root, fixedStart, "a00003", StateLost)
	release, _ := holdOnce(t)
	calls := 0
	hook := func(context.Context, sys.Lender, record.RunRef) error { calls++; return nil }
	rep, err := GC(context.Background(), root, 24*time.Hour, false,
		WithNow(func() time.Time { release(); return now }), WithSweepHook(hook),
		WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 || calls != 0 {
		t.Fatalf("deleted %v, hook calls %d; an unswept lost run must be kept", rep.Deleted, calls)
	}
	if _, err := os.Stat(filepath.Join(root, lost.ID)); err != nil {
		t.Fatalf("run directory gone: %v", err)
	}
}

// TestSweepWaitsOutAProbesHold: a probe's momentary hold of the lock no longer skips the hook.
func TestSweepWaitsOutAProbesHold(t *testing.T) {
	synctest.Test(t, testSweepWaitsOutAProbesHold)
}

func testSweepWaitsOutAProbesHold(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(time.Hour)
	lost := makeRun(t, root, fixedStart, "a00003", StateLost)
	release, acquired := holdOnce(t)
	// Start the hold's clock only once the probe owns the lock. Virtual time makes this exercise
	// the retry even when the machine cannot schedule a real 5 ms timer within freshLockWait.
	go func() {
		<-acquired
		time.Sleep(5 * time.Millisecond)
		release()
	}()
	calls := 0
	hook := func(context.Context, sys.Lender, record.RunRef) error { calls++; return nil }
	rep, err := GC(context.Background(), root, 24*time.Hour, false,
		WithNow(func() time.Time { return now }), WithSweepHook(hook),
		WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(rep.Swept) != 1 || rep.Swept[0] != lost.ID {
		t.Fatalf("hook calls %d, swept %v", calls, rep.Swept)
	}
}

// TestAgentOfReadsOnlyTheFirstLine: listing a run must not fill a 64 KiB buffer for its one first line.
func TestAgentOfReadsOnlyTheFirstLine(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "a00001", StateEnded)
	repo := NewRunRepository(root).(*fsRunRepository)
	if a, err := repo.agentOf(ref.ID); err != nil || a != "retriever" {
		t.Fatalf("agentOf = %q, %v", a, err)
	}
	const n = 200
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for range n {
		_, _ = repo.agentOf(ref.ID)
	}
	runtime.ReadMemStats(&m1)
	if per := (m1.TotalAlloc - m0.TotalAlloc) / n; per > 32<<10 {
		t.Fatalf("agentOf allocates %d bytes per run; want under 32 KiB", per)
	}
}
