// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// busyScheduler keeps three goroutines on two processors, so a goroutine that waits is picked up by another
// thread; the returned function stops them.
func busyScheduler() (stop func()) {
	prev := runtime.GOMAXPROCS(2)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 0
			for {
				select {
				case <-done:
					return
				default:
				}
				for j := range 100000 {
					x += j
				}
			}
		}()
	}
	return func() { close(done); wg.Wait(); runtime.GOMAXPROCS(prev) }
}

// moveThread asks the scheduler to run the calling goroutine on another thread and reports whether it did. Two
// tries are enough when the goroutine is free (a wait under the busy scheduler lasts a time slice); a goroutine
// locked to its thread never moves and pays both.
func moveThread() bool {
	t0 := unix.Gettid()
	for range 2 {
		runtime.Gosched()
		time.Sleep(20 * time.Microsecond)
		if unix.Gettid() != t0 {
			return true
		}
	}
	return false
}

// TestPlaneKeyProbeStaysOnOneThread: doctor's key_permission fixture is made from a goroutine that a busy
// scheduler is asked to move to another thread between every two syscalls of the sequence. A process keyring is in
// the credentials of the thread that installed it, so a goroutine that moves loses possession and the kernel
// answers EACCES, which planeOutcome reads as "refused" and the probe blames the hook for (the 2026-11-24 flake of
// lsm/key_permission). Both ways to make the key are driven: planePrivateKey (the pre-made key) and doctor's own
// side, planeControlAction with no key made.
func TestPlaneKeyProbeStaysOnOneThread(t *testing.T) {
	defer busyScheduler()()
	// The scheduler must be able to move a goroutine at all, or this test proves nothing.
	var calibrated atomic.Bool
	for range 100 {
		done := make(chan bool)
		go func() { done <- moveThread() }()
		if <-done {
			calibrated.Store(true)
			break
		}
	}
	if !calibrated.Load() {
		t.Skip("the scheduler did not move a free goroutine to another thread in 100 tries")
	}
	var moves, runs atomic.Int64
	planeKeyBetween = func() {
		runs.Add(1)
		if moveThread() {
			moves.Add(1)
		}
	}
	defer func() { planeKeyBetween = nil }()

	const iterations = 6
	for i := range iterations {
		key, err := planePrivateKey()
		if err != nil {
			t.Fatalf("planePrivateKey, iteration %d: %v (%d thread moves in %d pauses)", i, err, moves.Load(), runs.Load())
		}
		planeReleaseKey(key)
		if err := planeControlAction("key_permission", planeMakeEach); err != nil {
			if errors.Is(err, unix.EDQUOT) {
				t.Skipf("the key quota ended the loop at iteration %d (an ordinary user holds 200 keys): run as root for the full count", i)
			}
			t.Fatalf("key_permission action, iteration %d: %v (%d thread moves in %d pauses)", i, err, moves.Load(), runs.Load())
		}
	}
	if moves.Load() != 0 {
		t.Errorf("the sequence ran on %d different threads: it must stay on one", moves.Load())
	}
	t.Logf("%d iterations, %d pauses between the syscalls, %d thread moves", iterations, runs.Load(), moves.Load())
}

// TestPlaneKeyUpdateFromAnyThread: the key a helper made before its probe row was armed is updated later from
// whatever thread the goroutine is on, which owner rights allow without possessing the ring (the comment in
// planePrivateKey). Each goroutine here runs on a thread of its own (onThrowawayThread).
func TestPlaneKeyUpdateFromAnyThread(t *testing.T) {
	key, err := planePrivateKey()
	if err != nil {
		t.Skipf("no private key here: %v", err)
	}
	defer planeReleaseKey(key)
	pre := planeMakeEach
	pre.key = key
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A thread of its own that ends with the goroutine; never the main thread, which a goroutine
			// that exits locked to it would park for good (onThrowawayThread).
			onThrowawayThread(func() { errs <- planeControlAction("key_permission", pre) })
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("update of the pre-made key from another thread: %v", err)
		}
	}
}
