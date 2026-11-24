// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
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

// keyctlUnavailable reports whether err says the host has no keyctl for this process: EPERM (a seccomp profile) or
// ENOSYS (no CONFIG_KEYS). Nothing else is a reason to skip.
func keyctlUnavailable(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS)
}

// TestKeyctlUnavailableIsOnlyEPERMAndENOSYS: the skip of TestPlaneKeyProbeStaysOnOneThread is for those two and for
// nothing else: EACCES (the race the test hunts), EDQUOT, ENOMEM and the like fail it.
func TestKeyctlUnavailableIsOnlyEPERMAndENOSYS(t *testing.T) {
	for _, tc := range []struct {
		err  error
		skip bool
	}{
		{unix.EPERM, true}, {unix.ENOSYS, true}, {fmt.Errorf("wrapped: %w", unix.EPERM), true},
		{unix.EACCES, false}, {unix.EDQUOT, false}, {unix.ENOMEM, false}, {unix.ENOKEY, false}, {errors.New("other"), false},
	} {
		if got := keyctlUnavailable(tc.err); got != tc.skip {
			t.Errorf("keyctlUnavailable(%v) = %v, want %v", tc.err, got, tc.skip)
		}
	}
}

// TestPlaneKeyProbeStaysOnOneThread: doctor's key_permission fixture is made from a goroutine that a busy
// scheduler is asked to move to another thread between every two syscalls of the sequence. A process keyring is in
// the credentials of the thread that installed it, so a goroutine that moves loses possession and the kernel
// answers EACCES, which planeOutcome reads as "refused" and the probe blames the hook for (the 2026-11-24 flake of
// lsm/key_permission). Both ways to make the key are driven: planePrivateKey (the pre-made key) and doctor's own
// side, planeControlAction with no key made.
func TestPlaneKeyProbeStaysOnOneThread(t *testing.T) {
	// A host with no keyctl cannot run this test at all: Docker's default seccomp profile answers EPERM for add_key
	// and keyctl, a kernel built without CONFIG_KEYS answers ENOSYS. The first sequence, made before any forced thread
	// move, says so; any other failure of it is a failure of the test.
	key, err := planePrivateKey()
	if err != nil {
		if keyctlUnavailable(err) {
			t.Skipf("no keyctl on this host (%v): a seccomp profile (Docker's default) or a kernel without CONFIG_KEYS refuses add_key and keyctl", err)
		}
		t.Fatalf("planePrivateKey, before any thread move: %v", err)
	}
	planeReleaseKey(key)
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

// keyOnAHeldThread makes planePrivateKey's key on a goroutine that stays locked to its thread until the returned
// function is called, which releases the key there and ends the thread. The key is linked only in the process keyring
// that lives in the credentials of the thread that installed it, and the kernel destroys a keyring with the last
// credentials that hold it, which takes the key with it: a key made on a thread the Go scheduler may end (any
// thread a goroutine that exits locked lands on, onThrowawayThread) is gone for every thread afterwards, and an update
// of it answers ENOKEY, "required key not available" (the 2026-11-24 flake of TestPlaneKeyUpdateFromAnyThread, a key
// made on whatever thread the test goroutine had and then lost when one of the throwaway goroutines ran there and
// ended it). The helper child of the product never ends a thread while it holds its key, so this is a property of the
// test only.
func keyOnAHeldThread() (int, func(), error) {
	type made struct {
		key int
		err error
	}
	madeC := make(chan made)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		// Held until the key is released, then given back. It is unlocked and not ended: this goroutine can be on the
		// main thread, and a goroutine that exits locked to the main thread parks it for good, which fails every later
		// test that needs a goroutine there (TestThrowawayThreadIsNeverTheMainThread, 2026-11-24).
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		k, err := planePrivateKey()
		madeC <- made{k, err}
		if err != nil {
			return
		}
		<-stop
		planeReleaseKey(k)
	}()
	m := <-madeC
	return m.key, func() { close(stop); <-done }, m.err
}

// TestPlaneKeyUpdateFromAnyThread: the key a helper made before its probe row was armed is updated later from
// whatever thread the goroutine is on, which owner rights allow without possessing the ring (the comment in
// planePrivateKey). Each goroutine here runs on a thread of its own (onThrowawayThread); the key is made on a thread
// that is held until the test ends (keyOnAHeldThread), so none of them can end the thread that holds its ring.
func TestPlaneKeyUpdateFromAnyThread(t *testing.T) {
	key, release, err := keyOnAHeldThread()
	if err != nil {
		if keyctlUnavailable(err) {
			t.Skipf("no keyctl on this host: %v", err)
		}
		t.Fatalf("the key this test updates could not be made: %v", err)
	}
	defer release()
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
