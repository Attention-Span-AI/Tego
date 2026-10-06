// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCloseOnceUnderRace: 64 goroutines close one FD at once, by Close and CloseNow, and close(2) runs for
// its number exactly once (ADR 0023's own test, run 200 rounds; meaningful under -race, which CI's race job
// and scripts/fd-churn.sh give it). The closeNumber seam counts each round's close(2)s on its number, and
// that count is the check; the OnClosed hook cannot count them, since finishClose hands it to one closer only.
// The hook also puts a sentinel on the freed number the moment close(2) returns, so a second close(2) that
// comes after it closes the sentinel, which the round then finds gone; one that comes before it does not.
func TestCloseOnceUnderRace(t *testing.T) {
	const goroutines, rounds = 64, 200
	// No test in this package is parallel, so no other test runs while the seam is swapped.
	var number atomic.Int64 // the round's number
	var closes atomic.Int32 // the close(2)s on it this round
	number.Store(-1)
	prev := closeNumber
	closeNumber = func(n int) error {
		if int64(n) == number.Load() {
			closes.Add(1)
		}
		return prev(n)
	}
	t.Cleanup(func() { closeNumber = prev })
	for round := range rounds {
		f := openNull(t)
		n := numOf(f)
		number.Store(int64(n))
		closes.Store(0)
		var hooked bool
		var sentinel identity
		var serr error
		if err := f.OnClosed(func(error) {
			hooked = true
			sentinel, serr = placeSentinel(n)
		}); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if i%2 == 0 {
					_ = f.Close()
				} else {
					_ = f.CloseNow()
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := closes.Load(); got != 1 {
			t.Fatalf("round %d: close(2) ran %d times on fd %d, want exactly 1", round, got, n)
		}
		if !hooked || serr != nil {
			t.Fatalf("round %d: no sentinel on fd %d (the hook ran: %v; placing it: %v)", round, n, hooked, serr)
		}
		wantOpen(t, n, sentinel, fmt.Sprintf("round %d: the sentinel after 64 concurrent closes", round))
		_ = unix.Close(n)
	}
}

// TestLeaseVsCloseUnderChurn: four borrowers against a concurrent Close, with a fifth goroutine opening and
// closing files so that a freed number is taken at once. A borrowed number always names the owner's own
// (dev, ino), on every one of 2,000 rounds: the number is never closed under a lease (A1).
func TestLeaseVsCloseUnderChurn(t *testing.T) {
	const rounds, borrowers = 2000, 4
	stop := make(chan struct{})
	var churn sync.WaitGroup
	churn.Add(1)
	go func() {
		defer churn.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n, err := unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
				_ = unix.Close(n)
			}
		}
	}()
	defer func() { close(stop); churn.Wait() }()
	for range rounds {
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		id := idOf(t, f)
		var wg sync.WaitGroup
		var bad atomic.Value
		for range borrowers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					err := f.Borrow(func(n int) error {
						got, err := statNum(n)
						if err != nil || got != id {
							bad.Store(errors.Join(err, errors.New("a borrowed number named another file")))
						}
						return nil
					})
					if errors.Is(err, ErrClosed) {
						return
					}
				}
			}()
		}
		_ = f.Close()
		wg.Wait()
		if v := bad.Load(); v != nil {
			t.Fatal(v)
		}
	}
}

// TestOnClosedVsCloseNowRace: Close, CloseNow and the last Return race from three goroutines, 1,000 rounds.
// The hook runs exactly once, after close(2): fstat on the number gives EBADF inside it, and nothing in this
// test opens a descriptor that could take the number in between.
func TestOnClosedVsCloseNowRace(t *testing.T) {
	for range 1000 {
		f := openNull(t)
		n := numOf(f)
		var runs atomic.Int32
		var after atomic.Bool
		if err := f.OnClosed(func(error) {
			runs.Add(1)
			_, err := statNum(n)
			after.Store(errors.Is(err, unix.EBADF))
		}); err != nil {
			t.Fatal(err)
		}
		l, err := f.Hold()
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var nowErr error
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); <-start; _ = f.Close() }()
		go func() { defer wg.Done(); <-start; nowErr = f.CloseNow() }()
		go func() { defer wg.Done(); <-start; l.Return() }()
		close(start)
		wg.Wait()
		if nowErr != nil && !errors.Is(nowErr, ErrLeased) {
			t.Fatalf("CloseNow = %v, want nil or ErrLeased", nowErr)
		}
		if err := f.CloseNow(); err != nil {
			t.Fatalf("CloseNow once all three were done = %v, want nil", err)
		}
		if runs.Load() != 1 || !after.Load() {
			t.Fatalf("the hook ran %d times (want 1), after close(2): %v", runs.Load(), after.Load())
		}
	}
}
