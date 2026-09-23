// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"testing"
	"time"
)

// TestListenerReleasesItsMarksWhereItStops is the ordering a hung machine depends on.
//
// A FAN_OPEN_PERM event with no listener reading the group is not failed open: the kernel blocks the
// opener in fanotify_get_response until a response arrives or the group is closed. The marks used to be
// removed only by Detach, which the run reaches several steps after it joins this loop — after draining
// the pipeline and after the ledger writer appends to chain.log. That append is itself an open(2), and if
// it lands on a marked mount it waits on a listener that has already returned. So would every other open
// on that mount, by any process on the machine, until the run is killed.
func TestListenerReleasesItsMarksWhereItStops(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(context.CancelFunc, *fanotifyListener)
	}{
		{"cancelled", func(cancel context.CancelFunc, _ *fanotifyListener) { cancel() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One removal takes every mount mark the group holds (unmarkMounts), so each mark still in
			// place when it is asked for counts as removed by it. unmarkAll calls it holding mu, so it reads
			// the marks directly.
			var unmarked []string
			f := &fanotifyListener{
				fd:        -1, // Close tolerates a group that was never opened (§8 I10)
				markMount: func(string, uint64) error { return nil },
				marks:     map[string]uint64{"/": fanPermMask, "/home": fanPermMask},
			}
			f.unmarkMounts = func() error {
				for m := range f.marks {
					unmarked = append(unmarked, m)
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- f.loop(ctx) }()
			tc.stop(cancel, f)

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("a cancelled loop returned %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the loop did not return after cancellation")
			}
			if len(unmarked) != 2 {
				t.Fatalf("the loop ended having removed %v, want both marks gone before it returned", unmarked)
			}
			if len(f.marks) != 0 {
				t.Errorf("%d marks are still installed after the loop returned", len(f.marks))
			}
		})
	}
}

// TestCloseStaysIdempotentAfterTheLoop keeps the later Detach from double-unmarking: the run calls Close
// again through Detach, and a second pass must remove nothing and report nothing.
func TestCloseStaysIdempotentAfterTheLoop(t *testing.T) {
	calls := 0
	f := &fanotifyListener{
		fd:           -1,
		markMount:    func(string, uint64) error { return nil },
		unmarkMounts: func() error { calls++; return nil },
		marks:        map[string]uint64{"/": fanPermMask},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.loop(ctx) }()
	cancel()
	<-done
	if calls != 1 {
		t.Fatalf("the loop removed %d marks, want 1", calls)
	}
	if err := f.Close(); err != nil {
		t.Errorf("the Detach that follows reported %v, want a silent no-op", err)
	}
	if calls != 1 {
		t.Errorf("Detach removed the mark a second time (%d calls)", calls)
	}
}
