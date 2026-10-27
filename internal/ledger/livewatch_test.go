// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// liveChanges runs lw.Changes on a goroutine and hands each change over the returned channel until ctx ends.
func liveChanges(t *testing.T, lw *LiveWatch) (<-chan LiveChange, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan LiveChange, 2*MaxLiveFollowed)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for c, err := range lw.Changes(ctx) {
			if err != nil {
				if ctx.Err() == nil {
					t.Errorf("Changes: %v", err)
				}
				return
			}
			ch <- c
		}
	}()
	return ch, func() { cancel(); <-done; _ = lw.Close() }
}

// expectChange waits for the next change and checks it.
func expectChange(t *testing.T, ch <-chan LiveChange, want LiveChange) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("change %+v, want %+v", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no change; want %+v", want)
	}
}

// TestLiveWatchReportsEnterAndLeave: a run listed in the live index is reported entered, one cleared is reported
// left, a name that is no run id is passed over, and an index made after the watch started is found.
func TestLiveWatchReportsEnterAndLeave(t *testing.T) {
	root := t.TempDir()
	a := runID(fixedStart, "aaaaaa")
	b := runID(fixedStart.Add(time.Second), "bbbbbb")
	lw := WatchLive(root)
	ch, stop := liveChanges(t, lw)
	defer stop()
	if err := MarkLive(root, a); err != nil { // makes .live: the watch was on the root until now
		t.Fatal(err)
	}
	expectChange(t, ch, LiveChange{Kind: LiveEntered, Run: a})
	if err := os.WriteFile(filepath.Join(root, LiveDir, "not-a-run"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, b); err != nil {
		t.Fatal(err)
	}
	expectChange(t, ch, LiveChange{Kind: LiveEntered, Run: b})
	if err := ClearLive(root, a); err != nil { // a's run directory is not there: the entry goes
		t.Fatal(err)
	}
	expectChange(t, ch, LiveChange{Kind: LiveLeft, Run: a})
	select {
	case c := <-ch:
		t.Fatalf("an unexpected change: %+v", c)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestLiveWatchFollowsAtMost512: an index listing more runs than MaxLiveFollowed has the first MaxLiveFollowed
// it reads followed and the rest reported as excess, never dropped silently; as followed runs leave, listed ones
// are taken up and the excess shrinks.
func TestLiveWatchFollowsAtMost512(t *testing.T) {
	root := t.TempDir()
	const listed = MaxLiveFollowed + 88
	ids := make([]string, listed)
	if err := os.MkdirAll(filepath.Join(root, LiveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range ids {
		ids[i] = runID(fixedStart.Add(time.Duration(i)*time.Second), "k7m2pq")
		if err := os.WriteFile(filepath.Join(root, LiveDir, ids[i]), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lw := WatchLive(root)
	ch, stop := liveChanges(t, lw)
	defer stop()
	entered := map[string]bool{}
	for len(entered) < MaxLiveFollowed {
		select {
		case c := <-ch:
			if c.Kind != LiveEntered {
				t.Fatalf("before %d runs entered: %+v", MaxLiveFollowed, c)
			}
			entered[c.Run] = true
		case <-time.After(10 * time.Second):
			t.Fatalf("%d runs entered, want %d", len(entered), MaxLiveFollowed)
		}
	}
	expectChange(t, ch, LiveChange{Kind: LiveExcess, Excess: listed - MaxLiveFollowed})
	excess := listed - MaxLiveFollowed
	// Ten followed runs leave: ten of the excess are taken up.
	gone := 0
	for _, id := range ids {
		if entered[id] && gone < 10 {
			if err := os.Remove(filepath.Join(root, LiveDir, id)); err != nil {
				t.Fatal(err)
			}
			gone++
		}
	}
	lefts, ins := 0, 0
	for lefts < 10 || ins < 10 {
		select {
		case c := <-ch:
			switch c.Kind {
			case LiveLeft:
				lefts++
			case LiveEntered:
				if entered[c.Run] {
					t.Fatalf("%s entered twice", c.Run)
				}
				ins++
			case LiveExcess:
				excess = c.Excess // a scan that saw only some of the removals reports the excess it saw
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("after ten removals: %d left, %d entered", lefts, ins)
		}
	}
	deadline := time.After(10 * time.Second)
	for excess != listed-MaxLiveFollowed-10 {
		select {
		case c := <-ch:
			if c.Kind != LiveExcess {
				t.Fatalf("unexpected %+v", c)
			}
			excess = c.Excess
		case <-deadline:
			t.Fatalf("excess %d, want %d", excess, listed-MaxLiveFollowed-10)
		}
	}
}
