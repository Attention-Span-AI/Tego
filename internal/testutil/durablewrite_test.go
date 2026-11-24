// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"
	"time"
)

// The probe reports the longest write it saw, a write still stalled when it is ended included.
func TestProbeDurableWritesSeesAStall(t *testing.T) {
	calls := 0
	end := ProbeDurableWrites(t.TempDir(), func(string) error {
		calls++
		if calls == 2 {
			time.Sleep(600 * time.Millisecond)
		}
		return nil
	})
	time.Sleep(900 * time.Millisecond)
	if got := end(); got < 550*time.Millisecond || got > 2*time.Second {
		t.Fatalf("the probe saw %v of a 600ms stall", got)
	}
	block := make(chan struct{})
	end = ProbeDurableWrites(t.TempDir(), func(string) error { <-block; return nil })
	time.Sleep(400 * time.Millisecond)
	got := end()
	close(block)
	if got < 350*time.Millisecond {
		t.Fatalf("a write that was still stalled counted %v, want about 400ms", got)
	}
	if err := DurableWrite(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
