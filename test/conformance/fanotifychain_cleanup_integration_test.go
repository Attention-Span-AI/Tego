// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"os"
	"testing"
)

func TestFanotifyProbeCancellationClosesGroup(t *testing.T) {
	t.Run("already_cancelled", func(t *testing.T) {
		stop := make(chan struct{})
		close(stop)
		closed := 0
		// A stopped responder must close the group before touching the kernel. No root or fanotify support is needed.
		err := answerUntil(-1, stop, func() { closed++ })
		if err == nil {
			t.Fatal("responder without an event returned success")
		}
		if closed != 1 {
			t.Fatalf("group closed %d times after cancellation, want 1", closed)
		}
	})
	if os.Geteuid() == 0 {
		t.Run("pending_permission", testFanotifyProbeBlockedOpenCancellation)
	}
}
