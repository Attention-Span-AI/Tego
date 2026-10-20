// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// pidfdOpen reports whether c still owns an open pidfd: a closed owner lends nothing (sys.ErrClosed).
func pidfdOpen(c *Child) bool { return c.PidFD.Borrow(func(int) error { return nil }) == nil }

// pollExit waits up to timeoutMS for c's process to exit, through its pidfd, and reports whether it did.
func pollExit(t testing.TB, c *Child, timeoutMS int) bool {
	t.Helper()
	var exited bool
	if err := c.PidFD.Borrow(func(pidfd int) error {
		var err error
		exited, err = sys.PollPidfd(pidfd, timeoutMS)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return exited
}

// takeListener is for a test that does not serve the listener WaitNotifyFD hands it: takeListener(t)(results)
// closes the listener at cleanup and returns WaitNotifyFD's error.
func takeListener(t testing.TB) func(*sys.FD, error) error {
	return func(l *sys.FD, err error) error {
		if l != nil {
			t.Cleanup(func() { _ = l.Close() })
		}
		return err
	}
}
