// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"testing"
	"time"
)

// TestMain prints this binary's clock times in UTC: the pages print them in the local zone (time.Local), and the
// Locked goldens (TestLockedPagesUnchanged) hold them in UTC. time.Local is a variable that every time.Now reads, so it
// is set once, here, before any test or goroutine of one runs, and never again. A test that set it for its own length
// raced each goroutine still reading the clock then, such as the connection goroutines of an earlier test's HTTP
// server, which finish after its Close (the race job failed TestLockedPagesUnchanged so after TestEventsStream).
// t.Setenv("TZ") does not reach it either, since time.Local is read from TZ only once.
func TestMain(m *testing.M) {
	time.Local = time.UTC
	os.Exit(m.Run())
}
