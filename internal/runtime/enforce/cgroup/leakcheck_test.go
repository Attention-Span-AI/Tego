// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"io"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain).
// The binary fails, too, when anything in the invoking user's real ~/.tego or ~/.bash_history changed while the tests
// ran (testutil.GuardedLeakCheckMain, tools/isocheck GO-4): its integration tests run the tegotesthooks binary
// (testutil.TegoEnv). With fakeTimerEnv set the binary is a stand-in timer process instead
// (TestIsTimerProcessKnowsARealTimer): it reads its standard input to its end and exits, running no test.
func TestMain(m *testing.M) {
	if os.Getenv(fakeTimerEnv) != "" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(testutil.GuardedLeakCheckMain(m))
}
