// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): Serve's accept loop and the handlers it runs must end when the listener is
// closed.
// The binary fails, too, when anything in the invoking user's real ~/.tego or ~/.bash_history changed while the tests
// ran (testutil.GuardedLeakCheckMain, tools/isocheck GO-4): its tests import internal/runtime, which can start a run,
// a sweep or a gc in-process.
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedLeakCheckMain(m))
}
