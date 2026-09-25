// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the fanotify probe's opener and the seccomp probe's thread must each end with
// the probe that started them (ADR 0029 step 1).
//
// It also makes the test binary the plane probe's child (/proc/self/exe __doctor-plane-probe), as cmd/tego is.
// The binary fails, too, when anything in the invoking user's real ~/.tego or ~/.bash_history changed while the tests
// ran (testutil.GuardedLeakCheckMain, tools/isocheck GO-4): its integration tests run the tegotesthooks binary
// (forrun_integration_test.go).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == PlaneProbeCommand {
		os.Exit(PlaneProbeMain(os.Args[2:]))
	}
	os.Exit(testutil.GuardedLeakCheckMain(m))
}
