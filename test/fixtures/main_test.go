// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails the binary when the replays touched the invoking user's real ~/.tego. Each view reads a
// ledger root its own TEGO_CONFIG names, and $HOME isolates nothing (tego's home is the passwd entry's), so
// what could still reach the real home is tego.log: the views write it only when one fails, and this makes
// that failure's line in the developer's own log a second, named failure rather than a silent one.
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedMain(m))
}
