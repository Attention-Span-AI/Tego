// SPDX-License-Identifier: Apache-2.0

package container

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails the binary when these tests touched the invoking user's real ~/.tego or ~/.bash_history
// (testutil.GuardedMain, tools/isocheck GO-4): TestHelloContractVerdicts runs cli.Main in-process, and tego's home is
// the passwd entry's, so $HOME and TEGO_CONFIG isolate the ledger root but not the own log a failing command writes.
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedMain(m))
}
