// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails the binary when the suite's tests touched the invoking user's real ~/.tego or ~/.bash_history
// (testutil.GuardedMain, tools/isocheck GO-4): the suite starts the binary its -tego flag names, a stand-in
// script in these tests (fakeTego), and a test that forgot the stand-in would start the real one.
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedMain(m))
}
