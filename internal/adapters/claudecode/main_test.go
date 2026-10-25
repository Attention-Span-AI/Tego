// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// helperEnv makes the test binary the hook itself (Run over its own arguments), so a test can start hook processes
// at once, as Claude Code does for parallel tool calls.
const helperEnv = "TEGO_CLAUDECODE_TEST_HOOK"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(Run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:]))
	}
	os.Exit(testutil.GuardedMain(m))
}
