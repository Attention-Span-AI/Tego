// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// helperEnv makes the test binary the hook itself (Run over its own arguments), so a test can start hook processes
// at once, as Claude Code does for parallel tool calls.
const helperEnv = "TEGO_CLAUDECODE_TEST_HOOK"

// Correctness stress tests share their test deadline with the helper. Production's lock budget
// is a latency limit; it cannot bound eight instrumented processes on a contended CI runner.
const helperBudgetEnv = "TEGO_CLAUDECODE_TEST_LOCK_BUDGET"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		budget := LockBudget
		if raw := os.Getenv(helperBudgetEnv); raw != "" {
			var err error
			budget, err = time.ParseDuration(raw)
			if err != nil || budget <= 0 {
				fmt.Fprintf(os.Stderr, "invalid test hook lock budget %q: %v\n", raw, err)
				os.Exit(1)
			}
		}
		os.Exit(run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:], os.Getenv, uint32(os.Getuid()), budget)) //nolint:gosec // a uid fits 32 bits
	}
	os.Exit(testutil.GuardedMain(m))
}
