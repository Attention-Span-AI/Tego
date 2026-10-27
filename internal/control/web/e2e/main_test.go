// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails the binary when the invoking user's real ~/.tego or shell history changed while the journey ran: it
// starts the tego binary and tego-control (tools/isocheck GO-4).
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedMain(m))
}

// outsideEveryRun skips a journey run from inside a tego run's cgroup, or from where that cannot be told (a private
// cgroup namespace): the dashboard refuses every POST and sign-in from a socket made there (governed.go), which is
// the point of that check, so the journey would fail for where it was started rather than for what it tests. The skip
// is on no allowlist, so scripts/skipgate.sh still fails a CI job that hits it.
func outsideEveryRun(t *testing.T) {
	t.Helper()
	if in, err := runscope.InRun(); in {
		t.Skipf("this test runs inside a tego run's cgroup, or cannot show it does not (%v): the dashboard refuses its changes", err)
	}
}
