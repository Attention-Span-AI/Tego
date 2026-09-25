// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the watcher Events starts over cgroup.events must end when its context does
// (ADR 0029 step 1).
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
