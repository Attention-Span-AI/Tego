// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): Watcher.Run must return when its context ends and keep no goroutine past that.
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
