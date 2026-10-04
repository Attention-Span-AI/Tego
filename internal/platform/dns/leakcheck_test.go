// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the refresher Run starts must end when its context does.
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
