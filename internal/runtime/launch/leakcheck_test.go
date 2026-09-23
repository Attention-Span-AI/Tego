// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package launch

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the goroutine that keeps the agent's forking thread alive must end when its
// Child is closed; integration_test.go's TestMain applies the same gate to the integration build.
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
