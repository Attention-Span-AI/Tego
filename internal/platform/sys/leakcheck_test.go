// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package sys

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): a goroutine that locks its thread to take other ids (threadcreds.go) must end
// once it has, and so must every helper goroutine a test starts beside it (ADR 0029 step 1).
// threadcreds_integration_test.go's TestMain applies the same gate to the integration build.
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
