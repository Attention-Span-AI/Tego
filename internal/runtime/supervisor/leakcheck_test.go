// SPDX-License-Identifier: Apache-2.0

//go:build !(integration && (amd64 || arm64))

package supervisor

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the notification workers and the models refresher must end when Run returns;
// integration_test.go's TestMain applies the same gate to the integration build.
func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}
