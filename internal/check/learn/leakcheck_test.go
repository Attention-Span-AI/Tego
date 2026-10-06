// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain).
func TestMain(m *testing.M) { os.Exit(testutil.LeakCheckMain(m)) }
