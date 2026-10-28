// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestMain(m *testing.M) { os.Exit(testutil.GuardedMain(m)) }
