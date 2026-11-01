// SPDX-License-Identifier: Apache-2.0

// Package binary is non-test code that imports internal/testutil: depguard's testutil-never-in-binary rule
// must deny it (ADR 0023 A7), which scripts/check-fd_test.sh checks.
package binary

import "github.com/attention-span-ai/tego/internal/testutil" // want testutil-never-in-binary

var _ = testutil.NoFDLeak
