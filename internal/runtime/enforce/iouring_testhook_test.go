// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package enforce

import "testing"

// TestFallbackIOUringVariableIsTheWarningsName: the warning a test build gives names the variable its seam reads, and
// the cgroup package's governed-run cell sets the same name, which it cannot import.
func TestFallbackIOUringVariableIsTheWarningsName(t *testing.T) {
	if EnvTestFallbackIOUring != envTestFallbackIOUring {
		t.Fatalf("the seam reads %q, the warning names %q", EnvTestFallbackIOUring, envTestFallbackIOUring)
	}
	if want := "TEGO_TEST_FALLBACK_IOURING"; EnvTestFallbackIOUring != want {
		t.Fatalf("the seam reads %q; the cgroup package's cell sets %q", EnvTestFallbackIOUring, want)
	}
}
