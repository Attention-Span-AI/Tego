// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// ShortRuntimeDir makes a test-owned mode-0700 runtime base for Linux socket
// clients with a pathname budget. It is a unique child of the login runtime,
// never that runtime itself: Tego may sweep only this test's crashed runs (R27).
// Durable configs, ledgers and logs still belong under the test's TempDir.
func ShortRuntimeDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp(filepath.Join("/run/user", strconv.Itoa(os.Getuid())), "t")
	if err != nil {
		t.Fatalf("short private runtime base: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove private runtime base: %v", err)
		}
	})
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}
