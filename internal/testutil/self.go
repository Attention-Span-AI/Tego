// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ExecutableForAnyUID returns a copy of the running test binary that every uid can execute: a 0755 file in a
// 0755 directory under the system temp directory, removed when t ends. A test that runs its own binary as
// another uid (a root test dropping to uid 1000) cannot exec os.Args[0] where the harness left it: a CI
// runner's work directory under its home is not searchable by that uid, and the exec fails with EACCES, while
// the KVM guest's /vm happened to be.
func ExecutableForAnyUID(t testing.TB) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("testutil: own executable: %v", err)
	}
	dir, err := os.MkdirTemp("", "tego-self-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	path := filepath.Join(dir, filepath.Base(self))
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil { // the umask narrows OpenFile's mode
		t.Fatal(err)
	}
	return path
}
