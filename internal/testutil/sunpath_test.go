// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSunPathDirBindsUnderALongTmpdir: whatever TMPDIR is, a socket named as long as the caller said binds beneath
// the directory SunPathDir returns, and its directory is gone when the test ends.
func TestSunPathDirBindsUnderALongTmpdir(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("l", 90))
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	var dir string
	t.Run("fixture", func(t *testing.T) {
		t.Setenv("TMPDIR", long)
		const name = "/daemon.sock"
		dir = SunPathDir(t, "sp", len(name))
		if strings.HasPrefix(dir, long) {
			t.Fatalf("%s is beneath the long TMPDIR", dir)
		}
		l, err := net.Listen("unix", dir+name)
		if err != nil {
			t.Fatalf("a socket the caller sized for does not bind: %v", err)
		}
		_ = l.Close()
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("%s is still there after the test: %v", dir, err)
	}
}

// TestSunPathDirStaysBeneathTmpdirWhenItFits: a short TMPDIR is used, so a fixture keeps its files where the run's
// others are.
func TestSunPathDirStaysBeneathTmpdirWhenItFits(t *testing.T) {
	short, err := os.MkdirTemp("/tmp", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	t.Setenv("TMPDIR", short)
	dir := SunPathDir(t, "sp", 2)
	if !strings.HasPrefix(dir, short) {
		t.Fatalf("%s is not beneath TMPDIR %s", dir, short)
	}
}
