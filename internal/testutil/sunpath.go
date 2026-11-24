// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// SunPathMax is the longest Unix socket pathname that fits sockaddr_un.sun_path (108 bytes, less the NUL).
const SunPathMax = 107

// SunPathDir makes a temporary directory, removed when t ends, with every symlink in its name resolved, that is short
// enough for a socket whose name is tail bytes long beneath it (a slash included: "/s" is 2) to fit sun_path. It is
// beneath TMPDIR when that leaves room and beneath /tmp when it does not, so a long TMPDIR (a lane's or a runner's
// scratch folder) never fails a socket fixture with EINVAL from bind. A test's own t.TempDir name holds the test's
// name and outgrows sun_path beneath a TMPDIR of 40 bytes, which is why a socket fixture takes this instead. prefix
// should be short. It fails the test when neither place leaves room, never skips: a test that wants a long path on
// purpose builds it itself and states its length requirement.
func SunPathDir(t testing.TB, prefix string, tail int) string {
	t.Helper()
	for _, base := range []string{"", "/tmp"} {
		tmp, err := os.MkdirTemp(base, prefix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(tmp) })
		dir, err := filepath.EvalSymlinks(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(dir)+tail <= SunPathMax {
			return dir
		}
	}
	t.Fatalf("no temporary directory leaves room for a %d-byte socket name in sun_path (%d bytes)", tail, SunPathMax)
	return ""
}
