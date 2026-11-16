// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestInitReadOnlyFolderSaysWhereToGo: init in a folder it cannot write (a Mac folder seen read-only from Tego's
// VM is the common case) names the folder, says why, and points to a folder it can write, before creating anything.
// It used to fail on its first mkdir with "mkdir: ... read-only file system [io]" and no next step. The exit code
// stays 125 [io] (R25, TestInitReadOnlyParent).
func TestInitReadOnlyFolderSaysWhereToGo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a mode-0555 directory")
	}
	t.Setenv("TEGO_HINTS", "on")
	dir := filepath.Join(t.TempDir(), "my-app")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	code, _, errs := run(t, "init", dir)
	if code != identity.ExitError {
		t.Fatalf("exit %d, want %d\nstderr %s", code, identity.ExitError, errs)
	}
	for _, want := range []string{dir + " is not writable", "[io]", "next:", "mkdir -p ~/my-app && cd ~/my-app"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q\nstderr %s", want, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".tego")); !os.IsNotExist(err) {
		t.Errorf(".tego was created in a folder init refused: %v", err)
	}
}
