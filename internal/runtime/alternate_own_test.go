// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// ADR 0057 D2: the supervisor refuses a person's alternate from the run's runtime directories, which the compiled
// table does not name: the launcher hands it $XDG_RUNTIME_DIR/tego by its spelling and its resolved path.
func TestRuntimeOwnStateIsTheRuntimeDirectoriesParent(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "xdg")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", link)
	got := runtimeOwnState()
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, filepath.Join(link, "tego")) || !slices.Contains(got, filepath.Join(resolved, "tego")) {
		t.Fatalf("runtimeOwnState() = %q; want both spellings of $XDG_RUNTIME_DIR/tego", got)
	}
	for _, v := range []string{"", "relative/dir"} {
		t.Setenv("XDG_RUNTIME_DIR", v)
		if got := runtimeOwnState(); got != nil {
			t.Errorf("XDG_RUNTIME_DIR=%q: %q, want none", v, got)
		}
	}
}
