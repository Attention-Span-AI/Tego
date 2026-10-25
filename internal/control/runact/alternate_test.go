// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenAlternate: a stand-in is an existing regular file named by an absolute path with no symbolic link on the
// way, as `tego alternate --file` requires; the broker is given the kernel's name for the descriptor.
func TestOpenAlternate(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "stand-in.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	a, named, err := openAlternate(file)
	if err != nil || named != file {
		t.Fatalf("regular file: %q %v", named, err)
	}
	_ = a.f.Close()
	for _, bad := range []string{"", "stand-in.txt", link, filepath.Join(link, "x"), dir, filepath.Join(dir, "missing"), dir + "/./stand-in.txt"} {
		if _, _, err := openAlternate(bad); !errors.Is(err, ErrBadAlternate) {
			t.Errorf("%q: %v, want ErrBadAlternate", bad, err)
		}
	}
}
