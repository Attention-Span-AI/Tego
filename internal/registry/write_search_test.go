// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// A directory walk needs search permission on the ancestors, as a whole-path open does, never read: an ancestor
// the caller may search but not list is passed, and only the destination, which is listed and synced, is read.
// A parent the caller cannot search is refused as before.
func TestOpenDirectoryNeedsOnlySearchOnAncestors(t *testing.T) {
	base := t.TempDir()
	searchOnly := filepath.Join(base, "search-only")
	dest := filepath.Join(searchOnly, "dest")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(searchOnly, 0o311); err != nil { // write and search, no read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(searchOnly, 0o700) })

	t.Run("search-only ancestor", func(t *testing.T) {
		d, err := OpenDirectory(dest, false)
		if err != nil {
			t.Fatalf("OpenDirectory(%s) beneath a 0311 ancestor: %v; want it opened, a walk needs only search there", dest, err)
		}
		defer func() { _ = d.Close() }()
		if err := d.Write("entry.yaml", []byte("id: entry\n"), WriteOptions{Mode: 0o600}); err != nil {
			t.Fatalf("write beneath the opened destination: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dest, "entry.yaml")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("created beneath a search-only ancestor", func(t *testing.T) {
		made := filepath.Join(dest, "made", "deeper")
		d, err := OpenDirectory(made, true)
		if err != nil {
			t.Fatalf("OpenDirectory(%s, create): %v", made, err)
		}
		_ = d.Close()
	})

	t.Run("unsearchable parent", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches every directory: no mode refuses it a walk")
		}
		closed := filepath.Join(base, "closed")
		inner := filepath.Join(closed, "inner")
		if err := os.MkdirAll(inner, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(closed, 0o600); err != nil { // read, no search
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
		d, err := OpenDirectory(inner, false)
		if err == nil {
			_ = d.Close()
			t.Fatalf("OpenDirectory(%s) beneath a parent it cannot search: opened; want refused", inner)
		}
		if want := "open-directory inner: permission denied"; err.Error() != want {
			t.Fatalf("refusal = %q, want %q", err, want)
		}
	})
}
