// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPlaceNewFile: the file lands under its name with its bytes, a name already there — whatever it is — is
// os.ErrExist and is left as it was, and no temporary name is left behind.
func TestPlaceNewFile(t *testing.T) {
	dir := t.TempDir()
	if err := PlaceNewFile(dir, "stop.request", []byte("4s\n")); err != nil {
		t.Fatalf("PlaceNewFile: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "stop.request")); err != nil || string(b) != "4s\n" {
		t.Fatalf("placed %q %v", b, err)
	}
	if err := PlaceNewFile(dir, "stop.request", []byte("9s\n")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a second place: %v, want os.ErrExist", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "stop.request")); string(b) != "4s\n" {
		t.Fatalf("the first file was replaced: %q", b)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := PlaceNewFile(dir, "linked", nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a dangling link under the name: %v, want os.ErrExist", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a link under the name was followed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("left %v, want the file and the link only", entries)
	}
	for _, bad := range []string{"", ".", "..", "a/b"} {
		if err := PlaceNewFile(dir, bad, nil); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
}

// TestPlaceNewFileAsRootRefusesALinkedRunDirectory covers the ledger's level: a root `tego stop` made its
// marker by path in the run directory of a user's ledger root, so a run directory the user replaced with a
// link had root create the file wherever the link pointed. The walk refuses a link in a directory that is
// not root's alone, and nothing is created at the target.
func TestPlaceNewFileAsRootRefusesALinkedRunDirectory(t *testing.T) {
	asRoot(t)
	root, victim := t.TempDir(), t.TempDir()
	if os.Geteuid() == 0 {
		// Run as real root, the temporary directory is root's alone, where a link is followed: hand it to
		// another uid, as a user's ledger root is.
		if err := os.Chown(root, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	run := filepath.Join(root, "r-3f9c2a1b-0000000000001-link01")
	if err := os.Symlink(victim, run); err != nil {
		t.Fatal(err)
	}
	if err := PlaceNewFile(run, "stop.request", nil); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("PlaceNewFile through a linked run directory: %v, want ErrLinkRefused", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("the link's target holds %v", entries)
	}
}
