// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// componentDocsRoot is the folder whose docs/p0 holds the component documents: root itself where it has
// docs/p0, else the archive folder under root (a tree that keeps frozen copies of the notes holds them there, and one without an
// archive/ has none), else "" and the caller skips. The order matters: a tree that has a live docs/p0 is read there.
func componentDocsRoot(root string) string {
	for _, base := range []string{root, filepath.Join(root, "archive", "_p0")} {
		if st, err := os.Stat(filepath.Join(base, "docs", "p0")); err == nil && st.IsDir() {
			return base
		}
	}
	return ""
}

// TestComponentDocsRootOrder pins the lookup the doc-text tests rely on: a live docs/p0 first, the archived
// copy second, nothing otherwise (the skip a tree without them takes).
func TestComponentDocsRootOrder(t *testing.T) {
	root := t.TempDir()
	if got := componentDocsRoot(root); got != "" {
		t.Errorf("a tree with no component documents answered %q, want none", got)
	}
	arch := filepath.Join(root, "archive", "_p0", "docs", "p0")
	if err := os.MkdirAll(arch, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, want := componentDocsRoot(root), filepath.Join(root, "archive", "_p0"); got != want {
		t.Errorf("archived documents only: got %q, want %q", got, want)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs", "p0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := componentDocsRoot(root); got != root {
		t.Errorf("a live docs/p0 beside the archive: got %q, want the tree's own root", got)
	}
}
