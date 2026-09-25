// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// TestRootRunMakesNoRuntimeDir: a root launcher whose environment still carries the invoking user's
// XDG_RUNTIME_DIR (sudo -E) must not create or remove anything under it. The path is the user's, and its
// tego entry can be a symlink to wherever that user wants root to write; os.MkdirAll followed it, and the
// shutdown's os.RemoveAll then removed through it. As the user, the link is not followed either
// (privateRuntimeDirs): a run with no openai listener goes on with no runtime directory, and nothing is
// made under the link's target. A plain private directory is made as before.
func TestRootRunMakesNoRuntimeDir(t *testing.T) {
	base := privateTempDir(t)
	target := t.TempDir() // where a link planted by the user points
	if err := os.Symlink(target, filepath.Join(base, "tego")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", base)
	r := &runner{id: "r-00000000-000000000000a-aaaaaa", log: slog.New(slog.DiscardHandler)}
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if r.runtimeDir != "" || len(entries) != 0 {
		t.Fatalf("as uid %d: runtime dir %q, %d entries created through the link; want none", os.Geteuid(), r.runtimeDir, len(entries))
	}
	plain := privateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", plain)
	r = &runner{id: "r-00000000-000000000000a-aaaaaa", log: slog.New(slog.DiscardHandler)}
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && r.runtimeDir != filepath.Join(plain, "tego", "r-00000000-000000000000a-aaaaaa") {
		t.Fatalf("as uid %d: runtime dir %q, want the run's own under %s", os.Geteuid(), r.runtimeDir, plain)
	}
	if os.Geteuid() == 0 && r.runtimeDir != "" {
		t.Fatalf("as root: runtime dir %q, want none", r.runtimeDir)
	}
}
