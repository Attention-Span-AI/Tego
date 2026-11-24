// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// TestRuntimeFolderMessages: the runtime folder a message is about is printed, as a place given by a flag is: the
// person must see which folder is unsafe or could not be read (rule (c) of pkg/spec/identity envtext.go). A value
// that failed validation is not echoed: a relative XDG_RUNTIME_DIR, a parent run that is not a run id (rule (b)).
func TestRuntimeFolderMessages(t *testing.T) {
	base := filepath.Join(t.TempDir(), "qz-runtime")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "absent")
	for name, err := range map[string]error{
		"a base others can write":   privateRuntimeDirs(base),
		"a folder others can write": privateRuntimeDirs("", base),
		"a base that is not there":  privateRuntimeDirs(missing),
	} {
		if err == nil || !strings.Contains(err.Error(), base) {
			t.Errorf("%s: the message does not name the folder %s: %v", name, base, err)
		}
	}
	if err := privateRuntimeDirs(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cause is lost: %v", err)
	}
	for name, got := range map[string]string{
		"a relative XDG_RUNTIME_DIR":        unsetOr("qz-relative"),
		"a relative socket folder":          checkClaudeSocketPath("qz-relative").Error(),
		"a parent run that is not a run id": validIdentity(Deps{ParentRun: "qz-not-a-run"}).Error(),
	} {
		if strings.Contains(got, "qz-") || !strings.Contains(got, "echo $") {
			t.Errorf("%s: the value was echoed, or the message does not say how to print it: %s", name, got)
		}
	}
}
