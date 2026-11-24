// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCanceledSaveDoesNotInspectPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Save{}).WriteContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save inspected its name or path: %v", err)
	}
}

func TestCanceledSaveCompileDoesNotCreateRegistry(t *testing.T) {
	l := newLayout(t)
	if err := os.Remove(l.user); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sv := l.saveOf("bot")
	sv.Compile = func(string, []byte) error {
		cancel() // The compiler's path reads resume after the caller left.
		return nil
	}
	if _, err := sv.WriteContext(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("compile resumed into write: %v", err)
	}
	if _, err := os.Lstat(l.user); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("canceled compile created registry: %v", err)
	}
}

func TestSaveContextCreatesNestedRegistryThroughParentLink(t *testing.T) {
	base, actual := t.TempDir(), t.TempDir()
	link := filepath.Join(base, "registry-parent")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	sv := Save{Places: Places{User: filepath.Join(link, "nested", "user")}, Name: "bot", Text: []byte("fixture")}
	path, err := sv.WriteContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "fixture" {
		t.Errorf("nested registry write: %q, %v", got, err)
	}
	for _, path := range []string{filepath.Join(actual, "nested"), filepath.Join(actual, "nested", "user")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("registry component %s: info=%v err=%v", path, info, err)
		}
	}
}
