// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/guide"
)

// TestTegoBinaryIsTheOneAPersonTypes: the guide's build is that of the tego a person types: the first executable tego
// in an absolute folder of PATH; else the tego beside this tego-control when it runs from its file; never a folder
// PATH names relatively, a file that is not executable, or the sealed copy a handoff runs from.
func TestTegoBinaryIsTheOneAPersonTypes(t *testing.T) {
	dir := t.TempDir()
	mk := func(sub string, mode os.FileMode) string {
		d := filepath.Join(dir, sub)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "tego")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	first, second, beside := mk("a", 0o755), mk("b", 0o755), mk("c", 0o755)
	mk("noexec", 0o644)
	sealed := func() (string, error) { return "/memfd:tego-control (deleted)", nil }
	fromFile := func() (string, error) { return filepath.Join(dir, "c", "tego-control"), nil }
	failing := func() (string, error) { return "", errors.New("no /proc") }
	for _, c := range []struct {
		name, path string
		self       func() (string, error)
		want       string
	}{
		{"the first on PATH", filepath.Join(dir, "noexec") + ":" + filepath.Dir(first) + ":" + filepath.Dir(second), sealed, first},
		{"a relative PATH folder is skipped", "a:" + filepath.Dir(second), sealed, second},
		{"beside tego-control", "/nonexistent", fromFile, beside},
		{"a sealed copy names no folder", "/nonexistent", sealed, ""},
		{"none", "", failing, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(dir)
			if got := tegoBinary(c.path, c.self); got != c.want {
				t.Errorf("tegoBinary = %q, want %q", got, c.want)
			}
		})
	}
	// The build named is the file's: BuildIDOf over it, never tego-control's own image.
	if a, b := guide.BuildIDOf(first, "v1", "c1"), guide.BuildIDOf(second, "v1", "c1"); a == "" || a == b {
		t.Errorf("two tego files give builds %q and %q", a, b)
	}
}
