// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadRefusesUnrecognisedDocs: no spec at all, and a docs/p0 file with no section 5 that is not on the
// allowlist, are errors and never a silent pass.
func TestLoadRefusesUnrecognisedDocs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "docs", "p0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if code := run(root, false, false, out); code != 2 {
		t.Errorf("run with no specs = %d, want 2", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := Load(root); err != nil {
		t.Errorf("README.md without a section 5 refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "FOO.md"), []byte("# foo\n\n## 5 Rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := Load(root); err == nil {
		t.Error("a spec with a renamed section 5 heading was skipped silently")
	}
	if code := run(root, false, false, out); code != 2 {
		t.Errorf("run with an unrecognised doc = %d, want 2", code)
	}
}

// TestMissingSpecificationsFailsWithoutP0 pins the public checkout's fail-closed inventory check.
func TestMissingSpecificationsFailsWithoutP0(t *testing.T) {
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if code := run(t.TempDir(), false, false, out); code != 2 {
		t.Fatalf("run without any specifications = %d, want 2", code)
	}
}

// TestPublicSpecificationsCannotDisappear removes each inventory input independently, with no docs/p0.
func TestPublicSpecificationsCannotDisappear(t *testing.T) {
	for _, missing := range publicSpecs {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			for _, rel := range publicSpecs {
				path := filepath.Join(root, rel)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("# Spec\n\nA public rule.\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkPublicSpecs(root); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, missing)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := checkPublicSpecs(root); err == nil {
				t.Fatal("missing required public specification passed")
			}
			if err := os.WriteFile(path, []byte("# Spec\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := checkPublicSpecs(root); err == nil {
				t.Fatal("empty required public specification passed")
			}
		})
	}
}
