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
