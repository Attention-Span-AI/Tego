// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unenforcedDiag returns the one unenforced diagnostic Compile produced, failing the test when
// there is none.
func unenforcedDiag(t *testing.T, ds []Diagnostic) Diagnostic {
	t.Helper()
	for _, d := range ds {
		if d.Code == CodeUnenforced {
			return d
		}
	}
	t.Fatalf("no unenforced warning:\n%s", render(ds))
	return Diagnostic{}
}

// TestDenyReadUnderExecDirNamesTheResolvedTargets holds the exec.allow-directory arm of the
// unenforced warning to E8: "Diagnostics name the declared path and its target when the two differ."
// The containment check compares resolved paths on both sides, so when a symlink takes either entry
// elsewhere the declared names alone look disjoint and the warning reads as a false positive.
func TestDenyReadUnderExecDirNamesTheResolvedTargets(t *testing.T) {
	t.Run("exec.allow directory is a symlink", func(t *testing.T) {
		f := newFixture(t)
		real := filepath.Join(f.root, "tools")
		secret := filepath.Join(real, "token")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(secret, "x", 0o600)
		link := filepath.Join(f.root, "toolslink")
		if err := os.Symlink(real, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + secret + "\"]\nexec:\n  allow: [\"" + link + "\"]\n"))
		d := unenforcedDiag(t, ds)
		note := resolvedNote(link, real)
		if !strings.Contains(d.Message, link+note) {
			t.Errorf("warning does not name the exec.allow entry %s with its target %s:\n%s", link, real, d.Message)
		}
		if !strings.Contains(d.Fix, link+note) {
			t.Errorf("fix does not name the exec.allow entry %s with its target %s:\n%s", link, real, d.Fix)
		}
	})

	t.Run("deny_read entry is a symlink", func(t *testing.T) {
		f := newFixture(t)
		bin := filepath.Join(f.root, "tools")
		secret := filepath.Join(bin, "token")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(secret, "x", 0o600)
		link := filepath.Join(f.root, "tokenlink")
		if err := os.Symlink(secret, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + link + "\"]\nexec:\n  allow: [\"" + bin + "\"]\n"))
		d := unenforcedDiag(t, ds)
		if !strings.Contains(d.Message, link+resolvedNote(link, secret)) {
			t.Errorf("warning does not name the deny_read entry %s with its target %s:\n%s", link, secret, d.Message)
		}
	})
}
