// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestThroughProc pins the walk: a path under /proc, a link whose target is one, and nothing else.
func TestThroughProc(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "tool")
	if err := os.WriteFile(plain, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(dir, "rel")
	if err := os.Symlink("tool", rel); err != nil {
		t.Fatal(err)
	}
	fdDir := filepath.Join(dir, "fd")
	if err := os.Symlink("/proc/self/fd", fdDir); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(dir, "usr")
	if err := os.Symlink("/usr", rootLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	up := filepath.Join(dir, "sub", "up")
	if err := os.Symlink("../", up); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{"/proc/self/exe", true},
		{"/proc", true},
		{"/procfoo/x", false},
		{plain, false},
		{rel, false},
		{filepath.Join(fdDir, "0"), true},
		{filepath.Join(dir, "missing"), false},
		// The kernel's reading of "..": after a link, it leaves the link's target, not the link's own directory.
		{dotDotChain(t, dir), true},
		{rootLink + "/../proc/self/exe", true}, // not filepath.Join, which would clean the ".." away
		{filepath.Join(up, "tool"), false},
	} {
		if _, got := ThroughProc(tc.p); got != tc.want {
			t.Errorf("ThroughProc(%s) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

// dotDotChain makes dir/s/b -> / and dir/s/a -> b/../proc and returns dir/s/a/self/exe, a spelling of
// /proc/self/exe only a walk that follows b before it applies ".." finds.
func dotDotChain(t *testing.T, dir string) string {
	t.Helper()
	s := filepath.Join(dir, "s")
	if err := os.Mkdir(s, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(s, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b/../proc", filepath.Join(s, "a")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s, "a", "self", "exe")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the chain does not reach /proc/self/exe: %v", err)
	}
	return p
}
