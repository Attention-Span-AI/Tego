// SPDX-License-Identifier: Apache-2.0

package realtego

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestUnder: a path is inside a directory by whole path elements, not by prefix, and a symbolic link into the
// directory is the directory (identity-config.md R27).
func TestUnder(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, ".tego")
	if err := os.MkdirAll(filepath.Join(dir, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	dirs := []string{dir}
	for path, want := range map[string]bool{
		dir:                                    true,
		filepath.Join(dir, "runs"):             true,
		filepath.Join(dir, "runs", "r-1"):      true, // does not exist yet
		filepath.Join(dir, "..", ".tego", "x"): true,
		filepath.Join(base, ".tego-other"):     false,
		filepath.Join(base, "elsewhere"):       false,
		link:                                   true,
		filepath.Join(link, "runs", "r-1"):     true,
		base:                                   false,
	} {
		if got := Under(path, dirs); got != want {
			t.Errorf("Under(%s) = %v, want %v", path, got, want)
		}
	}
	if Under(dir, nil) {
		t.Error("no directories contain nothing")
	}
}

// TestUnderResolvesARelativePathFromTheWorkingDirectory: a relative path is inside the directory when the working
// directory puts it there: a relative TEGO_TEST_CHAIN_ANCHOR of a process started in ~/.tego is its chain.log.
func TestUnderResolvesARelativePathFromTheWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, ".tego")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirs := []string{dir}
	t.Chdir(dir)
	for path, want := range map[string]bool{"chain.log": true, ".": true, "runs/r-1": true, "..": false, "../elsewhere": false} {
		if got := Under(path, dirs); got != want {
			t.Errorf("in %s: Under(%q) = %v, want %v", dir, path, got, want)
		}
	}
	t.Chdir(base)
	for path, want := range map[string]bool{".tego": true, ".tego/chain.log": true, ".": false, "chain.log": false, ".tego-other": false} {
		if got := Under(path, dirs); got != want {
			t.Errorf("in %s: Under(%q) = %v, want %v", base, path, got, want)
		}
	}
}

// TestDirsNameThePasswdHome: every directory is an absolute .tego, and UnderReal agrees with Under over Dirs.
func TestDirsNameThePasswdHome(t *testing.T) {
	for _, d := range Dirs() {
		if !filepath.IsAbs(d) || filepath.Base(d) != ".tego" {
			t.Errorf("Dirs() holds %q", d)
		}
		if !UnderReal(filepath.Join(d, "chain.log")) {
			t.Errorf("%s/chain.log is not under the real directory", d)
		}
	}
}

// TestDirsFallBackToHomeWithoutAPasswdHome: an account the passwd database names no home for (a containerized uid,
// or an LDAP/SSSD one that a CGO_ENABLED=0 build cannot look up) keeps its ledger root, anchor and own log under
// $HOME, where an unprivileged tego then looks (runtime ledgerRoot, cli ownLogHome), so that is one of the
// directories too. With every account resolved $HOME is not one, and a relative or empty $HOME names nothing.
func TestDirsFallBackToHomeWithoutAPasswdHome(t *testing.T) {
	homes := map[string]string{"1000": "/home/dev", "0": "/root", "7": "relative/home"}
	lookup := func(uid string) (string, error) {
		if h, ok := homes[uid]; ok {
			return h, nil
		}
		return "", fmt.Errorf("user: unknown userid %s", uid)
	}
	cases := []struct {
		uids []string
		home string
		want []string
	}{
		{[]string{"1000"}, "/elsewhere", []string{"/home/dev/.tego"}},
		{[]string{"4242"}, "/home/dev", []string{"/home/dev/.tego"}},
		{[]string{"4242"}, "/tmp/h/", []string{"/tmp/h/.tego"}},
		{[]string{"0", "4242"}, "/root", []string{"/root/.tego"}},
		{[]string{"0", "4242"}, "/home/dev", []string{"/root/.tego", "/home/dev/.tego"}},
		{[]string{"7"}, "/home/dev", []string{"/home/dev/.tego"}},
		{[]string{"4242"}, "", nil},
		{[]string{"4242"}, "rel", nil},
	}
	for _, c := range cases {
		if got := dirsOf(c.uids, lookup, c.home); !slices.Equal(got, c.want) {
			t.Errorf("uids %v, HOME %q: %v, want %v", c.uids, c.home, got, c.want)
		}
	}
}
