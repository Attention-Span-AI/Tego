// SPDX-License-Identifier: Apache-2.0

package realtego

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// TestRuntimeDirs: the runtime parents are the logind directory's tego/ for each uid (SUDO_UID's added under
// sudo), and <XDG_RUNTIME_DIR>/tego when the variable is absolute, by its resolved path, each once; a relative or
// empty XDG_RUNTIME_DIR adds nothing (identity-config.md R27 clause b4).
func TestRuntimeDirs(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "run", "user")
	if err := os.MkdirAll(filepath.Join(root, "1000"), 0o700); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(base, "xdg")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	toLogind, toOwn := filepath.Join(base, "to-logind"), filepath.Join(base, "to-own")
	if err := os.Symlink(filepath.Join(root, "1000"), toLogind); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(own, toOwn); err != nil {
		t.Fatal(err)
	}
	logind := func(uid string) string { return filepath.Join(root, uid, RuntimeDirName) }
	ownDir := filepath.Join(own, RuntimeDirName)
	cases := []struct {
		name string
		uids []string
		xdg  string
		want []string
	}{
		{"logind XDG", []string{"1000"}, filepath.Join(root, "1000"), []string{logind("1000")}},
		{"unset XDG", []string{"1000"}, "", []string{logind("1000")}},
		{"relative XDG", []string{"1000"}, "run/user/1000", []string{logind("1000")}},
		{"another XDG", []string{"1000"}, own, []string{logind("1000"), ownDir}},
		{"XDG unclean", []string{"1000"}, own + "/./", []string{logind("1000"), ownDir}},
		{"XDG linked to logind", []string{"1000"}, toLogind, []string{logind("1000")}},
		{"XDG linked elsewhere", []string{"1000"}, toOwn, []string{logind("1000"), ownDir}},
		{"sudo", uidsOf(0, "1000"), "", []string{logind("0"), logind("1000")}},
		{"sudo to self", uidsOf(1000, "1000"), "", []string{logind("1000")}},
	}
	for _, c := range cases {
		if got := runtimeDirsOf(root, c.uids, c.xdg); !slices.Equal(got, c.want) {
			t.Errorf("%s: uids %v, XDG_RUNTIME_DIR %q: %v, want %v", c.name, c.uids, c.xdg, got, c.want)
		}
	}
}

// TestRuntimeDirsReadTheStartEnvironment: RuntimeDirs reads XDG_RUNTIME_DIR and SUDO_UID as the process started
// with, so a TestMain that points XDG_RUNTIME_DIR at the tests' own directory moves nothing the guard watches; the
// effective uid's logind parent comes first.
func TestRuntimeDirsReadTheStartEnvironment(t *testing.T) {
	before := RuntimeDirs()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("SUDO_UID", "4242")
	if got := RuntimeDirs(); !slices.Equal(got, before) {
		t.Errorf("RuntimeDirs moved with the environment: %v, was %v", got, before)
	}
	want := resolved(filepath.Join(LogindRoot, strconv.Itoa(os.Geteuid()), RuntimeDirName))
	if len(before) == 0 || before[0] != want {
		t.Errorf("RuntimeDirs() = %v, want %s first", before, want)
	}
}
