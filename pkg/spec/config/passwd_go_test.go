// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestResolveNeverTakesTheHomeFromTheEnvironment: in a pure-Go build os/user's LookupId of the
// process's own uid answers user.Current, which builds an entry from $USER and $HOME when /etc/passwd lacks the uid.
// Resolve, through LookupPasswd, reads the passwd file itself, so with the uid missing from it the per-user layer is
// skipped with E9's warning whatever $USER and $HOME say, and a listed uid gets its passwd home, not $HOME.
func TestResolveNeverTakesTheHomeFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	envHome := filepath.Join(dir, "envhome")
	t.Setenv("HOME", envHome)
	t.Setenv("USER", "probe")
	uid := os.Getuid()
	old := passwdFile
	t.Cleanup(func() { passwdFile = old })
	write := func(body string) {
		t.Helper()
		passwdFile = filepath.Join(dir, "passwd")
		if err := os.WriteFile(passwdFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("other:x:" + strconv.Itoa(uid+1) + ":1::/other:/bin/sh\n")
	src, home, diags := Resolve(uid, false)
	if home != "" || src.User != "" {
		t.Errorf("uid %d missing from the passwd file: home %q, per-user layer %q, want both empty (not $HOME %s)", uid, home, src.User, envHome)
	}
	if len(diags) != 1 || diags[0].Code != CodeIgnored {
		t.Errorf("diagnostics = %+v, want E9's one warning", diags)
	}
	if h, err := PasswdHome(uid); err == nil {
		t.Errorf("PasswdHome(%d) = %q, want an error", uid, h)
	}

	write("me:x:" + strconv.Itoa(uid) + ":1::/passwd/home:/bin/sh\n")
	if _, home, _ := Resolve(uid, false); home != "/passwd/home" {
		t.Errorf("listed uid: home %q, want /passwd/home", home)
	}
	write("me:x:" + strconv.Itoa(uid) + ":1:::/bin/sh\n")
	if h, err := PasswdHome(uid); err == nil {
		t.Errorf("an entry with no home: PasswdHome = %q, want an error", h)
	}
}
