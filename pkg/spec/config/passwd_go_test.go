// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestResolveNeverTakesTheHomeFromTheEnvironment: in a pure-Go build os/user's LookupId of the
// process's own uid answers user.Current, which builds an entry from $USER and $HOME when /etc/passwd lacks the uid.
// Resolve, through LookupPasswd, reads the passwd file itself, so with the uid missing from it the per-user layer is
// unselected silently whatever $USER and $HOME say, and a listed uid gets its passwd home, not $HOME.
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
	if len(diags) != 0 {
		t.Errorf("diagnostics = %+v, want no missing-home warning", diags)
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

// The pure-Go passwd database has no entry for the actual invoking uid. A planted HOME layer
// must stay unread; selected explicit layers must still pass the same uid/mode trust checks.
func TestMissingPasswdHomeLoadsOnlySelectedLayers(t *testing.T) {
	dir := trustedDir(t)
	uid := os.Getuid()
	old := passwdFile
	t.Cleanup(func() { passwdFile = old })
	passwdFile = writeFile(t, dir, "passwd", "other:x:"+strconv.Itoa(uid+1)+":1::/other:/bin/sh\n", 0o600)
	t.Setenv("USER", "probe")
	t.Setenv("HOME", dir)
	if err := os.Mkdir(filepath.Join(dir, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".tego"), "config.yaml", "retention: 999d\nbaseline: {env: {deny: [PLANTED]}}\n", 0o600)
	for _, body := range []string{"", "baseline: {env: {deny: [SECRET]}}\n", "baseline: {fs: {deny_read: [/absolute]}}\n", "baseline: {fs: {deny_read: [~/secret]}}\n"} {
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			path := writeFile(t, dir, "explicit", "retention: 12d\n"+body, 0o600)
			t.Setenv(EnvConfigVar, path)
			for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
				src, home, discovery := Resolve(uid, false)
				src.Etc = "" // isolate the optional system path
				var opened []string
				m, ds, err := loadSources(src, home, uid, mode, func(path string, layer Layer, uid int) ([]byte, bool, error) {
					opened = append(opened, path)
					return readLayer(path, layer, uid)
				})
				if err != nil || m == nil || !m.BaselineKnown() || len(discovery) != 0 {
					t.Fatalf("mode %v: discovery %v load %v %v", mode, discovery, ds, err)
				}
				if home != "" || src.User != "" || m.Home != "" || m.Retention.Value != 12*24*time.Hour || !slices.Equal(opened, []string{path}) || !slices.Equal(m.Layers, []string{path}) || m.LayerSources()[1].State != LayerUnselected {
					t.Fatalf("base discovery/trust behavior changed: src %+v machine %+v opened %v", src, m, opened)
				}
				wantNotice := 0
				if body != "" {
					wantNotice = 0
				}
				if countCode(ds, CodeBaselineUnknown) != 0 || countCode(ds, CodeBaselineNotApplied) != wantNotice {
					t.Fatalf("unexpected diagnostics: %v", ds)
				}
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
			src, home, _ := Resolve(uid, false)
			src.Etc = ""
			if m, _, err := LoadSources(src, home, uid, TrustAbort); err == nil || m != nil {
				t.Fatal("missing passwd entry bypassed explicit-layer trust")
			}
		})
	}
}
