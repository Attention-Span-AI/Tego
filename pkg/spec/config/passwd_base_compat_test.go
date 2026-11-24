// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

// This test uses only the pre-baseline API so the exact test can be replayed over the base loader.
// The only intentional diagnostic difference is removal of the old missing-passwd warning.
func TestMissingPasswdBaseCompatibility(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	old := passwdFile
	t.Cleanup(func() { passwdFile = old })
	passwdFile = filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwdFile, []byte("other:x:"+strconv.Itoa(uid+1)+":1::/other:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USER", "probe")
	t.Setenv("HOME", dir)
	if err := os.Mkdir(filepath.Join(dir, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, UserRelPath), []byte("retention: 999d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "explicit")
	if err := os.WriteFile(path, []byte("retention: 12d\nledger_root: /explicit/runs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{"", path} {
		t.Setenv(EnvConfigVar, selected)
		for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
			src, home, discovery := Resolve(uid, false)
			src.Etc = "" // the base and current loader see only this fixture's paths
			m, ds, err := LoadSources(src, home, uid, mode)
			if err != nil || m == nil || src.User != "" || home != "" || m.Home != "" || len(ds) != 0 {
				t.Fatalf("load changed: src %+v machine %+v diagnostics %v error %v", src, m, ds, err)
			}
			wantLayers := []string(nil)
			wantRetention, wantRoot := 30*24*time.Hour, "~/.tego/runs"
			if selected != "" {
				wantLayers, wantRetention, wantRoot = []string{path}, 12*24*time.Hour, "/explicit/runs"
			}
			if !slices.Equal(m.Layers, wantLayers) || m.Retention.Value != wantRetention || m.LedgerRoot.Value != wantRoot || m.Prices.Value != "" || m.Profiles.Value != "" || m.Registry.Value != "" {
				t.Fatalf("ordinary config differs from base behavior: %+v", m)
			}
			if len(discovery) > 1 || (len(discovery) == 1 && discovery[0].Code != CodeIgnored) {
				t.Fatalf("unexpected discovery: %v", discovery)
			}
			t.Logf("selected=%t mode=%v: user unselected, no HOME layer, ordinary settings preserved; discovery warnings=%d", selected != "", mode, len(discovery))
		}
	}
}
