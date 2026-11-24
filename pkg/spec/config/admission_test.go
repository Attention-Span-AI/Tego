// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAdmissionSnapshotLayerIdentity(t *testing.T) {
	for _, mutation := range []string{"bytes", "replacement", "same-file-new-parent", "symlink", "absent-parent", "absent-redirection", "metadata", "unchanged"} {
		t.Run(mutation, func(t *testing.T) {
			dir := trustedDir(t)
			parent := filepath.Join(dir, "parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			text := "baseline: {}\n"
			path := writeFile(t, parent, "config", text, 0o600)
			if mutation == "symlink" {
				path = filepath.Join(dir, "selected")
				if err := os.Symlink(filepath.Join(parent, "config"), path); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mutation, "absent-") {
				path = filepath.Join(parent, "missing", "config")
			}
			src := Sources{User: path}
			load := func() *Machine {
				t.Helper()
				m, ds, err := LoadSources(src, dir, os.Getuid(), TrustAbort)
				if err != nil || HasErrors(ds) {
					t.Fatalf("strict load: %v %v", ds, err)
				}
				return m
			}
			prepared := load()
			switch mutation {
			case "bytes":
				writeFile(t, parent, "config", "baseline: {env: {deny: [TOKEN]}}\n", 0o600)
			case "replacement":
				newPath := writeFile(t, parent, "new", text, 0o600)
				if err := os.Rename(newPath, path); err != nil {
					t.Fatal(err)
				}
			case "same-file-new-parent":
				held := filepath.Join(dir, "held-config")
				if err := os.Rename(path, held); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(parent, parent+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(held, path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				newTarget := writeFile(t, parent, "other", text, 0o600)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(newTarget, path); err != nil {
					t.Fatal(err)
				}
			case "absent-parent":
				if err := os.Rename(parent, parent+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
			case "absent-redirection":
				if err := os.Rename(parent, parent+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-old", parent); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, time.Unix(1, 0), time.Unix(2, 0)); err != nil {
					t.Fatal(err)
				}
			}
			fresh := load()
			wantChanged := mutation != "metadata" && mutation != "unchanged"
			if err := prepared.CheckAdmissionSnapshot(fresh); (err != nil) != wantChanged {
				t.Fatalf("changed=%v: %v", wantChanged, err)
			}
			if mutation != "bytes" && !slices.Equal(prepared.LayerSources(), fresh.LayerSources()) {
				t.Fatal("public byte observations should stay equal for the identity-only mutation")
			}
		})
	}
}

func TestAdmissionSnapshotBaselineAndUnknown(t *testing.T) {
	for _, mutation := range []string{"empty-to-nonempty", "nonempty-to-other", "unknown", "nil", "home", "selection"} {
		t.Run(mutation, func(t *testing.T) {
			prepared, fresh := Builtin(), Builtin()
			switch mutation {
			case "empty-to-nonempty":
				fresh.baseline = Baseline{entries: []BaselineEntry{{Key: BaselineDenyEnv, Value: "TOKEN"}}}
			case "nonempty-to-other":
				prepared.baseline = Baseline{entries: []BaselineEntry{{Key: BaselineDenyEnv, Value: "TOKEN"}}}
				fresh.baseline = Baseline{entries: []BaselineEntry{{Key: BaselineDenyEnv, Value: "OTHER"}}}
			case "unknown":
				fresh.baseline.unknown = true
			case "nil":
				fresh = nil
			case "home":
				fresh.Home = "/different-owner-home"
			case "selection":
				fresh.sources = []LayerSource{{Layer: LayerUser, State: LayerUnselected}}
			}
			if err := prepared.CheckAdmissionSnapshot(fresh); err == nil {
				t.Fatal("changed admission snapshot accepted")
			}
		})
	}
}

func TestAdmissionSnapshotReadMutation(t *testing.T) {
	for _, mutation := range []string{"replacement", "new-absence", "appeared"} {
		t.Run(mutation, func(t *testing.T) {
			dir := trustedDir(t)
			path := filepath.Join(dir, "config")
			if mutation != "appeared" {
				writeFile(t, dir, "config", "baseline: {}\n", 0o600)
			}
			m, _, err := loadSources(Sources{User: path}, dir, os.Getuid(), TrustAbort, func(path string, _ Layer, uid int) ([]byte, bool, error) {
				data, absent, err := readTrusted(path, uid)
				if err != nil {
					return nil, false, err
				}
				switch mutation {
				case "replacement":
					newPath := writeFile(t, dir, "new", "baseline: {}\n", 0o600)
					if err := os.Rename(newPath, path); err != nil {
						t.Fatal(err)
					}
				case "new-absence":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "appeared":
					writeFile(t, dir, "config", "baseline: {}\n", 0o600)
				}
				return data, absent, nil
			})
			if m != nil || err == nil || !strings.Contains(err.Error(), "changed while it was being read") {
				t.Fatalf("incoherent read accepted: %v %v", m, err)
			}
		})
	}
}
