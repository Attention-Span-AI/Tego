// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

// Unlike the measured capacity trees, these fixtures retain every byte of the
// distribution files. The manifests pin contents and recreate links inside the
// temporary fixture roots, so no test follows a distribution link into the host.
func TestStockUnitContentCompatibility(t *testing.T) {
	manifests, err := filepath.Glob("testdata/unit-layouts/content/*/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 4 {
		t.Fatalf("want three measured distributions and the host distribution, got %d", len(manifests))
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			var inventory struct {
				Entries []struct {
					Path, Kind, Target, SHA256 string
				}
			}
			raw, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(raw, &inventory); err != nil {
				t.Fatal(err)
			}
			base := unitFixtureRoot(t)
			unresolved := map[string]bool{}
			files := 0
			for _, entry := range inventory.Entries {
				if !filepath.IsLocal(entry.Path) {
					t.Fatalf("fixture escapes its tree: %q", entry.Path)
				}
				path := filepath.Join(base, entry.Path)
				if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				switch entry.Kind {
				case "directory":
					err = os.MkdirAll(path, 0700)
				case "symlink":
					target := entry.Target
					if filepath.IsAbs(target) {
						target = filepath.Join(base, strings.TrimPrefix(target, "/"))
					}
					err = os.Symlink(target, path)
				case "file":
					content, readErr := os.ReadFile(filepath.Join(filepath.Dir(manifest), "root", entry.Path))
					if readErr != nil {
						t.Fatal(readErr)
					}
					digest := sha256.Sum256(content)
					if hex.EncodeToString(digest[:]) != entry.SHA256 {
						t.Fatalf("distribution content changed: %s", entry.Path)
					}
					// Check every original file, including shadowed files and unit
					// types the collector does not select. Launch uncertainty is
					// allowed; a syntax/size/unsupported refusal is not.
					_, parseErr := parseUnit(t.Context(), bytes.NewReader(content))
					if parseErr != nil && parseErr != errUnresolved {
						t.Errorf("original %s could not be read: %v", entry.Path, parseErr)
					}
					unresolved[path] = parseErr == errUnresolved
					files++
					err = os.WriteFile(path, content, 0600)
				default:
					t.Fatalf("unknown fixture kind %q", entry.Kind)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if files < 150 {
				t.Fatalf("fixture lost original files: %d", files)
			}

			o := commandOptions(t)
			o.Check = true
			if err = os.Remove(filepath.Join(o.Directory, ".claude")); err != nil {
				t.Fatal(err)
			}
			if err = os.RemoveAll(filepath.Join(o.ProcRoot, "20")); err != nil {
				t.Fatal(err)
			}
			high, low := filepath.Join(base, "etc/systemd/user"), filepath.Join(base, "usr/lib/systemd/user")
			o.SystemUnitRoots = []string{high, low}
			for _, root := range []string{high, low, filepath.Join(o.Directory, ".config/systemd/user"), filepath.Join(o.Directory, ".local/share/systemd/user")} {
				if err = os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := Collect(t.Context(), o).Snapshot
			if snapshot.Check != "none-observed" || snapshot.ExitCode() != 0 || snapshot.Counts.Units != 0 {
				t.Fatalf("stock units changed process-only check: check=%s exit=%d units=%d", snapshot.Check, snapshot.ExitCode(), snapshot.Counts.Units)
			}
			var uncertain []string
			for _, source := range snapshot.Sources {
				if source.Kind != "E" {
					continue
				}
				if source.State == "read" {
					continue
				}
				if source.State != "not-read" || source.Reason != "unresolved" || source.Locator == nil {
					t.Errorf("stock source could not be read: %+v", source)
					continue
				}
				path := string(*source.Locator)
				if !unresolved[path] {
					t.Errorf("unexpected stock uncertainty: %s", path)
				}
				uncertain = append(uncertain, path)
			}
			if len(uncertain) == 0 || snapshot.Status != "partial" {
				t.Fatalf("stock launch uncertainty was lost: count=%d status=%s", len(uncertain), snapshot.Status)
			}
			for _, verbose := range []bool{false, true} {
				var out, errs bytes.Buffer
				if err = result.Render(&out, &errs, snapshot, false, verbose, nil); err != nil {
					t.Fatal(err)
				}
				text := out.String() + errs.String()
				if strings.Contains(text, "could not be read") || strings.Contains(text, "No match among the rules and sources read") {
					t.Fatalf("stock content produced a read warning or negative summary (verbose %t): %s", verbose, text)
				}
				for _, path := range uncertain {
					if !strings.Contains(text, path) || !strings.Contains(text, "could not be determined") {
						t.Errorf("stock uncertainty not named (verbose %t): %s", verbose, path)
					}
				}
			}
			t.Logf("%d unchanged original files; %d selected unresolved sources disclosed", files, len(uncertain))
		})
	}
}

// The upstream examples document common commands in the Debian and Fedora
// image trees independently of their distribution packaging. Build-directory
// substitutions are recorded beside the fixtures.
func TestDocumentedUpstreamUnitContent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		want  error
		execs int
	}{
		{"ibus-1.5.32.service", errUnresolved, 0},
		{"pipewire-1.4.7.service", nil, 1},
		{"systemd-v257-clean.service", nil, 1},
		{"systemd-v257-clean.timer", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("testdata/unit-layouts/content/upstream", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := parseUnit(t.Context(), bytes.NewReader(content))
			if err != tc.want || len(doc.Exec) != tc.execs {
				t.Fatalf("upstream unit: got %+v (%v), want %d commands and %v", doc, err, tc.execs, tc.want)
			}
			for _, command := range doc.Exec {
				if command.Program != "" {
					t.Fatalf("upstream stock command matched an agent: %+v", command)
				}
			}
		})
	}
}
