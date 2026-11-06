// SPDX-License-Identifier: Apache-2.0

package container

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release job's handoff to the signer, as release.yml and CI's reproducible job run it.
const stageCommand = `python3 scripts/stage-release-assets.py "$SUMS" "$RUNNER_TEMP/release-assets"`

// stagingFixture is a checkout after a goreleaser run, laid out as goreleaser v2.18 leaves it: raw binaries in their
// build directories under names artifacts.json gives, archives and SBOMs at dist/'s top level, and checksum.extra_files
// in the checkout, absent from a snapshot's artifacts.json.
type stagingFixture struct {
	t         *testing.T
	root      string
	config    map[string]any
	artifacts []map[string]string
	sums      []string // "name" or "name=content": the checksums file lists name with content's digest
	extraSums []string // raw lines appended to the checksums file
}

func newStagingFixture(t *testing.T) *stagingFixture {
	f := &stagingFixture{t: t, root: t.TempDir()}
	f.config = map[string]any{"checksum": map[string]any{
		"name_template": "{{ .ProjectName }}_{{ .Version }}_checksums.txt",
		"extra_files":   []any{map[string]any{"glob": "./scripts/install.sh"}, map[string]any{"glob": "./profiles/*.yaml"}},
	}}
	for path, data := range map[string]string{
		"scripts/install.sh":                    "installer",
		"profiles/a.yaml":                       "profile a",
		"profiles/b.yaml":                       "profile b",
		"dist/tego_linux_amd64_v1/tego":         "engine",
		"dist/tego-control_linux_amd64_v1/tc":   "control",
		"dist/maze_1.0.0_linux_amd64.tar.gz":    "archive",
		"dist/tego_1.0.0_linux_amd64.sbom.json": "sbom",
	} {
		f.write(path, data)
	}
	for _, a := range [][3]string{
		{"tego", "dist/tego_linux_amd64_v1/tego", "Binary"},
		{"tego_1.0.0_linux_amd64", "dist/tego_linux_amd64_v1/tego", "Binary"},
		{"tego-control", "dist/tego-control_linux_amd64_v1/tc", "Binary"},
		{"tego-control_1.0.0_linux_amd64", "dist/tego-control_linux_amd64_v1/tc", "Binary"},
		{"maze_1.0.0_linux_amd64.tar.gz", "dist/maze_1.0.0_linux_amd64.tar.gz", "Archive"},
		{"tego_1.0.0_linux_amd64.sbom.json", "dist/tego_1.0.0_linux_amd64.sbom.json", "SBOM"},
		{"tego_1.0.0_checksums.txt", "dist/tego_1.0.0_checksums.txt", "Checksum"},
		{"metadata.json", "dist/metadata.json", "Metadata"},
	} {
		f.artifacts = append(f.artifacts, map[string]string{"name": a[0], "path": a[1], "type": a[2]})
	}
	f.sums = []string{"install.sh", "a.yaml", "b.yaml", "tego_1.0.0_linux_amd64", "tego-control_1.0.0_linux_amd64",
		"maze_1.0.0_linux_amd64.tar.gz", "tego_1.0.0_linux_amd64.sbom.json"}
	return f
}

func (f *stagingFixture) write(path, data string) {
	f.t.Helper()
	p := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *stagingFixture) extraFiles() []any {
	return f.config["checksum"].(map[string]any)["extra_files"].([]any)
}

func (f *stagingFixture) addGlob(entry map[string]any) {
	f.config["checksum"].(map[string]any)["extra_files"] = append(f.extraFiles(), entry)
}

// source is the file a checksummed name stands for, read by the test itself rather than by the script.
func (f *stagingFixture) source(name string) string {
	f.t.Helper()
	for _, a := range f.artifacts {
		if a["name"] == name {
			if filepath.IsAbs(a["path"]) {
				return a["path"]
			}
			return filepath.Join(f.root, a["path"])
		}
	}
	for _, p := range []string{"scripts", "profiles"} {
		if _, err := os.Stat(filepath.Join(f.root, p, name)); err == nil {
			return filepath.Join(f.root, p, name)
		}
	}
	f.t.Fatalf("no source for %s", name)
	return ""
}

// stage writes the configuration, artifacts.json and checksums file, and runs the script as release.yml does.
func (f *stagingFixture) stage(destination string) (string, error) {
	f.t.Helper()
	if f.config != nil {
		b, err := yaml.Marshal(f.config)
		if err != nil {
			f.t.Fatal(err)
		}
		f.write(".goreleaser.yaml", string(b))
	}
	b, err := json.Marshal(f.artifacts)
	if err != nil {
		f.t.Fatal(err)
	}
	f.write("dist/artifacts.json", string(b))
	var sums strings.Builder
	for _, entry := range f.sums {
		name, content, given := strings.Cut(entry, "=")
		data := []byte(content)
		if !given {
			if data, err = os.ReadFile(f.source(name)); err != nil {
				f.t.Fatal(err)
			}
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(data), name)
	}
	for _, line := range f.extraSums {
		sums.WriteString(line)
	}
	f.write("dist/tego_1.0.0_checksums.txt", sums.String())
	script, err := filepath.Abs("../../scripts/stage-release-assets.py")
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command("python3", script, "dist/tego_1.0.0_checksums.txt", destination)
	cmd.Dir = f.root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestReleaseAssetStaging holds scripts/stage-release-assets.py, which finds every file a release's checksums file
// lists and hands those bytes, verified, to the signing job. The release job once copied dist/$name for each line,
// which no raw binary and no checksum extra file is, so a tag's release job failed with "cp: cannot stat" after
// goreleaser had made the draft. This runs in scripts-and-workflows, and CI's reproducible job stages a full snapshot.
func TestReleaseAssetStaging(t *testing.T) {
	t.Run("workflows", func(t *testing.T) {
		stage := releaseStepNamed(t, readReleaseWorkflow(t).Jobs["release"], "stage the release assets for signing")
		requireReleaseValue(t, stage.Env["SUMS"], "${{ steps.sums.outputs.path }}")
		if !strings.Contains(stage.Run, stageCommand) || strings.Contains(stage.Run, "cp -- ") {
			t.Fatalf("the release job must stage through %s, from goreleaser's actual artifact paths:\n%s", stageCommand, stage.Run)
		}
		b, err := os.ReadFile("../../.github/workflows/ci.yml")
		if err != nil {
			t.Fatal(err)
		}
		var ci releaseWorkflow
		if err := yaml.Unmarshal(b, &ci); err != nil {
			t.Fatal(err)
		}
		snapshot := releaseStepNamed(t, ci.Jobs["reproducible"], "stage a full snapshot's release assets as the release job does")
		for _, want := range []string{
			"goreleaser release --snapshot --clean",
			`"stage the release assets for signing"`, // the release job's own step, read from release.yml
			`sha256sum --check --strict`,
		} {
			if !strings.Contains(snapshot.Run, want) {
				t.Fatalf("CI's snapshot staging lacks %q:\n%s", want, snapshot.Run)
			}
		}
	})

	for _, c := range []struct {
		name, fails string // fails is a fragment of the refusal; empty for a staging that must succeed
		change      func(f *stagingFixture)
	}{
		{"valid", "", func(*stagingFixture) {}},
		// A tag run's artifacts.json also lists release.extra_files, under the path fileglob returns; another spelling
		// of the same file is one source.
		{"tag-run-aliases", "", func(f *stagingFixture) {
			f.artifacts = append(f.artifacts, map[string]string{"name": "install.sh", "path": "scripts/install.sh", "type": "File"},
				map[string]string{"name": "a.yaml", "path": filepath.Join(f.root, "profiles/a.yaml"), "type": "File"})
		}},
		{"tampered-binary", "tego_1.0.0_linux_amd64: checksum mismatch", func(f *stagingFixture) {
			f.sums[3] = "tego_1.0.0_linux_amd64=engine"
			f.write("dist/tego_linux_amd64_v1/tego", "changed")
		}},
		{"tampered-extra-file", "install.sh: checksum mismatch", func(f *stagingFixture) {
			f.sums[0] = "install.sh=installer"
			f.write("scripts/install.sh", "changed")
		}},
		{"ambiguous-path", "tego_1.0.0_linux_amd64: expected exactly one artifact path, found 2", func(f *stagingFixture) {
			f.write("dist/other/tego", "engine") // the same bytes in another file are still two candidates
			f.artifacts = append(f.artifacts, map[string]string{"name": "tego_1.0.0_linux_amd64", "path": "dist/other/tego"})
		}},
		{"missing-artifact", "tego-control_1.0.0_linux_amd64: expected exactly one artifact path, found 0", func(f *stagingFixture) {
			f.sums[4] = "tego-control_1.0.0_linux_amd64=control"
			f.artifacts = slices.DeleteFunc(f.artifacts, func(a map[string]string) bool { return strings.HasPrefix(a["name"], "tego-control") })
		}},
		{"missing-file", "does not exist", func(f *stagingFixture) {
			f.sums[5] = "maze_1.0.0_linux_amd64.tar.gz=archive"
			if err := os.Remove(filepath.Join(f.root, "dist/maze_1.0.0_linux_amd64.tar.gz")); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"duplicate-name", "duplicate or reserved asset name: install.sh", func(f *stagingFixture) {
			f.sums = append(f.sums, "install.sh")
		}},
		{"reserved-name", "duplicate or reserved asset name: tego_1.0.0_checksums.txt", func(f *stagingFixture) {
			f.sums = append(f.sums, "tego_1.0.0_checksums.txt=x")
		}},
		{"malformed-manifest", "malformed checksum entry", func(f *stagingFixture) {
			f.extraSums = []string{"not-a-checksum  ../outside\n"}
		}},
		{"path-in-manifest", "malformed checksum entry", func(f *stagingFixture) {
			f.extraSums = []string{fmt.Sprintf("%x  ../outside\n", sha256.Sum256(nil))}
		}},
		{"crlf-manifest", "malformed checksum entry", func(f *stagingFixture) {
			f.extraSums = []string{fmt.Sprintf("%x  extra\r\n", sha256.Sum256(nil))}
		}},
		{"blank-line", "malformed checksum entry", func(f *stagingFixture) { f.extraSums = []string{"\n"} }},
		{"empty-manifest", "empty checksums file", func(f *stagingFixture) {
			f.sums = nil
			f.config["checksum"].(map[string]any)["extra_files"] = []any{}
		}},
		{"outside-checkout", "tego_1.0.0_linux_amd64: artifact is outside the checkout", func(f *stagingFixture) {
			outside := filepath.Join(f.t.TempDir(), "tego")
			if err := os.WriteFile(outside, []byte("engine"), 0o644); err != nil {
				f.t.Fatal(err)
			}
			f.sums[3] = "tego_1.0.0_linux_amd64=engine"
			f.artifacts[1]["path"] = outside
		}},
		{"symlink-out-of-checkout", "tego_1.0.0_linux_amd64: artifact is outside the checkout", func(f *stagingFixture) {
			outside := filepath.Join(f.t.TempDir(), "tego")
			if err := os.WriteFile(outside, []byte("engine"), 0o644); err != nil {
				f.t.Fatal(err)
			}
			f.sums[3] = "tego_1.0.0_linux_amd64=engine"
			link := filepath.Join(f.root, "dist/tego_linux_amd64_v1/tego")
			if err := os.Remove(link); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"glob-outside-checkout", "is outside the checkout", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "../outside/*.sh"})
		}},
		{"absolute-glob", "is outside the checkout", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "/etc/*.conf"})
		}},
		{"glob-matches-nothing", "glob './docs/*.md' matches no file", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./docs/*.md"})
		}},
		{"glob-matches-a-directory", "matches the directory", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./prof*"})
		}},
		{"recursive-glob", "syntax this staging cannot read", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./profiles/**/*.yaml"})
		}},
		{"brace-glob", "syntax this staging cannot read", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./scripts/{install,other}.sh"})
		}},
		{"template-glob", "syntax this staging cannot read", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./dist/{{ .Version }}.txt"})
		}},
		{"name-template", "only a plain glob is supported", func(f *stagingFixture) {
			f.addGlob(map[string]any{"glob": "./scripts/install.sh", "name_template": "setup.sh"})
		}},
		{"two-globs-one-name", "are both named a.yaml", func(f *stagingFixture) {
			f.write("other/a.yaml", "another profile a")
			f.addGlob(map[string]any{"glob": "./other/a.yaml"})
		}},
		{"extra-file-not-checksummed", "does not list: c.yaml", func(f *stagingFixture) {
			f.write("profiles/c.yaml", "profile c")
		}},
		// fileglob's * matches a leading dot, so goreleaser would checksum this file too.
		{"hidden-extra-file", "does not list: .c.yaml", func(f *stagingFixture) {
			f.write("profiles/.c.yaml", "hidden profile")
		}},
		{"split-checksums", "checksum.split", func(f *stagingFixture) {
			f.config["checksum"].(map[string]any)["split"] = true
		}},
		{"no-goreleaser-config", ".goreleaser.yaml", func(f *stagingFixture) { f.config = nil }},
		{"destination-exists", "already exists", func(*stagingFixture) {}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newStagingFixture(t)
			c.change(f)
			handoff := t.TempDir() // RUNNER_TEMP
			destination := filepath.Join(handoff, "release-assets")
			if c.name == "destination-exists" {
				if err := os.MkdirAll(destination, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			out, err := f.stage(destination)
			left, rerr := os.ReadDir(handoff)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if c.fails != "" {
				if err == nil || !strings.Contains(out, c.fails) {
					t.Fatalf("want a refusal with %q; got %v: %s", c.fails, err, out)
				}
				// Nothing is handed off: no destination, and no partial copy beside it.
				wantLeft := 0
				if c.name == "destination-exists" {
					wantLeft = 1
				}
				if len(left) != wantLeft {
					t.Fatalf("a refused staging left %v in the handoff directory", left)
				}
				return
			}
			if err != nil {
				t.Fatalf("staging failed: %v: %s", err, out)
			}
			if len(left) != 1 || left[0].Name() != "release-assets" {
				t.Fatalf("handoff directory holds %v", left)
			}
			requireStaged(t, destination, "tego_1.0.0_checksums.txt", f.sums, f.source)
		})
	}

	t.Run("this repository's checksum extra files", func(t *testing.T) { testRepositoryExtraFiles(t) })
}

// requireStaged checks destination holds the checksums file and exactly the listed names, each with its source's bytes.
func requireStaged(t *testing.T, destination, sumsName string, names []string, source func(string) string) {
	t.Helper()
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := []string{sumsName}
	for _, entry := range names {
		name, _, _ := strings.Cut(entry, "=")
		want = append(want, name)
		staged, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(source(name))
		if err != nil {
			t.Fatal(err)
		}
		if string(staged) != string(original) {
			t.Fatalf("%s: staged bytes differ from %s", name, source(name))
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	requireReleaseValue(t, got, want)
}

// testRepositoryExtraFiles stages this checkout's own checksum.extra_files under its own .goreleaser.yaml. Every glob
// must match a file (goreleaser accepts a wildcard glob that matches nothing, and the asset would silently drop out of
// the signed checksums file), and every file it matches must be staged, as a snapshot and as a tag run record it.
func testRepositoryExtraFiles(t *testing.T) {
	b, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Checksum struct {
			ExtraFiles []map[string]string `yaml:"extra_files"`
		}
		Release struct {
			ExtraFiles []map[string]string `yaml:"extra_files"`
		}
	}
	if err := yaml.Unmarshal(b, &config); err != nil {
		t.Fatal(err)
	}
	globs := func(entries []map[string]string) []string {
		var out []string
		for _, e := range entries {
			if !slices.Equal(slices.Collect(maps.Keys(e)), []string{"glob"}) {
				t.Fatalf("extra_files entry %v: only a plain glob is staged", e)
			}
			out = append(out, e["glob"])
		}
		slices.Sort(out)
		return out
	}
	checksummed := globs(config.Checksum.ExtraFiles)
	if len(checksummed) == 0 {
		t.Fatal("no checksum.extra_files: the installers and the Lima template are signed through them")
	}
	// Every file uploaded beside the build is in the checksums file, so signed and attested, and every checksummed
	// extra is uploaded, so a verifier can find it.
	requireReleaseValue(t, globs(config.Release.ExtraFiles), checksummed)

	for _, shape := range []string{"snapshot", "tag run"} {
		t.Run(shape, func(t *testing.T) {
			f := newStagingFixture(t)
			f.config = nil
			f.write(".goreleaser.yaml", string(b))
			f.sums = []string{"tego_1.0.0_linux_amd64"}
			sources := map[string]string{}
			for _, glob := range checksummed {
				matches, err := filepath.Glob(filepath.Join("../..", glob))
				if err != nil {
					t.Fatal(err)
				}
				files := 0
				for _, m := range matches {
					info, err := os.Stat(m)
					if err != nil || !info.Mode().IsRegular() {
						continue
					}
					files++
					rel, err := filepath.Rel("../..", m)
					if err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(m)
					if err != nil {
						t.Fatal(err)
					}
					f.write(rel, string(data))
					name := filepath.Base(m)
					if _, dup := sources[name]; dup {
						t.Fatalf("two checksum extra files are named %s", name)
					}
					sources[name] = filepath.Join(f.root, rel)
					f.sums = append(f.sums, name+"="+string(data))
					if shape == "tag run" {
						f.artifacts = append(f.artifacts, map[string]string{"name": name, "path": rel, "type": "File"})
					}
				}
				if files == 0 {
					t.Fatalf("checksum.extra_files glob %q matches no file", glob)
				}
			}
			destination := filepath.Join(t.TempDir(), "release-assets")
			out, err := f.stage(destination)
			if err != nil {
				t.Fatalf("staging this repository's extra files failed: %v: %s", err, out)
			}
			requireStaged(t, destination, "tego_1.0.0_checksums.txt", f.sums, func(name string) string {
				if s, ok := sources[name]; ok {
					return s
				}
				return f.source(name)
			})
		})
	}
}
