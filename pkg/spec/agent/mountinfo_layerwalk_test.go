// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileRefusesAmbiguousLayerSpellings(t *testing.T) {
	for _, kind := range []string{"parent component", "upperdir", "workdir"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			merged := filepath.Join(f.root, "merged")
			work := filepath.Join(f.root, "data")
			real := filepath.Join(f.root, "real")
			alias := filepath.Join(f.project, "out", "storage")
			for _, dir := range []string{merged, work, filepath.Join(real, "sub"), alias} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			actual, decoy := filepath.Join(real, "lower"), filepath.Join(work, "lower")
			option, why := "", "parent path component"
			if kind == "parent component" {
				if err := os.Symlink(filepath.Join(real, "sub"), filepath.Join(work, "link")); err != nil {
					t.Fatal(err)
				}
				option = "lowerdir=" + filepath.Join(real, "sub") + ":" + work + "/link/../lower"
			} else {
				// Legacy mount strings quote the next byte with backslash. FD
				// options print a literal path instead, with no origin marker.
				// Both interpretations exist; neither establishes separation.
				actual = filepath.Join(work, "upper")
				decoy = filepath.Join(work, `up\per`)
				normalUpper, normalWork := filepath.Join(work, "ordinary-upper"), filepath.Join(work, "ordinary-work")
				for _, dir := range []string{normalUpper, normalWork} {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				upper, scratch := normalUpper, normalWork
				if kind == "upperdir" {
					upper = decoy
				} else {
					scratch = decoy
				}
				option = "lowerdir=" + filepath.Join(real, "sub") + ",upperdir=" + escapeMount(upper) + ",workdir=" + escapeMount(scratch)
				why = "ambiguous overlay quoting"
			}
			for _, dir := range []string{actual, decoy} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "parent component" {
				walked, err := os.Stat(work + "/link/../lower")
				if err != nil {
					t.Fatal(err)
				}
				intended, err := os.Stat(actual)
				if err != nil || !os.SameFile(walked, intended) {
					t.Fatalf("fixture parent walk does not reach actual layer: %v", err)
				}
			}
			exe := filepath.Join(merged, "tego")
			f.file(exe, "tego", 0o755)
			mi := fakeMountInfo(f,
				"2 1 0:40 / "+merged+" rw - overlay overlay rw,"+option,
				"3 1 8:1 "+escapeMount(actual)+" "+alias+" rw - ext4 disk rw")
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					c := f.load(strings.Replace(writeSection(alias), "write:", field+":", 1))
					wantRefused(t, f, c, why, mi, WithOwnBinaries(exe), withInstallDirs())
				})
			}
		})
	}
}

func TestMountReadersRefuseAmbiguousLayerSpellings(t *testing.T) {
	for _, option := range []string{
		"lowerdir=/data/link/../lower",
		"lowerdir+=/data/link/../lower",
		"lowerdir+=/base,datadir+=/data/link/../lower",
		"lowerdir=/base,upperdir=/data/link/../upper,workdir=/work",
		"lowerdir=/base,upperdir=/upper,workdir=/data/link/../work",
		`lowerdir=/base,upperdir=/data/up\134per`,
		`lowerdir=/base,workdir=/data/work\134dir`,
	} {
		t.Run(option, func(t *testing.T) {
			rows := "1 0 0:2 / / rw - overlay overlay rw," + option + "\n"
			table, err := readMountSnapshot(strings.NewReader(rows), "fixture", false)
			if err != nil {
				t.Fatal(err)
			}
			for name, fm := range map[string]FileMount{"compile": table.fileMount("/"), "MountOf": MountOf([]byte(rows), "/")} {
				if !fm.Held || fm.Unmapped == "" || len(fm.Layers) != 0 {
					t.Errorf("%s inferred layer paths from ambiguous spelling: %+v", name, fm)
				}
			}
		})
	}
}
