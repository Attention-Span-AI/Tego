// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedColumnsReleaseTemporaryTrees(t *testing.T) {
	binDir := t.TempDir()
	bin, err := buildTego(binDir, "tegobpf")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := GenFSGrid()[:2]
	columns := generatedColumns(t, bin, buildActor(t), fixtures)
	if len(columns) != len(fixtures) {
		t.Fatalf("%d columns, want %d", len(columns), len(fixtures))
	}
	// t.TempDir's siblings remain until this test ends. Retaining each compile fixture there kept all 64
	// actor copies on the guest's RAM filesystem while the kernel axes ran, exhausting the 1536 MB guest.
	actors, err := filepath.Glob(filepath.Join(filepath.Dir(binDir), "*", "project", "bin", "actor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(actors) != 0 {
		t.Fatalf("compile-only fixture trees still retained after their columns were read: %v", actors)
	}
}

// Measure retained fixture data with a fixed 1 MiB actor, independent of build
// flags or kernel features. Exercise the same lifetime as TestConformanceCompile.
func TestCompileFixturesReleaseSpace(t *testing.T) {
	actor := filepath.Join(t.TempDir(), "actor")
	data := bytes.Repeat([]byte("a"), 1<<20)
	if err := os.WriteFile(actor, data, 0o755); err != nil {
		t.Fatal(err)
	}
	var bases []string
	var peak, largest int64
	fixtures := GenFSGrid()
	forCompileFixtures(t, fixtures, actor, func(t *testing.T, fx *Fixture, e *env) {
		bases = append(bases, e.base)
		got, err := os.ReadFile(e.path("bin/actor"))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s did not receive its independent actor copy: %v", fx.Name, err)
		}
		largest = max(largest, fixtureBytes(t, []string{e.base}))
		peak = max(peak, fixtureBytes(t, bases))
		// A changed fixture must never alter the source actor or the next fixture.
		got[0] = 'b'
		if err := os.WriteFile(e.path("bin/actor"), got, 0o755); err != nil {
			t.Fatal(err)
		}
	})
	remaining := fixtureBytes(t, bases)
	t.Logf("%d fixtures, 1 MiB actor: peak retained regular-file bytes=%d, largest fixture=%d, after comparisons=%d", len(bases), peak, largest, remaining)
	if len(bases) != len(fixtures) || peak > largest || remaining != 0 {
		t.Errorf("compile fixtures outlived their comparisons: fixtures=%d peak=%d largest=%d remaining=%d", len(bases), peak, largest, remaining)
	}
}

func fixtureBytes(t *testing.T, bases []string) int64 {
	t.Helper()
	var size int64
	for _, base := range bases {
		err := filepath.WalkDir(base, func(_ string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				info, err := d.Info()
				if err != nil {
					return err
				}
				size += info.Size()
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return size
}
