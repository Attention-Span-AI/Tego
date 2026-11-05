// SPDX-License-Identifier: Apache-2.0

package conformance

import (
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
