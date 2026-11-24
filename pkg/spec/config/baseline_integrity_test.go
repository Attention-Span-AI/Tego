// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineUnionLargeRepeatedEntry(t *testing.T) {
	const count = 100_000
	values := make([]baselineValue, count)
	for i := range values {
		values[i] = baselineValue{key: BaselineDenyEnv, value: "TOKEN", line: i + 1}
	}
	g := merger{file: "large.yaml", layer: LayerUser}
	start := time.Now()
	b := g.baseline(Baseline{}, values)
	elapsed := time.Since(start)
	entries := b.Entries()
	if len(entries) != 1 || len(entries[0].Sources) != count {
		t.Fatalf("lost repeated-entry provenance: %d entries", len(entries))
	}
	for i, source := range entries[0].Sources {
		if source != (Provenance{File: "large.yaml", Line: i + 1, Layer: LayerUser}) {
			t.Fatalf("source %d: %+v", i, source)
		}
	}
	// The old repeated linear scan takes seconds for this allowed layer; a source set
	// leaves ample room under this bound, including race instrumentation and a busy host.
	if elapsed > 5*time.Second {
		t.Fatalf("merging %d repeated entries took %s; limit is 5s", count, elapsed)
	}
	t.Logf("merged %d distinct sources in %s", count, elapsed)
	if got := g.baseline(b, values).Entries(); len(got) != 1 || len(got[0].Sources) != count {
		t.Fatal("merging the same layer twice duplicated provenance")
	}
}

func TestBaselineLayerEntryLimit(t *testing.T) {
	for _, total := range []int{100_000, 100_001} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			// Two lists bind the budget to the whole layer, not to one key or unique values.
			text := "baseline:\n  exec:\n    deny:\n" + strings.Repeat("      - command\n", total/2) +
				"  env:\n    deny:\n" + strings.Repeat("      - TOKEN\n", total-total/2)
			d, ds := parseLayer("limit.yaml", []byte(text))
			if total == 100_000 {
				if HasErrors(ds) || len(d.baseline) != total {
					t.Fatalf("allowed layer rejected: %d entries, %v", len(d.baseline), ds)
				}
				return
			}
			for _, diagnostic := range ds {
				if diagnostic.File == "limit.yaml" && diagnostic.Line > 0 &&
					diagnostic.Severity == SeverityError && strings.Contains(diagnostic.Message, "100000 entries per layer") {
					return
				}
			}
			t.Fatalf("oversized baseline accepted or unclear error: %v", ds)
		})
	}
}

func TestBaselineResolveRefusesDanglingLinks(t *testing.T) {
	dir := trustedDir(t)
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"absolute": filepath.Join(dir, "real", "missing"),
		"relative": "real/missing",
		"nested":   "absolute",
		"partial":  "real",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"absolute", "relative", "nested", "absolute/child"} {
		for _, layer := range []Layer{LayerEtc, LayerUser, LayerEnvFile} {
			t.Run(name+"/"+layer.String(), func(t *testing.T) {
				path := filepath.Join(dir, name)
				b := Baseline{entries: []BaselineEntry{{BaselineDenyRead, path, []Provenance{{"config.yaml", 7, layer}}}}}
				got, err := b.Resolve(BaselineOwner{os.Getuid(), dir})
				if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "dangling symlink") || len(got.Entries) != 0 {
					t.Fatalf("dangling link accepted or misreported: %+v, %v", got, err)
				}
			})
		}
	}
	// A valid link followed by a genuinely absent name remains a supported system guard.
	b := Baseline{entries: []BaselineEntry{{BaselineDenyRead, filepath.Join(dir, "partial", "child"), []Provenance{{"config.yaml", 7, LayerEtc}}}}}
	got, err := b.Resolve(BaselineOwner{os.Getuid(), dir})
	if err != nil || len(got.Entries) != 1 || got.Entries[0].State != LayerAbsent || got.Entries[0].Ancestor != filepath.Join(dir, "real") || got.Entries[0].Missing != "child" {
		t.Fatalf("valid link's absent suffix refused: %+v, %v", got, err)
	}
}

func TestBaselineUnknownCannotResolve(t *testing.T) {
	b := Baseline{unknown: true}
	if b.Empty() {
		t.Fatal("unknown baseline reported empty")
	}
	b = (merger{file: "later.yaml", layer: LayerEnvFile}).baseline(b, []baselineValue{{key: BaselineDenyEnv, value: "TOKEN", line: 1}})
	if !b.unknown {
		t.Fatal("merging a good layer erased unknown state")
	}
	if got, err := b.Resolve(BaselineOwner{UID: os.Getuid(), Home: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "UNKNOWN") || len(got.Entries) != 0 {
		t.Fatalf("unknown baseline resolved rules: %+v, %v", got, err)
	}
}
