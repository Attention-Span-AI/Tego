// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata")

// dirSource is a rooted ProfileSource for tests: <root>/<name>.yaml, never
// outside root (E7).
type dirSource struct{ root string }

func (s dirSource) Resolve(name string) (string, []byte, error) {
	p := filepath.Join(s.root, filepath.FromSlash(name)+".yaml")
	rel, err := filepath.Rel(s.root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", nil, err
	}
	return p, data, nil
}

func testProfiles() ProfileSource { return dirSource{root: filepath.Join("testdata", "profiles")} }

func render(ds []Diagnostic) string {
	var buf bytes.Buffer
	if err := WriteDiagnostics(&buf, ds); err != nil {
		panic(err)
	}
	return buf.String()
}

// TestGoldenBad loads every testdata/bad/*.yaml and compares the rendered
// diagnostics with the .golden file next to it (§10).
// agent-contract.md R3 (name-too-long, bad-name), R4 and E11 (empty-command, empty-command0), E1 (empty), E5 (extends-cycle), E6 (extends-not-found), E7 (extends-escape), E15 (extends-too-deep), E20 (bad-cidr), E26 (mcp-duplicate-name), E32 (tokens-overflow), E33 (bad-memory-unit) and I1 (unknown-field, unknown-nested-field) each have a golden here.
func TestGoldenBad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "bad", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 25 {
		t.Fatalf("want at least 25 bad fixtures, have %d", len(files))
	}
	for _, f := range files {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			c, ds, err := Load(f, testProfiles())
			if err == nil {
				t.Fatalf("%s: want an error, got contract %+v", f, c)
			}
			if c != nil {
				t.Errorf("%s: contract must be nil on error", f)
			}
			if !errors.Is(err, ErrInvalidContract) {
				t.Errorf("%s: error %v does not wrap ErrInvalidContract", f, err)
			}
			if !HasErrors(ds) {
				t.Errorf("%s: error returned but no error diagnostic", f)
			}
			for _, d := range ds {
				if d.Line == 0 {
					t.Errorf("%s: diagnostic without a line: %v", f, d)
				}
			}
			got := render(ds)
			golden := strings.TrimSuffix(f, ".yaml") + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%s: %v (run with -update)", golden, err)
			}
			if string(want) != got {
				t.Errorf("%s: diagnostics differ\n--- want\n%s--- got\n%s", f, want, got)
			}
		})
	}
}

// TestGoldenGood loads every testdata/good/*.yaml, expects no error and
// compares the warnings with the .golden file.
// agent-contract.md E2 and E3: bom-crlf loads clean, the BOM stripped and the CRLF line numbers unaffected.
func TestGoldenGood(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "good", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			c, ds, err := Load(f, testProfiles())
			if err != nil {
				t.Fatalf("%s: %v\n%s", f, err, render(ds))
			}
			if c == nil {
				t.Fatal("nil contract without error")
			}
			got := render(ds)
			golden := strings.TrimSuffix(f, ".yaml") + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%s: %v (run with -update)", golden, err)
			}
			if string(want) != got {
				t.Errorf("%s: warnings differ\n--- want\n%s--- got\n%s", f, want, got)
			}
		})
	}
}
