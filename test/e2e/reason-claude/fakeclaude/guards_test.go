// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestProgramImportsOnlyTheStandardLibrary holds the acceptance "imports stdlib only": the program must build with
// nothing of the tree beside it, so the claude-code provisioning test can build it into a fixture without the engine. A standard
// library path has no dot in its first element.
func TestProgramImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s, which is not the standard library", f, path)
			}
		}
	}
	if checked < 5 {
		t.Errorf("only %d program files found", checked)
	}
}

// TestReportPyUnitTests runs report.py's own tests the way the README says: python3 -I -m unittest in its directory.
func TestReportPyUnitTests(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	cmd := exec.Command(py, "-I", "-m", "unittest")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("python3 -I -m unittest: %v\n%s", err, out)
	}
}
