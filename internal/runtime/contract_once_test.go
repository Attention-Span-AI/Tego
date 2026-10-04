// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRuntimeNeverLoadsOrCompilesAContract is agent-contract.md E30 and I9: Load and Compile are called at
// most once per run, before it, never mid-run, so a binary upgraded under a live run leaves its in-memory
// *Contract and *RuleTable alone. I9 is enforced by internal/runtime's call graph: nothing in it, or under
// it, calls agent.Load, agent.LoadBytes or agent.Compile. The CLI, which starts the run, is the one caller.
func TestRuntimeNeverLoadsOrCompilesAContract(t *testing.T) {
	call := regexp.MustCompile(`\bagent\.(Load|LoadBytes|Compile)\(`)
	seen := 0
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		seen++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if call.MatchString(code) {
				t.Errorf("%s:%d calls %s: the run would re-read a contract mid-run", p, i+1, call.FindString(code))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 10 {
		t.Fatalf("only %d source files scanned: the walk missed the package", seen)
	}
}

// TestRuntimeNeverReloadsTheMachineConfig is identity-config.md E25: a binary upgraded mid-run leaves the
// running process its own in-memory *Machine, because the machine config is read once, by the CLI that starts
// the run. Nothing in internal/runtime, or under it, calls config.Load, LoadMode, LoadSources or Resolve, so no
// code of a running launcher re-reads the layers (or a constant of another version) after it has started.
func TestRuntimeNeverReloadsTheMachineConfig(t *testing.T) {
	call := regexp.MustCompile(`\bconfig\.(Load|LoadMode|LoadSources|Resolve)\(`)
	seen := 0
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		seen++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if call.MatchString(code) {
				t.Errorf("%s:%d calls %s: the run would re-read the machine config mid-run", p, i+1, call.FindString(code))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 10 {
		t.Fatalf("walked %d source files; the walk is not reaching internal/runtime", seen)
	}
}
