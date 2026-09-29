// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// readmeRowRe is a row of bpf/README.md's file table: its first cell is one source path in backticks.
var readmeRowRe = regexp.MustCompile("^\\| `([^`]+\\.bpf\\.c)` \\|")

// TestReadmeTableNamesEverySource holds bpf/README.md's file table to the tree: every .bpf.c under bpf/, the
// test-only and spike sources included, has a row, and no row names a file that does not exist. The table once
// listed three lsm_*.bpf.c files that were never written and left out the decision plane.
func TestReadmeTableNamesEverySource(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join(sourceDir, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text, _, found := strings.Cut(string(b), "\nRules:")
	if !found {
		t.Fatal("README.md has no \"Rules:\" line after its file table")
	}
	var listed []string
	for line := range strings.SplitSeq(text, "\n") {
		if m := readmeRowRe.FindStringSubmatch(line); m != nil {
			listed = append(listed, m[1])
		}
	}
	var onDisk []string
	for _, pattern := range []string{"*.bpf.c", "testonly/*.bpf.c", "spike/*.bpf.c"} {
		got, err := filepath.Glob(filepath.Join(sourceDir, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, p := range got {
			rel, err := filepath.Rel(sourceDir, p)
			if err != nil {
				t.Fatal(err)
			}
			onDisk = append(onDisk, filepath.ToSlash(rel))
		}
	}
	if len(onDisk) == 0 {
		t.Fatal("no .bpf.c sources found; this package must run from bpf/tests")
	}
	for _, f := range onDisk {
		if !slices.Contains(listed, f) {
			t.Errorf("bpf/%s has no row in README.md's file table", f)
		}
	}
	for _, f := range listed {
		if !slices.Contains(onDisk, f) {
			t.Errorf("README.md's file table lists %s, which does not exist", f)
		}
	}
}
