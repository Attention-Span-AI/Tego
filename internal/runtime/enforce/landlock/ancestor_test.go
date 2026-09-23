// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestAncestorSetGolden pins ancestorSet's output for a representative set of deny_read targets: two siblings under
// one directory, a target nested several levels deep, a target directly
// under "/", and a target whose ancestor chain partially overlaps another's. A change to the ancestry
// logic — which directories count as ancestors, or which child name on each level is the one excluded
// from a sibling grant (R3 (2)) — shows up as a diff here, independent of enumerate's real filesystem
// I/O (resolveTarget, bd.hold), which this test never touches: ancestorSet is pure.
func TestAncestorSetGolden(t *testing.T) {
	targets := []string{
		"/home/user/.ssh",
		"/home/user/.aws",
		"/home/user/project/secrets/key.pem",
		"/var/secrets",
		"/etc/private/nested/deep/file.env",
	}
	levels, onPath := ancestorSet(targets)

	var buf bytes.Buffer
	for _, l := range levels {
		names := make([]string, 0, len(onPath[l]))
		for n := range onPath[l] {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(&buf, "%s: %s\n", l, strings.Join(names, ","))
	}

	path := filepath.Join("testdata", "ancestor_set.txt")
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("ancestor set differs from %s:\n%s", path, buf.String())
	}
}

// TestAncestorSetSingleTarget is a small sanity check alongside the golden: one target's ancestor
// chain is exactly its parent up to "/", each level excluding the one child that is on the path.
func TestAncestorSetSingleTarget(t *testing.T) {
	levels, onPath := ancestorSet([]string{"/a/b/c"})
	wantLevels := []string{"/", "/a", "/a/b"}
	if len(levels) != len(wantLevels) {
		t.Fatalf("levels = %v, want %v", levels, wantLevels)
	}
	for i, l := range wantLevels {
		if levels[i] != l {
			t.Fatalf("levels = %v, want %v", levels, wantLevels)
		}
	}
	if !onPath["/"]["a"] || !onPath["/a"]["b"] || !onPath["/a/b"]["c"] {
		t.Fatalf("onPath = %v", onPath)
	}
}
