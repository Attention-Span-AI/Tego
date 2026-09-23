// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFirstMissingNamesFirstGap pins agent-contract.md E9: "Multi-segment missing parent chain
// (/work/out/deep/nested) -> path-missing names the *first* missing segment
// (only the leaf write dir is created by run)." Compile's own table test
// (TestCompilePathRules "write-parent-missing") only asserts the code, not
// which segment the message names; a version of firstMissing that reported
// the wrong segment (the leaf, or the whole original path) would still trip
// that test's CodePathMissing check while breaking the diagnostic's whole
// point — telling the operator exactly where to `mkdir -p`.
func TestFirstMissingNamesFirstGap(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		p    string
		want string
	}{
		{"leaf only missing", filepath.Join(root, "a", "b", "leaf"), filepath.Join(root, "a", "b", "leaf")},
		{"two segments missing, first one reported", filepath.Join(root, "a", "gone", "deeper"), filepath.Join(root, "a", "gone")},
		{"everything below root missing", filepath.Join(root, "x", "y", "z"), filepath.Join(root, "x")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstMissing(tc.p); got != tc.want {
				t.Errorf("firstMissing(%q) = %q, want %q", tc.p, got, tc.want)
			}
		})
	}
}
