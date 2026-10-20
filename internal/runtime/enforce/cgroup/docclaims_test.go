// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"strings"
	"testing"
)

// TestPackageDocNamesTheFallbackMutationRefusal holds the package doc (doc.go) and the policy type's comment
// (policy.go) to what decides a mutation in a tier-2 run. They said write denial, delete, rename and mkdir are
// Landlock's and that trace_proc only records them. At tier cgroup with no plane mode the supervisor refuses, by
// the root walk, a mutation beneath a deny_read nested in a write entry (supervisor fallbackMutation, supervisor
// R15's 2026-10-17 amendment, ADR 0021 (5)), and where a plane mode runs the plane decides it (the class fixed in
// supervisor R15 and agent-contract R15).
func TestPackageDocNamesTheFallbackMutationRefusal(t *testing.T) {
	for _, file := range []string{"doc.go", "policy.go"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var text []string
		for _, line := range strings.Split(string(b), "\n") {
			if c, ok := strings.CutPrefix(strings.TrimSpace(line), "//"); ok {
				text = append(text, c)
			}
		}
		comments := strings.Join(strings.Fields(strings.Join(text, " ")), " ")
		for _, want := range []string{"fallbackMutation", "ADR 0021 (5)", "plane"} {
			if !strings.Contains(comments, want) {
				t.Errorf("%s does not name %s", file, want)
			}
		}
		for _, stale := range []string{"Delete, rename and mkdir are Landlock's too",
			"write denial stays Landlock's, which decides it by inode. fanotify",
			"Write, delete, rename and mkdir denial stays with the inherited Landlock ruleset, which"} {
			if strings.Contains(comments, stale) {
				t.Errorf("%s still says %q, which the supervisor's fallback refusal makes false at tier cgroup", file, stale)
			}
		}
	}
}
