// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// hooksTarget expands "~" and "~/" to the home directory, as git does, and leaves "~user" unresolved rather
// than taking it as a directory of that name in the worktree.
func TestHooksTargetTilde(t *testing.T) {
	for _, tc := range []struct{ v, want string }{
		{"~", "/home/me"},
		{"~/h", "/home/me/h"},
		{"~bob/h", ""},
		{"~bob", ""},
		{"h", "/w/h"},
		{"/abs/h", "/abs/h"},
		{".husky/_", "/w/.husky"},
	} {
		if got := hooksTarget(tc.v, "/w", "/home/me"); got != tc.want {
			t.Errorf("hooksTarget(%q) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// A core.hooksPath naming another user's home ("~bob/h") is not resolved: the entry's warning says compile
// could not read it, naming the value, and nothing named "~bob" in the worktree stands in for it.
func TestDenyWriteOtherUsersHooksPathIsUnenforced(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.project, "src")
	gitRepo(t, f, src)
	f.file(filepath.Join(src, ".git", "config"), "[core]\n\thooksPath = ~bob/h\n", 0o644)
	const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"
	rt, ds := compileDiagsWithin(t, f, f.load(contract), 10*time.Second)
	for _, p := range denyWritePaths(rt) {
		if strings.Contains(p, "~bob") {
			t.Errorf("the value was taken literally: %s is in the set", p)
		}
	}
	if !cutBy(ds, "src/", `core.hooksPath "~bob/h"`) {
		t.Errorf("the entry's warning must name the hooksPath value compile could not resolve:\n%s", render(ds))
	}
	if slices.Contains(denyWritePaths(rt), filepath.Join(src, "~bob", "h")) {
		t.Error("a literal ~bob/h under the worktree is in the set")
	}
}
