// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCreateScopeNamesTheAdoptionsScope: an adoption's cgroup sits beside a run's, under the same slices, by the
// name the caller gives it, and Create's own name is unchanged.
func TestCreateScopeNamesTheAdoptionsScope(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.CreateScope("watch-claude", "r-abc", "adopt-r-abc.scope")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	want := filepath.Join(fs.Root(), "tego.slice", "tego-watch-claude.slice", "adopt-r-abc.scope")
	if c.Path != want || c.dir == nil || c.ID == 0 {
		t.Fatalf("CreateScope = %+v, want %s with an fd and an id", c, want)
	}
	if _, err := fs.CreateScope("watch-claude", "r-abc", "adopt-r-abc.scope"); !errors.Is(err, ErrCgroupExists) ||
		!errors.Is(err, unix.EEXIST) {
		t.Fatalf("second CreateScope: %v", err)
	}
	r, err := fs.Create("watch-claude", "r-abc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if filepath.Base(r.Path) != "run-r-abc.scope" {
		t.Fatalf("Create's scope is %s", r.Path)
	}
	for _, bad := range []string{"", ".", "..", "a/b.scope", "x\x00.scope", "adopt-x", "run-r-abc.scope"} {
		if _, err := fs.CreateScope("a", "r-x", bad); !errors.Is(err, ErrBadName) {
			t.Errorf("CreateScope(%q) = %v, want ErrBadName", bad, err)
		}
	}
}
