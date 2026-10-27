// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestDenyReadSnapshotRefusesWhatTheListingDidNotGrant is the snapshot on a real tree: after Prepare, a directory
// and a file made beside the target (at an enumerated ancestor) are refused, and a file in that directory too; a new
// file inside a sibling that was listed, a sibling renamed (its rule follows the inode), a write entry moved into a new
// directory, a directory (READ_DIR is the ancestor's), the target's own paths (the decision core's) and a path that does
// not exist are not. A sibling directory replaced by a new one is refused under its old name, and a listed file
// replaced by a new inode is too, on a file system that does not renumber files (ADR 0010's overlayfs doubt aside).
func TestDenyReadSnapshotRefusesWhatTheListingDidNotGrant(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secret/key", "old/g.txt", "moved/m.txt", "replaced/r.txt", "readme", "work/w.txt")
	rt := denyTable([]string{filepath.Join(root, "secret")})
	rt.FS = append(rt.FS, fsRule(agent.FSWrite, filepath.Join(root, "work")))
	h, _ := prepare(t, 7, rt)
	refuses := h.DenyReadSnapshot()
	if refuses == nil {
		t.Fatal("a run with an enforced deny_read keeps no snapshot")
	}
	mkTree(t, root, "late/f.txt", "late/sub/", "late.txt", "old/late.txt", "box/")
	for _, mv := range [][2]string{{"moved", "renamed"}, {"work", "box/work"}, {"replaced", "replaced.old"}} {
		if err := os.Rename(filepath.Join(root, mv[0]), filepath.Join(root, mv[1])); err != nil {
			t.Fatal(err)
		}
	}
	mkTree(t, root, "replaced/r.txt")
	if err := os.Remove(filepath.Join(root, "readme")); err != nil {
		t.Fatal(err)
	}
	mkTree(t, root, "readme")
	overlay := false
	var fs unix.Statfs_t
	if unix.Statfs(root, &fs) == nil && fs.Type == unix.OVERLAYFS_SUPER_MAGIC {
		overlay = true
	}
	for rel, want := range map[string]bool{
		"late/f.txt":          true,
		"late.txt":            true,
		"replaced/r.txt":      true,
		"readme":              !overlay,
		"old/late.txt":        false,
		"old/g.txt":           false,
		"renamed/m.txt":       false,
		"replaced.old/r.txt":  false,
		"box/work/w.txt":      false,
		"late":                false,
		"late/sub":            false,
		"secret/key":          false,
		"secret":              false,
		"late/missing.txt":    false,
		"nothing-here/at-all": false,
	} {
		if got := refuses(filepath.Join(root, rel)); got != want {
			t.Errorf("Refuses(%s) = %v, want %v", rel, got, want)
		}
	}
	for _, p := range []string{root, "/", "/proc/self/status", "relative/path", ""} {
		if refuses(p) {
			t.Errorf("Refuses(%q) = true, want false", p)
		}
	}
}

// TestDenyReadSnapshotIsNilWithNothingEnumerated: with no deny_read, or one the ruleset leaves unenforced beneath a
// write entry (R4), no ancestor is listed and the handle keeps no snapshot, so the supervisor refuses nothing more.
func TestDenyReadSnapshotIsNilWithNothingEnumerated(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "w/secret/key")
	if h, _ := prepare(t, 7, denyTable(nil, filepath.Join(root, "w"))); h.DenyReadSnapshot() != nil {
		t.Error("a run with nothing denied keeps a snapshot")
	}
	rt := denyTable([]string{filepath.Join(root, "w", "secret")}, filepath.Join(root, "w"))
	rt.FS[1].Unenforced = true
	if h, _ := prepare(t, 7, rt); h.DenyReadSnapshot() != nil {
		t.Error("a run whose only deny_read is unenforced keeps a snapshot")
	}
}
