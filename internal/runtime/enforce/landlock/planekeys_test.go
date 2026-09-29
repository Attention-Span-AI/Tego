// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

// TestPlaneKeysAreHeldWithTheirNeutralRules is enforce-plane R16 and R17 in the Landlock plan (TIER3-PLAN T6): with
// Run.Plane, every keyed path is held, under its own name for the plane's fill (PlaneHeld), a path an entry holds
// already by that entry's descriptor; each gets its neutral rule's read rights, onto a sealed deny_read target too
// (§2.4's condition 5), and nothing else; a keyed path that does not exist is skipped, and Close ends every lookup.
func TestPlaneKeysAreHeldWithTheirNeutralRules(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/", "secret/", "secret/k", "bin/", "bin/tool")
	out, keys, tool := filepath.Join(root, "out"), filepath.Join(root, "secret"), filepath.Join(root, "bin", "tool")
	absent := filepath.Join(root, "gone")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS: []agent.FSRule{
			fsRule(agent.FSWrite, out),
			fsRule(agent.FSDenyRead, keys),
		},
	}
	rows := &decide.PlaneRows{
		Keyed: []string{out, keys, filepath.Join(keys, "k"), tool, filepath.Dir(tool), absent},
		Neutral: []decide.NeutralRule{
			{Path: keys, Access: agent.AccessReadDir},
			{Path: tool, Access: agent.AccessReadFile | agent.AccessReadDir | agent.AccessWriteFile},
		},
	}
	fake := &fakeSyscalls{abi: 7}
	h, err := New(Options{syscalls: fake}).Prepare(context.Background(), rt, Run{Plane: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for _, p := range []string{out, keys, filepath.Join(keys, "k"), tool, filepath.Dir(tool)} {
		fd, ok := h.PlaneHeld(p)
		if !ok || fd < 0 {
			t.Errorf("PlaneHeld(%s) = %d, %v; want the held descriptor", p, fd, ok)
		}
	}
	if fd, ok := h.PlaneHeld(absent); ok {
		t.Errorf("PlaneHeld(%s) = %d for a path that does not exist", absent, fd)
	}
	if o, _ := h.PlaneHeld(out); o >= 0 {
		if e, _ := h.entry(out); e.FD != o || e.Kind != kindWrite {
			t.Errorf("the write entry's keyed path is held as %+v, want the entry's own descriptor %d", e, o)
		}
	}
	// The sealed deny_read target takes its neutral READ_DIR (and only that); the file its READ_FILE, never the
	// write right a malformed neutral rule carried.
	if e, _ := h.entry(keys); e.Kind != kindDenyTarget && e.Kind != kindDenyAncestor {
		t.Logf("the deny_read target is held as %s", kindName(e.Kind))
	} else if e.Access != accessReadDir {
		t.Errorf("the deny_read target's rights are %#x, want its neutral READ_DIR %#x", e.Access, accessReadDir)
	}
	if e, ok := h.entry(tool); !ok || e.Kind != kindPlaneKey || e.Access != accessReadFile {
		t.Errorf("the keyed file is %+v, %v; want a plane key with READ_FILE alone", e, ok)
	}
	if e, ok := h.entry(filepath.Join(keys, "k")); !ok || e.Kind != kindPlaneKey || e.Access != 0 {
		t.Errorf("the keyed file under the deny_read, with no neutral rule, is %+v, %v; want identity only", e, ok)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.PlaneHeld(out); ok {
		t.Error("PlaneHeld answers after Close")
	}
}

// TestPlaneNoFollowKeysHoldTheLinkItself: a NoFollow row (a deny_write target declared through a symlink,
// enforce-plane R11) is held at the link's own inode, not its target's, for identity alone, so the fill keys the
// row the kernel's walk from the link's dentry meets; one that does not exist is skipped.
func TestPlaneNoFollowKeysHoldTheLinkItself(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "h/", "h/real/", "h/dot/")
	link := filepath.Join(root, "h", "dot", "hooks")
	if err := os.Symlink(filepath.Join(root, "h", "real"), link); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "h"))}}
	rows := &decide.PlaneRows{Keyed: []string{filepath.Join(root, "h", "real")},
		NoFollow: []string{filepath.Join(root, "h", "dot"), link, filepath.Join(root, "h", "gone")}}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{Plane: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	fd, ok := h.PlaneHeld(link)
	if !ok {
		t.Fatal("the link is not held")
	}
	var held, own unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lstat(link, &own); err != nil {
		t.Fatal(err)
	}
	if held.Ino != own.Ino || held.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Errorf("the link is held at ino %d mode %o, want the link's own ino %d", held.Ino, held.Mode, own.Ino)
	}
	if e, ok := h.entry(link); !ok || e.Kind != kindPlaneKey || e.Access != 0 {
		t.Errorf("the link is %+v, %v; want a plane key held for identity alone", e, ok)
	}
	if _, ok := h.PlaneHeld(filepath.Join(root, "h", "dot")); !ok {
		t.Error("the link's directory is not held")
	}
	if _, ok := h.PlaneHeld(filepath.Join(root, "h", "gone")); ok {
		t.Error("a NoFollow path that does not exist is held")
	}
}

// TestNoPlaneKeysWithoutAPlane: a run without Run.Plane holds nothing for the plane.
func TestNoPlaneKeysWithoutAPlane(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "bin/", "bin/tool")
	h, _ := prepare(t, 7, &agent.RuleTable{Contract: contractWith(true, true)})
	if _, ok := h.PlaneHeld(filepath.Join(root, "bin", "tool")); ok {
		t.Error("a path no entry names is held")
	}
	for _, e := range h.fds.open {
		if e.Kind == kindPlaneKey {
			t.Errorf("a plane key %s without a plane", e.Path)
		}
	}
}
