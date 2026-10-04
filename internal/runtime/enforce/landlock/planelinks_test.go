// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPlaneExecLinksHoldEachLinkItsEntryNames is enforce-plane R16 and §6 E15 in the Landlock plan: the exec rows of two
// hard links of one inode (a multi-call binary's shape), which the E7 dedupe folds into one entry, each get a
// descriptor held at their own link, for the fill to key each link's row from its own dentry. The first link keeps
// the entry's descriptor; the second's is identity only (no rule: Landlock's rule is on the inode), and the dedupe
// still names the entry. Every descriptor names its own path (/proc/self/fd).
func TestPlaneExecLinksHoldEachLinkItsEntryNames(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "bin/", "bin/one")
	bin, one, two := filepath.Join(root, "bin"), filepath.Join(root, "bin", "one"), filepath.Join(root, "bin", "two")
	if err := os.Link(one, two); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true)}
	rows := &decide.PlaneRows{
		Keyed: []string{bin, one, two},
		Exec: []decide.PlaneExecRow{
			{Path: one, Parent: bin, Name: "one", Rule: 0},
			{Path: two, Parent: bin, Name: "two", Rule: 1},
		},
	}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{Plane: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	fds := map[int]string{}
	for _, p := range []string{one, two} {
		fd, ok := h.PlaneHeld(p)
		if !ok {
			t.Fatalf("%s is not held", p)
		}
		if other, dup := fds[fd]; dup {
			t.Fatalf("%s and %s share descriptor %d: the fill would key one link's row twice", other, p, fd)
		}
		fds[fd] = p
		if at, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err != nil || at != p {
			t.Errorf("descriptor %d held for %s names %q (%v)", fd, p, at, err)
		}
	}
	first, _ := h.entry(one)
	second, _ := h.entry(two)
	if first.id != second.id || second.Access != 0 || second.Kind != kindPlaneKey {
		t.Errorf("the second link is held as %+v, want the first's inode (%+v) for identity alone", second, first)
	}
	if i := h.fds.ids[first.id]; h.fds.open[i].Path != one {
		t.Errorf("the E7 dedupe names %s for the inode, want the entry %s", h.fds.open[i].Path, one)
	}
}

// TestPlaneExecLinksRefuseAReplacedPath: an exec row's path that names another inode by the time its own link
// descriptor is opened (replaced after the entry was held) fails Prepare rather than keying a row at another file.
func TestPlaneExecLinksRefuseAReplacedPath(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "bin/", "bin/one", "bin/other")
	bin, one, two := filepath.Join(root, "bin"), filepath.Join(root, "bin", "one"), filepath.Join(root, "bin", "two")
	if err := os.Link(one, two); err != nil {
		t.Fatal(err)
	}
	bd := &builder{ctx: context.Background(), fds: newFDSet(), run: Run{Plane: &decide.PlaneRows{
		Exec: []decide.PlaneExecRow{{Path: two, Parent: bin, Name: "two", Rule: 1}},
	}}}
	defer func() { _ = bd.fds.closeAll() }()
	if _, err := bd.hold(one, kindExecBinary, 0); err != nil {
		t.Fatal(err)
	}
	bd.fds.paths[two] = bd.fds.paths[one] // held under the second name by the dedupe
	if err := os.Rename(filepath.Join(bin, "other"), two); err != nil {
		t.Fatal(err)
	}
	if err := bd.planeExecLinks(); err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("a replaced exec path: %v", err)
	}
}
