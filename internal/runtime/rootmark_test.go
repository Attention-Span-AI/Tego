// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// rootMarksIn roots the root launch records in a temporary directory owned by this test's uid, and has the sweep
// run as if it were root.
func rootMarksIn(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("sweeps as if root while owning the run directory itself: needs a uid other than root")
	}
	prevDir, prevParent, prevOwner, prevUID := rootMarkDir, rootMarkParent, rootMarkOwner, sweeperUID
	t.Cleanup(func() {
		rootMarkDir, rootMarkParent, rootMarkOwner, sweeperUID = prevDir, prevParent, prevOwner, prevUID
	})
	rootMarkDir = markDir(filepath.Join(t.TempDir(), "launched"))
	rootMarkParent = func() error { return nil }
	rootMarkOwner = os.Geteuid()
	sweeperUID = func() int { return 0 }
}

// TestOrphanRootsSearchesTheMountRootOnlyForARootLaunchedRun: the cgroup mount root was always a candidate root for a
// run's scope, so a root sweep of a ledger root a user can write — a run directory planted under another user's
// root-launched run id, its run_start naming that run's scope — wrote cgroup.kill into another user's run. A run
// directory the sweeper does not own names a scope under the mount root only when root's record says root launched
// that very directory; otherwise only its owner's subtree.
func TestOrphanRootsSearchesTheMountRootOnlyForARootLaunchedRun(t *testing.T) {
	rootMarksIn(t)
	const id = "r-00000000-000000000000a-mark00"
	me := os.Geteuid()
	m := &fakeCgroups{root: "/sweeper/own/root"}
	planted := filepath.Join(t.TempDir(), id)
	launched := filepath.Join(t.TempDir(), id)
	for _, d := range []string{planted, launched} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if got, want := orphanRoots(m, rootMarkDir, pathDir(planted)), []string{cgroup.UserSubtree(me)}; !slices.Equal(got, want) {
		t.Fatalf("a run directory of another uid with no record: roots %v, want only its owner's subtree %v", got, want)
	}
	if err := writeRootMark(launched, id); err != nil {
		t.Fatal(err)
	}
	if got := orphanRoots(m, rootMarkDir, pathDir(launched)); !slices.Contains(got, cgroup.Mount) || slices.Contains(got, m.Root()) {
		t.Fatalf("the directory root's record names: roots %v, want the mount root and not the sweeper's own", got)
	}
	if got := orphanRoots(m, rootMarkDir, pathDir(planted)); slices.Contains(got, cgroup.Mount) {
		t.Fatalf("a planted directory of the recorded run's id: roots %v, want no mount root", got)
	}
	if err := writeRootMark(launched, id); err == nil {
		t.Fatal("a second record of one run id must be refused, never overwritten")
	}

	// A record others can write is no record of root's.
	if err := os.Chmod(filepath.Join(string(rootMarkDir), id), 0o620); err != nil {
		t.Fatal(err)
	}
	if rootMarkDir.launched(pathDir(launched)) {
		t.Fatal("a record writable by its group was trusted")
	}
	if err := os.Chmod(filepath.Join(string(rootMarkDir), id), 0o600); err != nil {
		t.Fatal(err)
	}
	removeRootMark(id)
	if rootMarkDir.launched(pathDir(launched)) {
		t.Fatal("the record outlived removeRootMark")
	}

	// A sweeper that is not root keeps every root for its own run directory, its own first (orphanScope takes
	// a mount-root candidate with no cgroup id to check only on a record).
	sweeperUID = os.Geteuid
	rootMarkOwner = 0
	if got := orphanRoots(m, rootMarkDir, pathDir(planted)); len(got) < 2 || got[0] != m.Root() || !slices.Contains(got, cgroup.Mount) {
		t.Fatalf("the sweeper's own run directory: roots %v, want its own root first and the mount root", got)
	}
}

// TestOrphanRootsOfARootSweeperNeedARecordForItsOwnRunDirectory: a root launcher killed between MakeRunDir and
// run_start leaves a root-owned run directory with no run_start in a ledger root its user owns. The user renames it
// to another user's live root-launched run id; a root sweeper owns it, so the mount root was searched with no record,
// and with no cgroup id to check the sweep killed the other run. A root sweeper searches the mount root only on a
// record naming that very directory, whoever owns it.
func TestOrphanRootsOfARootSweeperNeedARecordForItsOwnRunDirectory(t *testing.T) {
	rootMarksIn(t)
	sweeperUID = os.Geteuid // the sweeper owns the directory, and is the uid records are owned by: root
	const id = "r-00000000-000000000000a-mark01"
	m := &fakeCgroups{root: cgroup.Mount}
	killed := filepath.Join(t.TempDir(), "own-killed-run")
	if err := os.Mkdir(killed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeRootMark(killed, "own-killed-run"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(orphanRoots(m, rootMarkDir, pathDir(killed)), cgroup.Mount) {
		t.Fatal("root's own recorded run directory: want the mount root among its roots")
	}
	// A root launcher in a nested cgroup namespace made the scope under its manager's root, not the mount root;
	// a root stop of that recorded run searched the mount root alone and found nothing to kill (root-suites,
	// TestStopEscalatesOnlyTheRunsOwnScope, 2026-09-24).
	nested := &fakeCgroups{root: filepath.Join(cgroup.Mount, "nested.slice")}
	if got := orphanRoots(nested, rootMarkDir, pathDir(killed)); !slices.Contains(got, nested.root) {
		t.Fatalf("root's own recorded run directory: roots %v, want the manager's own root among them", got)
	}
	victim := filepath.Join(t.TempDir(), id)
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeRootMark(victim, id); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(filepath.Dir(killed), id)
	if err := os.Rename(killed, renamed); err != nil {
		t.Fatal(err)
	}
	if got := orphanRoots(m, rootMarkDir, pathDir(renamed)); slices.Contains(got, cgroup.Mount) {
		t.Fatalf("root's own run directory renamed to another recorded run's id: roots %v, want no mount root", got)
	}
	if got := orphanRoots(nested, rootMarkDir, pathDir(renamed)); slices.Contains(got, nested.root) {
		t.Fatalf("root's own run directory renamed to another recorded run's id: roots %v, want not the manager's root", got)
	}
}
