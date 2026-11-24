// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// fakeCgroupMount is a directory tree standing for a cgroup2 mount: n sibling groups, the one at index at holding
// the run, each with a cgroup.procs file. A cgroup's id is its directory's inode, as on cgroup2.
func fakeCgroupMount(t *testing.T, n, at int) (mount string, id uint64) {
	t.Helper()
	mount = t.TempDir()
	for i := range n {
		dir := filepath.Join(mount, "g"+string(rune('a'+i/26))+string(rune('a'+i%26)))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if i == at {
			var st syscall.Stat_t
			if err := syscall.Stat(dir, &st); err != nil {
				t.Fatal(err)
			}
			id = st.Ino
		}
	}
	return mount, id
}

// TestListenersOfOneRunWalkTheCgroupTreeOnce: every listener of a run has an admitter of its own, and each used to
// walk the cgroup tree for the run's directory on its first connection (28 to 67 ms on a box of 780 cgroups, GAPS
// C75). The directory is now kept for the process, so the second listener, and a burst of first connections to
// several at once, share one walk.
func TestListenersOfOneRunWalkTheCgroupTreeOnce(t *testing.T) {
	mount, id := fakeCgroupMount(t, 40, 31)
	before := cgroupWalks.Load()
	first, second := newProcAdmitter(), newProcAdmitter()
	for _, a := range []*procAdmitter{first, second} {
		a.mu.Lock()
		pids, err := a.runPIDs(mount, id)
		a.mu.Unlock()
		if err != nil || len(pids) != 1 {
			t.Fatalf("runPIDs = %v, %v", pids, err)
		}
	}
	if n := cgroupWalks.Load() - before; n != 1 {
		t.Fatalf("two listeners of one run walked the tree %d times, want 1", n)
	}

	// Several listeners' first connections at the same moment: one walk, and every one gets the directory.
	mount, id = fakeCgroupMount(t, 40, 7)
	before = cgroupWalks.Load()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := newProcAdmitter()
			a.mu.Lock()
			defer a.mu.Unlock()
			if _, err := a.runPIDs(mount, id); err != nil {
				t.Errorf("runPIDs: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := cgroupWalks.Load() - before; n != 1 {
		t.Fatalf("eight simultaneous first connections walked the tree %d times, want 1", n)
	}
}

// TestCgroupDirKeptForTheProcessIsCheckedEachTime: a kept directory whose inode is no longer the id (the group was
// removed and the name reused) is looked for again, and an id that is not in the tree is an error that is not kept.
func TestCgroupDirKeptForTheProcessIsCheckedEachTime(t *testing.T) {
	mount, id := fakeCgroupMount(t, 10, 4)
	a := newProcAdmitter()
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.runPIDs(mount, id); err != nil {
		t.Fatal(err)
	}
	dir, err := sharedCgroupDir(mount, id)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the directory: same path, new inode. The old directory is moved out of the tree and kept, because a
	// filesystem may give a removed directory's inode number to the next one made, and the name would then still have
	// the id.
	if err := os.Rename(dir, filepath.Join(t.TempDir(), "was")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := sharedCgroupDir(mount, id); err == nil {
		t.Fatal("a directory that no longer has the id was returned")
	}
	if _, err := sharedCgroupDir(mount, id+1<<40); err == nil {
		t.Fatal("an id that is in no group was found")
	}
}
