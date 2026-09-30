// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestMakeScratchDirSweepsADeadDoctorsEmptyCgroups: a doctor killed by SIGKILL leaves its empty prefix<pid> scratch
// cgroup in the delegated subtree for good; the next one removes it, and leaves a live pid's, a non-empty one, and
// another prefix's name alone.
func TestMakeScratchDirSweepsADeadDoctorsEmptyCgroups(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	dead := cmd.Process.Pid
	root := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(".tego-doctor-" + strconv.Itoa(dead))
	live := mk(".tego-doctor-" + strconv.Itoa(os.Getppid()))
	other := mk(".tego-doctor-progs-" + strconv.Itoa(dead))
	if _, err := makeScratchDir(root, ".tego-doctor-"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a dead doctor's empty scratch cgroup was kept")
	}
	for _, p := range []string{live, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	// A directory that is not empty stays (rmdir refuses it), as a cgroup holding a process would.
	full := mk(".tego-doctor-plane-" + strconv.Itoa(dead))
	if err := os.Mkdir(filepath.Join(full, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	sweepScratchDirs(root, ".tego-doctor-plane-")
	if _, err := os.Stat(full); err != nil {
		t.Errorf("a non-empty scratch directory was removed: %v", err)
	}
}
