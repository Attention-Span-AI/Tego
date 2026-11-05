// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// helperScope is the cgroup path suffix of tego's helper cgroup (internal/runtime/cgroup.StartHelper), where a
// build's timer runs.
const helperScope = "/tego.slice/helpers.scope"

// timerCgroups reads the cgroup of each timer in pids, a /proc scan's answer (timers), and says which run outside
// tego's helper cgroup (misplaced, pid to its cgroup) and which exited since the scan (gone). A timer started while
// another holds the build's timer lock exits at once on that lock (runTimer), so a scan that lists it can be
// followed by a read that finds no /proc entry: that timer is gone, not in a cgroup of "" (the reading that failed
// TestIntegrationAKilledTimerLeavesTheBuildUntilStop on public main 02d505d and on PR 23). Any other read error is
// returned.
func timerCgroups(pids []int) (misplaced map[int]string, gone []int, err error) {
	for _, pid := range pids {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		switch {
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH):
			gone = append(gone, pid)
			continue
		case err != nil:
			return nil, nil, err
		}
		if cg := strings.TrimSpace(string(b)); !strings.Contains(cg, helperScope) {
			if misplaced == nil {
				misplaced = map[int]string{}
			}
			misplaced[pid] = cg
		}
	}
	return misplaced, gone, nil
}

// TestTimerCgroupsTellsAnExitedTimerFromAMisplacedOne: a pid that exited and was reaped since the scan is gone, not
// misplaced in a cgroup of ""; a live process outside the helper cgroup (this test's) is misplaced, with its cgroup.
func TestTimerCgroupsTellsAnExitedTimerFromAMisplacedOne(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skipf("no /proc/self/cgroup: %v", err)
	}
	exited := exec.Command("/bin/true")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := exited.Process.Pid
	self := os.Getpid()
	own, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(own), helperScope) {
		t.Skip("this test runs in tego's helper cgroup itself")
	}
	misplaced, gone, err := timerCgroups([]int{dead, self})
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 1 || gone[0] != dead {
		t.Errorf("gone %v, want [%d]: a reaped process is one that exited since the scan", gone, dead)
	}
	if _, ok := misplaced[dead]; ok {
		t.Errorf("the reaped process %d is reported in cgroup %q", dead, misplaced[dead])
	}
	if cg, ok := misplaced[self]; !ok || cg != strings.TrimSpace(string(own)) {
		t.Errorf("misplaced %v, want this process %d in %q", misplaced, self, strings.TrimSpace(string(own)))
	}
}
