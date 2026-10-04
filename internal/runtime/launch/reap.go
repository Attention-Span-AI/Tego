// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// reapInterval is the backstop poll of RunReaper: SIGCHLD is coalesced and can be taken by another
// notifier, so the sweep also runs on a timer.
const reapInterval = 250 * time.Millisecond

// procCgroup is the cgroup line of /proc/<pid>/cgroup (cgroup v2: "0::/path"), "" when unreadable.
func procCgroup(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(b))
}

// procChildrenGlob names the per-thread children lists of this process. They exist only on a kernel built
// with CONFIG_PROC_CHILDREN (normally selected through CHECKPOINT_RESTORE); a test points it elsewhere to
// stand in for a kernel without them.
var procChildrenGlob = "/proc/self/task/*/children"

// adoptedCandidates returns the pids of this process's children. It reads the per-thread children lists when
// the kernel has them; without them (a kernel lacking CONFIG_PROC_CHILDREN, where the glob matches nothing) it
// scans /proc/<pid>/stat for PPid == self, so the reaper still finds adopted zombies there instead of silently
// finding none and letting them fill limits.pids.
func adoptedCandidates() []int {
	tasks, _ := filepath.Glob(procChildrenGlob)
	var pids []int
	read := false
	for _, f := range tasks {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		read = true
		for _, s := range bytes.Fields(b) {
			if pid, err := strconv.Atoi(string(s)); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	if read {
		return pids
	}
	return scanChildren(os.Getpid())
}

// scanChildren is the fallback of adoptedCandidates: every /proc/<pid> whose stat names ppid as its parent.
func scanChildren(ppid int) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if p, ok := procPPid(pid); ok && p == ppid {
			pids = append(pids, pid)
		}
	}
	return pids
}

// procPPid is the parent pid field of /proc/<pid>/stat.
func procPPid(pid int) (int, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return 0, false
	}
	f := bytes.Fields(b[end+1:])
	if len(f) < 2 {
		return 0, false
	}
	p, err := strconv.Atoi(string(f[1]))
	return p, err == nil
}

// procZombie reports whether /proc/<pid>/stat says the process is a zombie.
func procZombie(pid int) bool { return procStatState(pid) == 'Z' }

// procStatState is the state letter of /proc/<pid>/stat (R, S, T, Z ...), 0 when unreadable.
func procStatState(pid int) byte {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 || end+2 >= len(b) {
		return 0
	}
	return b[end+2]
}

// inCgroupTree reports whether the /proc cgroup line names own's cgroup or a descendant of it. The run's
// scope and every sub-cgroup of it are the run: cgroup.kill and Remove act on the whole subtree and
// pids.current counts it hierarchically, so a zombie that a tool of the agent's moved into a sub-cgroup of
// the scope (possible under --observe, which has no Landlock rule on /sys/fs/cgroup) is still the run's to
// reap. A line that is not a single cgroup v2 "0::/path" line matches only when it equals own exactly.
func inCgroupTree(line, own string) bool {
	if line == "" {
		return false
	}
	if line == own {
		return true
	}
	p, ok := strings.CutPrefix(line, "0::")
	o, oko := strings.CutPrefix(own, "0::")
	if !ok || !oko || strings.ContainsRune(line, '\n') || strings.ContainsRune(own, '\n') {
		return false
	}
	return strings.HasPrefix(p, strings.TrimSuffix(o, "/")+"/")
}

// ReapOrphans reaps the zombies of descendants the subreaper adopted (R1 of ADR 0006) and returns how many.
// A task that exited stays charged to the cgroup's pids.current until it is waited for, so an agent that
// keeps double-forking short-lived helpers would otherwise fill limits.pids with zombies and be killed as
// reason=pids while healthy. Only a zombie child of this process that is in the agent's own cgroup (or a
// sub-cgroup of it, see inCgroupTree) and is not the main child is reaped: the main child is Wait's (its
// status is the run's exit), and this process's other children are their own owners' to wait for.
func (c *Child) ReapOrphans() int {
	if c.cgroup == "" {
		return 0
	}
	n := 0
	keep := int(c.keep.Load())
	for _, pid := range adoptedCandidates() {
		if pid == c.PID || pid == keep || !procZombie(pid) || !inCgroupTree(procCgroup(pid), c.cgroup) {
			continue
		}
		var ws syscall.WaitStatus
		if wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil); err == nil && wpid == pid {
			n++
		}
	}
	return n
}

// KeepUnreaped names a child of this process in the run cgroup that ReapOrphans leaves to its own owner: the run's
// open deputy (ADR 0041 D2), a child of this process (CLONE_PARENT) that the agent can end. Its zombie then holds its
// pid until the run reaps it (runtime's closeDeputy), so no later process of the run is given the pid by which the
// kernel recorder drops the deputy's records (supervisor.md R7a). The zombie counts against limits.pids, one task.
func (c *Child) KeepUnreaped(pid int) { c.keep.Store(int64(pid)) }

// RunReaper calls ReapOrphans on every SIGCHLD and on a timer until ctx ends, with one last sweep then.
func (c *Child) RunReaper(ctx context.Context) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGCHLD)
	defer signal.Stop(ch)
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		c.ReapOrphans()
		select {
		case <-ctx.Done():
			c.ReapOrphans()
			return nil
		case <-ch:
		case <-t.C:
		}
	}
}
