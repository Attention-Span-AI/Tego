// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// TestTreeTasksCountsWhatTheMoveWouldMove: a pids ceiling counts tasks, every thread of every process in the cgroup,
// so the count a boundary adoption holds against limits.pids before its move is the threads of the tree's members that
// would move: the agent and its descendants still in its cgroup, not a descendant placed elsewhere, nor its parent
// shell or a sibling in the same session.
func TestTreeTasksCountsWhatTheMoveWouldMove(t *testing.T) {
	m := terminal()
	// Two more threads of the agent (200), and a child placed in a cgroup of its own, which does not move.
	for _, tid := range []int{210, 211} {
		m.procs[tid] = &fakeProc{ppid: 100, start: 1200, state: 'S', exe: "/usr/bin/node", cgroup: session, tgid: 200, thread: true}
	}
	m.add(203, 200, "/user.slice/user-1000.slice/user@1000.service/app.slice/run-x.scope", "/usr/bin/sleep", 1000)
	root := mustIdentify(m, 200)
	n, err := TreeTasks(m.env(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 200 with its two threads, 201, 202.
	if n != 5 {
		t.Errorf("TreeTasks = %d, want 5: the agent's three tasks and its two descendants in its cgroup", n)
	}

	// A member whose threads cannot be listed, alive, counts its stat's thread count; one that exited between the
	// walk and its listing counts nothing.
	failing := &tasksFail{machine: m, fail: map[int]bool{200: true, 202: true}, exitsWhenListed: 202, listed: map[int]bool{}}
	n, err = TreeTasks(Env{Proc: failing, FS: m, Live: m, Mount: m.mount}, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("TreeTasks with 200's threads unlisted and 202 gone = %d, want 4 (200's stat says 3, 201 one)", n)
	}

	// A root that is gone is the walk's error, as Move's.
	m.mu.Lock()
	delete(m.procs, 200)
	m.mu.Unlock()
	if _, err := TreeTasks(m.env(), root, nil); !errors.Is(err, ErrGone) {
		t.Errorf("TreeTasks of a gone root = %v, want ErrGone", err)
	}
}

// tasksFail is a machine whose task listing fails for the pids in fail; exitsWhenListed exits as its listing fails,
// so the stat read after it says exited.
type tasksFail struct {
	*machine
	fail            map[int]bool
	exitsWhenListed int
	listed          map[int]bool
}

func (f *tasksFail) Tasks(pid int) ([]int, error) {
	if f.fail[pid] {
		f.listed[pid] = true
		return nil, errors.New("listing refused")
	}
	return f.machine.Tasks(pid)
}

func (f *tasksFail) Stat(pid int) (proc.Stat, error) {
	st, err := f.machine.Stat(pid)
	if err == nil && pid == f.exitsWhenListed && f.listed[pid] {
		st.State = 'X'
	}
	return st, err
}
