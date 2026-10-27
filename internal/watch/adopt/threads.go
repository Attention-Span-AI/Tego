// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
)

// A process whose thread-group leader has exited while other threads of it run on (pthread_exit in main, or a raw
// exit(2) from the leader) reads in /proc/<pid>/stat as a zombie, state Z, but counts its live threads in num_threads,
// and those threads run its program and may fork; a child they fork names the process its parent. The kernel keeps
// the exited leader where it was: in a guest of 6.17,
// /proc/<pid>/cgroup (the leader's) and the source's cgroup.procs went on naming the old cgroup after a write of the
// pid to another cgroup.procs had moved the live threads, the destination's cgroup.procs named nothing and its
// cgroup.threads named the threads; /proc/<pid>/exe, cmdline and ns/* read as absent, /proc/<pid>/fd listed nothing,
// and each live thread's /proc/<tid> read as the process. A write of the pid moves its live threads both ways, from a
// frozen cgroup too. So a process in that state is a member like any other: it is identified through a thread of it
// that runs (liveTask), its cgroup is that thread's (cgroupOf), the move writes its pid, and a release finds it in the
// run's cgroup.threads (scopeProcs). Rejected: counting it as not moved (adoption-not-moved), which leaves code the
// agent runs outside the boundary on purpose for a trick that needs no privilege.

// liveTask is the task whose /proc entries answer for process pid, st its stat: pid itself, unless its leader exited
// (proc.Stat.LeaderExited), then the first other task of it that is neither dead nor a zombie and whose status names pid its
// thread group, with that task's start time, so a caller can tell after its reads that the task is still the one it
// read (sameTask). A process none of whose threads can be read so is ErrGone.
func liveTask(p Proc, pid int, st proc.Stat) (tid int, start uint64, err error) {
	if !st.LeaderExited() {
		return pid, st.StartTicks, nil
	}
	tids, err := p.Tasks(pid)
	if err != nil {
		return 0, 0, err
	}
	for _, t := range tids {
		if t == pid {
			continue
		}
		ts, err := p.Stat(t)
		if err != nil || ts.State == 'Z' || ts.State == 'X' {
			continue
		}
		if s, err := p.Status(t); err != nil || s.Tgid != pid {
			continue
		}
		return t, ts.StartTicks, nil
	}
	return 0, 0, fmt.Errorf("pid %d: %w (its leader exited and no thread of it could be read)", pid, ErrGone)
}

// sameTask reports whether tid, read as a task of process pid that started at start, still is one: a thread id is
// reused once its thread is released, by a thread of any process.
func sameTask(p Proc, pid, tid int, start uint64) bool {
	if tid == pid {
		return true
	}
	ts, err := p.Stat(tid)
	if err != nil || ts.StartTicks != start || ts.State == 'Z' || ts.State == 'X' {
		return false
	}
	s, err := p.Status(tid)
	return err == nil && s.Tgid == pid
}

// cgroupOf is the cgroup process pid's live threads are in, st its stat: /proc/<pid>/cgroup, or, for a process whose
// leader exited, a live thread's, since the kernel leaves the exited leader in the cgroup it was in.
func cgroupOf(p Proc, pid int, st proc.Stat) (string, error) {
	tid, start, err := liveTask(p, pid, st)
	if err != nil {
		return "", err
	}
	cg, err := p.Cgroup(tid)
	if err != nil {
		return "", err
	}
	if !sameTask(p, pid, tid, start) {
		return "", fmt.Errorf("pid %d: %w (the thread it was read through exited)", pid, ErrGone)
	}
	return cg, nil
}

// ListTasks is the tasks of process id as /proc lists them now, for procconn.Group (procconn.List): its lower bound,
// the tasks that run, and whether every one of them is already exiting. It lists none when /proc cannot read the
// process, it is dead or a zombie whose group has ended (proc.Stat.Gone), or its pid names a process with another start
// time (it was reused). A zombie task is left out, the exited leader of a process whose threads run on too; a task
// whose stat cannot be read or whose status no longer names the process (its tid was reused) is a change under the
// listing, which is taken again. It is where procconn.Group starts, for a process found running after the listener was
// subscribed: its exit events then tell its end.
func ListTasks(p Proc, id Identity) procconn.Listing {
	tasks := func() ([]int32, error) {
		st, err := p.Stat(id.PID)
		if err != nil || st.Gone() || st.StartTicks != id.Start {
			return nil, errGone
		}
		tids, err := p.Tasks(id.PID)
		out := make([]int32, 0, len(tids))
		for _, t := range tids {
			out = append(out, int32(t))
		}
		return out, err
	}
	state := func(tid int32) procconn.TaskState {
		ts, err := p.Stat(int(tid))
		switch {
		case err != nil || ts.State == 'X':
			return procconn.TaskDying
		case ts.State == 'Z':
			return procconn.TaskZombie
		}
		if s, err := p.Status(int(tid)); err != nil || s.Tgid != id.PID {
			return procconn.TaskDying
		}
		if ts.Exiting() {
			return procconn.TaskExiting
		}
		return procconn.TaskRunning
	}
	return procconn.List(tasks, state)
}

// errGone is a listed process that is no longer there.
var errGone = errors.New("adopt: the process is gone")

// CgroupOf is the cgroup process pid's live threads are in (cgroupOf, over a fresh stat): what holds the process
// now, for a process whose leader exited too.
func CgroupOf(p Proc, pid int) (string, error) {
	st, err := p.Stat(pid)
	if err != nil {
		return "", err
	}
	if st.Gone() {
		return "", fmt.Errorf("pid %d: %w (a zombie)", pid, ErrGone)
	}
	return cgroupOf(p, pid, st)
}

// scopeProcs is the processes with a live thread in dir (absolute): the process of each task its cgroup.threads lists,
// which names live tasks only. cgroup.procs is not it either way: it leaves out a process whose leader exited
// elsewhere and whose threads are in dir, and it goes on naming a leader that exited in dir while its group has a
// live thread anywhere, after a release moved that thread out. A
// thread whose process cannot be read is left out: it has exited. Only where cgroup.threads cannot be read (a kernel
// before 4.14, which has no cgroup.threads) is cgroup.procs the answer.
func scopeProcs(env Env, dir string) ([]int, error) {
	tids, err := env.FS.Threads(dir)
	if err != nil {
		return env.FS.Procs(dir)
	}
	var pids []int
	listed := map[int]bool{}
	for _, tid := range tids {
		s, err := env.Proc.Status(tid)
		if err != nil || s.Tgid <= 0 || listed[s.Tgid] {
			continue
		}
		listed[s.Tgid] = true
		pids = append(pids, s.Tgid)
	}
	return pids, nil
}
