// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"
	"sort"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// Skip is a process of the agent's tree that an adoption does not move, and why.
type Skip struct {
	PID int
	Why string
}

// The reasons a member of the tree is skipped.
const (
	SkipOtherCgroup = "in another cgroup"                 // a descendant someone placed elsewhere (systemd-run, a container): not followed
	SkipGone        = "exited"                            // it exited before it could move
	SkipReused      = "its pid now names another process" // identity check failed: nothing moved for that pid
	SkipTooMany     = "over the tree's cap"               // past MaxMembers
	SkipMoveFailed  = "the kernel refused the move"       // cgroup.procs refused the pid
)

// MaxMembers caps how many processes one adoption moves. An agent's tree is small; the cap is there so a fork storm
// cannot make the adopter's memory and its rounds grow without bound.
const MaxMembers = 4096

// entry is one process of a /proc snapshot: its parent, its start time and its stat.
type entry struct {
	ppid  int
	start uint64
	st    proc.Stat
}

// snapshot reads every process's parent and start time once. A process that is gone (dead, or a zombie) is left out;
// one whose leader exited while other threads of it run is not (proc.Stat.LeaderExited).
func snapshot(p Proc) (map[int]entry, map[int][]int, error) {
	pids, err := p.PIDs()
	if err != nil {
		return nil, nil, fmt.Errorf("adopt: list processes: %w", err)
	}
	all := make(map[int]entry, len(pids))
	kids := map[int][]int{}
	for _, pid := range pids {
		st, err := p.Stat(pid)
		if err != nil || st.Gone() {
			continue
		}
		all[pid] = entry{ppid: st.PPID, start: st.StartTicks, st: st}
		kids[st.PPID] = append(kids[st.PPID], pid)
	}
	for _, ks := range kids {
		sort.Ints(ks)
	}
	return all, kids, nil
}

// walk is one pass over the agent's tree: root and every descendant reached from it, parents first, through
// processes in from (the cgroup the agent was found in) or in dest (the run's, where a member already moved), plus
// the extra identities and theirs (descendants the caller followed by fork events, which /proc's parent links no
// longer tie to root once their parent exited). It returns the processes still in from, to move, and the ones it
// will not move. A descendant in any other cgroup is skipped and not descended into: someone placed it there on
// purpose. dest and from are cgroup paths relative to the mount, as /proc/<pid>/cgroup names them.
func walk(p Proc, root Identity, from, dest string, extra []Identity) ([]Process, []Skip, error) {
	all, kids, err := snapshot(p)
	if err != nil {
		return nil, nil, err
	}
	if e, ok := all[root.PID]; !ok || e.start != root.Start {
		return nil, nil, fmt.Errorf("adopt: pid %d: %w", root.PID, ErrGone)
	}
	var out []Process
	var skipped []Skip
	seen := map[int]bool{}
	queue := []int{root.PID}
	for _, x := range extra {
		if e, ok := all[x.PID]; ok && e.start == x.Start {
			queue = append(queue, x.PID)
		}
	}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		cg, err := cgroupOf(p, pid, all[pid].st)
		if err != nil {
			if pid != root.PID {
				skipped = append(skipped, Skip{PID: pid, Why: SkipGone})
			}
			continue
		}
		switch {
		case cg == from:
			if len(out) >= MaxMembers {
				skipped = append(skipped, Skip{PID: pid, Why: SkipTooMany})
				continue
			}
			t, err := Identify(p, pid)
			if err != nil || t.Start != all[pid].start {
				skipped = append(skipped, Skip{PID: pid, Why: SkipGone})
				continue
			}
			out = append(out, t)
		case dest != "" && cg == dest:
		default:
			if pid == root.PID {
				return nil, nil, fmt.Errorf("adopt: pid %d left %s for %s while it was adopted", pid, from, cg)
			}
			skipped = append(skipped, Skip{PID: pid, Why: SkipOtherCgroup + " (" + cg + ")"})
			continue
		}
		queue = append(queue, kids[pid]...)
	}
	return out, skipped, nil
}

// TreeTasks counts the tasks of the processes Move would move now (root and its descendants still in root's cgroup,
// and the extra identities'), every thread of each, as the pids controller counts them (pids.max, pids.current). A
// process that exits while it is counted is not counted; one whose threads cannot be listed while it lives counts
// its stat's thread count, at least one. It is a snapshot: the tree can grow before the move, so a caller holding a
// pids ceiling checks the destination again after it.
func TreeTasks(env Env, root Process, extra []Identity) (int, error) {
	todo, _, err := walk(env.Proc, root.Identity, root.Cgroup, "", extra)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range todo {
		tids, err := env.Proc.Tasks(t.PID)
		if err == nil {
			n += len(tids)
			continue
		}
		st, serr := env.Proc.Stat(t.PID)
		if serr != nil || st.Gone() || st.StartTicks != t.Start {
			continue // it exited: it will not move
		}
		n += max(st.NumThreads, 1)
	}
	return n, nil
}

// ErrIdentityChanged is a root whose start time is not the one it was identified with when the move came: its pid
// names another process, and nothing is moved.
var ErrIdentityChanged = errors.New("adopt: the process's pid now names another process")
