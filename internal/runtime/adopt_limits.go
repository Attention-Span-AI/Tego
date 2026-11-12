// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A boundary adoption's limits (ADR 0055, the 2026-11-11 limits amendment). Its table's cpu, cpu_weight and pids, a
// machine ceiling's or the contract's, are written into the adoption's scope while it is empty, before the arm and the
// move, by the same writer as a launched run's (cgroup.Manager.SetLimits): from its move on each process of the tree is
// throttled (cpu.max, cpu.weight), or refused a fork or a thread past pids.max (EAGAIN); the kernel ends none for them,
// though a program that cannot start a thread may end itself (Go's runtime aborts), which is why a tree moves only with
// room for one more task (checkTreeTasks). Every other kernel or time limit is refused before anything happens (the
// caller, and newAdoption again): memory already charged stays in the cgroup the agent came from, so a cap would count
// only what it allocates after the move, and one reached would OOM-kill it; wall and stall_after would end it; an
// adoption never ends the agent. A record-only adoption holds no rule and writes no limit (ADR 0055 (5)).

// adoptionApplied are the limits keys a boundary adoption writes, with the dimension of each.
var adoptionApplied = map[string]agent.BudgetSet{
	"cpu":        agent.BudgetCPU,
	"cpu_weight": agent.BudgetCPUWeight,
	"pids":       agent.BudgetPids,
}

// adoptionNeverHeld are the kernel and time limits no adoption can hold, which newAdoption refuses in a boundary
// table: the caller refuses them, named, before this; a table that still holds one is a caller bug.
var adoptionNeverHeld = map[string]agent.BudgetSet{
	"memory":      agent.BudgetMemory,
	"memory_high": agent.BudgetMemoryHigh,
	"wall":        agent.BudgetWall,
	"stall_after": agent.BudgetStallAfter,
}

// AdoptionApplies reports whether a boundary adoption writes the limits key (as the contract and the machine
// config's limits.* name it: "cpu", "pids") into its scope before the move.
func AdoptionApplies(key string) bool {
	_, ok := adoptionApplied[strings.TrimPrefix(key, "limits.")]
	return ok
}

// ErrAdoptLimits is a boundary adoption whose limits could not be applied as asked: a write the kernel refused (a
// controller the scope's parent does not enable: the error names the setup), or a pids ceiling below the tasks the
// agent's tree holds, before the move or after it. Nothing of the adoption is left: the scope is removed and what
// moved went back.
var ErrAdoptLimits = errors.New("runtime: the adoption's limits cannot be applied")

// adoptionLimits are the files a boundary adoption writes for l: cpu.max, cpu.weight and pids.max from the table's
// cpu, cpu_weight and pids, converted as a launched run's are (cgroup.FromResolved), and nothing else. A table that
// holds a limit no adoption can hold (adoptionNeverHeld) is refused.
func adoptionLimits(l agent.ResolvedLimits) (cgroup.Limits, error) {
	var held []string
	for _, key := range []string{"memory", "memory_high", "wall", "stall_after"} {
		if l.Bounded(adoptionNeverHeld[key]) {
			held = append(held, "limits."+key)
		}
	}
	if len(held) > 0 {
		return cgroup.Limits{}, fmt.Errorf("%w: a boundary table with %s, which no adoption can hold", ErrAdoptDeps,
			strings.Join(held, ", "))
	}
	all, err := cgroup.FromResolved(l)
	if err != nil {
		return cgroup.Limits{}, fmt.Errorf("%w: %w", ErrAdoptLimits, err)
	}
	return cgroup.Limits{CPUMax: all.CPUMax, CPUWeight: all.CPUWeight, PidsMax: all.PidsMax, PidsMaxSet: all.PidsMaxSet}, nil
}

// pidsCeiling is the pids.max the adoption wrote, ok false when it wrote none.
func (a *adoption) pidsCeiling() (int, bool) {
	return a.limits.PidsMax, a.limits.PidsMax != 0 || a.limits.PidsMaxSet
}

// checkTreeTasks refuses, before the move, a tree that holds as many tasks as the pids ceiling or more: moved under
// it, the live agent's next fork or thread would fail at once, and it could start none until enough of its tasks
// ended. An adoption moves a tree only with room for at least one more task. It runs under the move lock, right after
// the root's recheck; the tree can still grow before its last member moves, which checkScopeTasks catches.
func (a *adoption) checkTreeTasks() error {
	ceiling, ok := a.pidsCeiling()
	if !ok {
		return nil
	}
	n, err := adopt.TreeTasks(a.env, a.spec.Root, a.spec.Extra)
	if err != nil {
		return fmt.Errorf("%w: count the agent's tasks against pids.max %d: %w", ErrAdoptLimits, ceiling, err)
	}
	if n >= ceiling {
		return fmt.Errorf("%w: the agent's tree holds %d tasks (processes and threads), %s the pids ceiling %d "+
			"(limits.pids, pids.max): under it the agent's next process or thread would fail at once, so nothing "+
			"moved; raise limits.pids to %d or more, or adopt with no --boundary to record it", ErrAdoptLimits, n,
			atOrOver(n, ceiling), ceiling, n+1)
	}
	return nil
}

// checkScopeTasks refuses, after the move, a scope that holds as many tasks as its pids ceiling or more, as
// checkTreeTasks does before it. A fork inside the scope is held to pids.max by the kernel, but a migration is charged
// whatever the limit, so a tree that grew between checkTreeTasks and its last member's move can be at the ceiling or
// past it; the adoption is refused and its tree released (unwind), rather than kept where its next fork fails. A fork
// the moved agent made inside the scope in that time counts the same: it is refused too, which fails closed. A scope
// whose tasks cannot be listed is refused: its count is not known.
func (a *adoption) checkScopeTasks() error {
	ceiling, ok := a.pidsCeiling()
	if !ok {
		return nil
	}
	tids, err := a.env.FS.Threads(a.r.cg.Path)
	if err != nil {
		return fmt.Errorf("%w: count the moved tasks against pids.max %d: %w", ErrAdoptLimits, ceiling, err)
	}
	if n := len(tids); n >= ceiling {
		return fmt.Errorf("%w: the agent's tree grew to %d tasks (processes and threads) while it moved, %s the "+
			"pids ceiling %d (limits.pids, pids.max): under it the agent's next process or thread would fail at once, "+
			"so it was released where it came from", ErrAdoptLimits, n, atOrOver(n, ceiling), ceiling)
	}
	return nil
}

// atOrOver words a task count against the pids ceiling it reached.
func atOrOver(n, ceiling int) string {
	if n == ceiling {
		return "as many as"
	}
	return "more than"
}

// liftLimits writes the limits back to the kernel's default on a scope a release left processes in, which tego no
// longer governs (releaseTree): none of them keeps a limit the adoption wrote. A failure is kept, for unwind's error
// and run_end's detail (releaseSummary), and logged.
func (a *adoption) liftLimits() {
	if a.limits == (cgroup.Limits{}) || a.cgm == nil {
		return
	}
	if err := a.cgm.LiftLimits(a.r.cg); err != nil {
		a.liftErr = err
		a.r.log.Warn("adopt: lift the limits of the processes left in the scope", "path", a.r.cg.Path, "err", err)
	}
}
