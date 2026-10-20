// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"golang.org/x/net/bpf"
)

// Handle is a prepared, run-scoped enforcement state consumed by the child stage and the supervisor.
type Handle interface {
	// LandlockRuleset returns the ruleset fd to apply in the child stage, or ok=false when the tier has none.
	LandlockRuleset() (fd int, ok bool)
	// SeccompFilter returns the classic-BPF program to install with NEW_LISTENER, or ok=false when none.
	SeccompFilter() (prog []bpf.RawInstruction, ok bool)
	// Attach binds kernel-side state to the run cgroup (tier 2+); tier 1 returns nil.
	Attach(cgroupID uint64) error
	// Detach releases kernel-side state; safe to call twice.
	Detach() error
	// Close releases fds and memory; safe to call twice.
	Close() error
}

// Armer is a handle with kernel state that decides or records the run's own actions and so must not exist
// before the child stage's first execve (ADR 0021 (2)): tier 2's run-set row, which the recorder and (with a
// decision plane) every hook key on, and its fanotify marks. Placed at Prepare, they saw the stage's exec of
// tego's own binary as the run's first action: the group was asked about it while the launcher sat in the
// vfork of that same exec (E39's freeze), and the recorder took tego for the agent's first process.
//
// The facade calls Arm exactly once, after the stage has reported on the control pipe (launch.WaitNotifyFD:
// the stage writes that message only once its execve has returned) and before the ack, so the agent, which
// does not exist before the ack, meets the whole of it. A failed Arm fails the run before run_start. After a
// successful Arm the process starts nothing until Detach has removed the marks (internal/platform/proc.Start
// refuses, ADR 0021 (3)).
type Armer interface {
	Arm() error
}

// Listener is a handle that owns a loop for the length of the run: tier 2's fanotify listener, which must
// be answering before the agent's first open and stop when the run ends. A facade starts it in the run's
// own goroutine group; a handle without it needs nothing started.
type Listener interface {
	RunListener(ctx context.Context) error
}

// ListenerWaiter is a Listener whose workers can outlive its loop. Tier 2's fanotify listener returns at once
// on a fatal error so the run is ended (enforce-cgroup-observe §6 E15), while its workers still answer the
// events they hold, within three of E16's deadlines, and record a line for each. The facade waits for them
// between its workers' Wait and its final drain, or those lines land after the drain and are lost (E35).
type ListenerWaiter interface {
	WaitListener(ctx context.Context) error
}
