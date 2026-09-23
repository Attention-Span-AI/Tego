// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"fmt"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Limits are the cgroup v2 controller values written for a run. A zero value leaves the file
// untouched, which on a fresh cgroup means the kernel default "max" — E30's case, the contract
// omitting the key.
//
// The Set flags separate that case from a cap an operator wrote as exactly 0, which E30 never meant
// to cover and E16 makes a real cap: with the flag set the literal "0" is written, and the run
// cannot fork (pids.max) or cannot allocate (memory.max) and dies at once. Without them the zero
// value carries both meanings and the tightest cap an operator can express becomes no cap at all.
type Limits struct {
	CPUMax     string // cpu.max, e.g. "max 100000" or "200000 100000"; see FormatCPUMax
	CPUWeight  int    // cpu.weight, 1..10000
	MemoryMax  int64  // memory.max in bytes
	MemoryHigh int64  // memory.high in bytes
	PidsMax    int    // pids.max

	MemoryMaxSet  bool // memory.max was asked for, so 0 is a cap and not an absent key
	MemoryHighSet bool // memory.high likewise
	PidsMaxSet    bool // pids.max likewise
}

// Cgroup is one created run cgroup. Its directory is the O_DIRECTORY|O_CLOEXEC descriptor Create opened
// for clone3(CLONE_INTO_CGROUP) (kernel 5.7+), which Dir lends; ID is the 64-bit cgroup id (st_ino on
// cgroup2fs, the value bpf_get_current_cgroup_id() reports).
type Cgroup struct {
	Path string // absolute path under the cgroup2 mount
	ID   uint64
	// Controllers is the scope's cgroup.controllers at Create (the controllers its files exist
	// for); nil when unknown. The tests' Missing compares a Limits against it.
	Controllers []string
	// enableRefused is each controller a slice above the scope refused to enable at Create, with the
	// refusal, which SetLimits' missing-controller error carries (case 31). Nil when none was.
	enableRefused map[string]error
	// dir is the scope's directory descriptor (ADR 0023): one owner shared by every copy of the value
	// Create returned, because the descriptor belongs to the value and not to any one copy of it: Remove
	// takes a Cgroup by value, and the launcher's signal killer and the limits watcher each keep their own
	// copy of the same run's Cgroup. The owner closes once, whichever copy closes it (§9's "every
	// O_DIRECTORY fd is closed exactly once, on exactly one code path"), and a copy that uses it after that
	// gets sys.ErrClosed, never a number the process has since given to another file. A Cgroup outlives its
	// descriptor in the signal killer and the limits watcher, and both reach the kernel through
	// writeControl: resolving cgroup.kill against a reused number could write "1" into a file that is not
	// this run's (I8 — nothing force-empties a cgroup but its own cgroup.kill), so a closed one resolves
	// against Path (openControl), under a lease while open. Nil on a Cgroup built by hand, which owns none.
	dir *sys.FD
}

// Close closes the directory descriptor when it is open. Remove calls it; a caller that deferred Remove to
// a sweep calls it instead. Idempotent, and idempotent across copies of the same value (§9): the second
// Close is a no-op, never a close(2) of whatever unrelated file the process has since been handed that
// descriptor number under the kernel's lowest-free-fd rule. A Close while the number is lent (Dir, a
// control-file open) is deferred to the lease's end.
func (c *Cgroup) Close() error {
	if err := c.dir.Close(); err != nil {
		return fmt.Errorf("close(%s): %w", c.Path, err)
	}
	return nil
}

// Dir lends the scope's directory descriptor for clone3's CLONE_INTO_CGROUP (sys.CloneIntoCgroup borrows
// it across the start). It is nil on a Cgroup built by hand, which has no directory to clone into, and
// answers sys.ErrClosed once any copy of the value has closed it.
func (c Cgroup) Dir() sys.Lender {
	if c.dir == nil {
		return nil
	}
	return c.dir
}

// Manager creates and controls run cgroups (docs/p0/runtime-launch.md §2, §4). FS is the one
// implementation; the interface exists so the runtime facade can be tested against a fake.
type Manager interface {
	// Root returns the base under which tego.slice is created: the delegated user subtree of an
	// unprivileged launcher or the cgroup2 mount root of a privileged one.
	Root() string
	// Create makes tego.slice/tego-<agent>.slice/run-<id>.scope under Root, enabling the cpu,
	// memory and pids controllers on each slice where the parent allows it, and opens the scope's
	// directory fd. An existing scope is ErrCgroupExists.
	Create(agent, runID string) (Cgroup, error)
	// ID returns the cgroup id: name_to_handle_at's kernfs handle (5.5+), else st_ino.
	ID(c Cgroup) (uint64, error)
	// SetLimits writes every non-zero field of l, one write(2) each. ENOENT is a
	// *MissingControllerError (case 31), EINVAL wraps ErrInvalidLimit; neither is dropped.
	SetLimits(c Cgroup, l Limits) error
	// Kill writes 1 to cgroup.kill (5.14+). Delivery is asynchronous: callers confirm with WaitEmpty.
	Kill(c Cgroup) error
	// WaitEmpty blocks until cgroup.events reports populated 0 or ctx ends.
	WaitEmpty(ctx context.Context, c Cgroup) error
	// Events emits the populated flag on every transition until ctx ends; the channel is closed then.
	Events(ctx context.Context, c Cgroup) (<-chan bool, error)
	// OOMKilled reports whether memory.events shows an oom_kill for the run (false when the memory
	// controller is not delegated: the kernel cannot have OOM-killed by this cgroup's limit then).
	OOMKilled(c Cgroup) (bool, error)
	// Remove closes the fd and removes the scope, descendants first, retrying EBUSY five times over
	// one second (case 9); ErrBusy afterwards, for the sweep to finish. A failure to close the fd
	// never cancels the removal (R18).
	Remove(ctx context.Context, c Cgroup) error
}
