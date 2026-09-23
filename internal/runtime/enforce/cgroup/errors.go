// SPDX-License-Identifier: Apache-2.0

package cgroup

import "errors"

// Sentinel errors of the tier-2 backend. Every one of them is wrapped with %w and carries the context a
// launcher prints as `<file>:<line>: <message> [<code>]`; the table of docs/p0/enforce-cgroup-observe.md §7
// says which exit status each produces (125 for every Prepare failure).
var (
	// ErrNoTable is returned by Prepare for a nil rule table.
	ErrNoTable = errors.New("cgroup: nil rule table")
	// ErrTier is returned when the table was not compiled for the backend's tier (tier 2, or tier 3 for the
	// backend Options.Tier makes tier bpflsm).
	ErrTier = errors.New("cgroup: rule table is not compiled for this backend's tier")
	// ErrNeedsLSMMode is returned by tier bpflsm's Prepare when the plane it was handed is not in LSM mode: tier 3
	// is the plane in LSM mode, never another mode or the listener (enforce-plane R19).
	ErrNeedsLSMMode = errors.New("cgroup: tier bpflsm needs the decision plane in LSM mode")
	// ErrPlaneCannotHold is returned by tier bpflsm's Prepare for a table the plane cannot express (over a slot's
	// rows, decide.ErrPlaneCap; an exec entry that does not allow, decide.ErrPlaneExecVerdict). Tier 2 runs such a
	// table on the fanotify listener; tier 3 has none, and refuses it rather than enforce less (§6 E13, I7).
	ErrPlaneCannotHold = errors.New("cgroup: tier bpflsm cannot hold this contract in the decision plane")
	// ErrPlaneRowsChanged is returned by tier cgroup's Prepare when the plane rows the caller handed over
	// (Run.PlaneRows), which it checked the plane could hold before composing tier 1 from them, no longer hold (two
	// fs rows became one file under two names in between). The caller composes tier 1 again without them and
	// prepares again, so the run falls back to the listener with a filter composed for the listener (enforce-plane
	// I7); it is never a run on the listener with the plane-only relaxations.
	ErrPlaneRowsChanged = errors.New("cgroup: the plane rows tier 1 was composed from no longer hold")
	// ErrSlotsExhausted is returned when all run_idx slots are taken (§6 E12).
	ErrSlotsExhausted = errors.New("cgroup: no free run slot on this host")
	// ErrProgramLoad is returned when the kernel rejects a program or the binary carries none (§7).
	ErrProgramLoad = errors.New("cgroup: bpf program load failed")
	// ErrBuildLock is returned when the shared build lock cannot be taken; the caller retries.
	ErrBuildLock = errors.New("cgroup: build lock unavailable")
	// ErrMapFull is returned when a verdict map cannot hold the run's rules (§7).
	ErrMapFull = errors.New("cgroup: verdict map at capacity")
	// ErrRingbufSize is returned when record.ringbuf is not a power of two page multiple (§5 R16, §6 E28).
	ErrRingbufSize = errors.New("cgroup: record.ringbuf must be a power of two and a multiple of the page size")
	// ErrRingBudget is returned when the run's record ring would take the host's live rings past bpf.ring_budget
	// (ADR 0026 (2)). It is its own code because nothing is wrong with the run: other runs' rings fill the budget,
	// and the fix is to wait or raise it. A capture ring that does not fit is not this error from Prepare; the run
	// goes on without one (Handle.CaptureRefused).
	ErrRingBudget = errors.New("cgroup: the host's ring budget has no room for this run's rings")
	// ErrBpffsUnavailable is returned when the bpf filesystem is not mounted where pins belong (§6 E30).
	ErrBpffsUnavailable = errors.New("cgroup: bpf filesystem is not mounted")
	// ErrNotPrepared is returned by a handle method called before Prepare completed.
	ErrNotPrepared = errors.New("cgroup: handle is not prepared")
	// ErrRefreshShape is returned by RefreshNet for a table whose net entries are not the prepared ones with
	// new addresses: a refresh changes where a host resolves, never what the contract admits (§6 E7).
	ErrRefreshShape = errors.New("cgroup: a refreshed table changes more than addresses")
	// ErrFanotify is returned when the fanotify group cannot be created or marked (§7).
	ErrFanotify = errors.New("cgroup: fanotify unavailable")
	// ErrListenerDied is what the run context is cancelled with when the listener goroutine stops; the run
	// is killed rather than left in the kernel's fail-open window (§6 E15).
	ErrListenerDied = errors.New("cgroup: fanotify listener died")
	// ErrCgroupAttachConflict is returned when the kernel refuses this run's cgroup attachment with EPERM,
	// which on a privileged launcher means another manager holds an exclusive attachment at or above the
	// run's cgroup (§6 E36). It is its own code because the fix is on the host, not in the contract.
	ErrCgroupAttachConflict = errors.New("cgroup: the kernel refused this run's cgroup attachment")
	// ErrPidNamespace is returned when this process is not in the initial pid namespace: the slot table records
	// owners by pid and reads them back in /proc, and the table and the run_idx space are host-wide, so a
	// launcher in a pid namespace of its own would take another launcher's live slot for a dead one (§7).
	ErrPidNamespace = errors.New("cgroup: the launcher is not in the initial pid namespace")
)
