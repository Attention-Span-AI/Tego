// SPDX-License-Identifier: Apache-2.0

package agent

// FSAssurance chooses how a table's built-in deny_write targets (agent-contract R20) must be enforced where no
// kernel decision plane decides the run: tier landlock, and tier cgroup on its fanotify listener (ADR 0041 D1
// (a)). Best effort, the default, runs such a table with the seccomp supervisor's refusal of the targets'
// copied pathnames (supervisor R15c), which a racing sibling thread, a swapped symlink or an earlier hard link
// can defeat, and discloses it: one compile warning per target, run_start best_effort. Kernel refuses such a
// run before its child starts, so every run that starts decides the targets in the plane, race-free. A tier
// with a plane decides them in the kernel either way.
type FSAssurance string

const (
	FSAssuranceBestEffort FSAssurance = "best-effort"
	FSAssuranceKernel     FSAssurance = "kernel"
)

func validateFSAssurance(ds *diags, c *Contract, at func(string) Pos) {
	if c.FS == nil {
		return
	}
	switch c.FS.Assurance {
	case "", FSAssuranceBestEffort, FSAssuranceKernel:
	default:
		ds.errorf(at("fs.assurance"), CodeSchema, "fs.assurance %q: want best-effort or kernel", c.FS.Assurance)
	}
}

// FilesystemAssurance is the effective fs.assurance: kernel when either the compiled value or the contract's
// says so, so a hand-built table, or one whose compiled value was lost, never reads as weaker than its
// contract; best effort otherwise.
func (rt *RuleTable) FilesystemAssurance() FSAssurance {
	if rt.FSAssurance == FSAssuranceKernel ||
		(rt.Contract != nil && rt.Contract.FS != nil && rt.Contract.FS.Assurance == FSAssuranceKernel) {
		return FSAssuranceKernel
	}
	return FSAssuranceBestEffort
}

// DenyWriteNeedsPlane reports whether a run of the table needs a kernel decision plane to start: it has built-in
// deny_write targets and fs.assurance: kernel (enforce-landlock R5a). enforce.Select, the Landlock backend's
// Prepare and tier cgroup's plane choice ask it, so the three refuse the same tables.
func (rt *RuleTable) DenyWriteNeedsPlane() bool {
	return len(rt.DenyWrite) != 0 && rt.FilesystemAssurance() == FSAssuranceKernel
}
