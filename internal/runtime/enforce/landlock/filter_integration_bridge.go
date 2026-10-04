// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import "golang.org/x/net/bpf"

// BuildFilterMemfd exposes the shared builder only to the integration harness.
// The harness installs its filesystem, network, exec and memfd arms directly, and
// R11c's bind arm, which a run with a net: section installs; it does not model the
// per-kernel/per-tier arms selected by Prepare.
func BuildFilterMemfd(arch Arch, full bool, m MemfdArm) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{full: full, abi: minTruncateABI, memfd: m, unixBinds: true})
}

// BuildFilterWriteGate is the filter Prepare assembles for a run whose gate scores fs.write (filterOpts.gateWrite),
// exposed only to the integration harness: the plain filter of BuildFilterMemfd with no memfd arm, plus the chmod
// family notified at every record level (enforce-landlock R11, ADR 0041 Step 2).
func BuildFilterWriteGate(arch Arch, full bool) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{full: full, abi: minTruncateABI, unixBinds: true, gateWrite: true})
}

// BuildFilterReadGate is the filter Prepare assembles for a run whose gate scores fs.read only (filterOpts.gateRead),
// exposed only to the integration harness: the plain filter of BuildFilterMemfd with no memfd arm, with every open
// notified at every record level, a read-only one included (enforce-landlock R12).
func BuildFilterReadGate(arch Arch, full bool) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{full: full, abi: minTruncateABI, unixBinds: true, gateRead: true})
}

// BuildFilterGate is BuildFilterMemfd for a run whose gate scores fs actions (ADR 0041 Stage B): the read gate's arm
// notifies every read-open, the write gate's the chmod family as well as write-opens, under record: summary.
func BuildFilterGate(arch Arch, gateRead, gateWrite bool) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{gateRead: gateRead, gateWrite: gateWrite, abi: minTruncateABI, memfd: MemfdOpen, unixBinds: true})
}
