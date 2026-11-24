// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// CheckCaptureStack requires the live tail call that excludes a capture program
// from the JIT's per-CPU private stack. Read the kernel's translated instructions,
// including for adopted programs: the ELF alone cannot establish what survived
// verification. Only capture availability depends on this check.
func CheckCaptureStack(name string, prog *ebpf.Program) error {
	insns, err := captureInstructions(prog)
	if err != nil {
		return fmt.Errorf("uprobe: %s: cannot verify capture stack safety: read translated instructions: %w", name, err)
	}
	for _, ins := range insns {
		// bpf_insn_prepare_dump translates the internal BPF_TAIL_CALL opcode
		// back into the public helper call, preserving its helper number.
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
			return nil
		}
	}
	return fmt.Errorf("uprobe: %s: cannot verify capture stack safety: translated instructions have no tail call", name)
}

// Replaced only by host tests that cannot query privileged program information.
var captureInstructions = func(prog *ebpf.Program) (asm.Instructions, error) {
	info, err := prog.Info()
	if err != nil {
		return nil, err
	}
	return info.Instructions()
}
