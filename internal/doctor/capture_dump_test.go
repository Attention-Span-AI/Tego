// SPDX-License-Identifier: Apache-2.0

//go:build linux && (386 || amd64 || arm64)

package doctor

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// marshalCaptureInstructions exports a translated Linux stream, not a loadable
// program. The kernel can leave relative helper offsets in builtin calls. The
// assembler treats their high bits as platform tags and rejects some translated
// offsets. Preserve the full immediate and offset for these calls. Let the
// assembler handle other instruction forms, including double-wide loads, without
// resolving ELF references or replacing map identifiers. This is only used by
// test dumps.
func marshalCaptureInstructions(insns asm.Instructions) ([]byte, error) {
	var raw bytes.Buffer
	for i, ins := range insns {
		if ins.IsBuiltinCall() {
			// IsBuiltinCall requires both register fields to be zero.
			call := [asm.InstructionSize]byte{byte(ins.OpCode)}
			binary.LittleEndian.PutUint16(call[2:4], uint16(ins.Offset))
			binary.LittleEndian.PutUint32(call[4:8], uint32(ins.Constant))
			if _, err := raw.Write(call[:]); err != nil {
				return nil, err
			}
		} else if _, err := ins.Marshal(&raw, binary.LittleEndian); err != nil {
			return nil, fmt.Errorf("instruction %d: %w", i, err)
		}
	}
	return raw.Bytes(), nil
}
