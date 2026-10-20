// SPDX-License-Identifier: Apache-2.0

package perf

import (
	"encoding/binary"
	"fmt"
)

// TrueImage is the smallest static ELF executable for goarch that exits 0: one PT_LOAD segment and the three
// instructions of exit(0), no interpreter, no libc and no runtime start-up. The exec check (ADR 0048 P2's K7) execs
// it so that the loop's time is fork, exec and wait, and what the supervisor and the plane add to them.
func TrueImage(goarch string) ([]byte, error) {
	var machine uint16
	var code []byte
	switch goarch {
	case "amd64":
		machine = 62 // EM_X86_64
		code = []byte{
			0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
			0x31, 0xff, // xor edi, edi
			0x0f, 0x05, // syscall
		}
	case "arm64":
		machine = 183                                             // EM_AARCH64
		code = binary.LittleEndian.AppendUint32(nil, 0xd2800ba8)  // mov x8, #93 (exit)
		code = binary.LittleEndian.AppendUint32(code, 0xd2800000) // mov x0, #0
		code = binary.LittleEndian.AppendUint32(code, 0xd4000001) // svc #0
	default:
		return nil, fmt.Errorf("perf: no exit(0) image for %s", goarch)
	}
	const base, ehsize, phsize = 0x400000, 64, 56
	size := uint64(ehsize + phsize + len(code))
	le := binary.LittleEndian
	b := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0} // ELFCLASS64, little endian, version 1
	b = le.AppendUint16(b, 2)                                            // ET_EXEC
	b = le.AppendUint16(b, machine)
	b = le.AppendUint32(b, 1)                  // EV_CURRENT
	b = le.AppendUint64(b, base+ehsize+phsize) // e_entry: the code
	b = le.AppendUint64(b, ehsize)             // e_phoff
	b = le.AppendUint64(b, 0)                  // e_shoff: no sections
	b = le.AppendUint32(b, 0)                  // e_flags
	b = le.AppendUint16(b, ehsize)             // e_ehsize
	b = le.AppendUint16(b, phsize)             // e_phentsize
	b = le.AppendUint16(b, 1)                  // e_phnum
	b = append(b, 0, 0, 0, 0, 0, 0)            // e_shentsize, e_shnum, e_shstrndx
	b = le.AppendUint32(b, 1)                  // PT_LOAD
	b = le.AppendUint32(b, 5)                  // PF_R | PF_X
	b = le.AppendUint64(b, 0)                  // p_offset: the whole file
	b = le.AppendUint64(b, base)               // p_vaddr
	b = le.AppendUint64(b, base)               // p_paddr
	b = le.AppendUint64(b, size)               // p_filesz
	b = le.AppendUint64(b, size)               // p_memsz
	b = le.AppendUint64(b, 0x1000)             // p_align
	return append(b, code...), nil
}
