// SPDX-License-Identifier: Apache-2.0

package bpf

import "structs"

// BindResultEvent is the actual original-task bind syscall outcome. A zero
// Flags value intentionally supplies no kernel name or policy proof.
type BindResultEvent struct {
	_       structs.HostLayout
	Hdr     Header
	StartNS uint64
	Ret     int64
	Dev     uint64
	DirIno  uint64
	RuleIdx uint32
	Flags   uint32
	NameLen uint32
	Name    [108]byte
}
