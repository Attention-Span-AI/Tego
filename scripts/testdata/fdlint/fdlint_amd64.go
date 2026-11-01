// SPDX-License-Identifier: Apache-2.0

package fdlint

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// The primitives only amd64 has: syscall.Dup2 and SYS_DUP2 (arm64's kernel has dup3 alone).
func amd64Only(fd int) {
	_ = syscall.Dup2(fd, 9)                                  // want ADR 0023
	_, _, _ = unix.Syscall(unix.SYS_DUP2, uintptr(fd), 9, 0) // want ADR 0023
}
