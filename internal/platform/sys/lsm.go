// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LSMListModules returns the complete active LSM IDs (Linux 6.8+). It does not
// infer inactivity from a denied syscall or a masked securityfs mount.
func LSMListModules() ([]uint64, error) {
	var ids [64]uint64
	size := uint32(len(ids) * 8)
	n, _, errno := unix.Syscall(unix.SYS_LSM_LIST_MODULES, uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("lsm_list_modules: %w", errno)
	}
	if n == 0 || n > uintptr(len(ids)) || size != uint32(n)*8 {
		return nil, fmt.Errorf("invalid LSM list size: count=%d bytes=%d", n, size)
	}
	return ids[:n], nil
}
