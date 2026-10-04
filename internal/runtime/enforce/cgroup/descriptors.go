// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"

	"golang.org/x/sys/unix"
)

// StartDescriptorReservation overlaps optional descriptor-table growth with
// the CLI's compilation and backend selection. It opens no BPF object or build
// lock. The caller keeps held open until it joins the returned completion
// function on every exit. The borrowed descriptor is never closed here; using
// an existing CLI stream avoids consuming a plan's descriptor budget while the
// reservation waits. Nil held skips the optimization. The kernel loader retains
// its synchronous reservation as a barrier and fallback.
func StartDescriptorReservation(held *os.File) func() {
	if held == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		reserveBPFDescriptors(held)
		close(done)
	}()
	return func() { <-done }
}

// reserveBPFDescriptors grows the launcher's descriptor table once before it
// opens the build's maps, programs and links. Growing a table shared by Go's
// threads waits for an RCU grace period on Linux: crossing 64 then 128 descriptors
// added two 20–50 ms pauses to warm starts in the kernel matrix.
//
// Requesting descriptor 128 grows a smaller table to at least 256 slots on
// Linux. Unlike requesting the last slot, concurrent reservations can both fit
// in that table without forcing another expansion.
// F_DUPFD_CLOEXEC chooses a free descriptor; it never replaces one the launcher
// already owns. Closing only the duplicate retains both the enlarged table and
// the original build lock. A restrictive fd limit or another reservation failure
// merely leaves the kernel to grow the table normally.
func reserveBPFDescriptors(held *os.File) {
	if held == nil {
		return
	}
	raw, err := held.SyscallConn()
	if err != nil {
		return
	}
	// Control keeps the borrowed descriptor valid through duplication without
	// File.Fd changing a Go pipe's blocking mode or deadline behavior.
	_ = raw.Control(func(source uintptr) {
		fd, err := unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 128)
		if err == nil {
			_ = unix.Close(fd)
		}
	})
}
