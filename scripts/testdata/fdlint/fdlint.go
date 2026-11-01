// SPDX-License-Identifier: Apache-2.0

// Package fdlint is scripts/check-fd_test.sh's golangci-lint fixture (ADR 0023 C3): every primitive ADR 0023 A4
// forbids, once each, on a line marked "want ADR 0023", so the test can hold .golangci.yml's forbidigo rules to
// one report per primitive. It is under testdata, so `./...` never builds, vets or lints it, and fdcheck skips
// it; no binary links it (fdcheck F11).
package fdlint

import (
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	u "golang.org/x/sys/unix"
)

// Closes and dups by call, by value and through an aliased import.
func closesAndDups(fd int) {
	_ = u.Close(fd)                  // want ADR 0023
	_ = syscall.Close(fd)            // want ADR 0023
	_, _ = u.Dup(fd)                 // want ADR 0023
	_, _ = syscall.Dup(fd)           // want ADR 0023
	_ = u.Dup2(fd, 9)                // want ADR 0023
	_ = u.Dup3(fd, 9, 0)             // want ADR 0023
	_ = syscall.Dup3(fd, 9, 0)       // want ADR 0023
	_ = u.CloseRange(3, ^uint(0), 0) // want ADR 0023
	closer := u.Close                // want ADR 0023
	_ = closer
}

// The raw syscall numbers and the fcntl dup commands.
func rawNumbers(fd int) {
	_, _, _ = u.Syscall(u.SYS_CLOSE, uintptr(fd), 0, 0)             // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_CLOSE_RANGE, 3, 9, 0)                 // want ADR 0023
	_, _, _ = syscall.Syscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0) // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_DUP, uintptr(fd), 0, 0)               // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_DUP3, uintptr(fd), 9, 0)              // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_IO_URING_SETUP, 8, 0, 0)              // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_IO_URING_ENTER, 0, 0, 0)              // want ADR 0023
	_, _, _ = u.Syscall(u.SYS_IO_URING_REGISTER, 0, 0, 0)           // want ADR 0023
	_, _ = u.FcntlInt(uintptr(fd), u.F_DUPFD, 0)                    // want ADR 0023
	_, _ = u.FcntlInt(uintptr(fd), u.F_DUPFD_CLOEXEC, 0)            // want ADR 0023
	_, _ = u.FcntlInt(uintptr(fd), syscall.F_DUPFD_CLOEXEC, 0)      // want ADR 0023
}

// Wrapping and borrowing.
func wraps(fd int, oob []byte, f *os.File) {
	_ = os.NewFile(uintptr(fd), "x") // want ADR 0023
	_ = f.Fd()                       // want ADR 0023
	fdOf := (*os.File).Fd            // want ADR 0023
	_ = fdOf
	if msgs, err := u.ParseSocketControlMessage(oob); err == nil && len(msgs) > 0 { // want ADR 0023
		_, _ = u.ParseUnixRights(&msgs[0])  // want ADR 0023
		_, _ = syscall.ParseUnixRights(nil) // want ADR 0023
	}
	_, _ = syscall.ParseSocketControlMessage(oob)    // want ADR 0023
	_, _, _, _ = u.ParseOneSocketControlMessage(oob) // want ADR 0023
	_ = u.SCM_RIGHTS                                 // want ADR 0023
}

// cilium: the ownership-taking constructors and the unleased borrows.
func cilium(fd int, p *ebpf.Program, m *ebpf.Map) {
	_, _ = link.NewFromFD(fd)        // want ADR 0023
	_, _ = ebpf.NewMapFromFD(fd)     // want ADR 0023
	_, _ = ebpf.NewProgramFromFD(fd) // want ADR 0023
	_ = p.FD()                       // want ADR 0023
	_ = m.FD()                       // want ADR 0023
}

// Not forbidden: the producers and the allowed fcntl commands are fdcheck's, not forbidigo's.
func allowed(fd int) {
	_, _ = u.FcntlInt(uintptr(fd), u.F_GETFD, 0)
	_, _ = u.Open("/", u.O_RDONLY|u.O_CLOEXEC, 0)
}
