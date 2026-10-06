// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The helpers below replace (*os.File).Fd, which hands out an *os.File's number with no lease: the File's
// own cleanup may close it under the caller, the class ADR 0023 A4 names. Each runs under the
// standard library's own lease, (*os.File).SyscallConn's Control, which holds the File's descriptor open for
// the call and fails once the File is closed.

// FileDo runs fn with f's number under the standard library's lease, for the rare call no typed helper
// covers. fn must not keep the number past its return.
func FileDo(f *os.File, fn func(n int) error) error {
	if f == nil {
		return ErrClosed
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

// DupFile duplicates f's number into a new owner at min or above (F_DUPFD_CLOEXEC), as the cgroup tier's
// descriptor-table reservation does at 128 (ADR 0023 T2.3).
func DupFile(f *os.File, min int) (*FD, error) {
	var n int
	if err := FileDo(f, func(fd int) error {
		var err error
		n, err = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, min)
		if err != nil {
			return fmt.Errorf("fcntl(%d, F_DUPFD_CLOEXEC, %d): %w", fd, min, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	seal()
	return newFD(n, 0, true)
}

// Flock is flock(2) on f under the standard library's lease, restarted on EINTR. The lock lives as long as
// the open file description, so f is closed by its holder exactly when the lock is meant to drop.
func Flock(f *os.File, how int) error {
	return FileDo(f, func(fd int) error {
		for {
			err := unix.Flock(fd, how)
			if err != unix.EINTR {
				return err
			}
		}
	})
}

// FstatFile is fstat(2) on f under the standard library's lease.
func FstatFile(f *os.File, st *unix.Stat_t) error {
	return FileDo(f, func(fd int) error { return unix.Fstat(fd, st) })
}
