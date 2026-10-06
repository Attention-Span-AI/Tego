// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// procSelfFD is the directory the walks below list; a test points it at one that cannot be read.
var procSelfFD = "/proc/self/fd"

// closeRangeCloexec is close_range(first, ~0, CLOSE_RANGE_CLOEXEC) (Linux 5.11), a variable so a test can
// present a seccomp profile that refuses it.
var closeRangeCloexec = func(first int) error {
	return unix.CloseRange(uint(first), math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC)
}

// CloexecFrom sets FD_CLOEXEC on every descriptor from first up, so an execve keeps only those below it
// (ADR 0023 T1.3; launch's child stage keeps 0–2 for the agent, runtime-launch invariant 4a). close_range
// with CLOSE_RANGE_CLOEXEC does it in one call; where a seccomp profile around tego refuses that, the
// /proc/self/fd listing is walked instead, and a descriptor gone by the time it is reached (the listing's own)
// is not an error. When both fail it returns the error, and the caller fails closed: an inherited descriptor
// is access no Landlock rule can take back. Nothing is closed.
func CloexecFrom(first int) error {
	crErr := closeRangeCloexec(first)
	if crErr == nil {
		return nil
	}
	entries, err := os.ReadDir(procSelfFD)
	if err != nil {
		return fmt.Errorf("close_range(%d, ~0, CLOSE_RANGE_CLOEXEC): %v, and %s unreadable: %w", first, crErr, procSelfFD, err)
	}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < first {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(n), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("fcntl(%d, F_SETFD, FD_CLOEXEC): %w", n, err)
		}
	}
	return nil
}

// CloseInheritedFrom closes every descriptor from first up, keeping the Go runtime's own poller (its
// eventpoll and eventfd), which a blind close_range would close under the runtime: the reaper's start-up
// sweep, which makes its descriptor set exactly what its launcher passed on purpose whatever its parent was
// (ADR 0020 (2), ADR 0023's reaper). It must run before this process opens anything of its own from first up,
// since it cannot tell such a descriptor from a stray one; ReapMain calls it first. It returns an error when
// /proc/self/fd cannot be listed, where the sweep used to return silently: the reaper then exits 125 and
// starts no sweep. Like Inherited it is sealed (ADR 0023 A10): once this process has made an owner other than
// through Inherited or Stdio it answers ErrSealed and closes nothing, since the sweep would close numbers live
// owners hold, which they would then close again after the numbers were reused. fdcheck admits its calls only
// at the sites tools/fdcheck/sweep.txt lists.
func CloseInheritedFrom(first int) error {
	if ownersMade.Load() {
		return fmt.Errorf("close inherited descriptors from %d: %w", first, ErrSealed)
	}
	entries, err := os.ReadDir(procSelfFD)
	if err != nil {
		return fmt.Errorf("list %s to close inherited descriptors from %d: %w", procSelfFD, first, err)
	}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < first {
			continue
		}
		link, err := os.Readlink(filepath.Join(procSelfFD, e.Name()))
		if err != nil {
			continue // the listing's own descriptor, closed by now
		}
		if link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
			continue
		}
		_ = closeNumber(n) // freed whatever close(2) answers; no owner exists for it in this process
	}
	return nil
}
