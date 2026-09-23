// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetChildSubreaper marks the calling process as a child subreaper (prctl PR_SET_CHILD_SUBREAPER, Linux
// 3.4): orphaned descendants are re-parented to it instead of init, which keeps daemonized agent processes
// inside the run's Yama descendant set.
func SetChildSubreaper(on bool) error {
	return prctl("PR_SET_CHILD_SUBREAPER", unix.PR_SET_CHILD_SUBREAPER, boolArg(on))
}

// SetPdeathsig arms the parent-death signal of the calling thread (prctl PR_SET_PDEATHSIG). The signal is
// delivered when the thread that created this process exits, and the kernel clears it on every credential
// change (commit_creds), so it must be armed after the last uid or capability change.
func SetPdeathsig(sig syscall.Signal) error {
	return prctl("PR_SET_PDEATHSIG", unix.PR_SET_PDEATHSIG, uintptr(sig))
}

// SetNoNewPrivs sets the calling thread's no_new_privs bit (prctl PR_SET_NO_NEW_PRIVS, Linux 3.5). The bit
// is inherited across fork and execve and can never be cleared.
func SetNoNewPrivs() error {
	return prctl("PR_SET_NO_NEW_PRIVS", unix.PR_SET_NO_NEW_PRIVS, 1)
}

// NoNewPrivs reports the calling thread's no_new_privs bit (prctl PR_GET_NO_NEW_PRIVS).
func NoNewPrivs() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return false, fmt.Errorf("prctl(PR_GET_NO_NEW_PRIVS): %w", err)
	}
	return v == 1, nil
}

// SetDumpable sets the process dumpable flag (prctl PR_SET_DUMPABLE). pidfd_getfd refuses non-dumpable
// targets without CAP_SYS_PTRACE, and a capability drop resets the flag, so the child stage sets it to 1
// after dropping capabilities and before publishing its notify fd.
func SetDumpable(on bool) error {
	return prctl("PR_SET_DUMPABLE", unix.PR_SET_DUMPABLE, boolArg(on))
}

// Dumpable reports the process dumpable flag (prctl PR_GET_DUMPABLE): true only for SUID_DUMP_USER (1).
func Dumpable() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return false, fmt.Errorf("prctl(PR_GET_DUMPABLE): %w", err)
	}
	return v == 1, nil
}

// ClearAmbientCapabilities empties the calling thread's ambient capability set
// (prctl PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, Linux 4.3).
func ClearAmbientCapabilities() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL): %w", err)
	}
	return nil
}

func prctl(name string, option int, arg2 uintptr) error {
	if err := unix.Prctl(option, arg2, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(%s, %d): %w", name, arg2, err)
	}
	return nil
}

func boolArg(on bool) uintptr {
	if on {
		return 1
	}
	return 0
}
