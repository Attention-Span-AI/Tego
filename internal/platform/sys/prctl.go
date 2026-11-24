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

// SeccompMode is the calling thread's seccomp mode (prctl PR_GET_SECCOMP): 0 with no filter, 2 with one. A thread
// in strict mode (1) is killed by the call itself, as by any system call strict mode does not list.
func SeccompMode() (int, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("prctl(PR_GET_SECCOMP): %w", err)
	}
	return v, nil
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

// MakeUndumpable sets the process dumpable flag to 0 and reads it back: the flag a process that holds a secret sets
// before the secret enters its memory (ADR 0126, "Amendment 2026-11-21: the secret-holding launcher is not
// dumpable"). While it is 0, /proc/<pid>/{mem,environ,fd,fdinfo,maps,exe,cwd,root,ns/*} refuse every reader that has
// no CAP_SYS_PTRACE, and so does ptrace, process_vm_readv and pidfd_getfd, whichever Yama's ptrace_scope. An error is
// a process that could not be made so, or whose flag the read-back still shows set: the caller refuses to go on, since
// it must not take the secret into a memory another process of the same user can read.
//
// The flag is the process's, not the thread's, and is not inherited as 0 by what the process execs: an exec of a
// readable binary with unchanged credentials sets it to 1 again, so a child of this process is dumpable until it makes
// itself otherwise. A change of the effective or filesystem ids, or a capability set that is not a subset of the old
// one, resets it to fs.suid_dumpable (commit_creds), which is 1 on a host that set the sysctl so: a process that
// changes its credentials after this call, or that must hold the flag whatever it did, calls this again before it takes
// the next secret.
func MakeUndumpable() error {
	if err := SetDumpable(false); err != nil {
		return err
	}
	on, err := Dumpable()
	if err != nil {
		return err
	}
	if on {
		return fmt.Errorf("PR_GET_DUMPABLE is still 1 after PR_SET_DUMPABLE 0")
	}
	return nil
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
