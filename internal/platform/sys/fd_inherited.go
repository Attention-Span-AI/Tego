// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kind is what an inherited number must be for Inherited to own it.
type Kind int

// The kinds Inherited checks, each without /proc.
const (
	KindDir     Kind = iota + 1 // fstat S_IFDIR
	KindSocket                  // fstat S_IFSOCK
	KindFIFO                    // fstat S_IFIFO
	KindRegular                 // fstat S_IFREG, and not a pidfd
	KindPidfd                   // pidfd_send_signal(n, 0) answers 0, ESRCH or EPERM
	KindRuleset                 // landlock_add_rule with no access answers ENOMSG
)

// String names the kind as Inherited's errors do.
func (k Kind) String() string {
	switch k {
	case KindDir:
		return "dir"
	case KindSocket:
		return "socket"
	case KindFIFO:
		return "fifo"
	case KindRegular:
		return "regular"
	case KindPidfd:
		return "pidfd"
	case KindRuleset:
		return "ruleset"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// Inherited owns a number this process received at exec on purpose (the child stage's control, report and
// ruleset numbers; the reaper's pidfd and directories), named name in errors. Three run-time checks (ADR 0023
// A10 F1):
//   - Range: 0–2 are refused (ErrStdio).
//   - The seal: once this process has made any other owner (Own, OwnSyscall, Adopt, Dup or a helper),
//     Inherited is ErrSealed. Its calls are the process's first descriptor operations, so a second owner of
//     a live number cannot be minted later.
//   - Kind: the number must be open and be kind (ErrKind otherwise), so a number that is open only because
//     some other file took it is not owned as what the caller expects.
//
// A refused number is left open.
func Inherited(n int, kind Kind, name string) (*FD, error) {
	if n >= 0 && n <= 2 {
		return nil, fmt.Errorf("inherited %s at %d: %w", name, n, ErrStdio)
	}
	if ownersMade.Load() {
		return nil, fmt.Errorf("inherited %s at %d: %w", name, n, ErrSealed)
	}
	if err := checkKind(n, kind); err != nil {
		return nil, fmt.Errorf("inherited %s at %d: %w: %w", name, n, ErrKind, err)
	}
	return newFD(n, 0, false)
}

// checkKind answers nil when n is open and is kind.
func checkKind(n int, kind Kind) error {
	switch kind {
	case KindPidfd:
		err := unix.PidfdSendSignal(n, 0, nil, 0)
		if err == nil || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EPERM) {
			return nil
		}
		return fmt.Errorf("pidfd_send_signal(%d, 0): %w, want a pidfd", n, err)
	case KindRuleset:
		attr := unix.LandlockPathBeneathAttr{Parent_fd: -1}
		err := LandlockAddRule(n, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&attr), 0)
		if errors.Is(err, unix.ENOMSG) {
			return nil
		}
		return fmt.Errorf("landlock_add_rule(%d) with no access: %w, want ENOMSG from a ruleset", n, err)
	}
	var want uint32
	switch kind {
	case KindDir:
		want = unix.S_IFDIR
	case KindSocket:
		want = unix.S_IFSOCK
	case KindFIFO:
		want = unix.S_IFIFO
	case KindRegular:
		want = unix.S_IFREG
	default:
		return fmt.Errorf("unknown kind %v", kind)
	}
	var st unix.Stat_t
	if err := unix.Fstat(n, &st); err != nil {
		return fmt.Errorf("fstat(%d): %w", n, err)
	}
	if st.Mode&unix.S_IFMT != want {
		return fmt.Errorf("fstat(%d): mode %#o, want %v", n, st.Mode&unix.S_IFMT, kind)
	}
	if kind == KindRegular {
		// pidfs (Linux 6.9) gives a pidfd a regular-file mode; a regular file answers EBADF here.
		if err := unix.PidfdSendSignal(n, 0, nil, 0); !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("fd %d is a pidfd, not a regular file", n)
		}
	}
	return nil
}
