// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"

	"golang.org/x/sys/unix"
)

// errnoError is a sentinel that errors.Is also matches against one errno, so code that classifies a
// descriptor failure by errno keeps its class when the failure is the owner's (ADR 0023's 2026-10-05 note, A1
// "Errors": enforce-landlock's EBADF reading of a lost held descriptor, the launcher's and the supervisor's
// errno switches).
type errnoError struct {
	msg   string
	errno unix.Errno
}

func (e *errnoError) Error() string { return e.msg }

// Is matches the errno the sentinel stands for.
func (e *errnoError) Is(target error) bool { return target == e.errno }

var (
	// ErrClosed is a lend, give or dup of an FD that owns no open number any more: zero, nil, closed,
	// closing, released or abandoned. It matches unix.EBADF.
	ErrClosed error = &errnoError{"sys: descriptor owner is closed", unix.EBADF}

	// ErrLeased is a CloseNow, a strict Close or a Release while a lease is out. Nothing changed; the number
	// is still open. It matches unix.EBUSY.
	ErrLeased error = &errnoError{"sys: descriptor is leased", unix.EBUSY}

	// ErrStdio is a constructor given 0, 1 or 2. The Go runtime reopens a closed standard descriptor on
	// /dev/null before main, so a fresh descriptor is never one of them: a 0 here was not a descriptor (a
	// syscall that answers 0 for success), and owning it would close the process's stdin. Stdio is the one
	// way to own them.
	ErrStdio = errors.New("sys: 0, 1 and 2 are the standard descriptors, owned only through sys.Stdio")

	// ErrNotStrict is Flock on an FD that was not made strict at birth: a lock whose close a lease could
	// defer would stay held past the Close that was meant to drop it.
	ErrNotStrict = errors.New("sys: a lock descriptor must be strict (sys.Strict at birth)")

	// ErrSealed is Inherited or CloseInheritedFrom after this process made any other owner: a number inherited
	// at exec is owned, or swept, before anything else runs, or never, so a second owner of a live number cannot
	// be minted later and a sweep cannot close a number a live owner holds.
	ErrSealed = errors.New("sys: Inherited or CloseInheritedFrom after this process made another owner")

	// ErrKind is Inherited given a number that is not open or is not the kind its caller expects.
	ErrKind = errors.New("sys: inherited descriptor is not the expected kind")

	// ErrNotCloexec is a fresh number without FD_CLOEXEC, refused by a tegotesthooks build's Own and
	// OwnSyscall as the second line behind the lint's static close-on-exec rule.
	ErrNotCloexec = errors.New("sys: fresh descriptor without FD_CLOEXEC")

	errHookSet = errors.New("sys: OnClosed: a close hook is already registered")
)
