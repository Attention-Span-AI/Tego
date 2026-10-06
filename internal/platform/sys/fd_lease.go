// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"sync/atomic"
	"syscall"
)

// Lender is what an API that lends a descriptor across packages, off the hot path, returns (ADR 0023 A11):
// the borrower gets a lease, never the ownership. *FD satisfies it. A hot seam, one a per-notification or
// per-event path calls, returns the concrete *FD instead, whose Borrow allocates nothing; through an
// interface the compiler cannot see through, a Borrow whose closure captures locals allocates.
type Lender interface {
	Borrow(fn func(n int) error) error
	Hold() (*Lease, error)
}

// Owned is a Lender its holder may also close. *FD satisfies it.
type Owned interface {
	Lender
	Close() error
	CloseNow() error
}

// Lease is a lease taken by Hold, for a loop's lifetime: the number stays open, and names this FD's file,
// until Return. A Lease is used in one of two forms only (ADR 0023 A10 F2): scoped, with `defer l.Return()`
// right after the Hold, or handed to a goroutine whose function's first statement is `defer l.Return()`. It
// is never stored in a struct field, a global or a channel.
type Lease struct {
	fd       *FD
	num      int
	returned atomic.Bool
}

// Hold takes a lease for a loop's lifetime, or is ErrClosed when the FD lends nothing. Prefer Borrow, whose
// lease cannot outlive its call; there is no public unpaired Borrow and Return.
func (f *FD) Hold() (*Lease, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	f.holds.Add(1)
	l := &Lease{fd: f, num: int(f.num)}
	if testHooks != nil {
		testHooks.held(l)
	}
	return l, nil
}

// Num is the lent number while the lease is out, and -1 after Return; a tegotesthooks build panics on the
// latter, since a number read past its lease may name any file.
func (l *Lease) Num() int {
	if l == nil || l.returned.Load() {
		if testHooks != nil {
			testHooks.numAfterReturn()
		}
		return -1
	}
	return l.num
}

// Return ends the lease. It is idempotent: a second Return never ends another holder's lease. The last lease
// back after a Close performs the deferred close(2).
func (l *Lease) Return() {
	if l == nil || !l.returned.CompareAndSwap(false, true) {
		return
	}
	if testHooks != nil {
		testHooks.returned(l)
	}
	l.fd.unlease()
}

// HoldsForTest is the number of Holds this FD has granted, for the pins that count leases per Run and per
// loop (ADR 0023 P4). Tests and tegotesthooks files only.
func (f *FD) HoldsForTest() int {
	if f == nil {
		return 0
	}
	return int(f.holds.Load())
}

// CloneIntoCgroup runs start, a process start that clones into the cgroup whose directory dir lends
// (clone3's CLONE_INTO_CGROUP through attr's UseCgroupFD and CgroupFD), with the number under a lease for
// the start alone: a Close meanwhile is deferred, so clone3 never reads a number that was closed and reused
// (ADR 0023 T2.3, "the cgroup fd is borrowed across proc.Start"). start must make the clone before it returns
// and keep nothing of attr's number. On return CgroupFD is -1 and UseCgroupFD stays set, so attr keeps no
// number past the lease and a second start with it fails (EBADF) rather than reaching another file. A nil
// attr is an error and a lender that lends nothing (nil, closed) is ErrClosed; either way start is not run.
func CloneIntoCgroup(dir Lender, attr *syscall.SysProcAttr, start func() error) error {
	if attr == nil {
		return errors.New("sys: CloneIntoCgroup: nil SysProcAttr")
	}
	if dir == nil {
		return ErrClosed
	}
	return dir.Borrow(func(n int) error {
		attr.UseCgroupFD, attr.CgroupFD = true, n
		defer func() { attr.CgroupFD = -1 }()
		return start()
	})
}
