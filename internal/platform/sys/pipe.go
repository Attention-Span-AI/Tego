// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// The producers below return two numbers, or a number and an address, so they have owner forms of their own
// (ADR 0023 A10 F1): Own takes one number.

// Pipe2 is pipe2(2), both ends born owners. flags must carry O_CLOEXEC. The write end is strict: a peer waits
// for its EOF, so its Close must never be deferred by a lease (A1).
func Pipe2(flags int) (r, w *FD, err error) {
	var p [2]int
	if err := unix.Pipe2(p[:], flags); err != nil {
		return nil, nil, fmt.Errorf("pipe2(%#x): %w", flags, err)
	}
	seal()
	return pair(p, stStrict)
}

// Socketpair is socketpair(2), both ends born owners. typ must carry SOCK_CLOEXEC.
func Socketpair(domain, typ, proto int) (a, b *FD, err error) {
	p, err := unix.Socketpair(domain, typ, proto)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair(%d, %#x, %d): %w", domain, typ, proto, err)
	}
	seal()
	return pair(p, 0)
}

// pair owns two fresh numbers, the second with secondFlags; on a refusal neither stays open.
func pair(p [2]int, secondFlags uint64) (*FD, *FD, error) {
	a, err := newFD(p[0], 0, true)
	if err != nil {
		_ = closeNumber(p[1])
		return nil, nil, err
	}
	b, err := newFD(p[1], secondFlags, true)
	if err != nil {
		_ = a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

// Accept4 is accept4(2) on the listening socket ln, the accepted connection born an owner. flags must carry
// SOCK_CLOEXEC. ln is leased for the call, which may block: a Close of ln meanwhile is deferred until the
// accept returns, so a blocking accept needs a wake path of its own (ADR 0023, residual "Long blocks").
func Accept4(ln *FD, flags int) (*FD, unix.Sockaddr, error) {
	if ln == nil || !ln.acquire() {
		return nil, nil, ErrClosed
	}
	defer ln.unlease()
	n, sa, err := unix.Accept4(int(ln.num), flags)
	if err != nil {
		return nil, nil, err
	}
	seal()
	f, err := newFD(n, 0, true)
	if err != nil {
		return nil, nil, err
	}
	return f, sa, nil
}
