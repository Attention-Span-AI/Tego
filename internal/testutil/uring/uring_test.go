// SPDX-License-Identifier: Apache-2.0

//go:build linux

package uring

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestModesParseAsTheyPrint: uringsock takes a mode by the name String gives it, and refuses another.
func TestModesParseAsTheyPrint(t *testing.T) {
	for _, m := range []Mode{Inline, Async, SQPoll} {
		got, err := ParseMode(m.String())
		if err != nil || got != m {
			t.Errorf("ParseMode(%q) = %v, %v", m.String(), got, err)
		}
	}
	if _, err := ParseMode("poll"); err == nil {
		t.Error("ParseMode accepted a mode it does not have")
	}
}

// TestSocketInEveryMode makes a TCP socket through IORING_OP_SOCKET inline, from an io-wq worker and from the SQ
// thread, where this process has io_uring and the opcode (5.19+); a protocol the kernel lacks completes with its own
// errno in every mode. Unprivileged: SQPOLL needs no capability from 5.11.
func TestSocketInEveryMode(t *testing.T) {
	for _, m := range []Mode{Inline, Async, SQPoll} {
		res, err := SocketMode(m, unix.AF_INET, unix.SOCK_STREAM, 0)
		if errors.Is(err, ErrUnavailable) {
			t.Skipf("no io_uring here: %v", err)
		}
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if res == -int32(unix.EINVAL) {
			t.Skipf("%s: this kernel has no IORING_OP_SOCKET (-EINVAL)", m)
		}
		if res != 0 {
			t.Errorf("%s: a TCP socket completed with %d", m, res)
		}
		if res, err := SocketMode(m, unix.AF_INET, unix.SOCK_STREAM, 253); err != nil || res >= 0 {
			t.Errorf("%s: an unknown protocol completed with %d, %v; want a negative errno", m, res, err)
		}
	}
}

// TestSetsockoptInEveryMode sets TCP_NODELAY on a TCP socket through SOCKET_URING_OP_SETSOCKOPT inline, from an io-wq
// worker and from the SQ thread, where this process has io_uring and the command (6.7+), and reads it back with
// getsockopt(2): the path ADR 0018 (7)'s cgroup/setsockopt has to see, since no seccomp filter does.
func TestSetsockoptInEveryMode(t *testing.T) {
	for _, m := range []Mode{Inline, Async, SQPoll} {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		one := []byte{1, 0, 0, 0}
		res, err := Setsockopt(m, fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, one, len(one))
		if errors.Is(err, ErrUnavailable) {
			_ = unix.Close(fd)
			t.Skipf("no io_uring here: %v", err)
		}
		if err != nil {
			_ = unix.Close(fd)
			t.Fatalf("%s: %v", m, err)
		}
		if res == -int32(unix.EOPNOTSUPP) || res == -int32(unix.EINVAL) {
			_ = unix.Close(fd)
			t.Skipf("%s: this kernel has no SOCKET_URING_OP_SETSOCKOPT (%d)", m, res)
		}
		got, gerr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY)
		_ = unix.Close(fd)
		if res != 0 || gerr != nil || got != 1 {
			t.Errorf("%s: TCP_NODELAY through io_uring completed with %d; read back %d, %v", m, res, got, gerr)
		}
	}
}

// TestSubmissionWaitsThroughSignals: io_uring_enter returns the count it submitted when a signal cuts its wait short,
// with no completion yet, and Go's runtime signals its threads (preemption), so a submission whose completion comes
// from an io-wq worker or the SQ thread read "no completion" now and then (seen in the full unit run under load). The
// first enter here submits and returns at once, as an interrupted wait does, and every mode still returns its
// completion.
func TestSubmissionWaitsThroughSignals(t *testing.T) {
	defer func(was func(int, uintptr, uintptr, uintptr) unix.Errno) { ioURingEnter = was }(ioURingEnter)
	real := ioURingEnter
	for _, m := range []Mode{Inline, Async, SQPoll} {
		cut := 0
		ioURingEnter = func(ring int, toSubmit, minComplete, flags uintptr) unix.Errno {
			if toSubmit > 0 {
				cut++
				return real(ring, toSubmit, 0, flags&^enterGetEvents) // submitted, not waited for
			}
			return real(ring, toSubmit, minComplete, flags)
		}
		res, err := SocketMode(m, unix.AF_INET, unix.SOCK_STREAM, 0)
		if errors.Is(err, ErrUnavailable) {
			t.Skipf("no io_uring here: %v", err)
		}
		if res == -int32(unix.EINVAL) {
			t.Skipf("%s: this kernel has no IORING_OP_SOCKET (-EINVAL)", m)
		}
		if err != nil || res != 0 || cut != 1 {
			t.Errorf("%s: a submission whose wait was cut short: %d, %v (%d submissions)", m, res, err, cut)
		}
	}
}
