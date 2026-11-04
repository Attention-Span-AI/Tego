// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package uring is the smallest io_uring client the tests need: one ring, one submission, one completion, over raw
// syscalls. It exists to make the kernel paths a seccomp filter cannot see (io_uring's IORING_OP_SOCKET, BIND and
// LISTEN) from a test or a workload, so the decision plane's socket_create (ADR 0018 (5), TIER3-PLAN T13) and its
// listener hooks and their records (enforce-plane §2.20) can be checked on them. It is not tego's; nothing in tego
// submits to a ring.
package uring

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Opcodes and constants of include/uapi/linux/io_uring.h, stable ABI.
const (
	opSetxattr = 42 // IORING_OP_SETXATTR, 5.19+
	opSocket   = 45 // IORING_OP_SOCKET, 5.19+
	opBind     = 56 // IORING_OP_BIND, 6.11+
	opListen   = 57 // IORING_OP_LISTEN, 6.11+

	offSQRing = 0
	offCQRing = 0x8000000
	offSQEs   = 0x10000000

	enterGetEvents   = 1 << 0 // IORING_ENTER_GETEVENTS
	enterSQWakeup    = 1 << 1 // IORING_ENTER_SQ_WAKEUP
	featSingleMmap   = 1 << 0 // IORING_FEAT_SINGLE_MMAP
	setupSQPoll      = 1 << 1 // IORING_SETUP_SQPOLL
	sqeAsync         = 1 << 4 // IOSQE_ASYNC
	sqeSize, cqeSize = 64, 16

	registerPersonality = 9 // IORING_REGISTER_PERSONALITY, 5.6+
)

// Mode is which task of the process carries out a submission. The kernel decides a socket made through each the same
// way, in the process's cgroup, but they are three paths to __sock_create: the submitting thread itself, an io-wq
// worker and the SQPOLL thread are each an io thread of the process.
type Mode int

const (
	// Inline is an ordinary submission: io_uring_enter issues it on the calling thread.
	Inline Mode = iota
	// Async sets IOSQE_ASYNC, which punts the entry to an io-wq worker (iou-wrk) without trying it inline.
	Async
	// SQPoll sets the ring up with IORING_SETUP_SQPOLL, so the kernel's SQ thread (iou-sqp) reads and issues the entry;
	// the caller's io_uring_enter only wakes it and waits. Unprivileged from 5.11.
	SQPoll
)

// String names the mode as uringsock takes it.
func (m Mode) String() string {
	switch m {
	case Inline:
		return "inline"
	case Async:
		return "async"
	case SQPoll:
		return "sqpoll"
	}
	return "mode " + strconv.Itoa(int(m))
}

// ParseMode is String's inverse.
func ParseMode(s string) (Mode, error) {
	for _, m := range []Mode{Inline, Async, SQPoll} {
		if m.String() == s {
			return m, nil
		}
	}
	return Inline, fmt.Errorf("uring: no mode %q (inline, async, sqpoll)", s)
}

type sqRingOffsets struct {
	Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
	UserAddr                                                        uint64
}

type cqRingOffsets struct {
	Head, Tail, RingMask, RingEntries, Overflow, Cqes, Flags, Resv1 uint32
	UserAddr                                                        uint64
}

type params struct {
	SqEntries, CqEntries, Flags, SqThreadCPU, SqThreadIdle, Features, WqFd uint32
	Resv                                                                   [3]uint32
	SqOff                                                                  sqRingOffsets
	CqOff                                                                  cqRingOffsets
}

// ErrUnavailable is a kernel that offers no io_uring to this process: the syscall is refused (ENOSYS, a seccomp
// filter's answer, or EPERM, kernel.io_uring_disabled) or the ring cannot be mapped.
var ErrUnavailable = errors.New("uring: io_uring is not available")

// Socket submits one IORING_OP_SOCKET for (family, typ, proto) and returns the completion's result: a descriptor,
// which it closes, reported as 0, or the negative errno the kernel completed it with. err is ErrUnavailable, or
// another failure to set the ring up or submit; a kernel without the opcode completes it with -EINVAL.
func Socket(family, typ, proto int) (res int32, err error) {
	return SocketMode(Inline, family, typ, proto)
}

// SocketMode is Socket submitted in mode.
func SocketMode(mode Mode, family, typ, proto int) (res int32, err error) {
	res, err = submitMode(mode, func(sqe []byte) {
		sqe[0] = opSocket
		*(*int32)(unsafe.Pointer(&sqe[4])) = int32(family) // fd: the domain
		*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(typ)  // off: the type
		*(*uint32)(unsafe.Pointer(&sqe[24])) = uint32(proto)
	}, nil)
	if err == nil && res >= 0 {
		_ = unix.Close(int(res))
		res = 0
	}
	return res, err
}

// Bind submits one IORING_OP_BIND of the socket fd to the raw sockaddr bytes addr (the family first, as the kernel
// copies them) and returns the completion's result: 0 or a negative errno; a kernel without the opcode completes it
// with -EINVAL. The bind runs on the calling thread (inline submission), so a caller that needs one task for a
// sequence of operations locks its OS thread.
func Bind(fd int, addr []byte) (int32, error) {
	if len(addr) == 0 {
		return 0, errors.New("uring: empty address")
	}
	return submit(func(sqe []byte) {
		sqe[0] = opBind
		*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fd)
		*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(len(addr))                          // addr2: the length
		*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(&addr[0]))) // addr: the address
	}, addr)
}

// Listen submits one IORING_OP_LISTEN on the socket fd with backlog and returns the completion's result, as Bind.
func Listen(fd, backlog int) (int32, error) {
	return submit(func(sqe []byte) {
		sqe[0] = opListen
		*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fd)
		*(*uint32)(unsafe.Pointer(&sqe[24])) = uint32(backlog) // len: the backlog
	}, nil)
}

// opURingCmd and socketURingOpSetsockopt are IORING_OP_URING_CMD (5.19+) and its socket command
// SOCKET_URING_OP_SETSOCKOPT (6.7+, io_uring/cmd_net.c), which reaches do_sock_setsockopt with no setsockopt(2) a
// seccomp filter could see.
const (
	opURingCmd              = 46
	socketURingOpSetsockopt = 3
)

// Setsockopt submits one SOCKET_URING_OP_SETSOCKOPT on the socket fd, in mode, setting (level, optname) to optval with
// optlen (which may differ from len(optval), as setsockopt(2)'s may), and returns the completion's result: 0 or a
// negative errno. A kernel without the socket command completes it with -EOPNOTSUPP, one without the opcode with
// -EINVAL.
func Setsockopt(mode Mode, fd, level, optname int, optval []byte, optlen int) (int32, error) {
	if len(optval) == 0 {
		return 0, errors.New("uring: empty option value")
	}
	return submitMode(mode, func(sqe []byte) {
		sqe[0] = opURingCmd
		*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fd)
		*(*uint32)(unsafe.Pointer(&sqe[8])) = socketURingOpSetsockopt // cmd_op
		*(*uint32)(unsafe.Pointer(&sqe[16])) = uint32(level)
		*(*uint32)(unsafe.Pointer(&sqe[20])) = uint32(optname)
		*(*uint32)(unsafe.Pointer(&sqe[44])) = uint32(optlen)
		*(*uint64)(unsafe.Pointer(&sqe[48])) = uint64(uintptr(unsafe.Pointer(&optval[0]))) // optval
	}, optval)
}

// ioURingEnter is io_uring_enter(2) with no signal mask; a variable so a test can cut its wait short as a signal does.
var ioURingEnter = func(ring int, toSubmit, minComplete, flags uintptr) unix.Errno {
	_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(ring), toSubmit, minComplete, flags, 0, 0)
	return errno
}

// SetxattrPersonality submits one IORING_OP_SETXATTR of name=value on path under a registered personality: the ring
// registers the calling thread's credentials (IORING_REGISTER_PERSONALITY), change replaces that thread's (any
// commit_creds), and the entry names the registered ones, so the kernel issues it under override_creds with
// credentials userspace chose (security_uring_override_creds). The entry always goes to an io-wq worker. The decision
// plane's capability floor must not take that for a filesystem's own backing override (ADR 0055). It returns the
// completion's result, 0 or a negative errno.
func SetxattrPersonality(path, name string, value []byte, change func() error) (int32, error) {
	if len(value) == 0 {
		return 0, errors.New("uring: empty xattr value")
	}
	buf := make([]byte, 0, len(path)+len(name)+len(value)+2)
	buf = append(append(append(append(append(buf, path...), 0), name...), 0), value...)
	at := func(off int) uint64 { return uint64(uintptr(unsafe.Pointer(&buf[off]))) }
	var personality uint16
	runtime.LockOSThread() // registration, the change and the submission are one thread's credentials
	defer runtime.UnlockOSThread()
	return submitRing(Inline, func(ring int) error {
		id, _, errno := unix.Syscall6(unix.SYS_IO_URING_REGISTER, uintptr(ring), registerPersonality, 0, 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("%w: register a personality: %w", ErrUnavailable, errno)
		}
		personality = uint16(id)
		return change()
	}, func(sqe []byte) {
		sqe[0] = opSetxattr
		*(*uint64)(unsafe.Pointer(&sqe[8])) = at(len(path) + 1 + len(name) + 1) // addr2: the value
		*(*uint64)(unsafe.Pointer(&sqe[16])) = at(len(path) + 1)                // addr: the name
		*(*uint32)(unsafe.Pointer(&sqe[24])) = uint32(len(value))               // len: the value's size
		*(*uint16)(unsafe.Pointer(&sqe[42])) = personality                      // personality
		*(*uint64)(unsafe.Pointer(&sqe[48])) = at(0)                            // addr3: the path
	}, buf)
}

// submit sets a ring up, submits the one entry fill writes inline, waits for its completion and returns its result.
// keep is memory the entry points at, kept alive until the completion.
func submit(fill func(sqe []byte), keep []byte) (res int32, err error) {
	return submitMode(Inline, fill, keep)
}

// submitMode is submit in mode.
func submitMode(mode Mode, fill func(sqe []byte), keep []byte) (res int32, err error) {
	return submitRing(mode, nil, fill, keep)
}

// submitRing is submitMode with onRing, when set, called on the new ring before the entry is written.
func submitRing(mode Mode, onRing func(ring int) error, fill func(sqe []byte), keep []byte) (res int32, err error) {
	var p params
	if mode == SQPoll {
		p.Flags |= setupSQPoll
		p.SqThreadIdle = 2000 // ms the SQ thread polls before it sleeps; the entry is written well within it
	}
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 4, uintptr(unsafe.Pointer(&p)), 0)
	if errno != 0 {
		return 0, fmt.Errorf("%w: io_uring_setup: %w", ErrUnavailable, errno)
	}
	ring := int(fd)
	defer func() { _ = unix.Close(ring) }()
	sqSize := int(p.SqOff.Array + p.SqEntries*4)
	cqSize := int(p.CqOff.Cqes + p.CqEntries*cqeSize)
	if p.Features&featSingleMmap != 0 && cqSize > sqSize {
		sqSize = cqSize
	}
	sq, err := unix.Mmap(ring, offSQRing, sqSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return 0, fmt.Errorf("%w: map the submission ring: %w", ErrUnavailable, err)
	}
	defer func() { _ = unix.Munmap(sq) }()
	cq := sq
	if p.Features&featSingleMmap == 0 {
		if cq, err = unix.Mmap(ring, offCQRing, cqSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
			return 0, fmt.Errorf("%w: map the completion ring: %w", ErrUnavailable, err)
		}
		defer func() { _ = unix.Munmap(cq) }()
	}
	sqes, err := unix.Mmap(ring, offSQEs, int(p.SqEntries)*sqeSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return 0, fmt.Errorf("%w: map the submission entries: %w", ErrUnavailable, err)
	}
	defer func() { _ = unix.Munmap(sqes) }()
	if onRing != nil {
		if err := onRing(ring); err != nil {
			return 0, err
		}
	}

	u32 := func(b []byte, off uint32) *uint32 { return (*uint32)(unsafe.Pointer(&b[off])) }
	tail := atomic.LoadUint32(u32(sq, p.SqOff.Tail))
	idx := tail & *u32(sq, p.SqOff.RingMask)
	sqe := sqes[idx*sqeSize : (idx+1)*sqeSize]
	clear(sqe)
	fill(sqe)
	if mode == Async {
		sqe[1] |= sqeAsync // flags
	}
	*(*uint64)(unsafe.Pointer(&sqe[32])) = 0x7e57 // user_data
	*(*uint32)(unsafe.Pointer(&sq[p.SqOff.Array+idx*4])) = idx
	atomic.StoreUint32(u32(sq, p.SqOff.Tail), tail+1)
	enter := uintptr(enterGetEvents)
	if mode == SQPoll {
		enter |= enterSQWakeup // the SQ thread issues the entry; a sleeping one is woken, a polling one ignores it
	}
	for {
		errno = ioURingEnter(ring, 1, 1, enter)
		if errno != unix.EINTR {
			break // a signal before anything was submitted submits nothing: enter again
		}
	}
	if errno != 0 {
		runtime.KeepAlive(keep)
		return 0, fmt.Errorf("io_uring_enter: %w", errno)
	}
	// io_uring_enter returns the count it submitted when a signal cuts its wait short, with no completion yet, and Go's
	// runtime signals its threads (preemption): wait again, submitting nothing, until the completion is there.
	head := atomic.LoadUint32(u32(cq, p.CqOff.Head))
	for deadline := time.Now().Add(10 * time.Second); head == atomic.LoadUint32(u32(cq, p.CqOff.Tail)); {
		if time.Now().After(deadline) {
			runtime.KeepAlive(keep)
			return 0, errors.New("uring: no completion")
		}
		errno = ioURingEnter(ring, 0, 1, enter)
		if errno != 0 && errno != unix.EINTR {
			runtime.KeepAlive(keep)
			return 0, fmt.Errorf("io_uring_enter: wait: %w", errno)
		}
	}
	runtime.KeepAlive(keep)
	cqe := p.CqOff.Cqes + (head&*u32(cq, p.CqOff.RingMask))*cqeSize
	res = *(*int32)(unsafe.Pointer(&cq[cqe+8]))
	atomic.StoreUint32(u32(cq, p.CqOff.Head), head+1)
	return res, nil
}
