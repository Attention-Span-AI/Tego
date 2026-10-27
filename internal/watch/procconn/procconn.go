// SPDX-License-Identifier: Apache-2.0

// Package procconn is the agent watcher's eyes on process starts (POC, docs/poc/agent-watcher.md). It
// listens on the Linux proc connector (NETLINK_CONNECTOR, the kernel's own fork/exec/exit notifications)
// and decodes each message into a typed Event. The decode is pure and tested without privilege; opening the
// listener needs CAP_NET_ADMIN, because the proc connector is a multicast netlink group.
//
// The watcher uses Exec and Fork events to recognise an agent process — by a signature the caller supplies,
// never by anything this package knows — and to follow the processes it starts. The connector carries only
// pids; the caller reads /proc/<tgid>/exe and /proc/<tgid>/cmdline to match a signature, and must tolerate a
// process that has already exited (the read then fails and the match is skipped).
package procconn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Kind is the proc_event.what field (linux/cn_proc.h). Only the three the watcher uses are named; any other
// value decodes as its raw number with Kind(n).
type Kind uint32

const (
	// Fork fires when a task creates a child. The Event carries the child and its parent, so the watcher can
	// follow a matched agent's descendants before they exec.
	Fork Kind = 0x00000001
	// Exec fires when a task calls execve. The Event carries the task; this is where a signature is matched.
	Exec Kind = 0x00000002
	// Exit fires when a task exits, so the watcher can end a run when its last task is gone.
	Exit Kind = 0x80000000
)

func (k Kind) String() string {
	switch k {
	case Fork:
		return "fork"
	case Exec:
		return "exec"
	case Exit:
		return "exit"
	default:
		return fmt.Sprintf("kind(%#x)", uint32(k))
	}
}

// Event is one decoded proc-connector message. PID is the task (the thread) the event is about; TGID is its
// process, the number to read under /proc. For Fork, PID/TGID are the child and ParentTGID its parent. For
// Exit, ExitCode is the task's own exit_code, a raw wait status: the process's end and status are Group's to tell.
// Fields that do not apply to a Kind are zero.
type Event struct {
	Kind        Kind
	CPU         uint32
	TimestampNS uint64
	PID         int32
	TGID        int32
	ParentTGID  int32
	ExitCode    uint32
}

// native is the byte order of the running kernel. The proc connector speaks the host's own order, not
// network order, so every field is read with this.
var native = binary.NativeEndian

// Netlink and connector constants (linux/netlink.h, linux/connector.h, linux/cn_proc.h). x/sys/unix does
// not export the connector ones, so they are named here.
const (
	netlinkConnector  = 11
	cnIdxProc         = 0x1
	cnValProc         = 0x1
	procCNMcastListen = 1

	cnMsgHeaderLen   = 20 // struct cn_msg: cb_id(8) + seq(4) + ack(4) + len(2) + flags(2)
	procEventPrefix  = 16 // proc_event: what(4) + cpu(4) + timestamp_ns(8), before the union
	execEventLen     = 8  // process_pid(4) + process_tgid(4)
	forkEventLen     = 16 // parent_pid, parent_tgid, child_pid, child_tgid
	exitEventLenBase = 16 // process_pid, process_tgid, exit_code, exit_signal (newer kernels append more)
)

// ErrShort is returned when a message is too short to hold the structure its what field claims.
var ErrShort = errors.New("procconn: message shorter than its event")

// decodeProcEvent decodes a proc_event (the bytes after the cn_msg header). It returns ErrShort if the
// buffer cannot hold the union its what field selects. An event kind the watcher does not use decodes with
// its pid fields left zero, so the caller can ignore it by Kind.
func decodeProcEvent(b []byte) (Event, error) {
	if len(b) < procEventPrefix {
		return Event{}, ErrShort
	}
	ev := Event{
		Kind:        Kind(native.Uint32(b[0:4])),
		CPU:         native.Uint32(b[4:8]),
		TimestampNS: native.Uint64(b[8:16]),
	}
	u := b[procEventPrefix:]
	switch ev.Kind {
	case Exec:
		if len(u) < execEventLen {
			return Event{}, ErrShort
		}
		ev.PID = int32(native.Uint32(u[0:4]))
		ev.TGID = int32(native.Uint32(u[4:8]))
	case Fork:
		if len(u) < forkEventLen {
			return Event{}, ErrShort
		}
		ev.ParentTGID = int32(native.Uint32(u[4:8]))
		ev.PID = int32(native.Uint32(u[8:12]))
		ev.TGID = int32(native.Uint32(u[12:16]))
	case Exit:
		if len(u) < exitEventLenBase {
			return Event{}, ErrShort
		}
		ev.PID = int32(native.Uint32(u[0:4]))
		ev.TGID = int32(native.Uint32(u[4:8]))
		ev.ExitCode = native.Uint32(u[8:12])
	}
	return ev, nil
}

// DecodeCnMsg decodes one connector payload: a cn_msg header followed by a proc_event. It is the data of a
// single netlink message (what unix.ParseNetlinkMessage returns in NetlinkMessage.Data). A payload whose
// connector id is not the proc group is reported with ok=false and no error, so a caller can skip it.
func DecodeCnMsg(data []byte) (ev Event, ok bool, err error) {
	if len(data) < cnMsgHeaderLen {
		return Event{}, false, ErrShort
	}
	if native.Uint32(data[0:4]) != cnIdxProc || native.Uint32(data[4:8]) != cnValProc {
		return Event{}, false, nil
	}
	ev, err = decodeProcEvent(data[cnMsgHeaderLen:])
	if err != nil {
		return Event{}, false, err
	}
	return ev, true, nil
}

// ErrClosed is what Recv returns once Close has been called, whether Recv was blocked at the time or not.
var ErrClosed = errors.New("procconn: listener closed")

// IsOverrun reports whether err is the kernel telling the listener its socket overflowed: ENOBUFS. Events were
// dropped; the listener is still usable, and the next Recv goes on. A watcher must treat everything it knew about
// running processes as possibly stale and read /proc again.
func IsOverrun(err error) bool { return errors.Is(err, unix.ENOBUFS) }

// defaultRecvBuffer is the receive buffer Open asks for. A burst of forks (a build, a test suite) writes one
// small datagram per event, and the kernel's default of about 200 KiB overflows in a few thousand; a larger one
// makes an overrun rare, and the watcher still resynchronises when it happens.
const defaultRecvBuffer = 4 << 20

// Listener is an open proc-connector socket. Recv blocks for the next batch of events. It is not safe for
// concurrent Recv calls; one goroutine owns it. Close may be called from another goroutine, and wakes a Recv
// that is blocked.
type Listener struct {
	fd   int
	wake int // an eventfd Close writes, so a blocked Recv returns
	buf  []byte

	mu     sync.Mutex // held by Recv while it runs, so Close waits for it before closing the descriptors
	closed atomic.Bool
}

// Open creates the socket, binds it to the proc multicast group and subscribes to events. It needs
// CAP_NET_ADMIN; without it, bind fails with EPERM, which Open returns unwrapped enough to recognise.
func Open() (*Listener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, netlinkConnector)
	if err != nil {
		return nil, fmt.Errorf("procconn: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("procconn: bind (needs CAP_NET_ADMIN): %w", err)
	}
	l, err := newListener(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	_ = l.SetRecvBuffer(defaultRecvBuffer) // best effort: a smaller buffer only overruns sooner
	if err := l.subscribe(); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// newListener wraps a non-blocking datagram socket. It is split out so the wake-up is tested on a socket pair.
func newListener(fd int) (*Listener, error) {
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("procconn: eventfd: %w", err)
	}
	return &Listener{fd: fd, wake: wake, buf: make([]byte, 8192)}, nil
}

// SetRecvBuffer sets the socket's receive buffer to n bytes (SO_RCVBUFFORCE, which the listener's privilege
// allows to pass the system limit, then SO_RCVBUF). The kernel rounds it, and doubles it for its own bookkeeping.
func (l *Listener) SetRecvBuffer(n int) error {
	if err := unix.SetsockoptInt(l.fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n); err == nil {
		return nil
	}
	return unix.SetsockoptInt(l.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
}

// subscribe sends PROC_CN_MCAST_LISTEN so the kernel starts delivering events to this socket.
func (l *Listener) subscribe() error {
	const dataLen = 4 // one enum proc_cn_mcast_op
	total := unix.SizeofNlMsghdr + cnMsgHeaderLen + dataLen
	msg := make([]byte, total)
	native.PutUint32(msg[0:4], uint32(total))   // nlmsghdr.len
	native.PutUint16(msg[4:6], unix.NLMSG_DONE) // nlmsghdr.type
	native.PutUint16(msg[6:8], 0)               // flags
	native.PutUint32(msg[8:12], 0)              // seq
	native.PutUint32(msg[12:16], 0)             // pid (0 = kernel assigns)
	c := msg[unix.SizeofNlMsghdr:]              // cn_msg
	native.PutUint32(c[0:4], cnIdxProc)         // id.idx
	native.PutUint32(c[4:8], cnValProc)         // id.val
	native.PutUint32(c[8:12], 0)                // seq
	native.PutUint32(c[12:16], 0)               // ack
	native.PutUint16(c[16:18], dataLen)         // len
	native.PutUint16(c[18:20], 0)               // flags
	native.PutUint32(c[cnMsgHeaderLen:], procCNMcastListen)
	if err := unix.Sendto(l.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("procconn: subscribe: %w", err)
	}
	return nil
}

// Recv returns the events in the next datagram. A datagram may carry several netlink messages; one that is
// not a proc event is skipped. It blocks until a datagram arrives, the socket overflows (the error then satisfies
// IsOverrun and the listener goes on) or Close is called (ErrClosed).
func (l *Listener) Recv() ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if l.closed.Load() {
			return nil, ErrClosed
		}
		fds := []unix.PollFd{{Fd: int32(l.fd), Events: unix.POLLIN}, {Fd: int32(l.wake), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("procconn: poll: %w", err)
		}
		if fds[1].Revents != 0 || l.closed.Load() {
			return nil, ErrClosed
		}
		n, _, err := unix.Recvfrom(l.fd, l.buf, 0)
		switch err {
		case nil:
			return eventsIn(l.buf[:n]), nil
		case unix.EAGAIN, unix.EINTR:
			continue
		}
		return nil, fmt.Errorf("procconn: recvfrom: %w", err)
	}
}

// maxDrain bounds one Drain: a queue that refills as fast as it empties must not hold the caller forever.
const maxDrain = 1 << 16

// Drain returns every event already queued on the socket, without blocking. After an overrun it is how a caller
// reads the older events that survived, so that what it learns from /proc next is newer than all of them: events
// that arrive after the scan then replay what the scan already saw, in order and with none missing, instead of
// replaying a fork whose exit was dropped. An overrun during the drain is passed over (the caller rescans anyway).
func (l *Listener) Drain() ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for i := 0; i < maxDrain; i++ {
		if l.closed.Load() {
			return out, ErrClosed
		}
		n, _, err := unix.Recvfrom(l.fd, l.buf, 0)
		switch err {
		case nil:
			out = append(out, eventsIn(l.buf[:n])...)
		case unix.EAGAIN:
			return out, nil
		case unix.EINTR, unix.ENOBUFS:
		default:
			return out, fmt.Errorf("procconn: recvfrom: %w", err)
		}
	}
	return out, nil
}

// eventsIn walks the netlink messages in one datagram and decodes each proc event. It is split out so the
// datagram framing is tested without a socket.
func eventsIn(buf []byte) []Event {
	var out []Event
	for len(buf) >= unix.SizeofNlMsghdr {
		mlen := native.Uint32(buf[0:4])
		if mlen < unix.SizeofNlMsghdr || int(mlen) > len(buf) {
			break
		}
		if ev, ok, err := DecodeCnMsg(buf[unix.SizeofNlMsghdr:mlen]); ok && err == nil {
			out = append(out, ev)
		}
		aligned := (int(mlen) + 3) &^ 3 // NLMSG_ALIGN
		if aligned <= 0 || aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return out
}

// Close stops delivery, wakes a Recv that is blocked (it returns ErrClosed) and closes the socket once that
// Recv has returned. It is safe to call more than once.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	_, _ = unix.Write(l.wake, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	l.mu.Lock()
	defer l.mu.Unlock()
	err := unix.Close(l.fd)
	_ = unix.Close(l.wake)
	return err
}
