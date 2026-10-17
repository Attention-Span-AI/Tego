// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrUnavailable is a deputy that cannot answer: it never started, it died, or its socket broke. A held open then
// fails closed (ADR 0041 D4, held-unavailable); it is never continued.
var ErrUnavailable = errors.New("deputy: unavailable")

// ErrNotStarted wraps the stage's report that the deputy did not start, with the errno it gave.
var ErrNotStarted = errors.New("deputy: the child stage could not start the open deputy")

// Client is the supervisor's side of the deputy: the launcher's end of the control socket and a pool of request
// sockets, one per concurrent caller. Safe for concurrent use.
type Client struct {
	control int
	pid     int
	// tick is how long a request waits for its reply before it calls the caller's wait function (OpenWait).
	tick time.Duration

	mu     sync.Mutex
	free   []*conn
	closed bool
	dead   atomic.Bool
	seq    atomic.Uint64
	// out counts the requests whose reply has not come back, the abandoned ones included: what Outstanding reads.
	out atomic.Int64
}

// conn is one request socket and the buffers its requests use.
type conn struct {
	sock int
	req  []byte
	rep  []byte
	oob  []byte
}

// Socketpair makes the control socketpair: launcher is the end the launcher keeps, with SO_PASSCRED so the hello
// carries the deputy's kernel-attested credentials; stage is the end the child stage passes to the deputy. Both are
// close-on-exec.
func Socketpair() (launcher, stage int, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, -1, fmt.Errorf("socketpair: %w", err)
	}
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return -1, -1, fmt.Errorf("SO_PASSCRED: %w", err)
	}
	return fds[0], fds[1], nil
}

// ReportFailure is the child stage's report, on the deputy's end of the control socket, that the deputy did not
// start: the launcher's Hello returns ErrNotStarted with errno and reason, what the stage or the deputy said of the
// failure (cut to maxLeaf bytes; "" for none).
func ReportFailure(stage int, errno unix.Errno, reason string) error {
	if errno == 0 {
		errno = unix.EIO
	}
	if len(reason) > maxLeaf {
		reason = reason[:maxLeaf]
	}
	rep := reply{op: opFail, errno: errno, leaf: reason}
	buf := make([]byte, maxReply)
	msg, err := rep.encode(buf)
	if err != nil {
		return err
	}
	return sendMsg(stage, msg, make([]byte, oobSize), -1)
}

// Hello reads the deputy's hello from the launcher's end of the control socket, within timeout, and returns a client
// that owns control. The deputy's pid is taken from the message's kernel-attested credentials (SCM_CREDENTIALS) and
// must equal the pid the hello names. ErrNotStarted is the stage's own report that the deputy did not start;
// ErrUnavailable an end of stream, a timeout or a hello that does not check out. On error control is not closed.
func Hello(control int, timeout time.Duration) (*Client, error) {
	fds := []unix.PollFd{{Fd: int32(control), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, fmt.Errorf("%w: no hello within %v", ErrUnavailable, timeout)
		}
		n, err := unix.Poll(fds, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: poll: %w", ErrUnavailable, err)
		}
		if n > 0 {
			break
		}
	}
	buf := make([]byte, maxReply)
	oob := make([]byte, oobSize)
	var creds unix.Ucred
	n, c, err := recvMsg(control, buf, oob, &creds)
	closeControl(c)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: the control socket closed with no hello", ErrUnavailable)
	}
	rep, err := decodeReply(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case rep.op == opFail && rep.leaf != "":
		return nil, fmt.Errorf("%w: %s: %w", ErrNotStarted, rep.leaf, rep.errno)
	case rep.op == opFail:
		return nil, fmt.Errorf("%w: %w", ErrNotStarted, rep.errno)
	case rep.op != opHello:
		return nil, fmt.Errorf("%w: first message is op %d, not a hello", ErrUnavailable, rep.op)
	case c.creds == nil || int32(c.creds.Pid) != rep.pid || rep.pid <= 0:
		return nil, fmt.Errorf("%w: the hello names pid %d, its credentials %v", ErrUnavailable, rep.pid, c.creds)
	}
	return &Client{control: control, pid: int(rep.pid), tick: 20 * time.Millisecond}, nil
}

// PID is the deputy's pid, from its hello.
func (c *Client) PID() int { return c.pid }

// Outstanding is how many requests have not been answered yet, abandoned ones included: what a held-open ceiling
// counts (R21).
func (c *Client) Outstanding() int64 { return c.out.Load() }

// Close closes the control socket, which ends the deputy, and every pooled request socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.dead.Store(true)
	for _, cn := range c.free {
		_ = unix.Close(cn.sock)
	}
	c.free = nil
	return unix.Close(c.control)
}

// get takes a pooled request socket, or makes one and hands its other end to the deputy.
func (c *Client) get() (*conn, error) {
	if c.dead.Load() {
		return nil, ErrUnavailable
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrUnavailable
	}
	if n := len(c.free); n > 0 {
		cn := c.free[n-1]
		c.free = c.free[:n-1]
		c.mu.Unlock()
		return cn, nil
	}
	c.mu.Unlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		// This process's own EMFILE or ENOMEM: tego-side, refused as held-unavailable, never presented as the
		// task's errno (D4).
		return nil, fmt.Errorf("%w: socketpair: %w", ErrUnavailable, err)
	}
	tv := unix.NsecToTimeval(c.tick.Nanoseconds())
	if err := unix.SetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return nil, fmt.Errorf("%w: SO_RCVTIMEO: %w", ErrUnavailable, err)
	}
	cn := &conn{sock: fds[0], req: make([]byte, maxRequest), rep: make([]byte, maxReply), oob: make([]byte, oobSize)}
	hello := request{op: opConn}
	msg, _ := hello.encode(cn.req)
	c.mu.Lock()
	closed := c.closed
	if !closed {
		err = sendMsg(c.control, msg, cn.oob, fds[1])
	}
	c.mu.Unlock()
	_ = unix.Close(fds[1])
	if closed || err != nil {
		_ = unix.Close(fds[0])
		if err != nil {
			c.dead.Store(true)
		}
		return nil, fmt.Errorf("%w: hand a request socket over: %v", ErrUnavailable, err)
	}
	return cn, nil
}

// put returns a request socket whose exchange completed to the pool.
func (c *Client) put(cn *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = unix.Close(cn.sock)
		return
	}
	c.free = append(c.free, cn)
}

// Pin walks q in the run (PinFunc) and returns what it pinned: the O_PATH descriptor, the caller's to close, its leaf
// and how it was reached. An errno is the walk's own; ErrUnavailable is the deputy's. wait is Open's.
func (c *Client) Pin(q PinQuery, wait func() bool) (Pinned, error) {
	r := request{op: opPin, walk: q.walkBits(), tid: int32(q.TID), tgid: int32(q.TGID), dirfd: q.DirFD, umask: -1, path: q.Path}
	rep, fd, err := c.exchange(r, -1, wait)
	if err != nil {
		return Pinned{FD: -1}, err
	}
	return Pinned{FD: fd, Leaf: rep.leaf, ByDescriptor: rep.byFD}, nil
}

// Pending is a pin request sent and not yet answered (PinOpenStart): the caller does its own checks of the copied
// name while the deputy walks, then takes the reply with Finish, or drops it with Abandon.
type Pending struct {
	c   *Client
	cn  *conn
	seq uint64
	op  uint8
}

// PinOpenStart sends PinOpen's request and returns at once; Finish reads its reply.
func (c *Client) PinOpenStart(q PinQuery, flags int) (*Pending, error) {
	r := request{op: opPinOpen, walk: q.walkBits(), tid: int32(q.TID), tgid: int32(q.TGID), dirfd: q.DirFD, flags: int32(flags), umask: -1, path: q.Path}
	cn, err := c.get()
	if err != nil {
		return nil, err
	}
	r.seq = c.seq.Add(1)
	msg, err := r.encode(cn.req)
	if err != nil {
		c.put(cn)
		return nil, err
	}
	c.out.Add(1)
	if err := sendMsg(cn.sock, msg, cn.oob, -1); err != nil {
		c.out.Add(-1)
		c.broken(cn)
		return nil, fmt.Errorf("%w: send: %w", ErrUnavailable, err)
	}
	return &Pending{c: c, cn: cn, seq: r.seq, op: r.op}, nil
}

// Finish reads a PinOpenStart's reply, with PinOpen's results.
func (p *Pending) Finish(wait func() bool) (pin Pinned, opened int, openErr error, err error) {
	rep, fd, second, err := p.c.receive(p.cn, p.seq, p.op, wait)
	return pinOpenResult(rep, fd, second, err)
}

// pinOpenResult is an opPinOpen reply's results (PinOpen).
func pinOpenResult(rep reply, fd, second int, err error) (Pinned, int, error, error) {
	if err != nil {
		return Pinned{FD: -1}, -1, nil, err
	}
	pin := Pinned{FD: fd, Leaf: rep.leaf, ByDescriptor: rep.byFD}
	if rep.opened && rep.openErrno != 0 {
		return pin, -1, rep.openErrno, nil
	}
	return pin, second, nil, nil
}

// Abandon drops a PinOpenStart whose reply the caller no longer wants: it is drained and closed on a goroutine.
func (p *Pending) Abandon() { go p.c.drain(p.cn, p.seq) }

// PinOpen is Pin and, for read-only flags and a pinned regular file or directory, the open too, in one exchange
// (opPinOpen): opened is the opened descriptor (-1 when none was made), openErr the open's errno when it failed. The
// caller delivers opened only once its checks of the pin pass, and closes it otherwise.
func (c *Client) PinOpen(q PinQuery, flags int, wait func() bool) (pin Pinned, opened int, openErr error, err error) {
	r := request{op: opPinOpen, walk: q.walkBits(), tid: int32(q.TID), tgid: int32(q.TGID), dirfd: q.DirFD, flags: int32(flags), umask: -1, path: q.Path}
	rep, fd, second, err := c.exchange2(r, -1, wait)
	return pinOpenResult(rep, fd, second, err)
}

// Open has the deputy open pin (the leaf beneath it, for a create) with flags, mode and, for a create, the task's
// umask. It returns the opened descriptor, the caller's. wait, when not nil, is called each time the reply has not
// come within the client's tick (a FIFO, a stalled network file system): it returns false to abandon the open, which
// is then ErrAbandoned while the deputy's late reply is drained and closed on a goroutine of its own.
func (c *Client) Open(pin int, leaf string, flags int, mode uint32, umask int, wait func() bool) (int, error) {
	r := request{op: opOpen, flags: int32(flags), mode: mode, umask: int32(umask), leaf: leaf}
	_, fd, err := c.exchange(r, pin, wait)
	return fd, err
}

// ErrAbandoned is an open whose caller stopped waiting for it (Open's wait returned false). The deputy may still
// complete it: its descriptor is closed when it arrives.
var ErrAbandoned = errors.New("deputy: open abandoned before its reply")

// exchange sends r with fd attached (-1 for none) on a pooled socket and reads its reply. A reply's errno is
// returned as a unix.Errno; anything else wrong is ErrUnavailable, and marks the client dead.
func (c *Client) exchange(r request, fd int, wait func() bool) (reply, int, error) {
	rep, got, second, err := c.exchange2(r, fd, wait)
	if second >= 0 {
		_ = unix.Close(second) // no request of exchange's carries two
	}
	return rep, got, err
}

// exchange2 is exchange with a reply's second descriptor returned too (-1 for none).
func (c *Client) exchange2(r request, fd int, wait func() bool) (reply, int, int, error) {
	cn, err := c.get()
	if err != nil {
		return reply{}, -1, -1, err
	}
	r.seq = c.seq.Add(1)
	msg, err := r.encode(cn.req)
	if err != nil {
		c.put(cn)
		return reply{}, -1, -1, err
	}
	c.out.Add(1)
	if err := sendMsg(cn.sock, msg, cn.oob, fd); err != nil {
		c.out.Add(-1)
		c.broken(cn)
		return reply{}, -1, -1, fmt.Errorf("%w: send: %w", ErrUnavailable, err)
	}
	return c.receive(cn, r.seq, r.op, wait)
}

// receive reads the reply to request seq (operation op) on cn, waiting as exchange2 does.
func (c *Client) receive(cn *conn, seq uint64, op uint8, wait func() bool) (reply, int, int, error) {
	r := request{seq: seq, op: op}
	for {
		n, ctl, err := recvMsg(cn.sock, cn.rep, cn.oob, nil)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if wait == nil || wait() {
				continue
			}
			go c.drain(cn, r.seq)
			return reply{}, -1, -1, ErrAbandoned
		}
		c.out.Add(-1)
		if err != nil || n == 0 {
			closeControl(ctl)
			c.broken(cn)
			if err == nil {
				err = errors.New("end of stream")
			}
			return reply{}, -1, -1, fmt.Errorf("%w: receive: %w", ErrUnavailable, err)
		}
		rep, err := decodeReply(cn.rep[:n])
		if err != nil || rep.seq != r.seq || rep.op != r.op || len(ctl.extra) > 1 {
			closeControl(ctl)
			c.broken(cn)
			return reply{}, -1, -1, fmt.Errorf("%w: reply %+v to request %d: %v", ErrUnavailable, rep, r.seq, err)
		}
		c.put(cn)
		if rep.errno != 0 {
			closeControl(ctl)
			return rep, -1, -1, rep.errno
		}
		second := -1
		if len(ctl.extra) == 1 {
			second = ctl.extra[0]
		}
		if ctl.fd < 0 || rep.opened && rep.openErrno == 0 && second < 0 {
			closeControl(ctl)
			return rep, -1, -1, fmt.Errorf("%w: reply to request %d carries no descriptor", ErrUnavailable, r.seq)
		}
		return rep, ctl.fd, second, nil
	}
}

// drain waits out an abandoned request's reply, closes whatever descriptor it carries and retires the socket: its
// exchange is over, and a socket whose reply is late is never pooled again.
func (c *Client) drain(cn *conn, seq uint64) {
	defer c.out.Add(-1)
	defer unix.Close(cn.sock) //nolint:errcheck // this goroutine owns the retired socket
	for {
		n, ctl, err := recvMsg(cn.sock, cn.rep, cn.oob, nil)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			if c.dead.Load() {
				return
			}
			continue
		}
		closeControl(ctl)
		_ = n
		_ = seq
		return
	}
}

// broken retires a socket whose exchange failed and marks the deputy unavailable: a socket that cannot carry a
// request means the deputy is gone or confused, and no later request is trusted to it.
func (c *Client) broken(cn *conn) {
	_ = unix.Close(cn.sock)
	c.dead.Store(true)
}
