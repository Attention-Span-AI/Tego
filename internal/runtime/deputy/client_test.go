// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newFakeDeputy returns a client whose deputy is this process: the test says the hello on the stage end (the kernel
// attests our own pid) and takes the request sockets the client hands over on it (acceptRequestSocket).
func newFakeDeputy(t *testing.T) (c *Client, stage int) {
	t.Helper()
	launcher, stage, err := Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(stage) })
	hello := reply{op: opHello, pid: int32(os.Getpid())}
	msg, err := hello.encode(make([]byte, maxReply))
	if err != nil {
		t.Fatal(err)
	}
	if err := sendMsg(stage, msg, make([]byte, oobSize), -1); err != nil {
		t.Fatal(err)
	}
	c, err = Hello(launcher, 5*time.Second)
	if err != nil {
		_ = unix.Close(launcher)
		t.Fatalf("hello: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, stage
}

// acceptRequestSocket takes the next request socket the client handed over on stage.
func acceptRequestSocket(stage int) (int, error) {
	buf := make([]byte, maxRequest)
	n, ctl, err := recvMsg(stage, buf, make([]byte, oobSize), nil)
	if err != nil || n == 0 || ctl.fd < 0 || len(ctl.extra) != 0 {
		closeControl(ctl)
		return -1, fmt.Errorf("no request socket handed over: %d %v", n, err)
	}
	if req, err := decodeRequest(buf[:n]); err != nil || req.op != opConn {
		_ = unix.Close(ctl.fd)
		return -1, fmt.Errorf("handover %+v %v, want opConn", req, err)
	}
	return ctl.fd, nil
}

// awaitRequest waits until a request is queued on sock, unread.
func awaitRequest(sock int) error {
	fds := []unix.PollFd{{Fd: int32(sock), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 5000)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return fmt.Errorf("no request on the deputy's socket: %d %v", n, err)
		}
		return nil
	}
}

// answerENOENT reads one request on sock and answers it ENOENT, a walk's own errno.
func answerENOENT(sock int) error {
	buf := make([]byte, maxRequest)
	n, ctl, err := recvMsg(sock, buf, make([]byte, oobSize), nil)
	closeControl(ctl)
	if err != nil || n == 0 {
		return fmt.Errorf("no request: %d %v", n, err)
	}
	req, err := decodeRequest(buf[:n])
	if err != nil {
		return err
	}
	rep := reply{op: req.op, seq: req.seq, errno: unix.ENOENT}
	msg, err := rep.encode(make([]byte, maxReply))
	if err != nil {
		return err
	}
	return sendMsg(sock, msg, make([]byte, oobSize), -1)
}

// requireUnavailableNoErrno fails unless err is ErrUnavailable and carries no errno: the supervisor answers the task
// with an errno it finds in a deputy's error (the walk's, or the kernel's for the deputy's open), and refuses an
// unavailable deputy held-unavailable (ADR 0041 D4).
func requireUnavailableNoErrno(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%s: %v, want ErrUnavailable", what, err)
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		t.Fatalf("%s: %v carries errno %s, which the supervisor would answer the task's open with", what, err, unix.ErrnoName(errno))
	}
}

// TestRequestSocketTheDeputyResetIsUnavailableNotItsErrno: a deputy that dies with a request unread resets the
// request socket, and the client's receive fails ECONNRESET. That is the deputy unavailable, and the error names the
// reset without carrying it: the race job's held race (TestGateFSOpenRaceIsHeldAndRaceFree, race_d) answered an
// agent's open ECONNRESET when its deputy died, where the open is refused held-unavailable.
func TestRequestSocketTheDeputyResetIsUnavailableNotItsErrno(t *testing.T) {
	c, stage := newFakeDeputy(t)
	deputy := make(chan error, 1)
	go func() {
		sock, err := acceptRequestSocket(stage)
		if err == nil {
			err = awaitRequest(sock)
			_ = unix.Close(sock) // the request unread: the client's end is reset
		}
		deputy <- err
	}()
	_, err := c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: "/"}, nil)
	if derr := <-deputy; derr != nil {
		t.Fatal(derr)
	}
	requireUnavailableNoErrno(t, "receive on a reset socket", err)
	if c.Outstanding() != 0 {
		t.Fatalf("%d requests outstanding after the reset", c.Outstanding())
	}
}

// TestRequestSocketTheDeputyClosedIsUnavailableNotItsErrno: a pooled request socket whose deputy end is gone fails
// the next send, and that is the deputy unavailable with no errno too; the walk's own errno, which the exchange before
// it returned, is the task's answer.
func TestRequestSocketTheDeputyClosedIsUnavailableNotItsErrno(t *testing.T) {
	c, stage := newFakeDeputy(t)
	deputy := make(chan error, 1)
	go func() {
		sock, err := acceptRequestSocket(stage)
		if err == nil {
			err = answerENOENT(sock)
			_ = unix.Close(sock)
		}
		deputy <- err
	}()
	q := PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: "/missing"}
	_, err := c.Pin(q, nil)
	if derr := <-deputy; derr != nil {
		t.Fatal(derr)
	}
	if !errors.Is(err, unix.ENOENT) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("first pin: %v, want the walk's ENOENT", err)
	}
	_, err = c.Pin(q, nil)
	requireUnavailableNoErrno(t, "send on a socket the deputy closed", err)
	_, err = c.Pin(q, nil)
	requireUnavailableNoErrno(t, "pin after the deputy broke", err)
}
