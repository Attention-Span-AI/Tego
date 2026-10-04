// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// Peer identifies the actual kernel sender, rather than a claimed wire UID.
type Peer struct {
	PID      int
	UID, GID uint32
}

func socketPeer(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var e error
	err = raw.Control(func(fd uintptr) { cred, e = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || e != nil {
		return Peer{}, errors.Join(err, e)
	}
	return Peer{int(cred.Pid), cred.Uid, cred.Gid}, nil
}

func setPassCred(c syscallConnection) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var e error
	err = raw.Control(func(fd uintptr) { e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	return errors.Join(err, e)
}

func packetPeer(oob []byte, flags int) (Peer, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return Peer{}, ErrProtocol
	}
	bad := flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0
	count := 0
	var peer Peer
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_CREDENTIALS:
			cred, e := unix.ParseUnixCredentials(&m)
			if e != nil {
				bad = true
				continue
			}
			count++
			peer = Peer{int(cred.Pid), cred.Uid, cred.Gid}
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS:
			fds, e := unix.ParseUnixRights(&m)
			if e == nil {
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
			}
			bad = true
		default:
			bad = true
		}
	}
	if bad || count != 1 || peer.PID <= 0 {
		return Peer{}, ErrProtocol
	}
	return peer, nil
}

// pidfdAlive reports whether the process fd refers to has not exited. No descriptor is no live process:
// poll(2) skips a negative fd and reports nothing ready, which read as alive. poll(2) with a zero
// timeout fails EINTR when a signal is pending (the Go runtime's own SIGURG, often), which is no exit: it is asked
// again.
func pidfdAlive(fd int) bool {
	if fd < 0 {
		return false
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if err == unix.EINTR {
			continue
		}
		return err == nil && n == 0
	}
}
