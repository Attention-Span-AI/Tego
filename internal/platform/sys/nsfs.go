// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// NamespaceType is ioctl(NS_GET_NSTYPE) on an open namespace file: the CLONE_NEW* flag of its kind. The descriptor
// must be open for reading; an O_PATH descriptor answers EBADF.
func (f *FD) NamespaceType() (int, error) {
	if f == nil || !f.acquire() {
		return 0, ErrClosed
	}
	defer f.unlease()
	return unix.IoctlRetInt(int(f.num), unix.NS_GET_NSTYPE)
}

// NamespaceOwner is ioctl(NS_GET_USERNS) on an open namespace file: a descriptor of the user namespace that owns
// the namespace, born an owner. The kernel answers EPERM unless that owner is the caller's own user namespace or
// one below it (ns_get_owner), takes no argument, and opens the result close-on-exec (open_related_ns). On a file
// that is not the kernel's own namespace file the result is whatever that file's filesystem chooses to answer (a
// FUSE daemon picks the ioctl's return value), so a caller checks the file with Fstatfs before the call and the
// result after it.
func (f *FD) NamespaceOwner() (*FD, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	return OwnSyscall(unix.Syscall(unix.SYS_IOCTL, uintptr(f.num), unix.NS_GET_USERNS, 0))
}

// ConnectUnix is connect(2) of a unix socket to the absolute path. On a non-blocking socket a full accept queue is
// EAGAIN at once (unix_stream_connect waits only on a blocking one). EINTR is restarted.
func (f *FD) ConnectUnix(path string) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	for {
		err := unix.Connect(int(f.num), &unix.SockaddrUnix{Name: path})
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// PeerCred is SO_PEERCRED of a connected unix socket: on the connecting side, the credentials of the process that
// called listen, as the kernel copied them at the connect.
func (f *FD) PeerCred() (*unix.Ucred, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	return unix.GetsockoptUcred(int(f.num), unix.SOL_SOCKET, unix.SO_PEERCRED)
}

// ErrTooLong is a file longer than the limit ReadLimited was given.
var ErrTooLong = errors.New("sys: the file is longer than the read's limit")

// ReadLimited reads the file from its current offset to its end, at most limit bytes: ErrTooLong when more
// follows. EINTR is restarted.
func (f *FD) ReadLimited(limit int) ([]byte, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	buf := make([]byte, 0, 4096)
	for {
		if len(buf) > limit {
			return nil, fmt.Errorf("%w (%d bytes)", ErrTooLong, limit)
		}
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := unix.Read(int(f.num), buf[len(buf):cap(buf)])
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return nil, err
		case n == 0:
			return buf, nil
		}
		buf = buf[:len(buf)+n]
	}
}
