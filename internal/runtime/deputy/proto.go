// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Command is the argv[1] the child stage execs this binary with to start the deputy.
const Command = "__open-deputy"

// Descriptor numbers in the deputy: the launcher's socketpair end, and the pipe the deputy reports readiness on.
const (
	ControlFD = 3
	ReadyFD   = 4
)

// wireVersion is the first field of every message; a peer that speaks another is refused.
const wireVersion = 1

// Operations.
const (
	opHello = 1 // deputy → launcher, once, on the control socket: the deputy is up (its pid in the reply)
	opConn  = 2 // launcher → deputy, on the control socket: serve the attached request socket
	opPin   = 3 // walk a pathname as the task's lookup does; reply with an O_PATH descriptor
	opOpen  = 4 // open the attached pin with the task's flags; reply with the opened descriptor
	opFail  = 5 // child stage → launcher, on the control socket: the deputy did not start, errno says why
	// opPinOpen is a pin and, when the pinned object is a regular file or a directory and the flags only read, its open
	// in the same exchange: an open with no effect but atime, made before the supervisor's decision so a held read
	// costs one round trip; the supervisor delivers it only once its checks pass, and closes it otherwise.
	opPinOpen = 6
)

// Walk flags of a pin.
const (
	walkNofollow  = 1 << iota // a final symlink is ELOOP (O_NOFOLLOW, or O_CREAT|O_EXCL)
	walkCreate                // a missing final component is the leaf an O_CREAT open makes (walkCreate)
	walkEmpty                 // the descriptor itself (AT_EMPTY_PATH); no pathname is walked
	walkExcl                  // O_CREAT|O_EXCL: the parent is pinned and the final component, never followed, is the leaf
	walkDirectory             // the open needs a directory (O_DIRECTORY, O_TMPFILE): a final symlink not followed is ENOTDIR
)

// Sizes. A pathname the kernel accepts is at most PATH_MAX bytes with its NUL; a leaf is one component.
const (
	maxPath    = unix.PathMax
	maxLeaf    = 255
	reqHeader  = 40
	repHeader  = 24
	maxRequest = reqHeader + maxPath + maxLeaf
	maxReply   = repHeader + maxLeaf
	// oobSize holds one SCM_RIGHTS descriptor and one SCM_CREDENTIALS, each with its header and padding.
	oobSize = 64
)

// ErrProtocol is a message this side cannot read: the wrong version, a truncated or oversized message, a reply to
// another request.
var ErrProtocol = errors.New("deputy: malformed message")

// Request is one message the launcher sends.
type request struct {
	op    uint8
	walk  uint8
	tid   int32
	tgid  int32 // the task's thread group, which the walk reads /proc/self as (the deputy reads no /proc file)
	dirfd int32
	flags int32
	mode  uint32
	umask int32 // < 0: leave the umask as it is (no O_CREAT)
	seq   uint64
	path  string
	leaf  string
}

// encode writes r into buf and returns the message.
func (r *request) encode(buf []byte) ([]byte, error) {
	if len(r.path) >= maxPath || len(r.leaf) > maxLeaf {
		return nil, fmt.Errorf("%w: path %d bytes, leaf %d", ErrProtocol, len(r.path), len(r.leaf))
	}
	n := reqHeader + len(r.path) + len(r.leaf)
	if len(buf) < n {
		return nil, fmt.Errorf("%w: buffer of %d bytes for %d", ErrProtocol, len(buf), n)
	}
	b := buf[:n]
	le := binary.LittleEndian
	le.PutUint16(b[0:], wireVersion)
	b[2], b[3] = r.op, r.walk
	le.PutUint32(b[4:], uint32(r.tid))
	le.PutUint32(b[8:], uint32(r.dirfd))
	le.PutUint32(b[12:], uint32(r.flags))
	le.PutUint32(b[16:], r.mode)
	le.PutUint32(b[20:], uint32(r.umask))
	le.PutUint16(b[24:], uint16(len(r.path)))
	le.PutUint16(b[26:], uint16(len(r.leaf)))
	le.PutUint32(b[28:], uint32(r.tgid))
	le.PutUint64(b[32:], r.seq)
	copy(b[reqHeader:], r.path)
	copy(b[reqHeader+len(r.path):], r.leaf)
	return b, nil
}

// decodeRequest reads one request; path and leaf are copied out of b.
func decodeRequest(b []byte) (request, error) {
	if len(b) < reqHeader {
		return request{}, fmt.Errorf("%w: request of %d bytes", ErrProtocol, len(b))
	}
	le := binary.LittleEndian
	if v := le.Uint16(b[0:]); v != wireVersion {
		return request{}, fmt.Errorf("%w: version %d", ErrProtocol, v)
	}
	pl, ll := int(le.Uint16(b[24:])), int(le.Uint16(b[26:]))
	if pl >= maxPath || ll > maxLeaf || len(b) != reqHeader+pl+ll {
		return request{}, fmt.Errorf("%w: request of %d bytes naming %d+%d", ErrProtocol, len(b), pl, ll)
	}
	return request{
		op: b[2], walk: b[3],
		tid: int32(le.Uint32(b[4:])), tgid: int32(le.Uint32(b[28:])), dirfd: int32(le.Uint32(b[8:])), flags: int32(le.Uint32(b[12:])),
		mode: le.Uint32(b[16:]), umask: int32(le.Uint32(b[20:])), seq: le.Uint64(b[32:]),
		path: string(b[reqHeader : reqHeader+pl]), leaf: string(b[reqHeader+pl : reqHeader+pl+ll]),
	}, nil
}

// reply is one message the deputy sends back.
type reply struct {
	op    uint8
	errno unix.Errno
	seq   uint64
	pid   int32 // the deputy's own, in a hello
	leaf  string
	// opened says an opPinOpen's open was made: its descriptor follows the pin's, or openErrno says why it failed.
	opened    bool
	openErrno unix.Errno
	// byFD is a pin's Pinned.ByDescriptor.
	byFD bool
}

// Bits of a reply's flags byte.
const (
	replyOpened = 1 << iota
	replyByFD
)

func (r *reply) encode(buf []byte) ([]byte, error) {
	if len(r.leaf) > maxLeaf {
		return nil, fmt.Errorf("%w: leaf of %d bytes", ErrProtocol, len(r.leaf))
	}
	n := repHeader + len(r.leaf)
	if len(buf) < n {
		return nil, fmt.Errorf("%w: buffer of %d bytes for %d", ErrProtocol, len(buf), n)
	}
	b := buf[:n]
	le := binary.LittleEndian
	le.PutUint16(b[0:], wireVersion)
	b[2], b[3] = r.op, 0
	if r.opened {
		b[3] |= replyOpened
	}
	if r.byFD {
		b[3] |= replyByFD
	}
	le.PutUint32(b[4:], uint32(r.errno))
	le.PutUint64(b[8:], r.seq)
	le.PutUint16(b[16:], uint16(len(r.leaf)))
	le.PutUint16(b[18:], uint16(r.openErrno))
	le.PutUint32(b[20:], uint32(r.pid))
	copy(b[repHeader:], r.leaf)
	return b, nil
}

func decodeReply(b []byte) (reply, error) {
	if len(b) < repHeader {
		return reply{}, fmt.Errorf("%w: reply of %d bytes", ErrProtocol, len(b))
	}
	le := binary.LittleEndian
	if v := le.Uint16(b[0:]); v != wireVersion {
		return reply{}, fmt.Errorf("%w: version %d", ErrProtocol, v)
	}
	ll := int(le.Uint16(b[16:]))
	if ll > maxLeaf || len(b) != repHeader+ll {
		return reply{}, fmt.Errorf("%w: reply of %d bytes naming a leaf of %d", ErrProtocol, len(b), ll)
	}
	return reply{
		op: b[2], errno: unix.Errno(le.Uint32(b[4:])), seq: le.Uint64(b[8:]), pid: int32(le.Uint32(b[20:])),
		opened: b[3]&replyOpened != 0, byFD: b[3]&replyByFD != 0, openErrno: unix.Errno(le.Uint16(b[18:])),
		leaf: string(b[repHeader : repHeader+ll]),
	}, nil
}

// cmsgSpace is CMSG_SPACE(n) on this architecture.
func cmsgSpace(n int) int { return unix.CmsgSpace(n) }

// putRights writes an SCM_RIGHTS control message carrying fd into oob and returns it: unix.UnixRights without its
// allocation.
func putRights(oob []byte, fd int) []byte {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_SOCKET
	h.Type = unix.SCM_RIGHTS
	h.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0):], uint32(fd))
	return oob[:cmsgSpace(4)]
}

// control is what one recvmsg's ancillary data carried: at most one descriptor (-1 for none) and, when the
// receiving socket has SO_PASSCRED, the sender's kernel-attested credentials.
type control struct {
	fd    int
	creds *unix.Ucred
	extra []int // descriptors past the first, which no message of this protocol carries: closed by the caller
}

// parseControl reads oob without allocating in the common case. Every descriptor it finds is returned, so none
// is left open by a malformed message.
func parseControl(oob []byte, creds *unix.Ucred) control {
	c := control{fd: -1}
	for len(oob) >= unix.CmsgLen(0) {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		l := int(h.Len)
		if l < unix.CmsgLen(0) || l > len(oob) {
			break
		}
		data := oob[unix.CmsgLen(0):l]
		switch {
		case h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_RIGHTS:
			for i := 0; i+4 <= len(data); i += 4 {
				fd := int(int32(binary.NativeEndian.Uint32(data[i:])))
				if c.fd < 0 {
					c.fd = fd
				} else {
					c.extra = append(c.extra, fd)
				}
			}
		case h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_CREDENTIALS && len(data) >= int(unsafe.Sizeof(unix.Ucred{})) && creds != nil:
			*creds = *(*unix.Ucred)(unsafe.Pointer(&data[0]))
			c.creds = creds
		}
		next := cmsgSpace(l - unix.CmsgLen(0))
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return c
}

// closeControl closes every descriptor c holds.
func closeControl(c control) {
	if c.fd >= 0 {
		_ = unix.Close(c.fd)
	}
	for _, fd := range c.extra {
		_ = unix.Close(fd)
	}
}

// putRights2 is putRights for two descriptors.
func putRights2(oob []byte, a, b int) []byte {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_SOCKET
	h.Type = unix.SCM_RIGHTS
	h.SetLen(unix.CmsgLen(8))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0):], uint32(a))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0)+4:], uint32(b))
	return oob[:cmsgSpace(8)]
}

// sendMsg2 sends msg with fd attached when fd >= 0, and second after it when second >= 0 too.
func sendMsg2(sock int, msg, oob []byte, fd, second int) error {
	if fd < 0 || second < 0 {
		return sendMsg(sock, msg, oob, fd)
	}
	o := putRights2(oob, fd, second)
	for {
		_, err := unix.SendmsgN(sock, msg, o, nil, unix.MSG_NOSIGNAL)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

// sendMsg sends msg on sock with fd attached when fd >= 0. A SOCK_SEQPACKET send is one message or none.
func sendMsg(sock int, msg, oob []byte, fd int) error {
	var o []byte
	if fd >= 0 {
		o = putRights(oob, fd)
	}
	for {
		_, err := unix.SendmsgN(sock, msg, o, nil, unix.MSG_NOSIGNAL)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

// recvMsg receives one message into buf; descriptors arrive close-on-exec. A message the buffer cuts is
// ErrProtocol, with every descriptor it carried closed. n == 0 with a nil error is the peer's end of stream.
func recvMsg(sock int, buf, oob []byte, creds *unix.Ucred) (int, control, error) {
	for {
		n, oobn, flags, _, err := unix.Recvmsg(sock, buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, control{fd: -1}, err
		}
		c := parseControl(oob[:oobn], creds)
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			closeControl(c)
			return 0, control{fd: -1}, fmt.Errorf("%w: message cut (flags %#x)", ErrProtocol, flags)
		}
		return n, c, nil
	}
}
