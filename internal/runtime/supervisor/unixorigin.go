// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// A pathname unix socket under a write entry is admitted implicitly only when a process of the run bound
// it. The filter notifies bind(2) under a net: section (enforce-landlock R11c), and handleBind records the socket
// object a run task is about to bind — its sockfs inode and its SO_COOKIE, which no other socket of this boot
// carries — and when the bind was answered, before it answers. Nothing about the bind's name is recorded or
// trusted: which bind of a socket took, by which bytes and from which directory, is the run's to race (an address a
// sibling rewrites, a descriptor swapped after it was duplicated, a symlink changed before the kernel's lookup), and
// none of it changes whose socket object it is. The socket is the run's because a task of the run held it, bound to
// nothing, and called bind on it (ADR 0041's note of 2026-10-17).
//
// Deciding a connect or a datagram, the loop has the socket file the name reaches in the task's own view, pinned
// (unixWalk), and asks whether it is the file one of those socket objects is bound to, by identity. The kernel's
// socket diagnostics (sock_diag(7)) report a bound socket's file as UNIX_DIAG_VFS: its superblock's device
// (d_sb->s_dev) and its inode's low 32 bits (owns):
//   - Where stat(2)'s st_dev is the superblock's (ext4, xfs, tmpfs), the superblock and an inode number that fits the
//     32 bits are one file: a live socket's binding holds its file's inode, so the number is not reused while it
//     lives (ownsFile).
//   - Where st_dev is not the superblock's (a btrfs subvolume, an overlayfs layer), the pair is shared by files of
//     the superblock's other subvolumes, which repeat inode numbers. The file is the socket's only when it was born
//     while the socket was being bound — its birth time (STATX_BTIME) within bindBornWithin after one of the binds of
//     it the loop answered, and no later than the loop first saw it bound — and no socket outside the run is bound to
//     a file with the same pair: a dump of this network namespace's unix sockets (NLM_F_DUMP), begun after the file
//     was placed, lists none but the run's (ownsIfAlone, alone). For a relayed connect the dump must be one the kernel
//     made in one pass of its socket table (dumpNeed, UnixDump): the kernel resumes each later datagram of a dump at
//     a saved index into a hash bucket, and a socket the run closes in that bucket meanwhile makes it skip one bound
//     throughout. A foreign socket file that existed before the bind is refused by
//     its birth time, one born during it by the dump, and an unknown birth time, a dump the loop cannot read, or a
//     namespace whose sockets do not fit one pass where a connect needs one refuses too (unix-origin-unread). What is
//     left is residual (4) of R11a: a socket a process in another network namespace, which this namespace's dump does
//     not list, binds on the same superblock during one of the run's binds at the inode number of the run's socket,
//     or one in this namespace whose bind is under way while the dump is read; and, within a datagram's best effort
//     (residual (1)), one a datagram's dump skipped.
//
// The exact lookups by inode and cookie need no privilege for a socket in this network namespace, and a socket that
// is gone, or a number reused by another, answers ENOENT or ESTALE, which drops it from the set. A bound socket's
// binding cannot change while it lives, so it is kept once seen (runSock) and the kernel is asked again only whether
// the socket still lives; the lookups and the dumps one notification makes are bounded (unixPass).

// sockID is one socket's identity: its inode on sockfs (st_ino of a descriptor for it) and its SO_COOKIE.
type sockID struct {
	ino, cookie uint64
}

// unixBinding is what UNIX_DIAG_VFS reports of a bound unix socket: the device of its file's superblock and the
// low 32 bits of the file's inode (struct unix_diag_vfs).
type unixBinding struct {
	bound        bool
	major, minor uint32
	ino32        uint32
}

// bindingKey is a binding's (superblock, low 32 bits of the inode): all UNIX_DIAG_VFS says of a socket's file.
type bindingKey struct {
	major, minor, ino32 uint32
}

func (b unixBinding) key() bindingKey {
	return bindingKey{major: b.major, minor: b.minor, ino32: b.ino32}
}

// unixFile is the socket file a unix name resolves to, as R11a matches it: stat(2)'s device and inode, the id of
// the mount it was reached on (STATX_MNT_ID; mnt is 0 when the kernel did not report one), whose superblock device
// mountinfo names (kernel.MountDev), and its birth time.
type unixFile struct {
	nlink    uint64
	parents  [64]fileID
	parentsN int
	dev, ino uint64
	mnt      uint64
	// born is the file's birth time (STATX_BTIME) in nanoseconds since the epoch, 0 when the filesystem did not
	// report one.
	born int64
	// placed is when, in its notification's pass, the loop reached the file (unixPass.tick): a dump of the
	// namespace's sockets begun after it lists every socket of the namespace bound to the file then. 0 until a pass
	// stamps it.
	placed uint64
}

// id is the file's stat(2) identity.
func (f unixFile) id() fileID { return fileID{dev: f.dev, ino: f.ino} }

// errWideInode is owns's answer for a file whose low 32 bits match a run socket's binding while the file's inode
// number is wider: UNIX_DIAG_VFS cannot tell the two files apart, so R11a refuses the implicit admit.
var errWideInode = errors.New("supervisor: the socket file's inode number is wider than the 32 bits sock_diag reports")

// errNoMount is owns's answer for a file whose superblock could not be named: no mount id, or one this process's
// mountinfo does not list.
var errNoMount = errors.New("supervisor: the socket file's mount could not be read")

// errNoBirth is owns's answer, where st_dev is not the superblock's, for a file whose filesystem reported no birth
// time: whether it was born while one of the run's sockets was being bound cannot be read.
var errNoBirth = errors.New("supervisor: the socket file's birth time is not reported, and on this filesystem it decides")

// errBindUnrecorded is owns's answer, where st_dev is not the superblock's, for a socket of the run's bound more times
// than the loop records (bindRecsMax) whose binding matches a file born after its first recorded bind and in no
// recorded bind's window: a later, unrecorded bind of it may have made that file, so the loop can neither admit it
// nor call it foreign.
var errBindUnrecorded = errors.New("supervisor: the socket was bound more times than are recorded")

// errBornUnaccounted is owns's answer, where st_dev is not the superblock's, for a file born after the first bind of
// the run's socket the loop recorded but within no recorded bind's window (bornUnaccounted): a bind of the socket the
// loop did not record (one through a descriptor swapped after it was duplicated) or one delayed past bindBornWithin
// may have made it, or a process outside the run another subvolume's file; the loop cannot say which.
var errBornUnaccounted = errors.New("supervisor: the socket file was born during the run but in no recorded bind of the socket")

// errBindingShared is alone's answer for a binding another socket, not the run's, shares in this namespace's dump: a
// file in another subvolume or layer of the same superblock with the same inode number is bound by a socket outside
// the run, and UNIX_DIAG_VFS cannot tell which of the two files the name reached.
var errBindingShared = errors.New("supervisor: a socket outside the run is bound to a file with the same superblock and inode number")

// errNotListed is alone's answer when the namespace's dump lists none of the run's sockets under the binding a lookup
// had just found, so the file is not known to be its socket's: the socket went away meanwhile, or the dump leaves it
// out — a socket no connect reaches through a file (a connected stream or seqpacket one, reachable), one a stream or
// seqpacket socket's connect cannot reach (a datagram socket another socket connected to, which that connect's need
// does not ask for, needConnect; the kernel would refuse the connect EPROTOTYPE), or one a datagram's dump read
// across datagrams skipped (needDatagram). Each is refused unix-origin-unread.
var errNotListed = errors.New("supervisor: the namespace's socket list does not hold the run's socket the file matched")

// errUnixDumpCap is UnixDump's answer for a network namespace holding more unix sockets than one dump reads
// (unixDumpMax): the namespace's socket count is a cost a run can grow, so the dump stops there and fails closed.
var errUnixDumpCap = errors.New("supervisor: the network namespace holds more unix sockets than one dump reads")

// errUnixDumpSplit is UnixDump's answer for a dump the kernel did not provably make in one pass of its socket table:
// the namespace's listed sockets needed more than one datagram, or the one the
// kernel sent was too full to show that its walk had ended. Each later datagram resumes at a saved index into a hash
// bucket, so a socket that leaves that bucket in between — one the run closes, binds or connects — makes the dump
// skip a socket bound throughout, which may be the foreign one alone is asked about; so the dump fails closed.
var errUnixDumpSplit = errors.New("supervisor: the namespace's unix sockets did not fit one pass of the kernel's dump")

// ownership is what owns can say of a file one of the run's sockets' binding matches.
type ownership int

const (
	// ownsNot: the binding does not name the file.
	ownsNot ownership = iota
	// ownsFile: the binding names the file — st_dev is the superblock's, and the superblock and the inode number,
	// which fits the 32 bits, are one file.
	ownsFile
	// ownsIfAlone: st_dev is not the superblock's, and the file was born while the socket was being bound; it is the
	// socket's own when no socket outside the run is bound by the same binding (runSockets.alone).
	ownsIfAlone
)

// fileSB asks owns's questions about one file f, reading the superblock device mountinfo names for f's mount at
// most once however many bindings it is asked about (boundTo asks it of every remembered socket whose binding
// shares f's low 32 bits, which on btrfs, whose subvolumes repeat inode numbers, can be many).
type fileSB struct {
	k    kernel
	f    unixFile
	read bool
	dev  uint64
	err  error
}

func (m *fileSB) mountDev() (uint64, error) {
	if !m.read {
		m.dev, m.err = m.k.MountDev(m.f.mnt)
		m.read = true
	}
	return m.dev, m.err
}

// owns is what the binding b of the run's socket rs says of m's file. The binding names a file only when its low 32
// bits are the file's, its superblock is the file's — stat(2)'s st_dev when the two are equal, and otherwise the
// device mountinfo names for the file's mount (a btrfs file's st_dev is its subvolume's, never the superblock's) —
// and the file's inode number fits the 32 bits. Where st_dev is the superblock's that is the file (ownsFile). Where
// it is not, the file must have been born during one of rs's binds (runSock.birth), and is the socket's only if no
// socket outside the run shares the binding (ownsIfAlone). err is set when owns cannot tell: f's superblock could not
// be read, f's inode is wider than 32 bits, its birth time is not reported where it decides (errNoBirth), or it was
// born during the run but in no recorded bind of rs (errBornUnaccounted, or errBindUnrecorded when rs was bound more
// times than are recorded).
func (m *fileSB) owns(b unixBinding, rs *runSock) (ownership, error) {
	f := m.f
	if !b.bound || uint64(b.ino32) != f.ino&0xffffffff {
		return ownsNot, nil
	}
	sb := unix.Mkdev(b.major, b.minor)
	if sb != f.dev {
		if f.mnt == 0 {
			return ownsNot, errNoMount
		}
		dev, err := m.mountDev()
		if err != nil {
			return ownsNot, errNoMount
		}
		if dev != sb {
			return ownsNot, nil
		}
	}
	if f.ino > 0xffffffff {
		return ownsNot, errWideInode
	}
	if sb == f.dev {
		return ownsFile, nil
	}
	// f's st_dev is a subvolume's (btrfs) or a layer's (overlayfs): the superblock's other subvolumes repeat its
	// inode number, and the file's birth time says whether a bind of rs made it.
	switch rs.birth(f.born) {
	case bornUnknown:
		return ownsNot, errNoBirth
	case bornElsewhere:
		return ownsNot, nil // a file that existed before the socket's binds, or was made after it was bound
	case bornUnaccounted:
		if rs.bindsOver {
			return ownsNot, errBindUnrecorded
		}
		return ownsNot, errBornUnaccounted
	case bornInBind:
	}
	return ownsIfAlone, nil
}

// bindBornSlack is how far before the loop answered a bind the file that bind makes can read as born: inode times
// come from the kernel's coarse clock, which lags the one the loop reads by up to a tick (10 ms at HZ=100).
const bindBornSlack = 50 * time.Millisecond

// bindBornWithin is how soon after the loop answered a bind the file it makes is born, at most: the kernel's bind
// runs as soon as the task is scheduled after CONTINUE. A file of the run's own born later than that after every bind
// of its socket the loop recorded is refused where the birth time decides, fail closed.
const bindBornWithin = 10 * time.Second

// birthFit is what a file's birth time says of it against one of the run's sockets (runSock.birth).
type birthFit int

const (
	// bornUnknown: the filesystem reported no birth time.
	bornUnknown birthFit = iota
	// bornElsewhere: born before the socket's first recorded bind, or after a lookup first saw the socket bound: no
	// bind of the socket made the file. The socket was bound to nothing when the loop recorded that bind, so a bind
	// of it makes its file after; and it was bound when seen, so its file was born before.
	bornElsewhere
	// bornInBind: born within bindBornSlack before, and bindBornWithin after, one of the binds of the socket the
	// loop recorded.
	bornInBind
	// bornUnaccounted: born between those, within no recorded bind's window.
	bornUnaccounted
)

// birth is what a file born at born (ns since the epoch, 0 unknown) can be to rs (birthFit).
func (rs *runSock) birth(born int64) birthFit {
	if born == 0 {
		return bornUnknown
	}
	if rs.seen != 0 && born > rs.seen {
		return bornElsewhere
	}
	first := int64(0)
	for i, at := range rs.binds {
		if i == 0 || at < first {
			first = at
		}
		if born >= at-int64(bindBornSlack) && born <= at+int64(bindBornWithin) {
			return bornInBind
		}
	}
	if len(rs.binds) == 0 || born < first-int64(bindBornSlack) {
		return bornElsewhere
	}
	return bornUnaccounted
}

// errSocketGone is UnixBound's answer for a socket the kernel no longer has under that identity.
var errSocketGone = errors.New("supervisor: the socket is gone")

// errUnixDiagMissing is UnixBound's answer on a kernel with no socket diagnostics for AF_UNIX: unix_diag not built
// (CONFIG_UNIX_DIAG), or a module the kernel cannot load (no modprobe, modules disabled). The kernel answers ENOENT
// then, as it does for a socket that is gone, so a probe of a live socket of this process's own tells the two apart.
var errUnixDiagMissing = errors.New("supervisor: no sock_diag for AF_UNIX on this kernel")

// diagProbe caches whether the kernel answers sock_diag for AF_UNIX: once it has, for the process's life, and an
// unanswered probe is asked again at most once a second, since a module can be loaded while a run lasts.
var diagProbe struct {
	mu      sync.Mutex
	ok      bool
	checked time.Time
}

// UnixDiagAvailable reports whether the kernel answers sock_diag for AF_UNIX, which R11a's implicit admit of a socket
// under a write entry needs at every tier: without it every such socket is refused unix-origin-unread. tego doctor
// names it on the unix sockets row (CAPABILITIES.md).
func UnixDiagAvailable() bool { return unixDiagAvailable() }

// unixDiagAvailable reports whether the kernel answers an exact UNIX_DIAG lookup, by asking it about one end of a
// socketpair this process makes for the question.
func unixDiagAvailable() bool {
	diagProbe.mu.Lock()
	defer diagProbe.mu.Unlock()
	if diagProbe.ok {
		return true
	}
	if !diagProbe.checked.IsZero() && time.Since(diagProbe.checked) < time.Second {
		return false
	}
	diagProbe.checked = time.Now()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }()
	id, err := sysKernel{}.SocketID(fds[0])
	if err != nil {
		return false
	}
	_, err = unixDiagLookup(id)
	diagProbe.ok = err == nil
	return diagProbe.ok
}

// SocketID reads a socket descriptor's identity (R11a).
func (sysKernel) SocketID(fd int) (sockID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sockID{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return sockID{}, unix.ENOTSOCK
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return sockID{}, err
	}
	return sockID{ino: st.Ino, cookie: cookie}, nil
}

// Sizes and offsets of linux/unix_diag.h's structures; golang.org/x/sys defines the netlink constants only.
const (
	nlmsgHdrLen    = 16 // struct nlmsghdr
	unixDiagReqLen = 24 // struct unix_diag_req: family, protocol, pad, states, ino, show, cookie[2]
	unixDiagMsgLen = 16 // struct unix_diag_msg: family, type, state, pad, ino, cookie[2]
	udiagShowVFS   = 0x2
	udiagShowName  = 0x1
	unixDiagName   = 0 // UNIX_DIAG_NAME
	unixDiagVFS    = 1 // UNIX_DIAG_VFS
	nlmsgError     = 2 // NLMSG_ERROR
	nlmsgDone      = 3 // NLMSG_DONE
	nlaHdrLen      = 4
	tcpEstablished = 1 // the state of a connected unix socket (net/unix/af_unix.c uses the TCP state names)
	// unixDumpUnconnected is the udiag_states mask (one bit per sk_state) of a dump that leaves connected sockets
	// out (dumpNeed.connected false): every state but TCP_ESTABLISHED. A relayed connect from a stream or seqpacket
	// socket reaches through a file only a listener of its own type (unix_find_other refuses another type), and a
	// connected stream or seqpacket socket never listens (reachable); connected streams are most of a namespace's
	// sockets (some 830 of 950 on this box), and leaving them out is what lets the rest fit one pass of the kernel's
	// walk (UnixDump). A datagram socket another socket connected to is TCP_ESTABLISHED too (unix_dgram_connect sets
	// both ends) and still takes datagrams from anyone, so a datagram's decision, and a datagram socket's connect, ask
	// for every state.
	unixDumpUnconnected = 0xffffffff &^ (1 << tcpEstablished)
)

// One pass of the kernel's dump (UnixDump). netlink_dump fills each datagram of a dump into a buffer of
// max_recvmsg_len bytes — the largest receive this socket has made, capped at SKB_WITH_OVERHEAD(32768) since Linux
// 4.6 — when that allocation succeeds, and of NLMSG_GOODSIZE (SKB_WITH_OVERHEAD of a page, at most 8 KiB) when it
// does not; unix_diag_dump stops a datagram only at a socket whose message does not fit. A datagram with room left
// for the largest message is the end of the walk.
const (
	// unixDumpRoom is the least room of a dump datagram the large allocation filled: 32 KiB less a skb_shared_info,
	// which is under 1 KiB with the most fragments a kernel can be built for (MAX_SKB_FRAGS 45).
	unixDumpRoom = 32<<10 - 1<<10
	// unixDumpRoomSmall is the least room of one NLMSG_GOODSIZE filled: a 4 KiB page less the same.
	unixDumpRoomSmall = 4<<10 - 1<<10
	// unixDumpLargeAlloc is the receive-queue charge (SO_MEMINFO's rmem_alloc, the datagram's truesize) at and above
	// which the first datagram is the large allocation: an NLMSG_GOODSIZE one charges at most some 8.5 KiB, a 32 KiB
	// one 32 KiB and more.
	unixDumpLargeAlloc = 12 << 10
	// unixDumpMsgMax bounds the size of one socket's message in a dump with UDIAG_SHOW_VFS: 52 bytes (the header,
	// unix_diag_msg, UNIX_DIAG_VFS and the unconditional UNIX_DIAG_SHUTDOWN), with room for attributes a later kernel
	// adds; a message larger than half of it raises the bound to twice that message.
	unixDumpMsgMax = 256
)

// UnixBound asks the kernel which file the unix socket id is bound to (UNIX_DIAG_VFS, one exact lookup by inode
// and cookie). errSocketGone means no socket of this boot has that identity now, errUnixDiagMissing that the kernel
// cannot say; bound false, a socket that is not bound to a pathname.
func (sysKernel) UnixBound(id sockID) (unixBinding, error) {
	if id.ino == 0 || id.ino > 0xffffffff {
		return unixBinding{}, errSocketGone // udiag_ino is 32 bits; sockfs never hands out a larger one
	}
	b, err := unixDiagLookup(id)
	if errors.Is(err, errSocketGone) && !unixDiagAvailable() {
		return unixBinding{}, errUnixDiagMissing
	}
	return b, err
}

// sockDiagSocket opens the netlink socket one sock_diag question is asked on, with a receive timeout for a kernel
// that does not answer: the kernel answers inside the sendmsg that asks.
func sockDiagSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return -1, fmt.Errorf("sock_diag: socket: %w", err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("sock_diag: timeout: %w", err)
	}
	return fd, nil
}

// unixDiagLookup is UnixBound's one exact lookup, its ENOENT taken for a socket that is gone.
func unixDiagLookup(id sockID) (unixBinding, error) {
	reply, err := unixDiagExact(unixDiagRequest(id, false))
	if err != nil {
		return unixBinding{}, err
	}
	return parseUnixDiagReply(reply, id)
}

// unixDiagExact sends one exact sock_diag request on a socket of its own and returns the kernel's one reply, unparsed:
// the exchange unixDiagLookup and UnixAbstractName share, so the socket has one owner and one close.
func unixDiagExact(req []byte) ([]byte, error) {
	fd, err := sockDiagSocket()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag: send: %w", err)
	}
	buf := make([]byte, 1024)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("sock_diag: receive: %w", err)
	}
	return buf[:n], nil
}

// UnixAbstractName is the kernel seam's abstract-name lookup: unixDiagLookup's exact question with UDIAG_SHOW_NAME in
// place of UDIAG_SHOW_VFS.
func (sysKernel) UnixAbstractName(id sockID) (string, error) {
	req := unixDiagRequest(id, false)
	binary.NativeEndian.PutUint32(req[nlmsgHdrLen+12:], udiagShowName)
	reply, err := unixDiagExact(req)
	if err != nil {
		return "", err
	}
	m, err := parseUnixDiagReplyMsg(reply, id)
	if err != nil {
		return "", err
	}
	if name, ok := strings.CutPrefix(m.name, "\x00"); ok {
		return name, nil
	}
	return "", nil
}

// unixDiagRequest is an nlmsghdr and a unix_diag_req asking for sockets' files (UDIAG_SHOW_VFS), any state: the one
// socket id names, by inode and cookie, or, with dump, every unix socket of this network namespace (NLM_F_DUMP). The
// header and the request are in host order.
func unixDiagRequest(id sockID, dump bool) []byte {
	req := make([]byte, nlmsgHdrLen+unixDiagReqLen)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	flags := uint16(unix.NLM_F_REQUEST)
	if dump {
		flags |= unix.NLM_F_DUMP
	}
	ne.PutUint16(req[6:], flags)
	ne.PutUint32(req[8:], 1) // sequence
	body := req[nlmsgHdrLen:]
	body[0] = unix.AF_UNIX
	ne.PutUint32(body[4:], 0xffffffff) // every state
	ne.PutUint32(body[8:], uint32(id.ino))
	ne.PutUint32(body[12:], udiagShowVFS)
	ne.PutUint32(body[16:], uint32(id.cookie))
	ne.PutUint32(body[20:], uint32(id.cookie>>32))
	return req
}

// unixDiagMsg is one unix_diag_msg of a reply: the socket's identity, type and state, and its file when it is bound
// to one.
type unixDiagMsg struct {
	id         sockID
	typ, state uint8
	b          unixBinding
	// name is UNIX_DIAG_NAME's bytes where it was asked for: an abstract name with its leading NUL, or a path.
	name string
	// size is the netlink message's length, set by parseUnixDump.
	size int
}

// parseUnixDiagMsg reads one SOCK_DIAG_BY_FAMILY message's body: a unix_diag_msg and its attributes, of which only
// UNIX_DIAG_VFS and UNIX_DIAG_NAME are asked for.
func parseUnixDiagMsg(body []byte) (unixDiagMsg, error) {
	ne := binary.NativeEndian
	if len(body) < unixDiagMsgLen || body[0] != unix.AF_UNIX {
		return unixDiagMsg{}, errors.New("sock_diag: reply is not a unix_diag_msg")
	}
	m := unixDiagMsg{typ: body[1], state: body[2],
		id: sockID{ino: uint64(ne.Uint32(body[4:])), cookie: uint64(ne.Uint32(body[8:])) | uint64(ne.Uint32(body[12:]))<<32}}
	for attrs := body[unixDiagMsgLen:]; len(attrs) >= nlaHdrLen; {
		alen, atyp := int(ne.Uint16(attrs[0:])), ne.Uint16(attrs[2:])
		if alen < nlaHdrLen || alen > len(attrs) {
			return unixDiagMsg{}, errors.New("sock_diag: malformed attribute")
		}
		if atyp == unixDiagVFS && alen >= nlaHdrLen+8 {
			dev := ne.Uint32(attrs[nlaHdrLen+4:]) // the superblock's kernel dev_t: major << 20 | minor
			m.b = unixBinding{bound: true, ino32: ne.Uint32(attrs[nlaHdrLen:]), major: dev >> 20, minor: dev & 0xfffff}
		}
		if atyp == unixDiagName {
			m.name = string(attrs[nlaHdrLen:alen])
		}
		step := (alen + 3) &^ 3
		if step > len(attrs) {
			break
		}
		attrs = attrs[step:]
	}
	return m, nil
}

// parseUnixDiagReply reads the kernel's answer to an exact lookup: a unix_diag_msg for the socket with its
// UNIX_DIAG_VFS attribute when it is bound to a file, or an NLMSG_ERROR — ENOENT for an inode no socket has, ESTALE
// for one another socket has now. The reply's inode and cookie are checked against the question.
func parseUnixDiagReply(msg []byte, id sockID) (unixBinding, error) {
	m, err := parseUnixDiagReplyMsg(msg, id)
	return m.b, err
}

// parseUnixDiagReplyMsg is parseUnixDiagReply returning the whole message, its name among the rest.
func parseUnixDiagReplyMsg(msg []byte, id sockID) (unixDiagMsg, error) {
	ne := binary.NativeEndian
	if len(msg) < nlmsgHdrLen {
		return unixDiagMsg{}, fmt.Errorf("sock_diag: short reply of %d bytes", len(msg))
	}
	total := int(ne.Uint32(msg[0:]))
	if total < nlmsgHdrLen || total > len(msg) {
		return unixDiagMsg{}, fmt.Errorf("sock_diag: reply length %d of %d bytes", total, len(msg))
	}
	switch typ := ne.Uint16(msg[4:]); typ {
	case nlmsgError:
		if total < nlmsgHdrLen+4 {
			return unixDiagMsg{}, errors.New("sock_diag: short error reply")
		}
		errno := unix.Errno(-int32(ne.Uint32(msg[nlmsgHdrLen:])))
		if errno == unix.ENOENT || errno == unix.ESTALE {
			return unixDiagMsg{}, errSocketGone
		}
		return unixDiagMsg{}, fmt.Errorf("sock_diag: %w", errno)
	case unix.SOCK_DIAG_BY_FAMILY:
	default:
		return unixDiagMsg{}, fmt.Errorf("sock_diag: reply of type %d", typ)
	}
	m, err := parseUnixDiagMsg(msg[nlmsgHdrLen:total])
	if err != nil {
		return unixDiagMsg{}, err
	}
	if m.id != id {
		return unixDiagMsg{}, errors.New("sock_diag: reply names another socket")
	}
	return m, nil
}

// unixDumpEntry is one socket a dump of the namespace lists bound to a file a connect or a datagram can reach.
type unixDumpEntry struct {
	id sockID
	b  unixBinding
}

// reachable reports whether a connect or a datagram can reach the socket m through its file. A stream or seqpacket
// socket that is connected cannot: an accepted one reports its listener's file (unix_stream_connect copies the
// listener's path) but is not in the table a lookup by inode searches, and a bound one that connected is no listener
// and can never become one (listen(2) refuses a connected socket), so a connect to its file is refused and a datagram
// is the wrong type. Every other socket bound to a file — a listener, a stream socket bound and not yet listening, a
// datagram socket in any state (one another socket connected to reads TCP_ESTABLISHED, and takes datagrams from any)
// — is one a name reaching that file can reach.
func (m unixDiagMsg) reachable() bool {
	if !m.b.bound {
		return false
	}
	return !((m.typ == unix.SOCK_STREAM || m.typ == unix.SOCK_SEQPACKET) && m.state == tcpEstablished)
}

// dumpNeed is what one decision needs of the namespace's dump (alone, UnixDump): which sockets it lists, and whether
// only one the kernel made in one pass of its socket table will do.
type dumpNeed struct {
	// connected asks for connected sockets too (TCP_ESTABLISHED): a datagram socket another one connected to is
	// such a socket and still takes datagrams and connects from any (unixDumpUnconnected).
	connected bool
	// onePass takes only a dump the kernel made in one pass (errUnixDumpSplit otherwise): a relayed connect is made
	// on the socket decided, so its decision must not rest on a list the run's churn can have thinned.
	onePass bool
}

// needDatagram is a datagram's need: every socket, in as many datagrams as the kernel sends. A datagram's decision
// is best effort whatever the dump says — the kernel looks its name up again when it sends, so a run that swaps a
// symlink on the name in between reaches any socket (R13b, R11a's residual (1)) — and a socket a dump skips because
// the run churned its own sockets meanwhile is within that residual, while asking for one pass would refuse the run's
// own datagram sockets on btrfs wherever the namespace holds more sockets than one pass lists.
var needDatagram = dumpNeed{connected: true}

// needConnect is a relayed connect's need, on a socket of type typ (SO_TYPE, 0 when unread): one pass always, and
// connected sockets for any type but stream and seqpacket, whose connect reaches only an unconnected listener of
// its own type (unixDumpUnconnected). So such a connect to the run's own datagram socket that another socket
// connected to finds it not listed (errNotListed), refused unix-origin-unread where the kernel would answer EPROTOTYPE.
func needConnect(typ int) dumpNeed {
	return dumpNeed{connected: typ != unix.SOCK_STREAM && typ != unix.SOCK_SEQPACKET, onePass: true}
}

// serves reports whether a dump made for need d serves a decision that needs n.
func (d dumpNeed) serves(n dumpNeed) bool {
	return (d.connected || !n.connected) && (d.onePass || !n.onePass)
}

// UnixDump lists the unix sockets of this network namespace bound to a file a connect or a datagram can reach
// (reachable), from one NLM_F_DUMP of SOCK_DIAG_BY_FAMILY with UDIAG_SHOW_VFS, connected ones only when need asks
// (unixDumpUnconnected). unix_diag_dump fills one datagram at a time, walking each hash bucket whole under that
// bucket's lock, and starts the next datagram at a saved (bucket, index) pair: a socket that leaves that bucket in
// between — closed, bound, or made at its head after the walk passed and closed again — shifts the sockets after it,
// so the next datagram skips one that stayed bound throughout, and a run churns its own sockets at will (1 to 3 of
// 4,000 sockets skipped in 9 of 40 dumps while a sibling made and closed sockets, TestUnixDumpIsOnePassOrRefused).
// Within one datagram nothing is skipped. So where need asks for one pass
// the dump is taken only as one datagram that ended the walk: this socket first receives with a 32 KiB buffer, so the
// kernel fills the dump's first datagram into its large allocation; what that datagram charges the receive queue says
// whether it got it (unixDumpLargeAlloc); the datagram must leave room for one more message (unixDumpRoom,
// unixDumpMsgMax); and the next must hold no socket. Otherwise errUnixDumpSplit, fail closed. It reads at most limit
// messages, whatever they say: past that errUnixDumpCap. A namespace's other unix sockets, and sockets of other
// namespaces, are not listed (sock_diag answers for its own namespace only).
func (sysKernel) UnixDump(limit int, need dumpNeed) ([]unixDumpEntry, error) {
	fd, err := sockDiagSocket()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	nl := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	// A dump's replies come in datagrams of up to 32 KiB (netlink caps max_recvmsg_len there); a buffer that size
	// never truncates one. Its first use, on the reply to an exact lookup of inode 0 (refused at once, EINVAL), sets
	// this socket's max_recvmsg_len, so the dump's first datagram is filled into 32 KiB rather than a page.
	buf := make([]byte, 32<<10)
	if err := unix.Sendto(fd, unixDiagRequest(sockID{}, false), 0, nl); err != nil {
		return nil, fmt.Errorf("sock_diag: send: %w", err)
	}
	if _, _, _, _, err := unix.Recvmsg(fd, buf, nil, 0); err != nil {
		return nil, fmt.Errorf("sock_diag: receive: %w", err)
	}
	req := unixDiagRequest(sockID{}, true)
	if !need.connected {
		binary.NativeEndian.PutUint32(req[nlmsgHdrLen+4:], unixDumpUnconnected)
	}
	if err := unix.Sendto(fd, req, 0, nl); err != nil {
		return nil, fmt.Errorf("sock_diag: send: %w", err)
	}
	// The kernel filled the first datagram inside that send and queued it; SO_MEMINFO's first word is what it
	// charges the queue.
	room := unixDumpRoomSmall
	if charge, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MEMINFO); err == nil && charge >= unixDumpLargeAlloc {
		room = unixDumpRoom
	}
	var out []unixDumpEntry
	read, biggest := 0, 0
	for i := 0; ; i++ {
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		switch {
		case err != nil:
			return nil, fmt.Errorf("sock_diag: receive: %w", err)
		case flags&unix.MSG_TRUNC != 0:
			return nil, errors.New("sock_diag: a dump datagram was truncated")
		}
		msgs := 0
		done, err := parseUnixDump(buf[:n], func(m unixDiagMsg) bool {
			read++
			if read > limit {
				return false
			}
			msgs++
			biggest = max(biggest, m.size)
			if m.reachable() {
				out = append(out, unixDumpEntry{id: m.id, b: m.b})
			}
			return true
		})
		switch {
		case err != nil:
			return nil, err
		case read > limit:
			return nil, errUnixDumpCap
		case need.onePass && msgs > 0 && i > 0:
			// Sockets in a later datagram: the walk resumed from a saved index.
			return nil, errUnixDumpSplit
		case need.onePass && msgs > 0 && n+max(unixDumpMsgMax, 2*biggest) > room:
			// Too full to show that the walk ended in it: the next socket's message may not have fit.
			return nil, errUnixDumpSplit
		case done:
			return out, nil
		}
	}
}

// parseUnixDump reads one datagram of a dump's replies, handing each unix_diag_msg to each until it returns false;
// done reports the dump's NLMSG_DONE.
func parseUnixDump(msgs []byte, each func(unixDiagMsg) bool) (done bool, err error) {
	ne := binary.NativeEndian
	for len(msgs) >= nlmsgHdrLen {
		total := int(ne.Uint32(msgs[0:]))
		if total < nlmsgHdrLen || total > len(msgs) {
			return false, fmt.Errorf("sock_diag: dump message length %d of %d bytes", total, len(msgs))
		}
		switch typ := ne.Uint16(msgs[4:]); typ {
		case nlmsgDone:
			// Its payload is the dump's own result: 0, or the errno that ended it early.
			if total >= nlmsgHdrLen+4 {
				if errno := int32(ne.Uint32(msgs[nlmsgHdrLen:])); errno < 0 {
					return false, fmt.Errorf("sock_diag: dump ended: %w", unix.Errno(-errno))
				}
			}
			return true, nil
		case nlmsgError:
			if total < nlmsgHdrLen+4 {
				return false, errors.New("sock_diag: short error reply")
			}
			return false, fmt.Errorf("sock_diag: dump: %w", unix.Errno(-int32(ne.Uint32(msgs[nlmsgHdrLen:]))))
		case unix.SOCK_DIAG_BY_FAMILY:
			m, err := parseUnixDiagMsg(msgs[nlmsgHdrLen:total])
			if err != nil {
				return false, err
			}
			m.size = total
			if !each(m) {
				return false, nil
			}
		default:
			return false, fmt.Errorf("sock_diag: dump reply of type %d", typ)
		}
		step := (total + 3) &^ 3
		if step >= len(msgs) {
			break
		}
		msgs = msgs[step:]
	}
	return false, nil
}

// runSocketsMax bounds the sockets R11a remembers. Past it a newly bound socket is not remembered, after the set
// is pruned of the ones that are gone; its bind is remembered as unrecorded instead, and the implicit admit refuses
// it: fail closed, with a warning.
const runSocketsMax = 4096

// unrecordedMax bounds the paths of binds R11a could not record; past it the set stops naming paths and every
// refusal under a write entry says a bind went unrecorded (runSockets.lost).
const unrecordedMax = 256

// unixPassUnboundMax bounds the sock_diag lookups one notification makes that answer "bound to nothing" (or fail):
// past it, a file no remembered socket is known to be bound to is refused unix-origin-unread rather than looked up
// further. A lookup that finds a socket bound, or gone, is not counted: each happens once in a
// socket's life, since the binding it finds is kept and a gone socket is forgotten, so their cost is one lookup per
// bind the run made, not one per decision.
const unixPassUnboundMax = 256

// unixDumpMax bounds the sockets one dump of the namespace reads (UnixDump); past it the dump fails closed. A dump's
// cost is the namespace's socket count, about 0.17 ms for 950 on this box (6.17), so this bounds one at some 12 ms. A
// dump that must be one pass (a relayed connect's) stops at the kernel's second datagram, some 600 sockets.
const unixDumpMax = 1 << 16

// unixPassDumpMax bounds the dumps one notification makes: one per file a decision reaches after the last dump was
// begun and born less than dumpSettle before it (unixPass.dumpFor), so a sendmmsg batch naming many sockets of the
// run's on btrfs or overlayfs makes one, or a handful when they were bound just now; past it, a decision that needs
// one more is refused unix-origin-unread.
const unixPassDumpMax = 16

// runSocketsPruneEvery is how often a full set is pruned of its gone sockets at most: a bind past the bound sooner
// than that after a prune is remembered as unrecorded without asking the kernel about every remembered socket again.
const runSocketsPruneEvery = time.Second

// errUnixPassCap is boundTo's answer when the notification spent its lookups (unixPassUnboundMax) before every
// remembered socket bound to nothing had been asked whether it is bound now, and dumpFor's when it spent its dumps.
var errUnixPassCap = errors.New("supervisor: more of the run's sockets are bound to nothing than one notification asks sock_diag about")

// errBindingChanged is boundTo's answer when the kernel reports another binding for a live socket than the one
// kept, which bind(2) cannot make: the decision fails closed, and the new binding is kept.
var errBindingChanged = errors.New("supervisor: sock_diag reports another file for a socket than it did before")

// bindRecsMax bounds the binds of one socket R11a records. A socket is bound once, so a program makes one bind of
// it, or a second after a first that failed; past the bound a file born after the recorded ones is refused
// unix-bind-unrecorded where the birth time decides (runSock.bindsOver).
const bindRecsMax = 4

// runSock is one remembered socket: when the binds of it the loop recorded were answered, its binding once a lookup
// has seen it bound, and when that was. A bound socket's binding cannot change while it lives — a second bind fails
// EINVAL, and the binding holds its file's inode, so the inode is not reused either — so it is kept, and the kernel is
// asked again only whether the socket still lives, and only when the binding names the file a decision is about.
type runSock struct {
	// binds are the times (ns since the epoch) at which the loop found the socket bound to nothing, answering a bind
	// of it: the file a bind of it makes is born after one of them.
	binds     []int64
	bindsOver bool
	b         unixBinding
	// seen is when a lookup first saw the socket bound (ns since the epoch): its file was born before.
	seen int64
}

// runSockets is the set of sockets processes of the run bound to a pathname (R11a), each with when its binds were
// answered and its binding once seen, the bound ones indexed by their file's low 32 bits, and what is known of the
// binds of the run that could not be recorded.
type runSockets struct {
	mu      sync.Mutex
	ids     map[sockID]*runSock
	byIno   map[uint32][]sockID // the bound ones, by unix_diag_vfs's inode
	unbound []sockID            // remembered sockets no lookup has seen bound, oldest first (stale entries skipped)
	// gen counts the changes a pass's memory of a sweep depends on: a socket remembered.
	gen    uint64
	pruned time.Time // the last prune of a full set
	full   bool      // warned once that the set is full
	// clock is the time R11a reads, ns since the epoch (CLOCK_REALTIME, the clock inode birth times are kept in); nil
	// is time.Now.
	clock func() int64
	// unrecorded holds the absolute paths of pathname binds of the run that could not be recorded: the trapping
	// task's socket could not be duplicated (a non-dumpable process, such as ssh-agent, at tier landlock) or read,
	// or the set was full. lostAny says a bind whose path is not known went unrecorded: its address could not be
	// read (the same non-dumpable process), its path could not be placed, or unrecorded was full. Either way the
	// loop cannot say that no process of the run bound a socket, and a refusal names that (ruleUnixBindUnrecorded)
	// instead of calling the socket foreign. unrecList holds the same paths in the order they were lost; both only
	// grow until lostAny empties them, and an element of unrecList is never written again, so a pass reads the ones
	// it has not stat'ed yet outside the lock (mayBeUnrecorded).
	unrecorded map[string]struct{}
	unrecList  []string
	lostAny    bool
	// abstract holds the sockets a task of the run called bind(2) with an abstract name on, as ids holds the
	// pathname ones (ADR 0070): an abstract name has no file to match, so holdsAbstract asks the kernel which name each
	// holds now. At most abstractMax; a bind past them is not recorded and its name stays refused (fail closed).
	abstract []sockID
}

// abstractMax bounds runSockets.abstract, so one decision makes at most this many exact lookups.
const abstractMax = 64

// addAbstract remembers a socket a task of the run is binding to an abstract name, dropping the ones gone when the set
// is full; it reports false when it is still full.
func (s *runSockets) addAbstract(k kernel, id sockID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.abstract, id) {
		return true
	}
	if len(s.abstract) >= abstractMax {
		s.abstract = slices.DeleteFunc(s.abstract, func(old sockID) bool {
			_, err := k.UnixAbstractName(old)
			return errors.Is(err, errSocketGone)
		})
		if len(s.abstract) >= abstractMax {
			return false
		}
	}
	s.abstract = append(s.abstract, id)
	return true
}

// holdsAbstract reports whether one of the run's own sockets is bound to the abstract name now: abstract names are
// unique in a network namespace, so a connect or a datagram to it reaches that socket. A socket gone is dropped; a
// lookup that fails otherwise is an error, which refuses (unix-origin-unread). Residual, disclosed: the run's socket
// may close between this answer and the relayed call, and a process outside the run bind the freed name in between.
func (s *runSockets) holdsAbstract(k kernel, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lookupErr error
	held := false
	s.abstract = slices.DeleteFunc(s.abstract, func(id sockID) bool {
		if held || lookupErr != nil {
			return false
		}
		got, err := k.UnixAbstractName(id)
		switch {
		case errors.Is(err, errSocketGone):
			return true
		case err != nil:
			lookupErr = err
		case got == name:
			held = true
		}
		return false
	})
	if held {
		return true, nil
	}
	return false, lookupErr
}

// now is the set's clock.
func (s *runSockets) now() int64 {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now().UnixNano()
}

// unixPass is what one notification has learnt from the kernel about the set (R11a): every R11a question a
// notification asks — one per addressed message of a sendmmsg batch — shares it, so a socket is looked up at most once
// per notification, a sweep of the sockets bound to nothing is made once, the path of each unrecorded bind is
// stat'ed once, whatever binds other workers record meanwhile, and a dump of the namespace is made
// again only for a file reached after the last one was begun. It belongs to the notification (notif.unixPass), whose
// questions are asked one at a time: its sock_diag half is used under runSockets.mu, and its stat and dump halves,
// which only its own questions touch, outside it.
type unixPass struct {
	looked    map[sockID]struct{} // sockets a lookup in this pass found alive
	spent     int                 // lookups that answered "bound to nothing" or failed (unixPassUnboundMax)
	swept     bool                // every socket bound to nothing was asked, at generation sweptGen, and none failed
	sweptGen  uint64
	unrecDone int                 // the paths of unrecorded binds this pass has stat'ed: unrecList's first unrecDone
	unrec     map[fileID]struct{} // the files they named when stat'ed
	// places are the unix names the notification has resolved in the task's view (unixTarget), so a batch naming
	// one socket in many messages walks it once.
	places map[unixQuery]unixPlaceMemo
	// ticks orders the files the pass reached and the dumps it began (tick), dump is the last dump, and dumps counts
	// them (unixPassDumpMax).
	ticks uint64
	dump  *unixDump
	dumps int
}

// unixDump is one dump of the namespace's unix sockets (UnixDump), by binding, made for need and begun at the pass's
// tick after and at the time began (ns since the epoch): it lists every socket need asks for that was bound, when it
// began, to a file reached at an earlier tick, or born more than dumpSettle before it began (covers) — save, for a
// dump that need not be one pass (a datagram's), one it skipped between two of the kernel's datagrams (dumpSettle).
type unixDump struct {
	need  dumpNeed
	after uint64
	began int64
	by    map[bindingKey][]sockID
}

// dumpSettle is how long before a dump began a file must have been born for the dump to list the socket bound to it
// whenever the file was reached: unix_bind_bsd creates the file and then, in the same syscall, hashes the socket, so a
// socket bound to a file born a second before is in the table unless its bind stalled that long between the two,
// which only a process the loop cannot pace could do (residual (4)). A file reached before the dump began is covered
// whatever its birth. "In the table" is "in the dump" for a dump made in one pass (dumpNeed.onePass); a datagram's,
// read across several datagrams, can skip a socket in it, within the datagram's best effort.
const dumpSettle = time.Second

// covers reports whether d lists every socket of the namespace bound to f that a decision needing need asks about
// (dumpFor).
func (d *unixDump) covers(f unixFile, need dumpNeed) bool {
	return d.need.serves(need) && ((f.placed != 0 && f.placed < d.after) || (f.born != 0 && f.born < d.began-int64(dumpSettle)))
}

func newUnixPass() *unixPass { return &unixPass{looked: map[sockID]struct{}{}} }

// tick is the pass's next moment.
func (p *unixPass) tick() uint64 {
	p.ticks++
	return p.ticks
}

// dumpFor is a dump of the namespace's unix sockets, made for need, that lists every socket bound to f
// (unixDump.covers): the pass's last one when it does — made for a need that serves this one, and begun after f was
// reached or more than dumpSettle after f was born — else one made now, at time now, at most unixPassDumpMax per pass
// (errUnixPassCap past them). A socket the dump does not list was not bound to f when the loop reached f — save one
// whose bind was under way then, in a process the loop cannot pace — or lies in another network namespace (residual
// (4)), or is a connected one need leaves out, which the connect it is asked for cannot reach; and for a dump that
// need not be one pass (a datagram's, needDatagram), one the dump skipped because sockets left its hash bucket
// between two of its datagrams, within the datagram's best effort (residual (1)).
func (p *unixPass) dumpFor(k kernel, f unixFile, now int64, need dumpNeed) (*unixDump, error) {
	if p.dump != nil && p.dump.covers(f, need) {
		return p.dump, nil
	}
	if p.dumps >= unixPassDumpMax {
		return nil, errUnixPassCap
	}
	p.dumps++
	d := &unixDump{need: need, after: p.tick(), began: now, by: map[bindingKey][]sockID{}}
	entries, err := k.UnixDump(unixDumpMax, need)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		key := e.b.key()
		d.by[key] = append(d.by[key], e.id)
	}
	p.dump = d
	return d, nil
}

func (s *runSockets) initLocked() {
	if s.ids == nil {
		s.ids, s.byIno = map[sockID]*runSock{}, map[uint32][]sockID{}
	}
}

// add remembers a bind of socket id the loop is about to answer, at the time `at` it found the socket bound to
// nothing; false when the set is full of live sockets, or full and pruned less than runSocketsPruneEvery ago. A
// socket remembered already gains the bind beside its earlier ones: its first bind failed (its name
// taken), and this one may be the one that takes, or a sibling thread races it; the file whichever takes makes is
// born after one of them.
func (s *runSockets) add(k kernel, id sockID, at int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	if rs, ok := s.ids[id]; ok {
		if len(rs.binds) < bindRecsMax {
			rs.binds = append(rs.binds, at)
		} else {
			rs.bindsOver = true
		}
		return true
	}
	if len(s.ids) >= runSocketsMax {
		if !s.pruned.IsZero() && time.Since(s.pruned) < runSocketsPruneEvery {
			return false
		}
		s.pruned = time.Now()
		for old, rs := range s.ids {
			switch b, err := k.UnixBound(old); {
			case errors.Is(err, errSocketGone):
				s.dropLocked(old)
			case err == nil && b.bound:
				s.boundLocked(old, rs, b)
			}
		}
		s.compactLocked()
		if len(s.ids) >= runSocketsMax {
			return false
		}
	}
	s.ids[id] = &runSock{binds: []int64{at}}
	s.unbound = append(s.unbound, id)
	s.gen++
	return true
}

// lost remembers a pathname bind of the run that could not be recorded, at absolute path p, or at no known path
// ("").
func (s *runSockets) lost(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lostAny {
		return
	}
	if p == "" || len(s.unrecorded) >= unrecordedMax {
		s.lostAny, s.unrecorded, s.unrecList = true, nil, nil
		return
	}
	if _, ok := s.unrecorded[p]; ok {
		return
	}
	if s.unrecorded == nil {
		s.unrecorded = map[string]struct{}{}
	}
	s.unrecorded[p] = struct{}{}
	s.unrecList = append(s.unrecList, p)
}

// mayBeUnrecorded reports whether f can be the socket of a bind of the run that went unrecorded: one whose path is
// not known, or one whose path named f when this pass stat'ed it. Each path is stat'ed at most once per pass, so at
// most unrecordedMax times per notification, however many questions the notification asks and whatever the set does
// meanwhile, and outside the set's lock: a path is the run's choice, and a deep one is a long walk.
// A stat that is stale by the end of a pass changes only which refusal is named, unix-bind-unrecorded or
// unix-foreign, never a refusal into an admit.
func (s *runSockets) mayBeUnrecorded(k kernel, f unixFile, p *unixPass) bool {
	for {
		s.mu.Lock()
		if s.lostAny {
			s.mu.Unlock()
			return true
		}
		// The paths lost since this pass last looked: the list only grows until lostAny empties it, and its elements
		// are never written again, so they are read outside the lock.
		todo := s.unrecList[p.unrecDone:]
		s.mu.Unlock()
		if len(todo) == 0 {
			_, ok := p.unrec[f.id()]
			return ok
		}
		if p.unrec == nil {
			p.unrec = make(map[fileID]struct{}, len(todo))
		}
		for _, path := range todo {
			if got, err := k.StatID(path); err == nil {
				p.unrec[got] = struct{}{}
			}
		}
		p.unrecDone += len(todo)
	}
}

// dropLocked forgets a socket that is gone. Its entry in unbound, if any, is left for compactLocked.
func (s *runSockets) dropLocked(id sockID) {
	rs, ok := s.ids[id]
	if !ok {
		return
	}
	delete(s.ids, id)
	if rs.b.bound {
		s.unindexLocked(id, rs.b.ino32)
	}
}

func (s *runSockets) unindexLocked(id sockID, ino32 uint32) {
	list := s.byIno[ino32]
	for i, x := range list {
		if x == id {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.byIno, ino32)
	} else {
		s.byIno[ino32] = list
	}
}

// boundLocked keeps the binding a lookup found for a remembered socket, indexes it, and, the first time it is seen
// bound, notes when: its file was born before.
func (s *runSockets) boundLocked(id sockID, rs *runSock, b unixBinding) {
	if rs.b.bound {
		if rs.b == b {
			return
		}
		s.unindexLocked(id, rs.b.ino32)
	} else if rs.seen == 0 {
		rs.seen = s.now()
	}
	rs.b = b
	s.byIno[b.ino32] = append(s.byIno[b.ino32], id)
}

// compactLocked drops from unbound the sockets that are gone or seen bound.
func (s *runSockets) compactLocked() {
	keep := s.unbound[:0]
	for _, id := range s.unbound {
		if rs, ok := s.ids[id]; ok && !rs.b.bound {
			keep = append(keep, id)
		}
	}
	clear(s.unbound[len(keep):])
	s.unbound = keep
}

// boundTo reports what R11a can say of file f (owns): ownsFile when a socket the run bound is bound to it now,
// ownsIfAlone, with the binding, when one is bound by a binding f shares with files of other subvolumes and f was born
// while it was being bound — the caller then asks whether a socket outside the run shares the binding (alone) — and
// ownsNot otherwise. err is set when the kernel could not answer for a socket that might have been the one
// (sock_diag missing or refusing), when owns could not tell (errNoMount, errWideInode, errNoBirth,
// errBindUnrecorded), or when the pass spent its lookups before asking every socket bound to nothing
// (errUnixPassCap): the caller refuses then, with a rule that says the origin could not be read rather than that
// the socket is foreign.
//
// The work is bounded per pass: a bound socket is looked up only when its kept binding names f, and
// at most once per pass; a socket bound to nothing is looked up at most once per pass, newest first, and at most
// unixPassUnboundMax of those lookups are made; a sweep that asked them all is not made again in the pass until the
// set changes. A sendmmsg batch to many socket files no process of the run bound therefore costs one sweep, not one
// per message.
func (s *runSockets) boundTo(k kernel, f unixFile, p *unixPass) (ownership, bindingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	var unknown error
	fsb := fileSB{k: k, f: f}
	// The bound sockets whose kept binding names f, each asked whether it still lives. The index is not changed
	// while it is walked: what the lookups find is applied after.
	type change struct {
		id sockID
		b  unixBinding
	}
	var gone []sockID
	var changed []change
	found, key := ownsNot, bindingKey{}
	for _, id := range s.byIno[uint32(f.ino)] {
		rs := s.ids[id]
		if rs == nil {
			continue
		}
		o, err := fsb.owns(rs.b, rs)
		if err != nil {
			unknown = err
		}
		if o == ownsNot {
			continue
		}
		if _, ok := p.looked[id]; ok {
			found, key = o, rs.b.key()
			break
		}
		b, err := k.UnixBound(id)
		switch {
		case errors.Is(err, errSocketGone):
			gone = append(gone, id)
			continue
		case err != nil:
			unknown = err
			continue
		}
		p.looked[id] = struct{}{}
		if b == rs.b {
			found, key = o, rs.b.key()
			break
		}
		// Another binding than the one kept, which a live socket cannot have: not admitted on either, and the
		// new one is kept for the next question.
		unknown = errBindingChanged
		if b.bound {
			changed = append(changed, change{id, b})
		}
	}
	for _, id := range gone {
		s.dropLocked(id)
	}
	for _, c := range changed {
		s.boundLocked(c.id, s.ids[c.id], c.b)
	}
	if found != ownsNot {
		return found, key, nil
	}
	if p.swept && p.sweptGen == s.gen {
		return ownsNot, key, unknown
	}
	if p.spent >= unixPassUnboundMax {
		return ownsNot, key, errUnixPassCap
	}
	complete, dirty := true, false
	for i := len(s.unbound) - 1; i >= 0; i-- {
		id := s.unbound[i]
		rs, ok := s.ids[id]
		if !ok || rs.b.bound {
			continue
		}
		if _, ok := p.looked[id]; ok {
			continue
		}
		if p.spent >= unixPassUnboundMax {
			complete, unknown = false, errUnixPassCap
			break
		}
		b, err := k.UnixBound(id)
		switch {
		case errors.Is(err, errSocketGone):
			s.dropLocked(id)
			dirty = true
			continue
		case err != nil:
			p.spent++
			complete, unknown = false, err
			continue
		}
		p.looked[id] = struct{}{}
		if !b.bound {
			p.spent++
			continue
		}
		s.boundLocked(id, rs, b)
		dirty = true
		o, err := fsb.owns(b, rs)
		if o != ownsNot {
			s.compactLocked()
			return o, b.key(), nil
		}
		if err != nil {
			unknown = err
		}
	}
	if dirty {
		s.compactLocked()
	}
	if complete {
		p.swept, p.sweptGen = true, s.gen
	}
	return ownsNot, key, unknown
}

// alone is ownsIfAlone's question: whether every socket of this network namespace bound by the binding key to a file
// the decision's connect or datagram can reach is one the run bound, in a dump made for need and begun after f was
// reached (unixPass.dumpFor), and the run's own socket is among them. Where st_dev is not the superblock's, a foreign
// socket in another subvolume or layer with the same inode number shares the key, and UNIX_DIAG_VFS cannot tell
// which of the two files a name reached: errBindingShared, which refuses the run's own socket too, fail closed. A
// relayed connect's dump must be one pass of the kernel's walk (needConnect; errUnixDumpSplit, unix-origin-unread,
// where the namespace's sockets do not fit one). A run's socket the dump does not list under the key — one need left
// out, or one gone — is not taken on boundTo's word: errNotListed.
func (s *runSockets) alone(k kernel, key bindingKey, f unixFile, p *unixPass, need dumpNeed) error {
	d, err := p.dumpFor(k, f, s.now(), need)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	own := false
	for _, id := range d.by[key] {
		if _, ok := s.ids[id]; !ok {
			return errBindingShared
		}
		own = true
	}
	if !own {
		return errNotListed
	}
	return nil
}

// recordRunSocket remembers the socket a pathname bind(2) of the run names, before the bind is answered (R11a): the
// socket taken on a duplicate of the trapping task's descriptor, as a connect's socket is, and the moment the loop
// found it bound to nothing, after which the file this bind or any other bind of it makes is born. A socket that is
// bound already is not remembered: this bind fails EINVAL, and a run holding another program's listener (passed to
// it, or inherited) cannot make it its own by calling bind on it. Nothing of the bind's name is recorded: which bind
// of the socket takes, with which bytes, from which directory, does not change whose socket it is, and the file it
// makes is decided by identity (owns). A bind whose socket cannot be read — not duplicated, not a socket — is
// remembered as unrecorded at the path its walk reaches in the task's view (lostBind), which only ever refuses; so is
// a bind the full set turns away. joined is R6's spelling of the name, which the fake kernel keys on.
func (l *Loop) recordRunSocket(n *notif, d dest, joined string) {
	q := unixQuery{tid: n.pid, path: d.unixPath, joined: joined, parent: true}
	dup, err := l.duplicate(n, int(int32(n.args[0])))
	if err != nil {
		if !n.gone {
			l.log.Debug("supervisor: the socket a unix bind names could not be duplicated", "err", err)
			l.lostBind(n, q)
		}
		return
	}
	defer l.closeDup(dup)
	id, err := l.k.SocketID(dup)
	if err != nil {
		l.log.Debug("supervisor: the socket a unix bind names could not be read", "err", err)
		l.lostBind(n, q)
		return
	}
	// Taken before the socket is found bound to nothing: any bind of it that makes a file makes it after.
	at := l.runSockets.now()
	if b, err := l.k.UnixBound(id); err == nil && b.bound {
		// Bound already, so this bind fails EINVAL and binds nothing: the socket's binding is not the run's.
		return
	}
	if l.runSockets.add(l.k, id, at) {
		return
	}
	place, werr := l.unixTarget(n, q)
	if n.gone {
		return
	}
	l.runSockets.lost(unixLostPath(place, werr, d.unixPath))
	l.runSockets.mu.Lock()
	warn := !l.runSockets.full
	l.runSockets.full = true
	l.runSockets.mu.Unlock()
	if warn {
		l.log.Warn("supervisor: the run holds more bound unix sockets than R11a remembers; a socket bound past the bound is not admitted implicitly",
			"max", runSocketsMax)
	}
}

// lostBind remembers a bind of the run whose socket could not be read as unrecorded, at the path its walk reaches in
// the task's view, or at no known path (lostAny) when the walk fails.
func (l *Loop) lostBind(n *notif, q unixQuery) {
	place, err := l.unixTarget(n, q)
	if n.gone {
		return
	}
	l.runSockets.lost(unixLostPath(place, err, q.path))
}

// boundByRun is R11a's question about the socket file f a name resolved to, for notification n: whether a process of
// the run bound it. The answer is the implicit admit's verdict: dec when it was, and otherwise a refusal naming why.
// Every question one notification asks shares its pass (unixPass), so its work is bounded per notification; n is
// nil only where no notification is being answered, and the question then has a pass of its own. A file the pass has
// not placed yet (a relayed connect's, pinned by the relay before it asks) is placed now. need is what the decision
// needs of a dump of the namespace, where one is made (alone): needConnect for a relayed connect, needDatagram for a
// datagram.
func (l *Loop) boundByRun(n *notif, f unixFile, dec verdictOf, need dumpNeed) verdictOf {
	var p *unixPass
	if n != nil {
		p = n.pass()
	} else {
		p = newUnixPass()
	}
	if f.placed == 0 {
		f.placed = p.tick()
	}
	o, key, err := l.runSockets.boundTo(l.k, f, p)
	if o == ownsIfAlone {
		if aerr := l.runSockets.alone(l.k, key, f, p, need); aerr != nil {
			o, err = ownsNot, aerr
		}
	}
	switch {
	case o != ownsNot:
		return dec
	case errors.Is(err, errBindUnrecorded):
		l.log.Debug("supervisor: R11a found the run's socket bound more times than it records", "err", err)
		return refuse(ruleUnixBindUnrecorded)
	case err != nil:
		l.log.Debug("supervisor: R11a could not say which socket is bound to a file", "err", err)
		return refuse(ruleUnixOriginUnread)
	case l.runSockets.mayBeUnrecorded(l.k, f, p):
		return refuse(ruleUnixBindUnrecorded)
	}
	return refuse(ruleUnixForeign)
}

// diagProber is the kernel seam's optional answer to whether sock_diag for AF_UNIX works (sysKernel's is
// unixDiagAvailable): a seam without it is not asked.
type diagProber interface{ UnixDiagAvailable() bool }

// UnixDiagAvailable is unixDiagAvailable on the real kernel.
func (sysKernel) UnixDiagAvailable() bool { return unixDiagAvailable() }

// warnNoUnixDiag warns, once at the loop's start, that a run deciding unix names (a net: section) on a kernel with
// no sock_diag for AF_UNIX refuses every socket under a write entry that no unix: entry names (R11a,
// unix-origin-unread): the run's own multiprocessing or MCP sockets included, which only ledger lines would explain.
func (l *Loop) warnNoUnixDiag(c *compiled) {
	if (c.netOpen && !c.hostSockets) || c.pol.Observe {
		return // the unix-only state of ADR 0070 decides unix names too
	}
	if p, ok := l.k.(diagProber); ok && !p.UnixDiagAvailable() {
		l.log.Warn("supervisor: the kernel has no sock_diag for AF_UNIX (CONFIG_UNIX_DIAG, the unix_diag module), so a unix socket under an fs.write path is refused unix-origin-unread unless a unix: entry names it")
	}
}

// isR11aRefusal reports whether rule is one of R11a's own refusals, which no kernel program of the run makes.
func isR11aRefusal(rule string) bool {
	switch rule {
	case ruleUnixForeign, ruleUnixOriginUnread, ruleUnixBindUnrecorded, ruleUnixAbsent:
		return true
	}
	return false
}
