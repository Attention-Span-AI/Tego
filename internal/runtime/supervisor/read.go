// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"errors"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Bounds on every read of a target (R3). They are P0 engineering defaults rather than figures a normative
// document sources, and they are the only thing standing between a hostile argument and this process's
// memory, so nothing here grows a buffer on a target-supplied length.
const (
	// sockaddrMax is sizeof(struct sockaddr_storage): every address is read at this fixed size whatever
	// addrlen claims (E4).
	sockaddrMax = 128
	// pathMax is PATH_MAX+1: the NUL-scan bound for one pathname (E20).
	pathMax = 4097
	// argvEntries is the cap on the argv pointer array, applied before any string is read (E11).
	argvEntries = 8192
	// argMax bounds one argv string on its own, so a single unterminated argument cannot eat the whole
	// byte budget before the next one is read.
	argMax = 4 * pathMax
	// sendBytes is the cap on the payload relayed for an allowed Fast-Open send (R12).
	sendBytes = 64 << 10
	// msgIovs is the cap on the iovec array of one sendmsg (R12); each iovec still shares sendBytes.
	msgIovs = 1024
	// mmsgMessages is the cap on the sendmmsg messages recorded one event each (R13b); past it a batch
	// writes one more line at most (mmsgTailLine). It bounds the ledger, not the read: see mmsgKernelMax.
	mmsgMessages = 64
	// mmsgKernelMax is UIO_MAXIOV, the clamp __sys_sendmmsg applies to vlen before sending every message up
	// to it. A batch is read this far, one header array and then one address per addressed message until an
	// undecidable one refuses it, because every message the kernel sends needs an address this tier can
	// decide before the batch may be continued, and one the policy does not admit needs the batch to leave a
	// line (R13b). It is the kernel's figure, not a P0 default.
	mmsgKernelMax = 1024
	// msgControlMax bounds the read of one message's control buffer for R13b's source-route check (refusesRoute):
	// one page, the reader's scan buffer it is read into. The kernel copies the whole of msg_controllen, up to
	// net.core.optmem_max, and walks every message in it; a buffer longer than this is walked as far as it was read,
	// and what lies past that is taken as a route (controlRoutes). Legitimate buffers are far shorter: an
	// SCM_RIGHTS array of SCM_MAX_FD descriptors is 1,032 bytes.
	msgControlMax = chunk
	// chunk is the read granularity of a NUL-scan: reads stop at a page boundary so that a string at the
	// end of a mapping is read in full instead of failing against the unmapped page after it.
	chunk = 4096
	// atFDCWD is AT_FDCWD as the target passes it in a register (E7).
	atFDCWD = -100
	// deletedSuffix is what readlink appends for an unlinked target (E8).
	deletedSuffix = " (deleted)"
)

// Markers a handler puts in an event's rule field when the argument itself could not be trusted. They are
// not reason codes (those are the closed REASON-CHANNEL set) but rule names, which is where the spec puts
// the specifics (§9).
const (
	ruleUnmatched      = agent.UnmatchedRule
	ruleArgsUnreadable = "args-unreadable"
	rulePathTruncated  = "path-truncated"
	rulePathUnreliable = agent.PathUnreliableRule
	ruleFDRaced        = "fd-raced"
	// ruleFDExhausted marks a socket this loop could not duplicate because its own descriptor table, or the
	// system's, was full (EMFILE, ENFILE): no race happened, and fd-raced would blame the target for it.
	ruleFDExhausted = "fd-exhausted"
	// ruleFDUnreadable marks a descriptor this loop may not duplicate: pidfd_getfd answered EPERM, its ptrace access
	// check (PTRACE_MODE_ATTACH_REALCREDS) refused, which at tier 1 is a target that made itself non-dumpable (ssh-agent,
	// gpg) or changed its credentials; or, below 6.9, the trapping thread's descriptor table is not its leader's, or
	// kcmp cannot say whether it is (dupFailure). No race happened, and fd-raced would blame one.
	ruleFDUnreadable = "fd-unreadable"
	ruleAncillary    = "ancillary-data"
	// ruleDatagramSize marks an admitted datagram on a guarded IP socket refused because this loop sends
	// such a datagram itself and whole (relayDatagram, R7): its payload was past sendBytes, spread over more
	// than msgIovs iovecs, or could not be read in full, so no relay could send the datagram the call asked
	// for.
	ruleDatagramSize = "datagram-size"
	// ruleZeroCopy marks a send this loop would have relayed (R12's Fast-Open send, a datagram on a guarded
	// IP socket) refused because its flags carry MSG_ZEROCOPY (zeroCopy says why a relay cannot honour it).
	ruleZeroCopy = "zerocopy"
	// ruleCorked marks an operation refused because it could start or join a pending frame (R13; frame.go): in a run
	// that decides datagrams, a send with MSG_MORE, a setsockopt(UDP_CORK), or a sendfile or splice into a socket that
	// can hold a frame (refusesFrame, refuseCork, spliceInto), and a datagram this loop would send itself
	// on a socket corked or whose cork could not be read (frameFree). A socket's pending frame takes every later
	// datagram before the kernel reads its address or runs sendmsg4/6, so the bytes would go to the frame's
	// destination under a line that names another.
	ruleCorked = "datagram-corked"
	// ruleExecAnon marks an exec of an anonymous image — a memfd, another anonymous inode, or an unlinked
	// file — that this loop refused because no tier below tier 3 can (SEMANTICS §4). It is a rule
	// name, not a reason: the reason is exec-not-allowed, and the specifics live here (§9).
	ruleExecAnon = "exec-anon"
	// ruleCodexHomeExec marks an exec, in a deny-list run (ADR 0048 (1)), whose image, or whose directly-invoked
	// loader's program, lies in the run's own CODEX_HOME, the write grant the run made on its own authority
	// (agent.CodexHomeGrant, agent-contract.md R10a). A deny-list leaves images unrestricted, so the grant would be a
	// directory the agent can write to and run from, and a copy of a denied program under another name is not that
	// program to the command rules. The reason is exec-not-allowed.
	ruleCodexHomeExec = "codex-home-exec"
	// ruleHookStateExec is ruleCodexHomeExec for the run's hook-state directory (agent.HarnessStateGrant,
	// agent-contract.md R27, ADR 0062), the other write grant the run makes on its own authority: the agent's harness
	// hook keeps its state there, and a copy of a denied program written there is not to run. The reason is
	// exec-not-allowed.
	ruleHookStateExec = "harness-state-exec"
	// ruleBatchSend marks a destination the policy would have admitted, refused because of the sendmmsg
	// batch it arrived in: on a stream socket without a peer, or on any stream socket under MSG_FASTOPEN,
	// R12's relay cannot reproduce the batch form (R13c), and on any socket another message in the same
	// batch carried an address this tier cannot decide (R4, E4). Either way the batch, not the host, is
	// what was refused.
	ruleBatchSend = "batch-send"
	// ruleUnspec marks connect(fd, {AF_UNSPEC}, len), the defined request to dissolve a socket's
	// association: it names no destination, so there is nothing for R7 to match (R4).
	ruleUnspec = "net.unspec"
	// ruleRelayLimit marks an allowed connect or Fast-Open send refused because relayCeiling relayed
	// syscalls were already outstanding, each holding a duplicate of a target socket (R21, E28).
	ruleRelayLimit = "relay-limit"
	// ruleSourceRouted marks a connect, Fast-Open send or datagram this loop would relay on an IP socket, one a
	// net gate admitted or one admitted under a net: section, refused because the socket carries a source route
	// (IP_OPTIONS LSRR or SSRR, IPV6_RTHDR), or its options could not be read: its first hop is not the address
	// the gate scored or the contract admitted (ADR 0041 D6, GAPS C34). Under a net gate or a net: section the
	// filter refuses the setsockopt that would add a route (enforce-landlock R11b), so the sockets that meet this
	// rule carried their route before the filter applied. It also marks a sendmsg or sendmmsg refused under a
	// net: section because a control message routes its datagram (refusesRoute, R13b).
	ruleSourceRouted = "relay-source-routed"
	// ruleRelayCredentials marks an admitted unix connect refused because this loop could not make it as
	// the task that trapped: the task's credentials could not be read, or no thread could take them (R11).
	// Relaying it with this process's own would be the escalation the relay exists to avoid.
	ruleRelayCredentials = "relay-credentials"
	// ruleUnixForeign marks a pathname unix socket under a write entry, refused because no process of the run bound
	// it (R11a): the implicit admit is for the run's own sockets, and a socket that existed before the run, or that
	// a process outside it made, belongs to whatever serves it outside the run. A unix: entry admits one on purpose.
	// A name that reaches a directory, or a file that is no socket, is refused with it too. compile --test names it
	// with the same constant.
	ruleUnixForeign = agent.UnixForeignRule
	// ruleHostSockets marks a unix destination the unix-only state refuses (ADR 0070, compiled.hostSockets): no net:
	// section, no host_sockets: true, and a socket no process of the run bound.
	ruleHostSockets = agent.HostSocketsRule
	// ruleRouteQuery marks a read-only request to the kernel on a NETLINK_ROUTE socket, and a bind of such a socket under
	// a listener policy (ADR 0128): no contract entry names it, every run may make it.
	ruleRouteQuery = "route-query"
	// ruleRouteChange marks a message to the kernel on a NETLINK_ROUTE socket that is not read-only: a NEW, DEL or SET
	// request, or anything routeReadOnly cannot read as a GET (ADR 0128).
	ruleRouteChange = "route-change"
	// ruleUnixOriginUnread marks the same socket refused because R11a could not say which socket is bound to it: no
	// sock_diag for AF_UNIX or a refused lookup, a file whose mount this process cannot name, or a file whose inode
	// number is wider than the 32 bits UNIX_DIAG_VFS reports while one of the run's sockets matches those bits; and,
	// where st_dev is not the superblock's (btrfs, overlayfs), a file whose birth time is unknown or in no recorded
	// bind's window, a pair a socket outside the run shares, a list of the namespace's sockets not read (refused, past
	// errUnixDumpCap or unixPassDumpMax, or not one pass for a connect, errUnixDumpSplit), or one that shows no socket
	// of the run's under the pair (errNotListed: one gone, one a datagram's list skipped, or one the list leaves out
	// because it cannot take the connect). R11a fails closed.
	ruleUnixOriginUnread = "unix-origin-unread"
	// ruleUnixBindUnrecorded marks the same socket refused because a bind of the run could not be recorded (R11a):
	// the binding task's socket or address could not be read — a non-dumpable process such as ssh-agent at tier
	// landlock — or the set was full. No socket of the run is bound to it as far as the loop knows, but the loop
	// cannot say that no process of the run bound it, so it does not call it foreign.
	ruleUnixBindUnrecorded = "unix-bind-unrecorded"
	// ruleUnixAbsent marks a datagram to a name under a write entry that names nothing in this process's view
	// (R11a): refused with the errno the kernel's own lookup would have met (ENOENT, ENOTDIR), not R10's.
	ruleUnixAbsent = agent.UnixAbsentRule
	// ruleUnixAskScope marks a pathname unix socket refused because the place it was reached at is a net.ask unix:
	// scope's (R11c) and no person was asked about it there: an addressed datagram, which is never asked (ASK-UDP), or
	// a connect whose name the loop's walk placed elsewhere and the relay's own walk then at the scope's place (the
	// agent repointed it in between). The contract named that place for a person, so neither the write entry around
	// it nor the run having bound the socket there admits it.
	ruleUnixAskScope = agent.UnixAskScopeRule
	ruleResolver     = agent.ResolverRule
	// ruleUnresolved marks a destination on the port of a guarded models[] endpoint whose name has not
	// resolved yet, refused because it could be that endpoint (modelGuard, R7): the answer
	// decide.Evaluate gives a literal address only an unresolved entry could match.
	ruleUnresolved = agent.UnresolvedRule
)

// reader reads one notification's arguments out of the target. Every logical read is bracketed by
// ID_VALID before the read and again before the bytes are used (R2, I1): the read is not atomic with the
// check, and the pid alone is not a safe key once the target can die and its id be reused (E3).
//
// A reader is owned by one handler on one worker and is never shared or cached across notifications.
type reader struct {
	l *Loop
	n *notif
	// failed is set when a read returned nothing with the notification still live: a decision then fails
	// closed (R5), a record-only handler still continues the syscall.
	failed bool
	// fault is set when a pathname read met unmapped memory before its NUL (or its address was 0): the kernel's own
	// copy of it fails EFAULT there, which a held open answers as the task's own errno (ADR 0041 D4). A read this
	// process could not make for its own reasons (a non-dumpable task's EPERM) is no fault.
	fault bool
	// lastFault says the last read failed EFAULT (unmapped memory), not EPERM or ESRCH.
	lastFault bool
	// note names what went wrong, for the event's rule field when nothing matched.
	note string
	// unreadPath names the first pathname argument pathRaw could not read whole: args-unreadable when
	// nothing of it was read (a NULL pointer, an unmapped page, a target this process may not read), and
	// path-truncated when the read stopped before its NUL. denyWrite refuses a modification that carries
	// one (R15c): it cannot tell where such a path leads, and the kernel's own read of it may succeed.
	unreadPath string
	// noDirfd is set when a relative pathname's directory descriptor is not one the task holds: a negative one other
	// than AT_FDCWD, or one /proc/<pid>/fd does not list while the notification is live. The kernel's lookup fails
	// EBADF there before it reads a component, which a held open answers as the task's own errno (ADR 0041 D4).
	noDirfd bool
	// scratch is the NUL-scan buffer, one per reader, so a scan allocates nothing per chunk.
	scratch [chunk]byte
	// walked holds the walks this notification made (Loop.fsTarget): its verdict, its deny_write and its
	// deny_read-move checks ask where the same end lands, and the walk is paid once per end.
	walked  [2]walkMemo
	nwalked int
	// deleted holds the relative paths resolve joined to a directory link that ends in " (deleted)". The
	// walk alone answers where such a path lands (pathQuery.deletedBase).
	deleted []deletedJoin
	// cwd is the task's cwd as resolve last read it for a name relative to AT_FDCWD, a live directory's canonical
	// path the kernel reported, "" when none was read or it was not one: where a relative unix name whose directory
	// is missing is placed from, its own ".." applied by the placement's walk, not by a lexical clean (unixScopeOf).
	cwd string
}

// deletedJoin is one path resolve joined to a " (deleted)" directory link: the dirfd it was relative to and
// the spelling resolve returned.
type deletedJoin struct {
	dirfd  int32
	joined string
}

// joinedToDeleted reports whether q's spelling came from a " (deleted)" directory link in this notification.
func (r *reader) joinedToDeleted(q pathQuery) bool {
	if strings.HasPrefix(q.path, "/") {
		return false
	}
	for _, d := range r.deleted {
		if d.dirfd == q.dirfd && d.joined == q.joined {
			return true
		}
	}
	return false
}

// walkMemo is one FSTarget answer of a notification: where the end lands and, for a pathname with a ".." component,
// the name its line gives it, both from the one walk (fsLanding).
type walkMemo struct {
	q    pathQuery
	at   string
	name string
	err  error
}

// newReader starts a bracketed read session for one notification. The reader carries a page-sized scan
// buffer, so it comes from a per-Loop pool rather than the heap on every notification; finish returns it
// once the handler is done, panic or no panic.
func (l *Loop) newReader(n *notif) *reader {
	r, _ := l.readers.Get().(*reader)
	if r == nil {
		r = &reader{}
	}
	r.l, r.n = l, n
	r.failed, r.note, r.unreadPath, r.fault, r.noDirfd = false, "", "", false, false
	r.nwalked = 0
	r.deleted = r.deleted[:0]
	n.r = r
	return r
}

// release returns a finished reader to the pool. A reader is never used after it, and the buffer it
// carries is overwritten before the next read, so no target bytes leak from one notification to the next.
func (l *Loop) release(r *reader) {
	if r == nil {
		return
	}
	r.l, r.n = nil, nil
	r.walked = [2]walkMemo{}
	clear(r.deleted)
	r.deleted = r.deleted[:0]
	l.readers.Put(r)
}

// ok reports whether everything read so far is trustworthy: the notification is still live and no read
// failed outright.
func (r *reader) ok() bool { return !r.failed && !r.n.gone }

// fail marks the session failed with a rule marker.
func (r *reader) fail(note string) {
	r.failed = true
	if r.note == "" {
		r.note = note
	}
}

// mark records a non-fatal defect (truncation, an unreliable base) without failing the session. It only
// names the defect for the event's rule field and never changes a verdict: a decision reads failed (via
// ok) and unreadPath, not the note.
func (r *reader) mark(note string) {
	if r.note == "" {
		r.note = note
	}
}

// read fills buf from the target and reports the byte count. It is the only place that touches target
// memory; the ID_VALID bracket around a logical read lives in the callers below.
func (r *reader) read(addr uint64, buf []byte) int {
	if r.n.gone || len(buf) == 0 {
		return 0
	}
	n, err := r.l.k.ReadMem(r.n.pid, addr, buf)
	r.lastFault = errors.Is(err, unix.EFAULT)
	if err != nil {
		r.l.log.Debug("supervisor: target memory read failed", "nr", r.n.nr, "err", err)
		return 0
	}
	if n < 0 || n > len(buf) {
		return 0
	}
	return n
}

// addrlenErr is the kernel's own answer to a connect or sendto whose addrlen move_addr_to_kernel refuses:
// EINVAL for one past sizeof(sockaddr_storage) or negative as the int it is (socklen reads it unsigned, so a
// negative one is past the bound too), before the address is copied or the socket touched. sockaddr clamps
// the read to sockaddrMax, so a relay performed with those bytes would succeed where the target's own call
// fails: an allowed relay answers this instead (R9, R12, I3). nil for a length the kernel takes.
func addrlenErr(addrlen int64) error {
	if addrlen > sockaddrMax {
		return unix.EINVAL
	}
	return nil
}

// msgNameErr is the same for a msghdr's msg_name: __copy_msghdr zeroes msg_namelen when msg_name is NULL,
// fails a negative one EINVAL, and clamps one past sizeof(sockaddr_storage) to it, so only a negative length
// with a name is the kernel's error; an over-long one is sent with the clamped address, as the relay sends it.
func msgNameErr(name uint64, namelen int64) error {
	if name != 0 && int32(uint32(namelen)) < 0 {
		return unix.EINVAL
	}
	return nil
}

// shortAddrErr is the kernel's own answer to a connect or send whose address the read came up short on: the
// kernel copies all min(addrlen, sizeof(sockaddr_storage)) bytes (move_addr_to_kernel, after __copy_msghdr
// clamps msg_namelen) and fails the call EFAULT when any of them faults. sockaddr keeps the readable prefix,
// which still parses and decides, but a relay performed with it would connect or send where the target's
// own call fails, so an allowed relay answers this instead (R9, R12, I3). err, the length's own error, wins:
// the kernel checks the length before it copies. nil when every byte was read.
func shortAddrErr(err error, raw []byte, addrlen int64) error {
	if err != nil {
		return err
	}
	if int64(len(raw)) < min64(addrlen, sockaddrMax) {
		return unix.EFAULT
	}
	return nil
}

// sockaddr reads the destination address of a connect or send: the fixed sockaddr_storage size, clamped
// whatever addrlen claims, and never more than the target said it passed (R3, R4, E4). It returns the raw
// bytes; parsing is parseSockaddr's job.
func (r *reader) sockaddr(addr uint64, addrlen int64) []byte {
	if addr == 0 || addrlen <= 0 {
		r.fail(ruleArgsUnreadable)
		return nil
	}
	size := int(min64(addrlen, sockaddrMax))
	if !r.l.valid(r.n) {
		return nil
	}
	buf := make([]byte, size)
	n := r.read(addr, buf)
	if n == 0 {
		r.fail(ruleArgsUnreadable)
		return nil
	}
	if !r.l.valid(r.n) { // the bytes are only trustworthy if the notification is still the same one
		return nil
	}
	if n < size {
		r.mark(ruleArgsUnreadable)
	}
	return buf[:n]
}

// blob reads up to limit bytes of a target buffer for a relayed send (R12). A short read is what gets sent.
func (r *reader) blob(addr uint64, length int64, limit int) []byte {
	if length <= 0 {
		return nil
	}
	size := int(min64(length, int64(limit)))
	if size < int(length) {
		r.mark(rulePathTruncated)
	}
	if !r.l.valid(r.n) {
		return nil
	}
	buf := make([]byte, size)
	n := r.read(addr, buf)
	if n == 0 && size > 0 {
		r.fail(ruleArgsUnreadable)
		return nil
	}
	if !r.l.valid(r.n) {
		return nil
	}
	return buf[:n]
}

// cstring reads a NUL-terminated string of at most limit bytes, scanning page by page so that a string at
// the end of a mapping reads in full. No NUL inside the bound is truncation, not an error (E20); cut says
// so, which is what argv_truncated is built from. The bracket is the caller's: cstring is called both
// alone (a path) and in a loop (argv).
func (r *reader) cstring(addr uint64, limit int) (s string, cut bool) {
	if addr == 0 || limit <= 0 {
		r.fault = r.fault || addr == 0
		r.fail(ruleArgsUnreadable)
		return "", false
	}
	var out []byte
	left := limit
	for left > 0 && !r.n.gone {
		size := chunk - int(addr%chunk)
		if size > left {
			size = left
		}
		n := r.read(addr, r.scratch[:size])
		if n == 0 {
			r.fault = r.fault || r.lastFault
			if len(out) == 0 {
				r.fail(ruleArgsUnreadable)
				return "", true
			}
			r.mark(rulePathTruncated)
			break
		}
		if i := bytes.IndexByte(r.scratch[:n], 0); i >= 0 {
			if len(out) == 0 {
				// The common case, a NUL in the first page read: one copy, into the string.
				return string(r.scratch[:i]), false
			}
			out = append(out, r.scratch[:i]...)
			return string(out), false
		}
		out = append(out, r.scratch[:n]...)
		addr += uint64(n)
		left -= n
		if n < size { // a short read is the end of what is mapped
			r.fault = true // the kernel's copy faults where this one stopped
			r.mark(rulePathTruncated)
			break
		}
	}
	r.mark(rulePathTruncated)
	return string(out), true
}

// path reads a pathname argument and resolves it against its dirfd (R6): AT_FDCWD through
// /proc/<pid>/cwd, any other descriptor through /proc/<pid>/fd/<n>, both single-hop magic symlinks that
// cannot loop (E12). The result is cleaned but never made canonical: no component of it is opened, and
// nothing under the run is ever resolved by this process.
func (r *reader) path(dirfd int32, addr uint64) string {
	p, _ := r.pathRaw(dirfd, addr)
	return p
}

// pathRaw is path together with the pathname exactly as the target passed it, which a walk made as the
// task needs (fsTarget, R15b): the join above is cleaned, and "link/.." cleaned names another file than
// the one the kernel resolves.
func (r *reader) pathRaw(dirfd int32, addr uint64) (p, raw string) {
	if !r.l.valid(r.n) {
		return "", ""
	}
	raw, cut := r.cstring(addr, pathMax)
	if !r.l.valid(r.n) {
		return "", ""
	}
	if r.unreadPath == "" {
		switch {
		case raw == "" && (cut || addr == 0):
			r.unreadPath = ruleArgsUnreadable
		case cut:
			r.unreadPath = rulePathTruncated
		}
	}
	if raw == "" {
		return "", ""
	}
	p = r.resolve(dirfd, raw)
	if p == "" && !r.n.gone && r.unreadPath == "" {
		// Read whole, but its join to the dirfd's directory is over PATH_MAX (resolve marked it): the kernel
		// resolves a relative name with no limit on the total, so it lands somewhere this loop has no spelling
		// for, and R15c refuses it as it refuses a cut name.
		r.unreadPath = rulePathTruncated
	}
	return p, raw
}

// resolve joins a relative path to its dirfd's directory. A dirfd whose directory was unlinked resolves
// to a " (deleted)" target: the suffix is stripped and the path marked unreliable rather than being
// concatenated verbatim (E8). A live directory whose own name ends in " (deleted)" keeps it. A path joined to
// either is answered by the walk alone (pathQuery.deletedBase).
func (r *reader) resolve(dirfd int32, p string) string {
	if strings.HasPrefix(p, "/") {
		return cleanPath(p)
	}
	var link string
	switch {
	case dirfd == atFDCWD:
		link = "/proc/" + strconv.Itoa(r.n.pid) + "/cwd"
		r.cwd = "" // set below from this read only
	case dirfd >= 0:
		link = "/proc/" + strconv.Itoa(r.n.pid) + "/fd/" + strconv.Itoa(int(dirfd))
	default:
		r.noDirfd = true // no descriptor has a negative number: the kernel answers EBADF
		r.mark(rulePathUnreliable)
		return cleanPath(p)
	}
	base, err := r.l.k.Readlink(link)
	// readlink spells an unlinked directory "<path> (deleted)", and a live directory may carry that very
	// name, which the agent chooses inside its write entries. Only the link count tells them apart: a live
	// directory has at least two links and an unlinked one has none. The stat is keyed by the pid as the
	// readlink is, so the ID_VALID below covers it too.
	deleted, unlinked := err == nil && strings.HasSuffix(base, deletedSuffix), false
	if deleted {
		gone, serr := r.l.k.Unlinked(link)
		unlinked = gone || serr != nil
	}
	// R2's second half, for the one read that is not a memory read: /proc/<pid>/{cwd,fd/N} is keyed by a
	// pid and the readlink is not atomic with the notification it belongs to, so only an ID_VALID after
	// it says that pid was still the task that trapped rather than one that reused the id (E3, E9b). The
	// pre-check is the caller's (path() re-checks between the cstring and this call; the connect path
	// re-checks after the sockaddr read), which is the same both-sides bracket the AT_EMPTY_PATH branch
	// of recordExec and recordSymlink's link target already carry. seccomp_unotify(2) states the hazard
	// for /proc/tid/mem — "the memory of the wrong process in the event that the target terminates and
	// its ID is recycled by another (unrelated) thread" — and a pid-keyed magic symlink is the same
	// address.
	if !r.l.valid(r.n) {
		return ""
	}
	if err != nil {
		// A descriptor the live task does not hold: its /proc entry is missing (a cwd always has one).
		r.noDirfd = dirfd != atFDCWD && errors.Is(err, unix.ENOENT)
		r.mark(rulePathUnreliable)
		return cleanPath(p)
	}
	if unlinked {
		base = strings.TrimSuffix(base, deletedSuffix)
		r.mark(rulePathUnreliable)
	}
	if !strings.HasPrefix(base, "/") {
		r.mark(rulePathUnreliable) // an fd that is not a directory: socket:[...], pipe:[...], anon_inode
		return cleanPath(p)
	}
	joined := base + "/" + p
	if len(joined) > pathMax {
		r.mark(rulePathTruncated)
		return ""
	}
	if dirfd == atFDCWD && !deleted {
		r.cwd = base
	}
	joined = cleanPath(joined)
	if deleted {
		// Either way the spelling may not be where the lookup starts: an unlinked directory's stripped path
		// can name a live one, and the descriptor may be replaced after the stat. The walk decides from the
		// dirfd itself.
		r.deleted = append(r.deleted, deletedJoin{dirfd: dirfd, joined: joined})
	}
	return joined
}

// argv reads an execve argument vector: the pointer array first, capped at argvEntries before a single
// string is read (E11), then each string against the shared byte budget (R3, R16). It reports whether
// either bound truncated the result, which becomes argv_truncated on the exec event (E10).
func (r *reader) argv(addr uint64, budget int) (out []string, truncated bool) {
	return r.argvLimited(addr, budget, argvEntries)
}

func (r *reader) argvLimited(addr uint64, budget, entries int) (out []string, truncated bool) {
	if addr == 0 {
		return nil, false
	}
	if !r.l.valid(r.n) {
		return nil, false
	}
	ptrs, more := r.pointersLimited(addr, entries)
	left := budget
	for _, p := range ptrs {
		if left <= 0 {
			truncated = true
			break
		}
		if p == 0 {
			continue
		}
		s, cut := r.cstring(p, min(left, argMax))
		if r.n.gone {
			return out, true
		}
		truncated = truncated || cut
		left -= len(s) + 1
		out = append(out, s)
	}
	if !r.l.valid(r.n) {
		return out, true
	}
	return out, truncated || more
}

func (r *reader) pointersLimited(addr uint64, entries int) (out []uint64, more bool) {
	const wordsPerRead = 64
	var words [wordsPerRead * 8]byte
	for len(out) < entries && !r.n.gone {
		want := min(wordsPerRead, entries-len(out))
		n := r.read(addr, words[:want*8])
		if n < 8 {
			if len(out) == 0 {
				r.fail(ruleArgsUnreadable)
				return out, false
			}
			// The array ran into something unreadable before its NULL terminator: what was collected is
			// a prefix of the real argv, which is exactly what argv_truncated exists to say (E10, E11).
			return out, true
		}
		for i := 0; i+8 <= n; i += 8 {
			p := leU64(words[i : i+8])
			if p == 0 {
				return out, false
			}
			out = append(out, p)
		}
		addr += uint64(n / 8 * 8)
	}
	if r.n.gone || len(out) < entries {
		return out, false
	}
	// The cap is reached. An array of exactly entries pointers ends in its NULL right here, and nothing
	// was cut; only a pointer past the cap, or a word that cannot be read, is more.
	n := r.read(addr, words[:8])
	return out, n < 8 || leU64(words[:8]) != 0
}

// leU64 decodes a little-endian 64-bit word; both supported architectures are little-endian.
func leU64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// leU32 decodes a little-endian 32-bit word.
func leU32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// cleanPath is path.Clean on an absolute path, with a lone "/" preserved; it never touches the filesystem.
func cleanPath(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

// min64 is the smaller of two int64s.
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
