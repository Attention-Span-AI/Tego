// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// struct msghdr and struct mmsghdr as the 64-bit kernel lays them out; both supported architectures use
// the same LP64 layout, so these offsets are constants rather than anything read from the target (R12).
const (
	msgNameOff       = 0  // void *msg_name
	msgNameLenOff    = 8  // socklen_t msg_namelen (4 bytes, 4 padding)
	msgIovOff        = 16 // struct iovec *msg_iov
	msgIovLenOff     = 24 // size_t msg_iovlen
	msgControlOff    = 32 // void *msg_control
	msgControlLenOff = 40 // size_t msg_controllen
	msgHdrSize       = 56 // sizeof(struct msghdr)
	mmsgHdrSize      = 64 // sizeof(struct mmsghdr): msghdr + unsigned msg_len, padded
	iovecSize        = 16 // sizeof(struct iovec)
	iovecBaseOff     = 0
	iovecLenOff      = 8
)

// handleSendTo decides a sendto that carries a destination address. On a stream socket it is TCP Fast
// Open and is decided exactly like a connect (R12): allowed, the bytes are relayed on the duplicate so
// they really leave on the target's own connection, and the real byte count or errno is the answer;
// refused, refusalErrno before any byte leaves the kernel. On a datagram socket the address is read and
// matched: a destination the policy refuses is refused, and an admitted one is continued (R13b) — the
// unprivileged tier's stated best-effort limit is that the kernel then reads the address again, which the root
// tiers close with cgroup/sendmsg — save on an IP socket under the models[] guard, where one the guard admits is
// relayed on the duplicate (R7, sendDecisionCtl, relayDatagram). An address this tier cannot
// match at all (an unrecognised family, or AF_UNSPEC outside connect(2)) is refused on every socket type,
// connected ones included, under a net: section, and AF_UNSPEC under any contract; the socket is read only
// so the refusal names its protocol (R4, E4, R7; refusesUndecidable). MSG_FASTOPEN on a stream socket is
// decided as R12 even when the socket has a peer (sendDecisionCtl).
func handleSendTo(l *Loop, n *notif) {
	addr, addrlen := n.args[4], socklen(n.args[5])
	if addr == 0 || addrlen == 0 {
		// No destination: nothing this package decides about one. The filter notifies such a sendto only when its
		// flags carry MSG_MORE in a run that decides datagrams (enforce-landlock R11), for the pending frame it could
		// start (refusesFrame); otherwise it tests only the pointer. A zero addrlen with a pointer is the kernel's
		// unaddressed send too: move_addr_to_kernel copies nothing, and every family either sends to the peer
		// connect decided (TCP without Fast Open, unix, raw) or fails the short name EINVAL (UDP, Fast Open). The
		// length is a register, so no sibling can lengthen it after the CONTINUE — unlike sendmsg's msg_namelen,
		// which is why sendUnaddressed relays some of those.
		if l.refusesFrame(n, l.table.Load(), int(int32(n.args[0])), n.args[3], dest{}) {
			return
		}
		l.respond(n, respContinue())
		return
	}
	r := l.newReader(n)
	raw := r.sockaddr(addr, addrlen)
	if n.gone {
		return
	}
	d := parseSockaddr(raw)
	if l.refusesFrame(n, l.table.Load(), int(int32(n.args[0])), n.args[3], d) {
		return
	}
	l.sendDecision(n, r, int(int32(n.args[0])), d, raw, n.args[3], func() (sendArgs, bool) {
		payload := r.blob(n.args[1], clampLen(n.args[2]), sendBytes)
		// Both of these mean the notification is gone, and respond is a no-op for it (R19).
		if n.gone || !l.valid(n) {
			return sendArgs{}, false
		}
		whole := n.args[2] <= sendBytes && uint64(len(payload)) == n.args[2] && !r.failed
		return sendArgs{payload: payload, flags: int(int32(n.args[3])), whole: whole, addrErr: shortAddrErr(addrlenErr(addrlen), raw, addrlen)}, true
	})
}

// sendArgs is what a relayed send needs once the decision is made: the bytes to send and the flags to
// send them with. They are gathered on the worker, before the relay goroutine exists, because the reader
// they come out of is pooled and returned the moment the handler finishes — nothing the relay touches may
// be read out of it after that.
type sendArgs struct {
	payload []byte
	flags   int
	// whole says payload is every byte the call would send: nothing was cut at sendBytes or msgIovs and no
	// read came up short. A stream may legally send fewer bytes than asked, so a Fast-Open relay ignores it;
	// a datagram is sent whole or not at all, so a relayed one needs it (relayDatagram).
	whole bool
	// addrErr is the kernel's own error for the address the call carried (addrlenErr, msgNameErr,
	// shortAddrErr): a relay answers it instead of sending, since the clamped or short address it read
	// would send where the target's own call fails.
	addrErr error
	// sendErr is the kernel's own error for a payload it would send none of (gather): an iovlen past
	// UIO_MAXIOV, an iovec array that cannot be read, a first buffer that faults. A relay answers it instead
	// of sending, after addrErr, which __copy_msghdr checks first.
	sendErr error
}

// handleSendMsg decides a sendmsg. The filter notifies every sendmsg because classic BPF cannot
// dereference msg_name (enforce-landlock R11), so the first thing this does is read the header: a
// connected send with no address is continued with no event at all, save where sendUnaddressed says. Under a
// net: section a send whose control messages give its datagram a source route is refused first, addressed or
// not (refusesRoute, R13b).
func handleSendMsg(l *Loop, n *notif) {
	r := l.newReader(n)
	var hdr [msgHdrSize]byte
	if !l.valid(n) {
		return
	}
	if got := r.read(n.args[1], hdr[:]); got < msgHdrSize {
		if n.gone {
			return
		}
		// R5 splits here: a send with an address is a decision kind, but an unreadable header means we
		// cannot even tell whether there was one. Fail closed: this is the connect-class path — save under a
		// contract that decides nothing (passesUnresolved).
		if c := l.table.Load(); c.passesUnresolved(r, dest{}, false) {
			l.continueUnresolved(n, c, r, dest{}, protoTCP, noteOr(r, ruleArgsUnreadable))
			return
		}
		l.respond(n, respErrno(refusalErrno))
		l.emitNet(n, l.table.Load(), dest{}, protoTCP, refuse(noteOr(r, ruleArgsUnreadable)), record.VerdictRefused, netMarks{})
		return
	}
	if !l.valid(n) {
		return
	}
	name, namelen := leU64(hdr[msgNameOff:]), int64(leU32(hdr[msgNameLenOff:]))
	iov, iovlen := leU64(hdr[msgIovOff:]), leU64(hdr[msgIovLenOff:])
	ctl := ctlOf(hdr[:])
	control := ctl.len != 0
	var ctls []msgCtl // refusesRoute reads the control messages, which can route the datagram (R13b)
	if control {
		ctls = []msgCtl{ctl}
	}
	addrErr := msgNameErr(name, namelen) // a short read of the name adds EFAULT below, once it is read
	prepare := func() (sendArgs, bool) {
		payload, whole, sendErr := l.gather(r, iov, iovlen)
		if n.gone || !l.valid(n) {
			return sendArgs{}, false
		}
		return sendArgs{payload: payload, flags: int(int32(n.args[2])), whole: whole && !r.failed, addrErr: addrErr, sendErr: sendErr}, true
	}
	if unaddressed(name, namelen) {
		if l.refusesFrame(n, l.table.Load(), int(int32(n.args[0])), n.args[2], dest{}) {
			return
		}
		if l.refusesRoute(n, r, int(int32(n.args[0])), dest{}, ctls) {
			return // a connected datagram is routed by its control messages too (udp_sendmsg's faddr)
		}
		l.sendUnaddressed(n, control, prepare)
		return
	}
	raw := r.sockaddr(name, namelen)
	if n.gone {
		return
	}
	addrErr = shortAddrErr(addrErr, raw, namelen)
	d := parseSockaddr(raw)
	if l.refusesFrame(n, l.table.Load(), int(int32(n.args[0])), n.args[2], d) {
		return
	}
	if l.refusesRoute(n, r, int(int32(n.args[0])), d, ctls) {
		return
	}
	l.sendDecisionCtl(n, r, int(int32(n.args[0])), d, raw, control, n.args[2], prepare)
}

// sendUnaddressed decides a sendmsg whose header names no destination. Such a send goes to the socket's
// peer, which connect decided (R13a), and is continued with no event — save where continuing it hands the
// destination back to the target's memory. After a CONTINUE the kernel copies the msghdr again
// (___sys_sendmsg, copy_msghdr_from_user), so a sibling thread that wrote an address into msg_name in between
// sends to that address, which nothing decided and no line names:
//
//   - a datagram, raw or seqpacket send on an IP socket under the models[] guard (R7), where udp_sendmsg and
//     raw_sendmsg send to a msg_name they are given, connected socket or not, and the guard's verdict is the
//     only one at tier 2 as well: the rewrite reached the model around the forwarder;
//   - MSG_FASTOPEN on an IP stream socket whose connects are decided (a net: section, the guard, or a live net
//     block, decidesFastOpen), where tcp_sendmsg_fastopen connects a peerless socket to the msg_name the kernel reads
//     (R12).
//
// Both are relayed on the duplicate as they were read, with no address: the kernel sends the datagram to the
// socket's peer, or answers the Fast-Open send as it would the send as read (EINVAL with no peer, EISCONN
// with one), and the relayed result is the answer (I3). Nothing new is decided, so a relayed send writes no
// line, as the continued one did not. A datagram is sent whole or not at all, so one a relay cannot reproduce
// is refused (relayDatagram), and so, on either, are ancillary data and MSG_ZEROCOPY, which a relay cannot
// honour (zeroCopy). MSG_FASTOPEN is read from the syscall's own
// flags argument, which no sibling can rewrite. A stream send without it is continued: TCP never reads
// msg_name outside Fast Open, and a deferred connect (TCP_FASTOPEN_CONNECT) sends to the address its connect
// named. A send with MSG_MORE that could leave a frame pending to the socket's peer never reaches here: handleSendMsg
// asked refusesFrame first, as every send handler does.
func (l *Loop) sendUnaddressed(n *notif, control bool, prepare func() (sendArgs, bool)) {
	c := l.table.Load()
	fo := fastOpen(n.args[2])
	if !c.pol.Rules.Gate.Has(gate.Net) && c.guard == nil && (!c.decidesFastOpen() || !fo) {
		// Nothing about an address is decided here: a datagram's is R13b's best effort at this tier, and
		// with no net: section a connect is not decided at all.
		l.respond(n, respContinue()) // connected socket: decided at connect (R13a)
		return
	}
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if n.gone {
			return
		}
		l.refuseNet(n, dest{}, protoOf(0, 0, dest{}), refuse(why))
		return
	}
	defer func() { l.closeDup(t.dup) }()
	t.proto = protoOf(t.sockType, t.sockProto, dest{})
	datagram := (t.guarded || (c.pol.Rules.Gate.Has(gate.Net) && l.ipDomain(c, &t))) && t.sockType != unix.SOCK_STREAM
	if !datagram && !(fo && t.sockType == unix.SOCK_STREAM && l.ipDomain(c, &t)) {
		l.respond(n, respContinue())
		return
	}
	if control {
		l.refuseNet(n, dest{}, t.proto, refuse(ruleAncillary))
		return
	}
	args, ready := prepare()
	if !ready {
		return // R19
	}
	if datagram && !args.whole {
		l.refuseNet(n, dest{}, t.proto, refuse(ruleDatagramSize))
		return
	}
	if zeroCopy(args.flags) {
		l.refuseNet(n, dest{}, t.proto, refuse(ruleZeroCopy))
		return
	}
	if datagram && !l.frameFree(&t, args.flags) {
		l.refuseNet(n, dest{}, t.proto, refuse(ruleCorked))
		return
	}
	l.relayToPeer(n, &t, args, nil)
}

// relayToPeer performs a send on the duplicate that goes to the socket's peer, which connect decided (R13a), and
// answers with its real result (I3) and no line: nothing new is decided (sendUnaddressed, sendConnectedUnixOnly). sa
// is the address the call carried where the kernel answers it without reading it (a connected unix stream socket's
// EISCONN), nil otherwise; the kernel's own answer to that address's length comes first, as in relaySend.
func (l *Loop) relayToPeer(n *notif, t *target, args sendArgs, sa []byte) {
	res, out := l.relay(n, t, func(dup int) resp {
		if args.addrErr != nil {
			return respResult(0, args.addrErr) // the kernel's own answer to that length: nothing is sent
		}
		if args.sendErr != nil {
			return respResult(0, args.sendErr) // the kernel's own answer to that payload: nothing is sent
		}
		sent, err := l.k.SendToRaw(dup, args.payload, args.flags, sa)
		return respResult(sent, err)
	})
	switch out {
	case relayDone:
		pipe := l.pipeSignal(n, t, res, args.flags)
		l.respond(n, res)
		l.raisePipe(n, pipe)
	case relayLimited:
		l.refuseNet(n, dest{}, t.proto, refuse(ruleRelayLimit))
	}
	// relayOrphaned: the bytes went to the peer connect decided, as a continued send's would have, and that
	// wrote no line either (E35's line is for a decision this loop carried out). relayCancelled: the run is
	// ending with the send in flight; there is nothing honest to answer (I3).
}

// sendConnectedUnixOnly answers an addressed send without MSG_FASTOPEN on a connected stream or seqpacket socket in
// ADR 0070's unix-only state. The kernel never reads such a send's address (tcp_sendmsg and unix_seqpacket_sendmsg
// drop it and send to the peer the connect decided; unix_stream_sendmsg answers it EISCONN before it reads the name or
// the payload), so nothing here decides or records it, and no line is written, as R13a writes none (relayed as a
// decision, the ignored name was recorded as the destination and refused when foreign, and a record past sendBytes
// was cut). What the state adds is the descriptor: continued, the kernel looks the number up again, and a
// sibling that dup2s an unconnected unix datagram socket over it and writes a host socket's name into the address
// reaches that socket. So, keyed on the duplicate's own domain and type, which no dup2 changes:
//   - a unix stream socket: the send is made on the duplicate with the copied address and without ancillary data, and
//     the kernel's answer is the result (EISCONN; EOPNOTSUPP for MSG_OOB where the kernel has no out-of-band data):
//     nothing is sent. An SCM_RIGHTS array is not passed on; the kernel validates one before it rejects the name, so a
//     malformed array's errno (EINVAL, EBADF) is EISCONN here, and the call sends nothing either way. Natively such a
//     send always fails; multiprocessing and Ray pass descriptors with no address (sendUnaddressed);
//   - an IP stream socket: the payload goes to the peer on the duplicate with no address, as sendUnaddressed relays,
//     where the relay reproduces the call exactly: no ancillary data, no MSG_ZEROCOPY, the payload read whole. A
//     larger one is continued rather than cut at sendBytes, since a blocking stream send returns every byte;
//   - a seqpacket socket: continued. A unix one's receiver reads the sender's pid in SCM_CREDENTIALS (the DNS broker
//     authenticates by it), which no relay from this process gives, and a record is sent whole, which a relay cannot
//     promise past sendBytes;
//   - a socket of a domain the state does not reach, or whose domain could not be read: refused (hostSocketRelayable).
//
// What is continued is the run_start cell host_sockets/datagram's residual, which below Landlock ABI 9 the agent can
// choose by the shape of its call (ADR 0070 Decision 3).
func (l *Loop) sendConnectedUnixOnly(n *notif, t *target, d dest, raw []byte, control bool, flags uint64, prepare func() (sendArgs, bool)) {
	switch {
	case !hostSocketRelayable(t.domain):
		l.refuseNet(n, d, t.proto, refuse(ruleHostSockets))
	case t.sockType != unix.SOCK_STREAM, t.domain != unix.AF_UNIX && (control || zeroCopy(int(int32(flags)))):
		l.respond(n, respContinue())
	default:
		args, ready := prepare()
		if !ready {
			return // R19: the target died while its payload was being read; there is nothing to answer
		}
		switch {
		case t.domain == unix.AF_UNIX:
			l.relayToPeer(n, t, args, raw)
		case args.whole:
			l.relayToPeer(n, t, args, nil)
		default:
			l.respond(n, respContinue())
		}
	}
}

// ipDomain reports whether t's socket is an AF_INET or AF_INET6 one, as a Fast-Open send with no address
// needs: a unix stream socket refuses a msg_name (unix_stream_sendmsg), so only an IP one can be redirected,
// and a relay on a unix one would have the listener read this process's credentials. Under the models[]
// guard or a net gate resolveSocket read the domain already; otherwise it is read here, and a domain that
// cannot be read is taken as IP, the side that decides.
func (l *Loop) ipDomain(c *compiled, t *target) bool {
	if c.guard != nil || c.pol.Rules.Gate.Has(gate.Net) {
		return t.guarded || t.ipGated
	}
	dom, err := l.k.SockDomain(t.dup)
	return err != nil || dom == unix.AF_INET || dom == unix.AF_INET6
}

// unaddressed reports whether a msghdr names no destination, by the kernel's own test: __copy_msghdr
// keeps an address only when msg_name is set and msg_namelen is not zero, and sets kmsg->msg_name to NULL
// otherwise. A message with a pointer and a zero length therefore goes to the socket's peer exactly as a
// NULL one does, which connect already decided (R13a); reading its "address" failed as unreadable (the
// reader refuses a zero length) and refused a send the kernel delivers.
func unaddressed(name uint64, namelen int64) bool { return name == 0 || namelen == 0 }

// clampLen reads a size_t length argument, clamped to what an int64 can carry so an absurd length becomes
// a bounded read rather than a negative one.
func clampLen(arg uint64) int64 {
	if arg > uint64(sendBytes) {
		return sendBytes
	}
	return int64(arg)
}

// handleSendMMsg decides one sendmmsg. The filter notifies every sendmmsg because classic BPF cannot
// dereference msg_name (enforce-landlock R11), so the socket type read here is what splits the two rules
// that meet in this handler: on a datagram socket the addressed messages are recorded — the first 64 one
// line each, and past them one line at most (mmsgTailLine) — and the syscall continued when the policy admits
// every destination the batch carries, and refused whole when it refuses one (R13b), and on a
// stream socket without a peer, or on any stream socket when MSG_FASTOPEN is set, an addressed message,
// wherever it lies in the batch, is the TCP Fast Open shape R12 decides exactly like a connect (R13c). On
// every socket type, a batch in which a message the kernel would send carries an address that refuses the
// same message passed to sendmsg is refused whole (R4, E4, R7; refusesUndecidable), and so, on an IP socket
// under the models[] guard, is every batch that carries an address (R7): one datagram there is relayed
// (relayDatagram), which a batch cannot be.
//
// The batch form is refused rather than relayed, whatever the destination matched. R12's relay works by
// performing the send on the duplicate and answering with its real result, and sendmmsg's result is not
// only a number: the kernel writes each message's byte count back into the caller's own mmsghdr array,
// and this loop reads the target's memory but never writes it. A relayed batch would therefore answer a
// count the target could not reconcile with its own msg_len fields, which is the fabricated result I3
// forbids — the same reason ancillary data is refused rather than dropped. Nothing is lost by it: the
// one-message forms sendto and sendmsg are relayed in full, so Fast Open to a declared host stays
// available, and an agent that reaches for the batch form of a connect-class operation gets R10's errno
// instead of a CONTINUE that would have let the bytes out to any host on a declared port (I2). An
// observe run is the exception (R30): respond answers that refusal CONTINUE, because nothing is enforced
// there, and each recorded message's line says observed. Under a net: section a batch in which any message the
// kernel sends carries a control message that routes its datagram is refused whole (refusesRoute, R13b).
func handleSendMMsg(l *Loop, n *notif) {
	r := l.newReader(n)
	c := l.table.Load()
	// The read stops only at an address that refuses the batch on every socket, since the socket is not
	// read yet; what a guarded IP socket refuses besides is asked of every entry once it is (below).
	head, tail, ctls := l.mmsgDests(r, n, func(d dest) bool { return c.refusesUndecidable(d, false, false) })
	if n.gone {
		return
	}
	// The first address the batch carries, wherever it lies, is what names the batch's protocol and what a
	// refusal made before any destination was decided is recorded against.
	var first dest
	if len(head) > 0 {
		first = head[0]
	} else if len(tail) > 0 {
		first = tail[0]
	}
	if uint32(n.args[2]) != 0 && l.refusesFrame(n, c, int(int32(n.args[0])), n.args[3], first) {
		return // its messages would form one frame, and one left pending would take the socket's next datagram
	}
	if c.netOpen && c.guard == nil && !c.recording() {
		// passesUnrecorded, asked of every address the batch carries.
		pass := true
		for _, ds := range [][]dest{head, tail} {
			for _, d := range ds {
				pass = pass && c.passesUnrecorded(r, d, false)
			}
		}
		if pass {
			l.respond(n, respContinue())
			return
		}
	}
	if !r.ok() {
		if c.passesUnresolved(r, dest{}, false) {
			l.continueUnresolved(n, c, r, dest{}, protoTCP, noteOr(r, ruleArgsUnreadable))
			return
		}
		l.refuseNet(n, dest{}, protoTCP, refuse(noteOr(r, ruleArgsUnreadable)))
		return
	}
	if l.refusesRoute(n, r, int(int32(n.args[0])), first, ctls) {
		return // one message's control messages route its datagram, so the batch is refused whole (R13b)
	}
	if len(head) == 0 && len(tail) == 0 {
		// The headers remain mutable until the kernel copies them. A guarded IP datagram batch cannot
		// be continued merely because these copies have no destination. ENOSYS identifies unsupported
		// batching; guarded launches configure glibc for individual queries instead of msg_len writes.
		if uint32(n.args[2]) != 0 && (c.guard != nil || c.pol.Rules.Gate.Has(gate.Net) || (fastOpen(n.args[3]) && c.decidesFastOpen())) {
			l.unaddressedBatch(n, c)
			return
		}
		l.respond(n, respContinue())
		return
	}
	// The socket type is what decides which rule this batch falls under, so it is read before anything is
	// answered, and a failure to read it fails closed like a failed duplicate (§7, E33).
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if n.gone {
			return
		}
		// Every address read is asked: one that refuses the batch on every socket refuses it without the
		// socket too (passesUnresolved).
		passes := true
		for _, ds := range [][]dest{head, tail} {
			for _, d := range ds {
				passes = passes && c.passesUnresolved(r, d, false)
			}
		}
		if passes {
			l.continueUnresolved(n, c, r, first, protoOf(0, 0, first), why)
			return
		}
		l.refuseNet(n, first, protoOf(0, 0, first), refuse(why))
		return
	}
	defer l.closeDup(t.dup)
	proto := protoOf(t.sockType, t.sockProto, first)
	stream := t.stream()
	if c.pol.Rules.Gate.Has(gate.Net) && !(stream && !fastOpen(n.args[3]) && l.k.Connected(t.dup)) {
		dec := verdictOf{rule: ruleBatchSend, kernelReason: record.ReasonNetGate, unsupported: true}
		for _, ds := range [][]dest{head, tail} {
			for _, d := range ds {
				base := l.decide(c, r, d, proto, false, t.guarded)
				if !base.allowed && !base.continued {
					// The ordinary refusal is the floor for the whole batch, even if
					// another entry already accumulated a stronger gate score.
					l.refuseNet(n, d, proto, base)
					return
				}
				candidate, g := l.gateNet(c, r, d, proto, base, gate.Allow)
				if g != nil && g.Verdict != gate.Allow && (dec.gate == nil || g.Verdict > dec.gate.Verdict || g.Score > dec.gate.Score) {
					candidate.allowed = false
					candidate.continued = false
					candidate.rule = g.Rule
					candidate.kernelReason = record.ReasonNetGate
					candidate.unsupported = g.Verdict == gate.Ask
					dec = candidate
					first = d
				}
			}
		}
		l.respond(n, respErrno(unix.ENOSYS))
		l.emitNet(n, c, first, proto, dec, record.VerdictRefused, netMarks{})
		return
	}
	// A message whose address this tier cannot place — an unrecognised family, or AF_UNSPEC, which
	// udp_sendmsg and raw_sendmsg send to as a sockaddr_in — is never matched, and the same msghdr passed to
	// sendmsg is refused outright, on every socket type, when refusesUndecidable says so (resolveTarget).
	// Continuing it here would make the batch form with vlen=1 the way around that refusal, the evasion R12
	// already closes for the stream shape, so a batch holding one is refused whole whatever the socket is.
	// mmsgDests read the addressed messages up to the kernel's own clamp, not only the ones recorded, so
	// every message the kernel would send is asked here: one answer covers the syscall, and none of its
	// messages leaves when one of them cannot be decided. The question is asked of every entry read, not of
	// where mmsgDests stopped reading, so the refusal does not rest on that early stop.
	undecidable := false
	for _, ds := range [][]dest{head, tail} {
		for _, d := range ds {
			if c.refusesUndecidable(d, false, t.guarded) {
				undecidable = true
			}
		}
	}
	if stream && !undecidable && !fastOpen(n.args[3]) && l.k.Connected(t.dup) {
		// The socket has a peer, so the kernel ignores every msg_name in the batch and the bytes go where
		// the connect decision already sent them (R13a). Nothing here is a new decision, and recording the
		// ignored addresses would invent refusals for destinations nothing was sent to. Not with
		// MSG_FASTOPEN, which makes tcp_sendmsg connect to msg_name whenever the socket has no peer by
		// the time the kernel runs it (see sendDecisionCtl).
		l.respond(n, respContinue())
		return
	}
	// R13b continues a datagram batch only when every address the kernel will send to was read, is one this
	// tier could match, and is one the policy admits: a batch that carries a destination the policy refuses is
	// refused whole, with R10's errno, as that message passed to sendmsg is (amended 2026-10-16, before, it was
	// continued with that destination's refused line marked best_effort, and the datagram left).
	// Each of the first 64 addressed messages has its own line, and past them one line names the message that
	// refused the batch, or the first addressed one there (mmsgTailLine).
	//
	// With no net: section there is no destination to protect (decide admits every one), so R13c's stream
	// refusal does not apply: it refuses because a decision could not be carried out, and here none is
	// needed. An unrecognised family is continued there too, and undecidable is already false for it;
	// AF_UNSPEC still refuses the batch, as it refuses sendmsg (refusesUndecidable). A continued batch's
	// lines are best-effort. An IP socket under a models[] guard is the exception, decided as under a net:
	// section (decideGuarded): a batch there, Fast-Open or datagram, is refused whole whatever its messages
	// matched. A continued one would have the kernel read every address again after this loop read it, so a
	// sibling that rewrote one to the guarded endpoint in between reached the model around the forwarder,
	// and this loop cannot relay a batch as it relays one datagram (relayDatagram): sendmmsg's result is
	// written into the caller's array, which this loop never writes (I3). A message the guard refuses names
	// the refusal; the others are recorded batch-send. A live net block decides a stream batch the same way
	// (decidesFastOpen): continued, the kernel would read an address the block was matched against again.
	refused := (stream && (c.decidesFastOpen() || t.guarded)) || t.guarded || undecidable
	decisions := make([]verdictOf, len(head))
	for i, d := range head {
		decisions[i] = l.decide(c, r, d, proto, false, t.guarded)
		refused = refused || !decisions[i].allowed
	}
	if !refused {
		for _, d := range tail {
			if !l.decide(c, r, d, proto, false, t.guarded).allowed {
				refused = true
				break
			}
		}
	}
	if refused {
		for i := range decisions {
			if decisions[i].allowed {
				// The destination is admitted; the batch it arrived in is what refused it.
				decisions[i] = refuse(ruleBatchSend)
			}
		}
	}
	td, tdec, tline := l.mmsgTailLine(c, r, n, tail, proto, refused, t.guarded)
	if refused {
		l.respond(n, respErrno(refusalErrno))
	} else {
		l.respond(n, respContinue())
	}
	for i, d := range head {
		l.emitNet(n, c, d, proto, decisions[i], netVerdict(d, decisions[i]), netMarks{bestEffort: !refused})
	}
	if tline {
		l.emitNet(n, c, td, proto, tdec, netVerdict(td, tdec), netMarks{bestEffort: !refused})
	}
}

// unaddressedBatch answers a sendmmsg that carries no address in any message the kernel
// sends. Guarded IP non-stream batches return ENOSYS: callers must use sendmsg/sendto, whose
// datagrams are relayed from immutable copies. Ordinary stream sends ignore msg_name (R13a).
// It also handles a batch that carries MSG_FASTOPEN and no address in any message the kernel
// sends, under a net: section, the models[] guard or a live net block (decidesFastOpen). After a CONTINUE the kernel copies each msghdr again, and
// a sibling that writes an address into the first one's msg_name has tcp_sendmsg_fastopen connect a peerless
// IP stream socket to it, a host nothing decided (R12). An addressed Fast-Open batch is already refused
// (R13c) and this one cannot be relayed either, so on an IP stream socket it is refused whole, rule
// batch-send. The kernel's own answer to the batch as read is EINVAL with no peer and EISCONN with one; only
// a socket connected with TCP_FASTOPEN_CONNECT would have sent, and sendmsg relays that send
// (sendUnaddressed). Every other socket is continued as before; a batch with MSG_MORE that could leave a frame
// pending never reaches here (refusesFrame, asked first by handleSendMMsg).
func (l *Loop) unaddressedBatch(n *notif, c *compiled) {
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if n.gone {
			return
		}
		l.refuseNet(n, dest{}, protoOf(0, 0, dest{}), refuse(why))
		return
	}
	defer l.closeDup(t.dup)
	if (t.guarded || (c.pol.Rules.Gate.Has(gate.Net) && l.ipDomain(c, &t))) && t.sockType != unix.SOCK_STREAM {
		l.respond(n, respErrno(unix.ENOSYS))
		l.emitNet(n, c, dest{}, protoOf(t.sockType, t.sockProto, dest{}), refuse(ruleBatchSend), record.VerdictRefused, netMarks{})
		return
	}
	if fastOpen(n.args[3]) && t.sockType == unix.SOCK_STREAM && l.ipDomain(c, &t) {
		l.refuseNet(n, dest{}, protoOf(t.sockType, t.sockProto, dest{}), refuse(ruleBatchSend))
		return
	}
	l.respond(n, respContinue())
}

// mmsgTailLine picks the one line a batch gets for its messages past mmsgMessages. One line keeps the
// ledger bounded at mmsgMessages+1 lines per call. A refused batch gets a line for the message that refused it
// when that lies past the 64th — one this tier cannot place, or one the policy refuses — else for the first
// addressed message there, which the batch refused along with it. A continued batch carries no destination the
// policy refuses (handleSendMMsg refuses every such batch, R13b as amended 2026-10-16), so it gets no line past
// the 64th: what stays unrecorded there is R13b's residual, the admitted destinations. The last result is
// false when there is no line to write.
func (l *Loop) mmsgTailLine(c *compiled, r *reader, n *notif, tail []dest, proto string, refused, guarded bool) (dest, verdictOf, bool) {
	if len(tail) == 0 || !refused {
		return dest{}, verdictOf{}, false
	}
	// The message that refused the batch, when it lies past the 64th, wherever in the tail it is.
	for _, d := range tail {
		if c.refusesUndecidable(d, false, guarded) {
			return d, refuse(ruleUnmatched), true
		}
		if dec := l.decide(c, r, d, proto, false, guarded); !dec.allowed {
			return d, dec, true
		}
	}
	d := tail[0]
	dec := l.decide(c, r, d, proto, false, guarded)
	if dec.allowed {
		dec = refuse(ruleBatchSend) // admitted; the batch it arrived in is what refused it
	}
	return d, dec, true
}

// mmsgDests reads a sendmmsg batch's destinations: head is every addressed message among the first
// mmsgMessages, each of which the batch records, and tail every addressed message past them up to and
// including the first whose address refuses the batch (stops, refusesUndecidable), which ends the read.
// A run of consecutive tail messages carrying the same address bytes is kept once, since the decision
// and the line mmsgTailLine can write for it are the same for each. A failed read is left on r for the
// caller (R5).
//
// The array is read as far as the kernel will send, not as far as the ledger records. __sys_sendmmsg
// clamps vlen to UIO_MAXIOV and then runs every message up to it, so a batch read only to mmsgMessages
// would CONTINUE with an AF_UNSPEC message at index 64 unread and udp_sendmsg would deliver it to the
// sockaddr_in behind the family word — the vlen=1 evasion the batch refusal closes, moved to vlen=65 —
// and a datagram past the 64th addressed to a host the policy does not admit would leave with no line in
// the ledger, which at this tier is R13b's only control. Both hold when the first mmsgMessages carry no
// address at all, which is why this runs before the caller's "nothing addressed" CONTINUE.
//
// The headers are one bracketed read of the whole array, and each address its own bracketed read (R2).
// A header the read did not reach is one the kernel is about to read: not "no destination" but not
// knowing whether there was one, on a syscall that may be the Fast-Open shape, so R5 fails it closed the
// way an unreadable sendmsg header already is.
//
// ctls are the control buffers of every message the kernel sends that carries one, addressed or not, taken from the
// header array before any address is read: one may route its datagram (refusesRoute).
func (l *Loop) mmsgDests(r *reader, n *notif, stops func(dest) bool) (head, tail []dest, ctls []msgCtl) {
	count := int(uint32(n.args[2])) // vlen is an unsigned int
	if count > mmsgKernelMax {
		count = mmsgKernelMax
	}
	if count == 0 || !l.valid(n) {
		return nil, nil, nil
	}
	hdrs := make([]byte, count*mmsgHdrSize)
	got := r.read(n.args[1], hdrs)
	if !l.valid(n) {
		return nil, nil, nil
	}
	if got < len(hdrs) {
		r.fail(ruleArgsUnreadable)
		return nil, nil, nil
	}
	for i := 0; i < count; i++ {
		if ctl := ctlOf(hdrs[i*mmsgHdrSize:]); ctl.len != 0 {
			ctls = append(ctls, ctl)
		}
	}
	var prev []byte // the address bytes of the last tail message kept
	for i := 0; i < count; i++ {
		hdr := hdrs[i*mmsgHdrSize:]
		name, namelen := leU64(hdr[msgNameOff:]), int64(leU32(hdr[msgNameLenOff:]))
		if unaddressed(name, namelen) {
			continue // a connected message in the batch: decided at connect (R13a)
		}
		raw := r.sockaddr(name, namelen)
		if !r.ok() {
			return nil, nil, nil
		}
		d := parseSockaddr(raw)
		if i < mmsgMessages {
			head = append(head, d)
			continue
		}
		if prev != nil && bytes.Equal(raw, prev) {
			continue
		}
		prev = raw
		tail = append(tail, d)
		if stops(d) {
			// One is enough to refuse the batch, and it is what the refusal's line names; the rest would
			// cost a read each and change neither. handleSendMMsg and mmsgTailLine ask every entry, so
			// neither depends on this being the last one. An address that does not refuse the batch — an
			// unrecognised family under no net: — is read past, so a later one that does is still reached.
			return head, tail, ctls
		}
	}
	return head, tail, ctls
}

// zeroCopy reports whether a send's flags argument carries MSG_ZEROCOPY, which a relay refuses rather than
// performs or strips (ruleZeroCopy). On a socket with SO_ZEROCOPY the kernel pins the pages of the buffer it
// is given and may transmit from them after the call returns; in a relay that buffer is this process's heap,
// and the completion that says the pages are free goes to the target's error queue, so this process never
// learns when the slice may be reused, and whatever the Go heap put there next could leave for a peer the
// agent chose. Stripping the flag sends a copy, but the target then waits on its error queue for a completion
// the kernel never makes, a relayed result that is not the call's (I3). SO_ZEROCOPY is not read: a sibling
// thread could set it between that read and the relay, while the flags argument no sibling can rewrite.
func zeroCopy(flags int) bool { return flags&unix.MSG_ZEROCOPY != 0 }

// fastOpen reports whether a send's flags argument carries MSG_FASTOPEN. With it, tcp_sendmsg connects to
// msg_name whenever the socket has no peer when the kernel runs the send, so a stream socket that had a
// peer when this loop looked is not enough to leave the address undecided (R12, R13a).
func fastOpen(flags uint64) bool { return int(int32(flags))&unix.MSG_FASTOPEN != 0 }

// sendDecision is sendDecisionCtl for a send that carries no ancillary data.
func (l *Loop) sendDecision(n *notif, r *reader, sockfd int, d dest, raw []byte, flags uint64, prepare func() (sendArgs, bool)) {
	l.sendDecisionCtl(n, r, sockfd, d, raw, false, flags, prepare)
}

// sendDecisionCtl is the shared body of sendto and sendmsg: resolve the socket, then either decide it
// like a connect (a stream socket without a peer, or any stream socket when the send carries
// MSG_FASTOPEN, R12), continue it (a stream socket with a peer, R13a), relay it (a datagram on an IP socket
// under the models[] guard, R7, or one a network gate admits), refuse it (a datagram whose destination the policy
// refuses, R13b) or record it and continue (any other datagram, a unix one under a gate included, R13b). prepare
// reads the bytes an allowed send will carry; the send itself is relayed on
// the duplicate. control says the send carries ancillary data, which a relay cannot reproduce; flags is
// the syscall's own flags argument.
func (l *Loop) sendDecisionCtl(n *notif, r *reader, sockfd int, d dest, raw []byte, control bool, flags uint64, prepare func() (sendArgs, bool)) {
	c := l.table.Load()
	if c.passesUnrecorded(r, d, false) {
		l.respond(n, respContinue())
		return
	}
	t, why, ok := l.resolveTarget(n, r, c, sockfd, d, false)
	if !ok {
		if n.gone {
			return
		}
		// Without the socket there is no way to tell a datagram send from a Fast-Open one, and an address
		// this tier cannot decide is refused on either; the connect-class answer is the fail-closed one
		// (R4, R5). t.proto names the socket's protocol whenever the socket was read. A contract that
		// decides nothing continues it instead (passesUnresolved).
		if c.passesUnresolved(r, d, false) {
			l.continueUnresolved(n, c, r, d, t.proto, why)
			return
		}
		l.refuseNet(n, d, t.proto, refuse(why))
		return
	}
	// A closure, because relay takes ownership of the duplicate: t.dup is -1 from that point.
	defer func() { l.closeDup(t.dup) }()
	if t.stream() && !fastOpen(flags) && l.k.Connected(t.dup) {
		// The socket already has a peer, so the kernel ignores the destination this send carries and the
		// bytes go to the endpoint the connect decided (R13a). Nothing here is a new decision.
		//
		// MSG_FASTOPEN is excluded because the peer is only what this loop saw, not what the kernel will
		// see: CONTINUE hands the syscall back, a sibling thread's connect(fd, {AF_UNSPEC}) — R4's allowed
		// disassociation — can land first, and tcp_sendmsg_fastopen then connects the now peerless socket
		// to this send's own address, a host nothing decided. Decided as R12 instead, a still-connected
		// socket loses nothing: the relayed send gets the kernel's own EISCONN, and a refused one R10's
		// errno in place of it.
		//
		// The unix-only state (ADR 0070) guards the descriptor as well, which the kernel looks up again after a
		// CONTINUE: sendConnectedUnixOnly.
		if c.hostSockets {
			l.sendConnectedUnixOnly(n, &t, d, raw, control, flags, prepare)
			return
		}
		l.respond(n, respContinue())
		return
	}
	if t.dec.allowed || t.dec.continued {
		var gd *gate.Decision
		t.dec, gd = l.gateNet(c, r, d, t.proto, t.dec, gate.Allow)
		if gd != nil && gd.Verdict == gate.Ask {
			t.dec.allowed = false
			t.dec.continued = false
			t.dec.rule = gd.Rule
			t.dec.kernelReason = record.ReasonNetGate
			t.dec.unsupported = true
		}
		if gd != nil && gd.Verdict != gate.Allow {
			l.refuseNet(n, d, t.proto, t.dec)
			return
		}
	}
	if !t.stream() {
		if !t.dec.allowed && l.askDatagram(n, c, &t, d, raw, control, prepare) {
			// A UDP destination nothing admits that a net.ask scope reaches is held for a person and, approved,
			// relayed from the copies read here (R13d).
			return
		}
		if t.guarded && !t.dec.allowed {
			// Under the models[] guard the guard's verdict is the only one, at tier 2 as well, whose network
			// programs stay detached for a contract with no net: section (R7). Continued, the datagram reached
			// the model around the forwarder — QUIC over an unconnected socket sends just this way — with a
			// refused line. Refusing loses nothing the contract admits, and no byte of this call leaves.
			l.refuseNet(n, d, t.proto, t.dec)
			return
		}
		// A gate relays only on an IP socket, as sendUnaddressed and unaddressedBatch do (ipDomain): a unix
		// datagram sent from here would resolve a relative name against this process's cwd, leave the agent's
		// Landlock scope behind and, at tiers 2/3, reach root-only sockets with the receiver reading this
		// process's credentials, the reason handleConnect never relays a unix connect. One the gate
		// admits is continued below, as without the gate (gate.md R4).
		if t.guarded || (t.ipGated && t.dec.allowed) {
			l.relayDatagram(n, c, &t, d, raw, control, prepare)
			return
		}
		if c.decidesNetlink() && !control && l.routeQuery(&t, raw) {
			l.relayRouteQuery(n, c, &t, d, raw, prepare)
			return
		}
		if c.hostSockets && !hostSocketRelayable(t.domain) {
			// An addressed datagram on a socket of a domain the unix-only state does not reach (AF_NETLINK save the
			// route query above, AF_PACKET, ...): refused, keyed on the socket's own domain, so it is never relayed
			// from this process with its credentials (hostSocketRelayable).
			l.refuseNet(n, d, t.proto, refuse(ruleHostSockets))
			return
		}
		if c.hostSockets && t.dec.allowed && l.relayUnixOnly(n, c, &t, d, raw, control, flags, prepare) {
			return // relayed, or the target gone while its payload was read
		}
		if dec, errno, ok := l.kernelRefusal(c, &t, d, raw); ok {
			// A kernel program of the run decides this destination on its own copy of the address and refuses
			// it: answered here, with that program's errno, the refusal is this loop's and the datagram's one
			// line, which a continued send's best-effort line was not (R13b, Options.KernelDatagrams). Nothing
			// is sent from here, a unix datagram above all (ADR 0041's rejected alternative 7).
			l.respond(n, respErrno(errno))
			l.emitNet(n, c, d, t.proto, dec, record.VerdictRefused, netMarks{})
			return
		}
		if !t.dec.allowed {
			// A destination the policy refuses is refused here, with R10's errno, and no byte of this call
			// leaves (R13b as amended 2026-10-16). A refusal needs no race: only an allow is
			// exposed to a sibling thread that rewrites the address after this read. Continued, the datagram
			// left the kernel under a refused line: net.dns.mode: off recorded a lookup sent from an
			// unconnected socket and the resolver answered it, while the same destination's connect was
			// refused.
			l.refuseNet(n, d, t.proto, t.dec)
			return
		}
		// Best-effort: the address was read and admitted, and the kernel sends to its own copy of it, which a
		// sibling thread can rewrite after this read (R13b, E33). best_effort marks exactly that.
		l.respond(n, respContinue())
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{bestEffort: true})
		return
	}
	if c.hostSockets && !hostSocketRelayable(t.domain) {
		// A stream send on a socket of a domain the unix-only state does not reach: refused, keyed on the socket's
		// own domain, as a connect of one is (handleConnect, hostSocketRelayable).
		l.refuseNet(n, d, t.proto, refuse(ruleHostSockets))
		return
	}
	if t.relaysIP() || c.hostSockets {
		// A Fast-Open send a net gate or a live net block admitted on an IP socket connects to the copy it decided,
		// relayed as handleConnect relays the connect (ADR 0041 D6). In the unix-only state a stream send that reaches here
		// (one on a socket without a peer, or one carrying MSG_FASTOPEN) is decided like a connect and relayed on
		// the duplicate rather than continued (ADR 0070 Decision 3), so a sibling's dup2 of a datagram socket over
		// the descriptor and rewrite of the address cannot redirect it.
		t.dec.continued = false
	}
	if t.dec.continued {
		// No net: section: nothing is decided, so the Fast-Open send is not performed here either
		// (handleConnect says why). The kernel runs it as the agent, ancillary data and all.
		l.respond(n, respContinue())
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{bestEffort: true})
		return
	}
	if !t.dec.allowed {
		l.refuseNet(n, d, t.proto, t.dec)
		return
	}
	if control {
		// The relay sends the gathered payload on the duplicate and cannot reproduce ancillary data: an
		// SCM_RIGHTS array names the target's descriptor numbers, which mean something else in this
		// process, and passing them on would hand out this process's own descriptors. An unconnected
		// stream socket cannot legally pass descriptors anyway, so this is refused rather than silently
		// dropped (I3: a relayed result is never fabricated).
		l.refuseNet(n, d, t.proto, refuse(ruleAncillary))
		return
	}
	args, ready := prepare()
	if !ready {
		return // R19: the target died while its payload was being read; there is nothing to answer
	}
	l.relaySend(n, c, &t, d, raw, args)
}

// relayDatagram sends an admitted datagram on a guarded IP socket itself, on the duplicate, to the address
// this loop read and with the payload it read (R7, R13b), as R12 relays a Fast-Open send. Continued, the
// kernel would read the address again, and a sibling thread that rewrote it to the guarded endpoint in
// between — 127.0.0.1:P, or 0.0.0.0:P, which the kernel sends to loopback — delivered the datagram to the
// model around the forwarder under a line that read allow, at tier 1 and at tier 2 alike, since tier 2
// attaches no cgroup/sendmsg program to a contract with no net: section. A datagram is sent whole or not at
// all, so one this loop cannot reproduce exactly is refused rather than altered (I3): ancillary data, which
// a relay would have to send with this process's credentials (an SO_MARK checks CAP_NET_ADMIN against the
// sender), a payload past sendBytes or msgIovs, or one that could not be read whole, and MSG_ZEROCOPY, which
// would have the kernel transmit from this process's heap (zeroCopy, refused in relaySend).
func (l *Loop) relayDatagram(n *notif, c *compiled, t *target, d dest, raw []byte, control bool, prepare func() (sendArgs, bool)) {
	if control {
		l.refuseNet(n, d, t.proto, refuse(ruleAncillary))
		return
	}
	args, ready := prepare()
	if !ready {
		return // R19
	}
	if !args.whole {
		l.refuseNet(n, d, t.proto, refuse(ruleDatagramSize))
		return
	}
	l.relaySend(n, c, t, d, raw, args)
}

// relayUnixOnly performs an addressed datagram ADR 0070's unix-only state admitted on the duplicate, from the copies
// read here, as handleConnect relays a connect: a unix-spelled copy as the task, to the inode its name resolves to
// (relayUnixDatagram), and any other with the copied bytes (relaySend), which the kernel refuses on a socket of
// another domain. Continued, the kernel reads the address and the descriptor again, and a sibling that rewrote the
// one or dup2'd a unix datagram socket over the other reached a host socket. It reports false, and relays nothing,
// for a datagram the relay cannot reproduce exactly (I3): ancillary data (QUIC's ECN and GSO, IP_PKTINFO, SCM_RIGHTS),
// MSG_ZEROCOPY, MSG_MORE or a corked socket, a payload past sendBytes or msgIovs or one not read whole. The caller
// continues that one, its line best effort: the run_start cell host_sockets/datagram names that residual, which the
// kernel closes from Landlock ABI 9 (RESOLVE_UNIX) for pathnames and ABI 6 (the abstract scope) for abstract names.
func (l *Loop) relayUnixOnly(n *notif, c *compiled, t *target, d dest, raw []byte, control bool, flags uint64, prepare func() (sendArgs, bool)) bool {
	fl := int(int32(flags))
	if control || zeroCopy(fl) || fl&unix.MSG_MORE != 0 {
		return false
	}
	args, ready := prepare()
	if !ready {
		return true // R19: the target died while its payload was being read; there is nothing to answer
	}
	if !args.whole || !l.frameFree(t, args.flags) {
		return false
	}
	t.dec.continued = false
	if d.isUnix() {
		l.relayUnixDatagram(n, c, t, d, raw, args)
	} else {
		l.relaySend(n, c, t, d, raw, args)
	}
	return true
}

// sizeofSockaddrNL is sizeof(struct sockaddr_nl): nl_family, nl_pad, nl_pid, nl_groups.
const sizeofSockaddrNL = 12

// decidesNetlink reports whether this run decides what its netlink sockets send: a net: section, or ADR 0070's
// unix-only state. Under host_sockets: true a send to the netlink family is continued like every destination there.
func (c *compiled) decidesNetlink() bool { return !c.netOpen || c.hostSockets }

// routeSocket reports whether t is a NETLINK_ROUTE socket, its domain and protocol read on the duplicate, which a
// sibling's dup2 cannot change. A domain or protocol that cannot be read is no route socket.
func (l *Loop) routeSocket(t *target) bool {
	dom, err := l.k.SockDomain(t.dup)
	if err != nil || dom != unix.AF_NETLINK {
		return false
	}
	t.domain = dom
	proto, err := l.k.SockProtocol(t.dup)
	return err == nil && proto == unix.NETLINK_ROUTE
}

// routeQuery reports whether an addressed datagram on t goes to the kernel on a route socket: a NETLINK_ROUTE socket
// (routeSocket) sending to nl_pid 0 with no multicast group, the sockaddr_nl that netlink_sendmsg accepts (at least
// sizeof(struct sockaddr_nl), family AF_NETLINK). glibc's getifaddrs, if_nameindex and getaddrinfo(AI_ADDRCONFIG), Go's
// net.Interfaces and libuv's interface list send their dumps so; relayRouteQuery reads what it asks. A message to
// another port id is one to a process (netlink unicast between processes needs no privilege), and one to a group a
// multicast, which netlink_allowed checks against the sender's CAP_NET_ADMIN: neither is a route query, and both stay
// refused.
func (l *Loop) routeQuery(t *target, raw []byte) bool {
	if len(raw) < sizeofSockaddrNL ||
		binary.NativeEndian.Uint16(raw) != unix.AF_NETLINK ||
		binary.NativeEndian.Uint32(raw[4:]) != 0 || binary.NativeEndian.Uint32(raw[8:]) != 0 {
		return false
	}
	return l.routeSocket(t)
}

// routeReadOnly reports whether a payload bound for rtnetlink is nothing but GET requests, walked as netlink_rcv_skb
// walks it, so that a GET cannot carry a NEWROUTE behind it in one datagram. rtnetlink_rcv_msg takes a request's kind
// from the two low bits of its type past RTM_BASE and asks CAP_NET_ADMIN of every kind but GET, so GET is the kernel's
// own line between reading and changing. A type the kernel would not take for a GET (a control message, one past
// RTM_MAX), a header that overruns the datagram and trailing bytes too short to be a header are refused: each is
// something the kernel would skip or stop at, and no query needs one. It reads the copy the relay sends, so no sibling
// changes what was read.
func routeReadOnly(p []byte) bool {
	for {
		if len(p) < unix.NLMSG_HDRLEN {
			return false
		}
		size, typ := binary.NativeEndian.Uint32(p), binary.NativeEndian.Uint16(p[4:])
		if size < unix.NLMSG_HDRLEN || uint64(size) > uint64(len(p)) ||
			typ < unix.RTM_BASE || typ > unix.RTM_MAX || (typ-unix.RTM_BASE)&rtmKindMask != rtmKindGet {
			return false
		}
		// The kernel clamps the aligned length to what is left: a request of 17 bytes, Go's, ends the datagram.
		next := (uint64(size) + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if next >= uint64(len(p)) {
			return true
		}
		p = p[next:]
	}
}

// A request's kind is the two low bits of its type past RTM_BASE: NEW, DEL, GET, SET (RTNL_KIND_MASK, RTNL_KIND_GET in
// include/net/rtnetlink.h, which no uapi header carries).
const (
	rtmKindMask = 3
	rtmKindGet  = 2
)

// relayRouteQuery performs a route query (routeQuery) on the duplicate, from the copies read, as the task (SendToRawAs:
// a thread with the task's credentials, so the kernel's capability checks, which netlink makes against the sender as
// well as the socket's opener, are the task's at every tier), and records it allow, rule route-query, under a net:
// section (ADR 0128) as in the unix-only state (ADR 0070 Decision 3). Refused, every interface
// enumeration failed EACCES (Node's os.networkInterfaces, Python's if_nameindex, psutil, Go's net.Interfaces), and
// under a net: section so did getaddrinfo's AI_ADDRCONFIG. Continued, the kernel would look the descriptor and the
// address up again, and a sibling that dup2'd a unix datagram socket over the one and wrote a host socket's name into
// the other reached it. A query is sent whole or not at all (ruleDatagramSize); one with ancillary data never reaches
// here. What is not read-only (routeReadOnly) is refused route-change and never sent: for an agent with no
// CAP_NET_ADMIN the kernel would answer EPERM, and this line is what says the run tried.
// Residual: on a socket nothing bound, the send autobinds it with this process's pid as its port id, which a reader
// that compares nlmsg_pid with its own pid would notice; glibc, Go and libuv bind before they send.
func (l *Loop) relayRouteQuery(n *notif, c *compiled, t *target, d dest, raw []byte, prepare func() (sendArgs, bool)) {
	args, ready := prepare()
	if !ready {
		return // R19: the target died while its payload was being read; there is nothing to answer
	}
	switch {
	case !args.whole:
		l.refuseNet(n, d, t.proto, refuse(ruleDatagramSize))
		return
	case zeroCopy(args.flags):
		l.refuseNet(n, d, t.proto, refuse(ruleZeroCopy))
		return
	case !routeReadOnly(args.payload):
		l.refuseNet(n, d, t.proto, refuse(ruleRouteChange))
		return
	}
	task, err := l.k.TaskOf(n.pid)
	// R2: /proc/<tid> is keyed by a tid the target may have given up, so what was read is trusted only if the
	// notification is still live after it.
	if !l.valid(n) {
		if err == nil {
			l.closeTask(task)
		}
		return
	}
	if err != nil {
		l.log.Debug("supervisor: the task's credentials could not be read", "tid", n.pid, "err", err)
		l.refuseNet(n, d, t.proto, refuse(ruleRelayCredentials))
		return
	}
	t.dec = verdictOf{rule: ruleRouteQuery, allowed: true}
	res, out := l.relay(n, t, func(dup int) resp {
		defer l.closeTask(task)
		if args.addrErr != nil {
			return respResult(0, args.addrErr) // the kernel's own answer to that length: nothing is sent
		}
		if args.sendErr != nil {
			return respResult(0, args.sendErr) // the kernel's own answer to that payload: nothing is sent
		}
		sent, err := l.k.SendToRawAs(dup, task, args.payload, args.flags, raw)
		return respResult(sent, err)
	})
	if out == relayLimited {
		l.closeTask(task)
	}
	l.finishRelaySend(n, c, t, d, args, res, out)
}

// kernelRefusal reports whether a kernel program of the run refuses the addressed datagram t carries to d, which
// this loop is about to continue (R13b): the refusal to record and the errno that program fails the send with
// (Options.KernelDatagrams). Those programs decide on the kernel's own copy of the address, so continued, a datagram
// one refuses was recorded refused with best_effort, "recorded without enforcing" of a refusal the kernel enforced,
// and a unix name decideUnix cleans and admits but the kernel refuses for its spelling was recorded allow
// (enforce-cgroup-observe §5 R7, enforce-plane §2.11 condition 1). Refused here instead, the agent gets the errno it
// would have got and the ledger the one line, the refusal this loop made (ADR 0016 (1)).
//
// Only what such a program decides, and only where the protocol's own checks before it pass, is refused, so that
// nothing the kernel would have answered otherwise changes:
//   - a unix datagram (SOCK_DGRAM on an AF_UNIX socket; the domain is the socket's own, never the copied family) whose
//     address unix_validate_addr accepts, to an abstract name or an absolute pathname that decideUnix refuses by its
//     name or that is not spelled canonically (agent.UnixCanonical). A relative name the programs leave to tier 1, and its
//     line stays R13b's best effort; a name refused for what it reaches in the task's view is this loop's refusal
//     (decideLanded), as R11a's are;
//   - a UDP datagram (IPPROTO_UDP) whose destination decide refused, to an AF_INET address on an AF_INET socket
//     or a non-mapped AF_INET6 one on an AF_INET6 socket, at least as long as udp_sendmsg and udpv6_sendmsg
//     require and with a port, which they refuse EINVAL first. An IPv4 or v4-mapped destination on an AF_INET6
//     socket is left to the kernel: there IPV6_V6ONLY decides between ENETUNREACH and sendmsg4.
//
// The checks that precede the programs in the kernel and that this cannot see stay as they were: a pending frame
// (R13: the run starts none, refusesFrame), a malformed control message or MSG_OOB fail or send there without the
// program running, and are refused here; nothing is sent either way, save a corked append, which this refuses.
func (l *Loop) kernelRefusal(c *compiled, t *target, d dest, raw []byte) (verdictOf, unix.Errno, bool) {
	if c.netOpen || t.sockType != unix.SOCK_DGRAM {
		return verdictOf{}, 0, false
	}
	switch {
	case d.isUnix():
		errno := l.kernelDgrams.Unix
		// unix_validate_addr: more than the family, at most sizeof(struct sockaddr_un).
		if errno == 0 || len(raw) <= sunPathOff || len(raw) > sunPathOff+sunPathMax {
			return verdictOf{}, 0, false
		}
		if d.unixPath != "" && !strings.HasPrefix(d.unixPath, "/") {
			return verdictOf{}, 0, false // relative: the programs leave it to tier 1
		}
		dec := t.dec
		if isR11aRefusal(dec.rule) || (dec.landed && !dec.allowed) {
			// R11a's refusal, and any refusal of what the name reaches in the task's view (decideLanded), is this
			// loop's own: the programs decide the name, which this loop admitted first, so the kernel would not
			// refuse it, and refuseNet answers it below (R10's errno, or unix-absent's lookup errno).
			return verdictOf{}, 0, false
		}
		if dec.allowed && d.unixPath != "" && !agent.UnixCanonical(d.unixPath) {
			// No row is looked up for such a spelling, so the kernel's refusal names no rule.
			dec = refuse(ruleUnmatched)
		}
		if dec.allowed || !l.socketDomainIs(t, unix.AF_UNIX) {
			return verdictOf{}, 0, false
		}
		return dec, errno, true
	case d.isInet():
		errno := l.kernelDgrams.UDP
		if errno == 0 || t.dec.allowed || t.sockProto != unix.IPPROTO_UDP || d.ap.Port() == 0 {
			return verdictOf{}, 0, false
		}
		switch {
		case d.family == unix.AF_INET && len(raw) >= unix.SizeofSockaddrInet4 && l.socketDomainIs(t, unix.AF_INET):
		case d.family == unix.AF_INET6 && d.ap.Addr().Is6() && len(raw) >= sin6Min && l.socketDomainIs(t, unix.AF_INET6):
		default:
			return verdictOf{}, 0, false
		}
		return t.dec, errno, true
	}
	return verdictOf{}, 0, false
}

// socketDomainIs reports whether t's socket is of domain dom, read on the duplicate where resolveSocket did not
// read it already. A domain that cannot be read is not dom: the datagram is then continued as before.
func (l *Loop) socketDomainIs(t *target, dom int) bool {
	if t.domain == 0 {
		got, err := l.k.SockDomain(t.dup)
		if err != nil {
			return false
		}
		t.domain = got
	}
	return t.domain == dom
}

// relaySend performs an allowed send on the target's own socket (its duplicate) and answers with the real
// result (R12, I3): a Fast-Open send, or a datagram on a guarded IP socket (relayDatagram). A send carrying
// MSG_ZEROCOPY is refused instead, on either (zeroCopy), and so is a datagram on a socket that could hold a pending
// frame (frameFree), whose bytes would go to that frame's destination under a line naming this one.
func (l *Loop) relaySend(n *notif, c *compiled, t *target, d dest, raw []byte, args sendArgs) {
	if zeroCopy(args.flags) {
		l.refuseNet(n, d, t.proto, refuse(ruleZeroCopy))
		return
	}
	if !l.frameFree(t, args.flags) {
		l.refuseNet(n, d, t.proto, refuse(ruleCorked))
		return
	}
	if l.sourceRouted(c, t) {
		l.refuseNet(n, d, t.proto, refuse(ruleSourceRouted))
		return
	}
	res, out := l.relay(n, t, func(dup int) resp {
		if args.addrErr != nil {
			return respResult(0, args.addrErr) // the kernel's own answer to that length: nothing is sent
		}
		if args.sendErr != nil {
			return respResult(0, args.sendErr) // the kernel's own answer to that payload: nothing is sent
		}
		sent, err := l.k.SendToRaw(dup, args.payload, args.flags, raw)
		return respResult(sent, err)
	})
	l.finishRelaySend(n, c, t, d, args, res, out)
}

// finishRelaySend answers and records a decided send the relay performed (relaySend, relayRouteQuery).
func (l *Loop) finishRelaySend(n *notif, c *compiled, t *target, d dest, args sendArgs, res resp, out relayOutcome) {
	switch out {
	case relayDone:
		pipe := l.pipeSignal(n, t, res, args.flags)
		l.respond(n, res)
		l.raisePipe(n, pipe)
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), l.answeredMarks(n))
	case relayOrphaned:
		// The target abandoned the send while this loop was performing it (E35): the bytes are already on
		// the wire, so the ledger carries the line even though no byte count ever reached the agent, and,
		// below 5.19 or without WAIT_KILLABLE_RECV, the restart the kernel is about to make will send them
		// a second time.
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{resultUnknown: true})
	case relayLimited:
		l.refuseNet(n, d, t.proto, refuse(ruleRelayLimit))
	}
	// relayCancelled: the run is ending with the send still in flight; nothing honest to answer (I3).
}

// pipeSignal returns a pidfd for the trapping task when the relayed send's real result is one the kernel pairs
// with SIGPIPE, and -1 otherwise. A send on a connection-oriented socket whose sending side is shut down
// returns EPIPE and, without MSG_NOSIGNAL, raises SIGPIPE on the calling thread (sk_stream_error): performed
// on the duplicate, that thread is this process's, whose Go runtime drops it, so the agent would read EPIPE
// and never the signal a native call gives it (I3), and a default-disposition agent would live on where it
// would have died. The pidfd is taken before the answer, while the notification still holds the task, and the
// notification is re-validated after the open: a pidfd pins its task, so one that exits once the answer is
// sent is ESRCH to the signal, and a tid reused by then is never signalled (raisePipe).
func (l *Loop) pipeSignal(n *notif, t *target, res resp, flags int) int {
	if res.errno != -int32(unix.EPIPE) || flags&unix.MSG_NOSIGNAL != 0 || !t.stream() {
		return -1
	}
	pidfd, err := l.openTargetPidFD(n)
	if err != nil {
		l.log.Debug("supervisor: no pidfd to raise SIGPIPE on", "tid", n.pid, "err", err)
		return -1
	}
	if !l.valid(n) {
		l.closeDup(pidfd)
		return -1
	}
	return pidfd
}

// raisePipe sends SIGPIPE through pipeSignal's pidfd once the EPIPE has been answered, then closes it. The
// signal arrives just after the syscall returns rather than as it returns; on a kernel with PIDFD_THREAD it is
// the trapping thread's, as the kernel's is, and below 6.9 the pidfd is the process's, so a threaded agent's
// SIGPIPE is process-directed there. A notification that was not answered (the target gone) gets none.
func (l *Loop) raisePipe(n *notif, pidfd int) {
	if pidfd < 0 {
		return
	}
	defer l.closeDup(pidfd)
	if !n.answered || n.gone {
		return
	}
	if err := l.k.SignalPidFD(pidfd, unix.SIGPIPE); err != nil && !errors.Is(err, unix.ESRCH) {
		l.log.Warn("supervisor: raising SIGPIPE for a relayed send", "tid", n.pid, "err", err)
	}
}

// gather reads the iovec array of an allowed send, bounded by msgIovs entries and sendBytes bytes in total
// (R12): a stream socket may legally send fewer bytes than asked, so a sendBytes cut relays a short write
// rather than failing a Fast-Open send. whole reports that nothing was cut and every read was complete, which
// a relayed datagram needs, since a datagram is sent whole or not at all (relayDatagram).
//
// out is always a prefix of the bytes the call names, in their order: the kernel's copy stops at the first
// buffer that faults (a NULL base with a length, or one that reads short), so gather stops there too, and a
// stream relay sends what the kernel would have sent before the fault. err is the kernel's own answer where it
// would send nothing at all (I3): EMSGSIZE for an iovlen past UIO_MAXIOV (__copy_msghdr; msgIovs equals it,
// so no legal short write stands for it), and EFAULT for an iovec array that cannot be read (import_iovec) or
// a first data buffer that faults before a byte is copied.
func (l *Loop) gather(r *reader, iov uint64, iovlen uint64) (out []byte, whole bool, err error) {
	if iovlen > msgIovs {
		r.mark(rulePathTruncated)
		return nil, false, unix.EMSGSIZE
	}
	if iovlen == 0 {
		return nil, true, nil
	}
	if iov == 0 {
		return nil, false, unix.EFAULT // a NULL array with a length: import_iovec's EFAULT, never a datagram
	}
	whole = true
	out = make([]byte, 0, 1024)
	i := uint64(0)
	for ; i < iovlen && len(out) < sendBytes; i++ {
		var e [iovecSize]byte
		if got := r.read(iov+i*iovecSize, e[:]); got < iovecSize {
			return nil, false, unix.EFAULT // the kernel copies the whole array before it sends a byte
		}
		base, length := leU64(e[iovecBaseOff:]), leU64(e[iovecLenOff:])
		if length == 0 {
			continue
		}
		if base == 0 {
			return out, false, faultErr(out) // the kernel's copy faults here: nothing past it is sent
		}
		room := sendBytes - len(out)
		want := min(length, uint64(room))
		if want < length {
			whole = false
		}
		part := r.blob(base, int64(want), room)
		if r.n.gone {
			return out, false, nil
		}
		out = append(out, part...)
		if uint64(len(part)) < want {
			return out, false, faultErr(out) // the copy faulted inside this buffer
		}
	}
	if i < iovlen {
		whole = false // sendBytes was reached with iovecs left unread
	}
	return out, whole, nil
}

// faultErr is the kernel's answer to a send whose copy faulted after the bytes in out: the count copied so
// far when there are any (tcp_sendmsg returns it, so the relay sends them), and EFAULT when there are none.
func faultErr(out []byte) error {
	if len(out) == 0 {
		return unix.EFAULT
	}
	return nil
}
