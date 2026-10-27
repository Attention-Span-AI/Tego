// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Pending frames (R13, ADR 0008's design note of 2026-10-20). A UDP, UDP-Lite or raw IP socket can hold a pending
// frame: a send carrying MSG_MORE, a sendfile or splice whose last write carried it, or UDP_CORK set, leaves the
// frame's bytes queued on the socket, and every later send on it joins that frame before the protocol reads the send's
// own address (udp_sendmsg and udpv6_sendmsg append before they read msg_name, and before the run's sendmsg4/6 runs;
// a raw socket sends the joined frame by its first send's route). So while a frame is pending, where a datagram's
// bytes go is a property of the socket, not of the call, and a line naming the call's address would name a
// destination the bytes did not reach. Every frame-forming operation the filter can see is therefore decided here,
// in one place per syscall family, on the socket's own SO_TYPE, SO_PROTOCOL and SO_DOMAIN (frameSocket), never on an
// address the call carries, and refused datagram-corked on a socket that can hold a frame (refusesFrame,
// handleSetsockopt's UDP_CORK, spliceInto); a datagram this loop sends itself is held to frameFree first. The
// filter notifies each of those operations exactly where agent.RuleTable.DecidesDatagrams holds (enforce-landlock
// R11d), which is the condition refusesFrame asks (compiled.datagrams), so no frame forms on a socket of such a run from a syscall either
// layer sees, and what the two read cannot disagree. Before, each send path asked its own question: a batch took the
// socket's protocol from its first address, so a unix one let a UDP batch with MSG_MORE through,
// UDP-Lite and unaddressed sends were added one at a time (-4), and a raw socket never was.

// frameSocket reports whether t's socket can hold a pending frame: a datagram socket of an IP domain other than a ping
// socket (UDP, UDP-Lite, or a protocol SO_PROTOCOL did not name), or a raw IP socket. A ping socket pushes each send
// as it is made (ping_v4_sendmsg, ping_v6_sendmsg), whatever MSG_MORE says; a unix or stream socket keeps no frame. The
// domain is read on the duplicate where resolveSocket did not read it, and one that cannot be read counts as IP, the
// side that refuses.
func (l *Loop) frameSocket(t *target) bool {
	switch t.sockType {
	case unix.SOCK_RAW:
	case unix.SOCK_DGRAM:
		if t.sockProto == unix.IPPROTO_ICMP || t.sockProto == unix.IPPROTO_ICMPV6 {
			return false
		}
	default:
		return false
	}
	if t.domain == 0 {
		dom, err := l.k.SockDomain(t.dup)
		if err != nil {
			l.log.Debug("supervisor: SO_DOMAIN unreadable", "err", err)
			return true
		}
		t.domain = dom
	}
	return t.domain == unix.AF_INET || t.domain == unix.AF_INET6
}

// refusesFrame decides, for a sendto, sendmsg or sendmmsg, the one thing about it that could start a pending frame: the
// syscall's own flags argument carries MSG_MORE (a register, which no sibling can rewrite) in a run that decides
// datagrams, on a socket that can hold a frame (frameSocket). Such a send is refused with R10's errno, rule
// datagram-corked, before anything about its destination is decided, and reports true; d only names the line (the
// call's address, or the batch's first, or none). A socket that cannot be read is refused as resolveSocket fails it,
// fd-exhausted, fd-unreadable or fd-raced, whatever its kind turns out to be: a TCP send with MSG_MORE included (the
// failure table's rows say so); its line is a net line, the send's, with protoOf's default (§9). Every other send reports false and goes on to its own decision with nothing read, so a send without
// the flag pays nothing here.
func (l *Loop) refusesFrame(n *notif, c *compiled, sockfd int, flags uint64, d dest) bool {
	if !moreFlag(flags) || !c.datagrams {
		return false
	}
	t, why, ok := l.resolveSocket(n, c, sockfd)
	if !ok {
		if n.gone {
			return true
		}
		l.refuseNet(n, d, protoOf(0, 0, d), refuse(why))
		return true
	}
	defer l.closeDup(t.dup)
	if !l.frameSocket(&t) {
		return false
	}
	l.refuseNet(n, d, protoOf(t.sockType, t.sockProto, d), refuse(ruleCorked))
	return true
}

// frameFree reports whether this loop may send a datagram of its own on t's socket (a relay, an approval) with flags:
// on a socket that can hold a frame (frameSocket), the send carries no MSG_MORE, which would leave the relay's own
// bytes pending on the agent's socket, and a UDP or UDP-Lite socket is not corked. The cork is read on the duplicate,
// and one that cannot be read counts as set. The run cannot set one (handleSetsockopt refuses UDP_CORK), so a corked
// socket here is one the run was handed: inherited, or received over a unix socket. A frame such a socket holds from a
// MSG_MORE send made before the run cannot be read from user space; at tiers 2 and 3 an approved datagram's line still
// tells it (askDatagram: its credit is left untaken).
func (l *Loop) frameFree(t *target, flags int) bool {
	if !l.frameSocket(t) {
		return true
	}
	if flags&unix.MSG_MORE != 0 {
		return false
	}
	if t.sockType != unix.SOCK_DGRAM {
		return true // a raw socket has no UDP_CORK; its frames come from MSG_MORE alone
	}
	corked, err := l.k.UDPCorked(t.dup)
	if err != nil {
		l.log.Debug("supervisor: UDP_CORK unreadable", "err", err)
		return false
	}
	return !corked
}

// refuseCork answers the setsockopt(SOL_UDP or SOL_UDPLITE, UDP_CORK) the filter notifies in a run that decides
// datagrams (enforce-landlock R11): refused with R10's errno, recorded refused, op setsockopt, rule datagram-corked,
// whatever the value and whatever the socket. Setting the cork would make every later datagram of the socket join one
// frame; the value is in the agent's memory, where a decision on it would race a sibling thread, and the level and
// option are the scalars the filter matched. An uncork is refused with it: the run can cork no socket, so one it
// could uncork is one it was handed corked, whose datagrams this loop then refuses to relay (frameFree). A run that
// decides no datagrams gets no such notification; one reaching here anyway is continued, as the filter would have. An
// observe run continues it with a gap line, never a refused one (refuseOp).
func (l *Loop) refuseCork(n *notif, level, option int32) {
	if !l.table.Load().datagrams {
		l.respond(n, respContinue())
		return
	}
	l.refuseOp(n, "setsockopt", record.SocketOption(level, option, nil, false), ruleCorked)
}

// refuseOp answers a pending-frame refusal that names no destination with R10's errno and records it as a refused line,
// op, target and rule as given, reason net-not-allowed: the run's network rules are why it was refused.
//
// An observe run refuses nothing (R30): the call is continued and no refused line is written, since the ledger would
// post it to last-refusal.json and the agent's reason channel as a refusal that never happened.
// What the enforcing run would refuse is recorded as gap what=record why=<rule>-<op> (datagram-corked-setsockopt,
// fd-unreadable-sendfile, ...), once per binary, syscall and rule, as an observed keyring syscall is (R32), and once per
// process for a non-dumpable one, whose binary the ptrace check behind fd-unreadable hides too (gapOwner): record v1 has
// no action kind for a cork or for a copy into a descriptor nobody read, and a net line would name a protocol and a
// destination nobody read.
func (l *Loop) refuseOp(n *notif, op, target, rule string) {
	if l.observing() {
		binary, key := l.gapOwner(n)
		if n.gone {
			return
		}
		l.respond(n, respContinue())
		if why := rule + "-" + op; l.frameSeen.first(key + "\x00" + why) {
			gap := l.event(n, record.KindGap, record.SourceSupervisor)
			l.emitFor(n, gap, record.GapPayload{What: record.GapRecord, Why: why, Binary: binary, Count: 1})
		}
		return
	}
	l.respond(n, respErrno(refusalErrno))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = rule, record.ReasonNetNotAllowed
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: target, Reason: record.ReasonNetNotAllowed, Rule: rule})
}

// handleSendfile and handleSplice decide the two syscalls that write a descriptor's bytes into a socket without a send
// this loop reads (R13's pending frames): the filter notifies them in a run that decides datagrams (enforce-landlock
// R11). splice_to_socket marks every write but a call's last with MSG_MORE, and splice_direct_to_actor marks a
// sendfile's last one too when the file ended before the count, so either can leave a frame pending on a UDP socket,
// and a splice with SPLICE_F_MORE always does. spliceInto refuses them into a socket that can hold a frame.
func handleSendfile(l *Loop, n *notif) { l.spliceInto(n, "sendfile", int(int32(n.args[0]))) }
func handleSplice(l *Loop, n *notif)   { l.spliceInto(n, "splice", int(int32(n.args[2]))) }

// spliceInto continues a sendfile or splice (op) whose output descriptor out is not a socket (a file, a pipe), or a
// socket that holds no frame, and refuses one into a socket that can hold a frame (frameSocket) with R10's errno,
// recorded refused, rule datagram-corked, with no destination: the bytes would go to the socket's peer, as a frame.
// Nothing is read but the descriptor's socket options. A descriptor not open in the target is continued (the kernel
// answers it EBADF itself). One this loop cannot duplicate or read may be such a socket and is refused, fail-closed as
// a send whose socket cannot be read is (refusesFrame), but on a refused line, op and target "fd <out>", not a net
// line: nothing says its bytes were bound for a network, and a net line would name a protocol nobody read. Its rule
// says why: fd-exhausted, fd-unreadable or fd-raced (dupFailure), or fd-raced for a type that
// could not be read. At tier 1 pidfd_getfd refuses every descriptor of a target that made itself non-dumpable, so in a
// run that decides datagrams such a process's every sendfile and splice is refused, a file copy included (the failure
// table's row; enforce-landlock R11d's cost).
func (l *Loop) spliceInto(n *notif, op string, out int) {
	if !l.table.Load().datagrams {
		l.respond(n, respContinue())
		return
	}
	dup, err := l.duplicate(n, out)
	switch {
	case err == nil:
	case errors.Is(err, unix.EBADF):
		l.respond(n, respContinue())
		return
	case n.gone:
		return
	default:
		l.refuseOp(n, op, "fd "+strconv.Itoa(out), l.dupFailure(err))
		return
	}
	defer l.closeDup(dup)
	styp, err := l.k.SockType(dup)
	if err != nil {
		if notSocket(err) {
			l.respond(n, respContinue())
			return
		}
		l.refuseOp(n, op, "fd "+strconv.Itoa(out), ruleFDRaced)
		return
	}
	t := target{dup: dup, sockType: styp}
	if p, err := l.k.SockProtocol(dup); err == nil {
		t.sockProto = p
	}
	if !l.frameSocket(&t) {
		l.respond(n, respContinue())
		return
	}
	l.refuseNet(n, dest{}, protoOf(t.sockType, t.sockProto, dest{}), refuse(ruleCorked))
}

// moreFlag reports whether a send's flags argument carries MSG_MORE.
func moreFlag(flags uint64) bool { return int(int32(flags))&unix.MSG_MORE != 0 }

// notSocket reports whether err is SockType's answer for a descriptor that is not a socket.
func notSocket(err error) bool { return errors.Is(err, unix.ENOTSOCK) }
