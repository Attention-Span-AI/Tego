// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// handleSocket and handleSocketpair answer a socket(2) or socketpair(2) the filter's allowlist did not admit
// (ADR 0018; enforce-landlock E30). Under a net: section the filter admits what the network rules govern —
// AF_UNIX, NETLINK_ROUTE (ADR 0128), and TCP, UDP and (with an ICMP entry) ping sockets on AF_INET and AF_INET6 — and
// notifies every other triple. Nothing reaches here to be allowed: an SCTP socket reached any address through
// setsockopt(SCTP_SOCKOPT_CONNECTX) and a peerless send(), which no other notification sees, and a family
// outside the net rules (AF_VSOCK, AF_TIPC, AF_PACKET) is governed by none of them. So the handler refuses,
// with the errno a kernel without the family or protocol answers, so that a runtime falls back, and records
// the refusal; it has no CONTINUE path, and an observe run's filter carries no such arm.
func handleSocket(l *Loop, n *notif)     { l.refuseSocket(n, "socket") }
func handleSocketpair(l *Loop, n *notif) { l.refuseSocket(n, "socketpair") }

// handleSetsockopt answers the one setsockopt(2) the filter notifies, SOL_TCP's TCP_ULP under a net: section (ADR 0018
// (7); enforce-landlock E30): an upper-layer protocol is how a run turned a TCP socket the allowlist admitted into one
// of another family (the smc module's "smc" ULP builds an AF_SMC socket in its place, which no socket(2) arm and no
// creation hook sees). No ULP is something the network rules govern, so every name is refused, with ENOENT, what a
// kernel without that ULP answers, so a runtime that tries kTLS falls back to its own TLS. The decision rests on the
// scalar level and option alone; the name is read from the agent's memory only for the line, at most the bytes the
// kernel would read, bracketed by ID_VALID as every read is (R2, I1), and a name that cannot be read is said to be
// unread. A notification gone across that read is neither answered nor recorded (R19). The filter also notifies
// UDP_CORK, at SOL_UDP or SOL_UDPLITE, in a run that decides datagrams (R13's pending frames), which refuseCork
// answers. Anything else reaching here, which the filter never notifies, is refused with EPERM and its numbers
// recorded: a decision kind never continues.
func handleSetsockopt(l *Loop, n *notif) {
	level, option := int32(n.args[1]), int32(n.args[2])
	if (level == unix.SOL_UDP || level == unix.IPPROTO_UDPLITE) && option == unix.UDP_CORK {
		l.refuseCork(n, level, option) // R13's pending frames: SOL_UDPLITE is IPPROTO_UDPLITE's number
		return
	}
	errno := unix.ENOENT
	var name []byte
	read := false
	if level == unix.SOL_TCP && option == unix.TCP_ULP {
		name, read = l.ulpName(n)
		if n.gone {
			return
		}
	} else {
		errno = unix.EPERM
	}
	l.respond(n, respErrno(errno))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = agent.UnmatchedRule, record.ReasonNetNotAllowed
	l.emitFor(n, ev, record.RefusedPayload{Op: "setsockopt", Target: record.SocketOption(level, option, name, read),
		Reason: record.ReasonNetNotAllowed, Rule: agent.UnmatchedRule})
}

// ulpName reads setsockopt(TCP_ULP)'s name from the agent's memory as the kernel would, min(optlen, 15) bytes, for the
// refused line alone: the bytes may change after the read, and nothing is decided on them. The read is a reader's,
// so ID_VALID brackets it on both sides (R2, I1) and a pid reused by another process is never read for the line; a
// notification gone before or across it is marked gone, which the caller checks.
func (l *Loop) ulpName(n *notif) ([]byte, bool) {
	size := int64(int32(n.args[4]))
	if size <= 0 {
		return nil, true
	}
	r := l.newReader(n)
	buf := r.blob(n.args[3], size, record.TCPULPNameMax)
	return buf, r.ok() && len(buf) > 0
}

// refuseSocket answers EPROTONOSUPPORT for an inet socket of a type or protocol outside the allowlist and for a
// netlink protocol but NETLINK_ROUTE (what netlink_create answers a protocol with no kernel side, and libaudit reads
// as a kernel without audit), and EAFNOSUPPORT for any other family (and for a socketpair of any family but AF_UNIX),
// then records a refused line naming the triple: reason net-not-allowed, rule unmatched, since no entry of the
// contract can name it.
func (l *Loop) refuseSocket(n *notif, op string) {
	family, typ, proto := int32(n.args[0]), int32(n.args[1]), int32(n.args[2])
	errno := unix.EAFNOSUPPORT
	if op == "socket" && (family == unix.AF_INET || family == unix.AF_INET6 || family == unix.AF_NETLINK) {
		errno = unix.EPROTONOSUPPORT
	}
	l.respond(n, respErrno(errno))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = agent.UnmatchedRule, record.ReasonNetNotAllowed
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: record.SocketTriple(family, typ, proto),
		Reason: record.ReasonNetNotAllowed, Rule: agent.UnmatchedRule})
}
