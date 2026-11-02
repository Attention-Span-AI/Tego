// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Protocol names as the net event's proto field spells them (record v1: tcp|udp|unix|raw).
const (
	protoTCP  = "tcp"
	protoUDP  = "udp"
	protoUnix = "unix"
	protoRaw  = "raw"
)

// verdictOf is one destination's decision: the rule that produced it, the declared host it names, and
// whether the destination is admitted.
type verdictOf struct {
	rule    string
	host    string
	allowed bool
	// continued marks a destination under a contract with no net: section (compiled.netOpen): admitted,
	// but answered CONTINUE and never performed here, so the line it gets is best-effort.
	continued bool
	// kernelReason is the reason the run's tier-2 program gave for refusing a connect this loop relayed
	// (kernelDecided); empty for every decision of this loop's own.
	kernelReason record.Reason
	gate         *gate.Decision
	unsupported  bool
	// errno is a refusal's errno when it is not R10's: the one the kernel's own syscall would have met for a
	// destination that names nothing (ruleUnixAbsent). Zero for every other decision.
	errno unix.Errno
	// landed says a unix datagram's decision was made on what its name reaches in the task's view (decideLanded),
	// not on the name alone: a refusal there is this loop's own, which no kernel program of the run makes, since
	// they decide the name (kernelRefusal).
	landed bool
	// human says a person approved the destination (askUnix): its allow line carries authority human.
	human bool
	// sockPath is the absolute pathname a unix destination's decision was made on: decideUnix's cleaned name, resolved
	// against the task's cwd when relative, or the name the relay's walk resolved (relayUnixAs). Empty for an abstract
	// name and for one never resolved. A refused line names what the socket gives from it (hostSocketWhat).
	sockPath string
}

// refuse is a refused decision with a rule marker naming why nothing admitted the destination.
func refuse(rule string) verdictOf { return verdictOf{rule: rule} }

// allow turns a resolver match into a decision; a nil match is unmatched, which is a refusal.
func allow(m *NetMatch) verdictOf {
	if m == nil {
		return refuse(ruleUnmatched)
	}
	return verdictOf{rule: m.Rule, host: m.Host, allowed: true}
}

// target is what one network notification resolved to: a duplicate of the target's socket, the protocol
// that duplicate speaks, and the policy's decision about the destination. The duplicate is owned by the
// caller, which closes it before returning unless relay has taken it over (t.dup is then -1).
type target struct {
	dup      int
	sockType int
	// sockProto is the socket's SO_PROTOCOL, 0 when it could not be read (protoOf).
	sockProto int
	proto     string
	dec       verdictOf
	// guarded says the destination is decided by decideGuarded: forwarder capture guards a models[]
	// endpoint, and the socket can reach an IP destination (resolveSocket).
	guarded bool
	// ipGated says the gate scores net actions and the socket can reach an IP destination (resolveSocket):
	// an admitted connect, Fast-Open send or addressed datagram on it is performed on the duplicate with
	// the copy the gate scored, never continued (ADR 0041 D6).
	ipGated bool
	// ipLive says a contract that continues its connects has a live net block in force and the socket can reach an IP
	// destination (compiled.liveRelays, resolveSocket): its admitted connect or Fast-Open send is performed on the
	// duplicate with the copy the block was matched against, never continued, as ipGated's is.
	ipLive bool
	// domain is the socket's SO_DOMAIN where resolveSocket read it, 0 otherwise.
	domain int
}

// relaysIP reports whether the socket's admitted connect or Fast-Open send is relayed for a decision on its address
// (ipGated, ipLive), whatever family the copied bytes spell.
func (t target) relaysIP() bool { return t.ipGated || t.ipLive }

// stream reports whether the socket is connection-oriented, which is what makes a send with an address
// decidable rather than best-effort (R12 vs R13b).
func (t target) stream() bool {
	return t.sockType == unix.SOCK_STREAM || t.sockType == unix.SOCK_SEQPACKET
}

// handleConnect decides one connect (R7, R9, R10). This is the only verdict the package is authoritative
// for, so outside an observe run it never answers CONTINUE to a connect it decided (I2): an allowed
// connect is performed here on a duplicate of the target's own socket and the real result relayed (I3),
// and a refused one gets refusalErrno before a single packet can leave the kernel. In an observe run (R30)
// respond turns that refusal, and every fail-closed answer, into CONTINUE, because nothing is enforced
// there; an allowed connect is still relayed.
//
// A contract with no net: section decides nothing, and there a connect is answered CONTINUE (R7,
// compiled.netOpen). Relaying it would perform it from this process, which has no Landlock domain and, at
// tier 2, runs as root: the agent would reach an abstract name its domain's scope refuses (enforce-landlock
// R7) and a root-only socket its own uid cannot open, with the listener reading this process's
// credentials. With no entry to hold to, the relay protects no decision, so the kernel runs the agent's
// own connect as the agent. Its line is this loop's best-effort one unless the run's kernel recorder records
// the connect itself (kernelRecords), in which case the kernel's is the only one. The exception is a contract that guards a models[] endpoint (decideGuarded):
// on an IP socket there is a decision to hold, so the connect is relayed as under a net: section. So is one a
// `net` gate admitted on an IP socket (t.ipGated, ADR 0041 D6): continued, the kernel read the address again,
// and a sibling that rewrote it after the gate scored the copy reached a destination the gate refuses. It is
// relayed with the copied bytes whatever family they spell, so a unix-spelled copy on an IP socket gets the
// kernel's own EAFNOSUPPORT rather than a CONTINUE whose second read could be AF_INET. A live net block makes
// the same decision (t.ipLive, compiled.liveRelays): it narrows a contract that admitted every destination, so an
// address a sibling swaps in is no longer one the contract admits, and continued, the block on 127.0.0.1:P was
// passed by a connect checked on another port and rewritten after the check.
func handleConnect(l *Loop, n *notif) {
	r := l.newReader(n)
	raw := r.sockaddr(n.args[1], socklen(n.args[2]))
	if n.gone {
		return // R19: the target died; there is nothing to answer and nothing to record
	}
	d := parseSockaddr(raw)
	c := l.table.Load()
	if c.passesUnrecorded(r, d, true) {
		l.respond(n, respContinue())
		return
	}
	t, why, ok := l.resolveTarget(n, r, c, int(int32(n.args[0])), d, true)
	if !ok {
		if n.gone {
			return
		}
		if c.pol.Rules.Gate.Has(gate.Net) {
			dec, _ := l.gateNet(c, &reader{failed: true}, d, t.proto, verdictOf{}, gate.Allow)
			l.refuseNet(n, d, t.proto, dec)
			return
		}
		if c.passesUnresolved(r, d, true) {
			if r.ok() && l.kernelRecords(d, socklen(n.args[2])) {
				l.respond(n, respContinue())
				return // the kernel recorder writes the line, from its own copy of the address (R7)
			}
			l.continueUnresolved(n, c, r, d, t.proto, why)
			return
		}
		l.refuseNet(n, d, t.proto, refuse(why))
		return
	}
	// The close is deferred through a closure because relay takes ownership of the duplicate when it
	// starts: t.dup is -1 from that point and this becomes a no-op.
	defer func() { l.closeDup(t.dup) }()
	if t.dec.allowed || t.dec.continued {
		var gd *gate.Decision
		t.dec, gd = l.gateNet(c, r, d, t.proto, t.dec, gate.Allow)
		if gd != nil && gd.Verdict == gate.Ask {
			if l.performAskConnect(n, c, &t, d, raw, gd.Rule, t.dec.host, false) {
				return
			}
		}
	}
	if c.hostSockets && !hostSocketRelayable(t.domain) {
		// A connect on a socket of a domain the unix-only state does not reach (AF_NETLINK, AF_PACKET, ...): refused,
		// keyed on the socket's own domain, so it is never relayed from this process (hostSocketRelayable).
		l.refuseNet(n, d, t.proto, refuse(ruleHostSockets))
		return
	}
	if t.relaysIP() || c.hostSockets {
		// A net gate's IP connect is relayed on the copy it scored (ADR 0041 D6), and one under a live net block on the
		// copy the block was matched against; in the unix-only state every connect is relayed on the duplicate (R7b,
		// ADR 0070), so the socket and the address it decided are the ones connected.
		t.dec.continued = false
	}
	if t.dec.continued {
		l.respond(n, respContinue())
		if l.kernelRecords(d, socklen(n.args[2])) {
			return // the run's kernel recorder writes this connect's line, from its own copy of the address
		}
		// The kernel's copy of the address carries no scope id, so neither does the line that stands for it.
		l.emitNet(n, c, d.unzoned(), t.proto, t.dec, netVerdict(d, t.dec), netMarks{bestEffort: true})
		return
	}
	if !t.dec.allowed {
		if l.askConnect(n, c, &t, d, raw) {
			return
		}
		l.refuseNet(n, d, t.proto, t.dec)
		return
	}
	addrErr := shortAddrErr(addrlenErr(socklen(n.args[2])), raw, socklen(n.args[2]))
	if d.isUnix() && !t.relaysIP() {
		if addrErr != nil {
			// The kernel's own answer to that addrlen, given before it touches the socket: the clamped
			// name this loop read would connect where the task's call fails (I3). Nothing is connected, and
			// the line is the name's, as for a unix connect whose lookup failed (finishUnix).
			l.respond(n, respResult(0, addrErr))
			l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{})
			return
		}
		// Made as the task would make it, with its credentials and on the socket its path resolves to,
		// not as this process — at tier 2, root (relayUnix, R11).
		l.relayUnix(n, c, &t, d, raw, nil)
		return
	}
	if !l.valid(n) {
		return // E31: the notification must still be live immediately before the duplicate is used
	}
	if l.sourceRouted(&t) {
		l.refuseNet(n, d, t.proto, refuse(ruleSourceRouted))
		return
	}
	res, out := l.relay(n, &t, func(dup int) resp {
		if addrErr != nil {
			return respResult(0, addrErr) // the kernel's own answer to that addrlen: nothing is connected
		}
		return respResult(0, l.k.ConnectRaw(dup, raw))
	})
	switch out {
	case relayDone:
		l.respond(n, res)
		dec, v := l.kernelDecided(n, d, t.proto, res, t.dec)
		l.emitNet(n, c, d, t.proto, dec, v, l.answeredMarks(n))
	case relayOrphaned:
		// The target abandoned the connect while this loop was performing it (E35). There is nothing to
		// answer, but the connect itself is real and the ledger must say so.
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{resultUnknown: true})
	case relayLimited:
		l.refuseNet(n, d, t.proto, refuse(ruleRelayLimit))
	}
	// relayCancelled: the run is ending with the connect still in flight. Its result will never be known
	// and the listener close fails the trapped syscall closed, so nothing is answered and nothing is
	// recorded — unlike E35, the run itself is over.
}

// kernelDecided is the line of an allowed IP connect this loop relayed, once its real result is known. At tier
// 2 the run's connect4/6 decides the relayed connect as well, on the agent's socket (enforce-cgroup-observe §5
// R1, R5), and a refusal there fails it with EPERM: the line is then the kernel's refusal, with the rule and
// reason its breadcrumb names, or `observed` when no fresh breadcrumb names this destination (§6 E5), since
// this loop's allow would say the run let through a connect that did not happen. A breadcrumb saying the
// kernel allowed it leaves the EPERM to something outside tego, and this loop's allow stands.
func (l *Loop) kernelDecided(n *notif, d dest, proto string, res resp, dec verdictOf) (verdictOf, record.Verdict) {
	v := netVerdict(d, dec)
	if l.kernelNet == nil || !d.isInet() || res.errno != -int32(unix.EPERM) {
		return dec, v
	}
	kv, rule, reason := l.kernelNet(d.ap, proto, n.recvAt)
	switch kv {
	case record.VerdictAllow:
		return dec, v
	case record.VerdictRefused:
		dec.rule, dec.kernelReason = rule, reason
		return dec, record.VerdictRefused
	}
	return dec, record.VerdictObserved
}

// kernelRecords reports whether the connect this loop has just continued is recorded by the run's kernel
// recorder, whose line is then the connect's only one (R7). security_socket_connect runs after the kernel
// has copied the address in, and it records an AF_INET or AF_INET6 address long enough to name its destination:
// every continued IP connect but one whose address length move_addr_to_kernel refuses (past sockaddr_storage),
// which fails EINVAL before the hook, and one shorter than its family's address (addrlen below
// sizeof(sockaddr_in), 16, for AF_INET, below SIN6_LEN_RFC2133, 24, for AF_INET6), which the hook returns early
// for rather than write a 0.0.0.0:0 its caller never named: both keep this loop's line, and the call fails
// EINVAL in the protocol's own length check. A unix
// connect, AF_UNSPEC and any other family the hook does not record, so they keep this loop's line too. A relayed or refused connect never
// reaches here: the agent's own task does not make it (a relay runs from this process's cgroup, which no
// run's row names), so this loop's line is its only one.
func (l *Loop) kernelRecords(d dest, addrlen int64) bool {
	if l.kernelConnects == nil || !d.isInet() || addrlen < kernelAddrMin(d.family) || addrlen > sockaddrMax {
		return false
	}
	return l.kernelConnects()
}

// kernelAddrMin is the shortest address security_socket_connect's record takes for an IP family: the
// lengths bpf/trace_proc.bpf.c's tego_socket_connect checks before it reserves a record, and the lengths
// tcp_v4_connect, ip4_datagram_connect, tcp_v6_connect and ip6_datagram_connect require.
func kernelAddrMin(family uint16) int64 {
	if family == unix.AF_INET6 {
		return sin6Min // SIN6_LEN_RFC2133
	}
	return unix.SizeofSockaddrInet4
}

// relayed is what the goroutine performing a relayed syscall hands back: the response, or the value a
// panic inside the kernel call carried. R25 recovers per notification on the worker, and the relay is the
// only place this package leaves that stack, so the panic travels rather than escaping (I12, E34).
type relayed struct {
	r        resp
	panicked *relayPanic
}

// relayPanic carries a panic out of a relay goroutine to the worker that re-raises it (R25). The stack is
// the goroutine's own, taken where it was recovered: the worker's recover would otherwise log only its own
// frames, and the panicking site could not be found after the fact.
type relayPanic struct {
	value any
	stack []byte
}

// relayOutcome is what a handler learned about a syscall it relayed on the target's own socket.
type relayOutcome int

const (
	// relayDone: the syscall returned and the answer carries its real result (I3).
	relayDone relayOutcome = iota
	// relayCancelled: the run was cancelled first. The notification is abandoned unanswered — the real
	// result will never be known and I3 forbids inventing one — and the listener close that follows is
	// what fails the trapped syscall closed with -ENOSYS (ARCHITECTURE §6).
	relayCancelled
	// relayOrphaned: the target abandoned the syscall while this loop was performing it (E35). Same
	// answer — none — but the side effect already happened. Below 5.19, or without WAIT_KILLABLE_RECV, a
	// non-fatal signal did it and the kernel is about to restart the syscall and notify again for it;
	// with the flag only a fatal signal can, and nothing restarts. A 5.19+ kernel without the 2025 fix
	// cce436aa keeps one window open (sys.SeccompSetFilterNewListener): a non-fatal signal that
	// lands as the answer is sent restarts the syscall after NOTIF_SEND succeeded. That is not an orphan —
	// nothing here sees it — so the performed call's line carries no result_unknown.
	relayOrphaned
	// relayLimited: relayCeiling relays were already outstanding, so this one was never started. Nothing
	// was performed and the handler still owns the duplicate; it answers the refusal (E28).
	relayLimited
)

// relayGrace is how long a relayed syscall runs before the loop starts watching it: a connect to a local
// or already-established endpoint returns well inside it, so the common case pays neither the extra
// ID_VALID ioctl nor the standby goroutine.
const relayGrace = 2 * time.Millisecond

// relayPoll is how often a relay still outstanding after relayGrace is checked against the notification.
// seccomp_unotify(2), "Caveats regarding blocking system calls", is explicit that this is the
// supervisor's job: "when the supervisor wishes to emulate a blocking system call, it must do so in such
// a way that it gets informed if the target's system call is interrupted by a signal handler ... it could
// employ a separate thread that uses the SECCOMP_IOCTL_NOTIF_ID_VALID operation to check if the target is
// still blocked". 20 ms is an unsourced P0 default: two ioctls a second per outstanding relay, against a
// window that is otherwise the kernel's whole SYN retry schedule.
const relayPoll = 20 * time.Millisecond

// relay performs an allowed connect or Fast-Open send on the target's own socket and waits for its real
// result. Once it starts the syscall it owns the duplicate: t.dup is cleared, and the goroutine closes
// the descriptor once the syscall has returned, whichever way this call ended (E28). The duplicate must
// not be closed while the syscall is still in it — the fd number would be reused under a kernel that is
// still writing to it — which is why ownership moves rather than being shared.
//
// The relayed syscall itself has no deadline, as §4 specifies: the duplicate shares the target's open
// file description, so a blocking socket gives a blocking connect(2), and against a blackholed route that
// is the kernel's whole SYN retry schedule (~127 s at the default tcp_syn_retries=6). What was not
// intended is that such a syscall, performed inline on the worker, is unreachable by cancellation: the
// wake byte and the poll slice only reach a worker inside receive(), so Run's workers.Wait() could not
// return, the runner's group.Wait() behind it could not return, and the run outlived by minutes the
// deadline that had already killed the agent. On its own goroutine the fast path is unchanged — the real
// result, never fabricated (I3) — and shutdown is bounded by the run's cancellation, not by the network.
//
// Waiting for it is not free either, and the wait is what the two watches below bound:
//
//   - the worker carrying this notification is handed to a standby and retires when the handler returns
//     (backfill, R21), so a slow relay costs the pool nothing. Without it four blackholed connects park
//     the default pool and every notified syscall of every thread of the run stops being answered.
//   - the notification is polled with ID_VALID, because the target can abandon its syscall and the
//     kernel does not tell the supervisor: the first it would otherwise hear is ENOENT from NOTIF_SEND,
//     after the connect or the send has already happened (E35, seccomp_unotify(2)). Below 5.19, or on a
//     listener installed without WAIT_KILLABLE_RECV, any signal can do that at any time; with the flag
//     only a fatal one can, and the target's other signals wait for the relay to return — except, on a
//     kernel without cce436aa, one that lands as the answer is sent (relayOrphaned).
//
// Neither bounds a relay nobody waits on any more, and that one still holds its goroutine and its
// duplicate, so the relays themselves are counted: past relayCeiling this refuses to start another and
// returns relayLimited, which the handler answers fail-closed like a duplicate it could not take (§7).
func (l *Loop) relay(n *notif, t *target, fn func(dup int) resp) (resp, relayOutcome) {
	if l.relays.Add(1) > l.relayCeiling() {
		l.relays.Add(-1)
		l.metrics.relayLimited.Add(1)
		l.log.Warn("supervisor: relayed syscalls at their ceiling, refusing another",
			"nr", n.nr, "id", n.id, "ceiling", l.relayCeiling())
		return resp{}, relayLimited
	}
	dup := t.dup
	t.dup = -1
	out := make(chan relayed, 1)
	go func() {
		var got relayed
		// R25 puts every dispatch call under a per-notification recover() in the worker loop, and this is
		// the one kernel call that no longer runs on that stack. Unrecovered here, a panic would take the
		// process down rather than one notification (I12, E34) and leak the duplicate with it (E28), so it
		// is caught, the descriptor is released on every path, and the value is carried back to the worker
		// to be re-raised where R25's wrapper can answer it.
		defer func() {
			if p := recover(); p != nil {
				got.panicked = &relayPanic{value: p, stack: debug.Stack()}
				l.log.Error("supervisor: relayed syscall panic", "nr", n.nr, "id", n.id, "panic", p)
			}
			l.closeDup(dup)
			// Released only once the duplicate is closed, so the count never reads lower than the
			// descriptors relays hold, and before the result is handed back, so a handler that saw
			// relayDone has already given its slot back.
			l.relays.Add(-1)
			out <- got
		}()
		got.r = fn(dup)
	}()
	watch := time.NewTimer(relayGrace)
	defer watch.Stop()
	for {
		select {
		case got := <-out:
			if got.panicked != nil {
				panic(*got.panicked) // R25: recovered per notification on the worker, never per Loop (I12)
			}
			return got.r, relayDone
		case <-n.done:
			n.detached = true
			l.log.Debug("supervisor: relay abandoned on shutdown", "nr", n.nr, "id", n.id)
			return resp{}, relayCancelled
		case <-watch.C:
			l.backfill(n)
			live, err := l.idValid(n)
			if err != nil {
				// Unknown, not abandoned: answering the notification now would invent a result for a syscall
				// still in flight (I3), so the relay is polled again.
				watch.Reset(relayPoll)
				continue
			}
			if !live {
				n.gone = true
				// The notification is marked gone, so respond and finish are both no-ops for it
				// (R19). The relay goroutine still owns the duplicate and closes it when the syscall
				// returns; what this loop cannot do is take the side effect back.
				l.metrics.orphaned.Add(1)
				l.log.Warn("supervisor: the target abandoned a syscall this loop had already performed",
					"nr", n.nr, "id", n.id)
				return resp{}, relayOrphaned
			}
			watch.Reset(relayPoll)
		}
	}
}

// netVerdict is the verdict one decided destination is recorded with. An address that names no
// destination at all — connect(2)'s AF_UNSPEC disassociation — reached nothing and decided nothing, so it
// is recorded as observed rather than as an allowed connection, the reading R28 gives a PATH-search
// candidate for the same reason.
func netVerdict(d dest, dec verdictOf) record.Verdict {
	switch {
	case !dec.allowed:
		return record.VerdictRefused
	case d.isUnspec():
		return record.VerdictObserved
	}
	return record.VerdictAllow
}

// resolveTarget duplicates the target's socket, reads its type and decides the destination. ok is false
// when the address itself was unusable or the duplicate could not be taken: both are fail-closed for a
// decision kind (R5, §7 "pidfd_getfd fails"), and why names which for the event's rule field. connectOp
// says the notification is a connect(2), the one syscall in which AF_UNSPEC is decidable (R4).
//
// t.proto is set whatever ok says, because the caller records the refusal with it. When ok is false the
// caller owns no duplicate (t.dup is -1), and t.proto is the socket's own protocol unless the refusal came
// before the socket was read (args-unreadable) or because it could not be read (fd-raced, fd-exhausted):
// those carry protoOf's default, which names no socket (§9).
func (l *Loop) resolveTarget(n *notif, r *reader, c *compiled, sockfd int, d dest, connectOp bool) (t target, why string, ok bool) {
	unread := target{dup: -1, proto: protoOf(0, 0, d)}
	if !r.ok() {
		return unread, noteOr(r, ruleArgsUnreadable), false
	}
	t, why, ok = l.resolveSocket(n, c, sockfd)
	if !ok {
		return unread, why, false
	}
	t.proto = protoOf(t.sockType, t.sockProto, d)
	if c.refusesUndecidable(d, connectOp, t.guarded) && !(!connectOp && d.family == unix.AF_NETLINK && l.routeSocket(&t)) {
		// An unrecognised family matches nothing (R4, E4), and is refused whatever the socket is: R13b's
		// CONTINUE is for a destination this tier read and matched, not for bytes it cannot place, so a
		// datagram udp_sendmsg would send to the sockaddr_in behind an AF_UNSPEC family word never leaves.
		// The socket was read only so the refusal names the protocol it was made on (R4); the answer does
		// not depend on it, and the duplicate is not kept. A send to the netlink family on a NETLINK_ROUTE socket
		// is the exception (ADR 0128): the caller keeps the duplicate and asks routeQuery, and what is no query
		// is refused unmatched there, decide having matched nothing.
		l.closeDup(t.dup)
		t.dup = -1
		return t, ruleUnmatched, false
	}
	t.dec = l.decide(c, r, d, t.proto, connectOp, t.guarded)
	return t, "", true
}

// refusesUndecidable reports whether an address this tier cannot match refuses the syscall it arrived
// in (R4, E4). Under a net: section every such address does. A contract with no net: section has nothing
// to match (decide), so an address of a family this tier does not parse goes on like any other — with
// one exception: AF_UNSPEC outside connect(2). That one is not an address this tier merely cannot name.
// udp_sendmsg and raw_sendmsg send to the sockaddr_in behind the family word, so continued it reached any
// host while its line said dst "unspec", verdict observed: bytes on the wire recorded as going nowhere,
// and a destination drift and measure never see. Refusing it costs nothing a program needs: a NULL
// address or AF_INET spells the same send (R7). guarded is the target's (decideGuarded): on an IP socket
// under a models[] guard every such address refuses, as under a net: section, because continued, its bytes
// are re-read by the kernel after this decision and a sibling thread can have made them the guarded
// endpoint's.
func (c *compiled) refusesUndecidable(d dest, connectOp, guarded bool) bool {
	if d.decidable(connectOp) {
		return false
	}
	return !c.netOpen || guarded || d.isUnspec()
}

// passesUnresolved reports whether a net notification whose address could not be read, or whose socket
// could not be duplicated, is continued rather than refused (R5). R5's refusal holds a decision this loop
// could not make, and a contract with no net: section, no models[] guard and host_sockets: true makes none:
// SEMANTICS §1 gives it "deny nothing", and decide admits every destination there, so the one it could not read is
// admitted too. The unix-only state (ADR 0070) decides every unix destination, so it refuses what it cannot read.
// Refusing it failed every connect of a task this unprivileged tier cannot read — one that made itself
// non-dumpable (ssh-agent, gpg) denies both process_vm_readv and pidfd_getfd to tier 1 — under a contract that
// restricts no network. The exception is an address this loop did read that refuses the syscall on every
// socket (AF_UNSPEC outside connect(2), refusesUndecidable): that refusal does not depend on the socket, so a
// socket that could not be read changes nothing about it.
func (c *compiled) passesUnresolved(r *reader, d dest, connectOp bool) bool {
	if c.pol.Rules.Gate.Has(gate.Net) || !c.netOpen || c.guard != nil || c.hostSockets {
		return false // the unix-only state decides every unix destination, so what it cannot read it refuses (R7b)
	}
	if c.blocks().HasNet() {
		return false // while a destination is blocked live, one this loop cannot read may be it (liveNet): refused
	}
	return !r.ok() || !c.refusesUndecidable(d, connectOp, false)
}

// passesUnrecorded reports whether an addressed connect or send is continued with no socket read at all: a
// contract that decides nothing (passesUnresolved) under record: off, where no allowed or observed line is
// kept (emitNet). Every branch past the socket then answers CONTINUE and writes nothing, so the duplicate
// resolveSocket takes (two ID_VALIDs, pidfd_open, pidfd_getfd, SO_TYPE, SO_PROTOCOL and the closes) would be
// taken only to be dropped, on every datagram of an agent sending to explicit addresses. An address that
// refuses the syscall on every socket (refusesUndecidable) is not passed, and keeps its refusal and line.
// With a recording run the duplicate is still taken: the line names the socket's protocol, and whether the
// kernel recorder writes a connect's line may be asked only after the answer (kernelRecords).
func (c *compiled) passesUnrecorded(r *reader, d dest, connectOp bool) bool {
	return !c.recording() && c.passesUnresolved(r, d, connectOp)
}

// continueUnresolved answers CONTINUE to a net notification passesUnresolved admits and records it observed,
// best-effort, under why (args-unreadable or fd-raced): nothing was decided, and the destination the line
// names is the one read here, or none when the address itself could not be read.
func (l *Loop) continueUnresolved(n *notif, c *compiled, r *reader, d dest, proto, why string) {
	l.respond(n, respContinue())
	if !r.ok() {
		d, proto = dest{}, protoOf(0, 0, dest{})
	}
	l.emitNet(n, c, d, proto, verdictOf{rule: why, allowed: true, continued: true}, record.VerdictObserved,
		netMarks{bestEffort: true})
}

// resolveSocket duplicates the target's socket and reads its type, which is what tells a Fast-Open send
// from a datagram one (E33) and what names the event's proto. Both failures are fail-closed for a
// decision kind (§7 "pidfd_getfd fails"); a duplicate that failed is named by dupFailure, and a type that
// could not be read is fd-raced. The caller owns the duplicate it returns.
//
// Under a models[] guard it also reads the socket's domain: an AF_INET or AF_INET6 socket is decided by
// decideGuarded whatever address the syscall names, since the kernel re-reads the address after a CONTINUE
// and a sibling thread can have rewritten a unix or unparsed one into the guarded endpoint's by then. Any
// other domain cannot reach an IP destination at all and goes on as under netOpen. A domain that cannot be
// read is taken as IP, the side that decides. Under a gate that scores net actions it is read for the same
// reason, and an IP socket is ipGated: its admitted addressed syscalls are relayed (ADR 0041 D6). So is it under a
// live net block on a contract that continues its connects, where it is ipLive. The domain is the socket's own, never
// the copied family word, which a sibling can flip.
func (l *Loop) resolveSocket(n *notif, c *compiled, sockfd int) (t target, why string, ok bool) {
	dup, err := l.duplicate(n, sockfd)
	if err != nil {
		return target{}, l.dupFailure(err), false
	}
	styp, err := l.k.SockType(dup)
	if err != nil {
		// The duplicate is not a socket any more, or never was: the fd number was closed and reused
		// between the trap and the duplicate (E33's race, seen from its failing side). There is nothing
		// to decide against, so this fails closed like a failed duplicate (§7 "pidfd_getfd fails").
		l.log.Debug("supervisor: SO_TYPE failed", "fd", sockfd, "err", err)
		l.closeDup(dup)
		return target{}, ruleFDRaced, false
	}
	t = target{dup: dup, sockType: styp}
	if p, err := l.k.SockProtocol(dup); err == nil {
		t.sockProto = p
	}
	gated, live := c.pol.Rules.Gate.Has(gate.Net), c.liveRelays()
	if c.guard != nil || gated || live {
		dom, err := l.k.SockDomain(dup)
		if err == nil {
			t.domain = dom
		}
		ip := err != nil || dom == unix.AF_INET || dom == unix.AF_INET6
		t.guarded = c.guard != nil && ip
		t.ipGated = gated && ip
		t.ipLive = live && ip
	}
	if c.hostSockets && t.domain == 0 {
		// The unix-only state keys its relay on the socket's own domain (ADR 0041 D6, ADR 0070 Decision 3): read on
		// the duplicate, which a sibling's dup2 cannot swap. A domain that cannot be read stays 0, not relayable, so
		// the socket is refused (hostSocketRelayable), fail closed.
		if dom, err := l.k.SockDomain(dup); err == nil {
			t.domain = dom
		}
	}
	return t, "", true
}

// sourceRouted reports whether a relay a net gate admitted on an IP socket must be refused because the socket
// carries a source route, or its options could not be read (ADR 0041 D6). IP_OPTIONS with LSRR or SSRR (which
// an unprivileged task may set before Linux 7.1 and its stable backports, and a task with CAP_NET_RAW on any
// kernel) and an IPV6_RTHDR send the first hop to an address in the route, not to the destination the gate scored.
// Only an ipGated relay is asked: the gate's score is about the destination.
//
// The read is a snapshot of a socket every thread of the agent shares, so on its own it is check-then-act: a
// sibling's setsockopt between it and the relayed call would add a route. The filter closes that: under a net
// gate it refuses every setsockopt that sets one (enforce-landlock R11b, sourceRouteTest), on scalar arguments.
// What the read still catches is a socket that carried a route before the filter applied, one the agent
// inherited or received over a unix socket.
func (l *Loop) sourceRouted(t *target) bool {
	if !t.ipGated {
		return false
	}
	routed, err := l.k.SourceRouted(t.dup, t.domain)
	if err != nil {
		l.log.Debug("supervisor: source-route options unreadable", "err", err)
		return true
	}
	return routed
}

// refuseNet answers refusalErrno and records the refusal. A refusal is recorded whatever record: says: it
// is the reason channel's second guarantee (spec/reason/REASON-CHANNEL.md §1). Order is always respond
// first, emit second, so the ledger can never delay the target (R23, I5).
func (l *Loop) refuseNet(n *notif, d dest, proto string, dec verdictOf) {
	errno := refusalErrno
	if dec.errno != 0 {
		errno = dec.errno
	}
	l.respond(n, respErrno(errno))
	l.emitNet(n, l.table.Load(), d, proto, dec, record.VerdictRefused, netMarks{})
}

// netMarks are the additive payload flags a net line may carry beyond record v1's own fields: one for a
// verdict this tier recorded without enforcing (R13b), one for a syscall it performed whose result never
// reached the agent (E35). Both are omitempty, so an ordinary decided line is unchanged.
type netMarks struct {
	bestEffort    bool
	resultUnknown bool
}

// answeredMarks is the payload marking a relay that returned its real result deserves: nothing, unless
// the answer carrying it never reached the target.
//
// respond sets gone when NOTIF_SEND failed, and for a syscall this loop had already performed that is the
// same condition the ID_VALID watch reports as relayOrphaned — the notification was withdrawn after the
// side effect (E35). Only the *slow* relay meets the watch; a connect to a local endpoint or a send that
// completes in microseconds returns before relayGrace has elapsed, and that is the commonest shape of all.
// Without this the ordinary case wrote a line indistinguishable from one the agent received, while,
// below 5.19 or without WAIT_KILLABLE_RECV, the kernel's restart of the abandoned syscall added a second
// for the same call (seccomp_unotify(2), "Interaction with SA_RESTART signal handlers").
func (l *Loop) answeredMarks(n *notif) netMarks {
	if !n.gone {
		return netMarks{}
	}
	l.metrics.orphaned.Add(1)
	l.log.Warn("supervisor: the answer to a syscall this loop had already performed never reached the target",
		"nr", n.nr, "id", n.id)
	return netMarks{resultUnknown: true}
}

// emitNet records a decided destination. Under record: off only refusals are kept.
func (l *Loop) emitNet(n *notif, c *compiled, d dest, proto string, dec verdictOf, v record.Verdict, m netMarks) {
	if v != record.VerdictRefused && !c.recording() {
		return
	}
	var reason record.Reason
	if v == record.VerdictRefused {
		reason = record.ReasonNetNotAllowed
		if dec.kernelReason != "" {
			reason = dec.kernelReason
		}
	}
	ev := action(l.event(n, record.KindNet, record.SourceSupervisor), dec.rule, v, reason)
	if dec.gate != nil && dec.gate.Verdict != gate.Allow {
		ev.Authority = record.AuthorityGate
	}
	if dec.human && v != record.VerdictRefused {
		ev.Authority = record.AuthorityHuman
	}
	payload := netPayload{
		NetPayload:    record.NetPayload{Proto: proto, Dst: d.String(), Host: dec.host},
		BestEffort:    m.bestEffort,
		ResultUnknown: m.resultUnknown,
		GateFields:    gatePayload(dec.gate, dec.unsupported),
	}
	if v == record.VerdictRefused && dec.rule == ruleHostSockets {
		payload.What = l.hostSocketWhat(dec, d)
	}
	if m.resultUnknown {
		// emitFor's gate is "answered first", because a decision this loop never reached is not a
		// decision the run made (R19, E1). An orphaned relay is the one case where that reading is wrong:
		// the decision was made and carried out on the target's own socket, and only the answer was lost.
		// Suppressing it would leave a connection this loop opened with no line in the ledger at all.
		l.awaitPrev(n)
		l.emit(ev, payload)
		return
	}
	l.emitFor(n, ev, payload)
}

// hostSocketWhat is what the socket a refusal of rule host-sockets names gives an agent that reaches it (agent-contract
// R19, ADR 0070 (4)), or "" for one R19's list does not name: looked up on the name the decision was made on
// (dec.sockPath, cleaned and resolved against the task's cwd), else on the cleaned absolute name the address spells,
// with the list's %U the invoking user's runtime directory (runtimeDirs), the one compile names.
func (l *Loop) hostSocketWhat(dec verdictOf, d dest) string {
	p := dec.sockPath
	if p == "" && strings.HasPrefix(d.unixPath, "/") {
		p = cleanPath(d.unixPath)
	}
	if p == "" {
		return ""
	}
	for _, dir := range l.runtimeDirs {
		if what := agent.HostSocketWhat(p, dir); what != "" {
			return what
		}
	}
	return ""
}

// hostRuntimeDirs is hostRuntimeDirsOf for this process: the invoking uid compile names the per-user sockets of
// (config.InvokingUID, SUDO_UID's at the root tiers, where this process is root) and its XDG_RUNTIME_DIR.
func hostRuntimeDirs() []string {
	uid, viaSudo := config.InvokingUID()
	return hostRuntimeDirsOf(uid, viaSudo, os.Getenv("XDG_RUNTIME_DIR"))
}

// hostRuntimeDirsOf is the directories R19's %U stands for when a refused line names what a socket gives: the
// invoking user's /run/user/<uid>, which compile's list names (hostSocketsFound), and, unless the run was started
// through sudo, whose XDG_RUNTIME_DIR is root's or none, an absolute XDG_RUNTIME_DIR that differs from it.
func hostRuntimeDirsOf(uid int, viaSudo bool, xdg string) []string {
	dirs := []string{"/run/user/" + strconv.Itoa(uid)}
	if xdg = filepath.Clean(xdg); !viaSudo && filepath.IsAbs(xdg) && xdg != dirs[0] {
		dirs = append(dirs, xdg)
	}
	return dirs
}

// decide matches a destination against the policy: the resolver exception first (R14), then the compiled
// net.allow entries for an IP destination (R7), then the unix entries for a socket path or abstract name
// (R11). First match wins; nothing matched is a refusal, never a default allow — except under a contract
// with no net: section, which SEMANTICS §1 gives every IP destination. There the Landlock builder handles no
// network port right (netRestricted) and decide.Evaluate reports allow, so an IP destination nothing names is
// admitted as unmatched; refusing it refused every connect of the run but DNS. In the unix-only state (ADR 0070,
// c.hostSockets) a unix destination is decideHostSocket's and every connect is relayed (handleConnect); under
// host_sockets: true every destination is admitted and marked continued, and so is one an entry names: with
// nothing to refuse there is no decision for a relay to hold, and the kernel performs it as the agent. An entry or the resolver exception still
// names what it matches. An AF_UNSPEC address in a send is refused even there (refusesUndecidable).
// connectOp says the notification is a connect(2), the one syscall in which AF_UNSPEC is decidable (R4).
// guarded is the target's: such a contract that guards a models[] endpoint decides an IP socket's
// destination after all (decideGuarded).
//
// The run's live blocks then refuse what they name of what that admits, or would ask a person for (liveNet).
func (l *Loop) decide(c *compiled, r *reader, d dest, proto string, connectOp, guarded bool) verdictOf {
	return c.liveNet(d, l.decideContract(c, r, d, proto, connectOp, guarded))
}

// decideContract is decide under the contract alone.
func (l *Loop) decideContract(c *compiled, r *reader, d dest, proto string, connectOp, guarded bool) verdictOf {
	if guarded {
		return l.decideGuarded(c, d, proto, connectOp)
	}
	dec := l.decideDest(c, r, d, proto, connectOp)
	if !c.netOpen || c.refusesUndecidable(d, connectOp, false) {
		return dec
	}
	if c.hostSockets && d.isUnix() {
		return l.decideHostSocket(d, dec)
	}
	return continuedOf(dec)
}

// decideHostSocket is a unix destination's decision in the unix-only state (ADR 0070, compiled.hostSockets, R7b), from
// decideUnix's: a name a runtime unix: grant names (tego's own endpoints: the DNS broker's socket) is admitted by it; a
// pathname under a write entry is admitted by the entry only when a process of the run bound the socket it reaches,
// which the relay asks for a connect (relayUnix, unixAdmit) and decideUnix's landing for a datagram (decideLanded); and
// an abstract name is admitted when one of the run's own sockets holds it now (runSockets.holdsAbstract: the sockets a
// task of the run called bind on with an abstract name, asked of the kernel), its line unmatched as an IP destination
// of such a contract is; and every other unix destination, a pathname no write entry encloses or an abstract name no
// socket of the run holds, is refused host-sockets: no process of the run could have bound the first or holds the
// second. A refusal on what the walk met (path-unreliable, unix-absent, unix-origin-unread) keeps its own rule, and so
// does an abstract lookup that failed (unix-origin-unread); unmatched and unix-foreign, which say the socket is no
// run's, become host-sockets (hostSocketsRule). Nothing is continued: the caller relays an admitted connect.
func (l *Loop) decideHostSocket(d dest, dec verdictOf) verdictOf {
	if len(d.abstract) > 0 && !dec.allowed {
		held, err := l.runSockets.holdsAbstract(l.k, string(d.abstract))
		switch {
		case err != nil:
			l.log.Debug("supervisor: which abstract name a socket of the run holds could not be read", "err", err)
			return refuse(ruleUnixOriginUnread)
		case held:
			return verdictOf{rule: ruleUnmatched, allowed: true}
		}
		if p, ok := l.k.(diagProber); ok && !p.UnixDiagAvailable() {
			// No sock_diag for AF_UNIX: the kernel answers every lookup ENOENT, so which name the run's sockets hold
			// cannot be read, and the refusal says so rather than calling the socket foreign (R11a).
			return refuse(ruleUnixOriginUnread)
		}
		return refuse(ruleHostSockets)
	}
	return hostSocketsRule(dec)
}

// hostSocketsRule names a unix refusal of the unix-only state: a socket no process of the run bound, unmatched by any
// entry or found foreign under a write entry, is refused host-sockets, the default that refuses it (ADR 0070).
func hostSocketsRule(dec verdictOf) verdictOf {
	if !dec.allowed && (dec.rule == ruleUnmatched || dec.rule == ruleUnixForeign) {
		dec.rule = ruleHostSockets
	}
	return dec
}

// hostSocketRelayable reports whether a socket the unix-only state relays is of a domain it reaches: IP (SEMANTICS §1's
// every IP destination, relayed on the duplicate) or unix (a socket a process of the run bound). dom is the socket's
// own, read on the duplicate (resolveSocket), which a sibling's dup2 cannot change, so the relay class is keyed on it
// and not on the copied address family (ADR 0041 D6); 0 means it could not be read, which is not relayable,
// so such a socket is refused, fail closed. A connect or addressed send on any other domain (AF_NETLINK, AF_PACKET, a
// bluetooth socket) names no destination the unix-only state admits: continued, a sibling's dup2 of a unix socket over
// the descriptor would reach a host socket (the race Decision 3 closes by relaying), and relayed from this process it
// would run with the supervisor's credentials, root at the root tiers, where a netlink multicast its uid could not
// make would pass netlink_allowed's CAP_NET_ADMIN check on the supervisor. Refused instead (ADR 0070 Decision 3).
func hostSocketRelayable(dom int) bool {
	return dom == unix.AF_INET || dom == unix.AF_INET6 || dom == unix.AF_UNIX
}

// continuedOf is a destination decided under a contract with no net: section (decide): admitted and
// continued, under the name the resolver exception or an entry gave it, or unmatched where they refused it.
func continuedOf(dec verdictOf) verdictOf {
	rule := dec.rule
	if !dec.allowed {
		rule = ruleUnmatched
	}
	return verdictOf{rule: rule, host: dec.host, allowed: true, continued: true}
}

// ContinuedNet names an IP destination the way this loop's line for a connect or datagram it continues
// names it (decide under a contract with no net: section): the rule, the declared host and the verdict.
// ok is false when this loop would not continue one: the contract has a net: section, or guards a
// models[] endpoint (decideGuarded), so the connect is relayed or refused and the agent's own task never
// makes it. It is the one lookup the tier-2 kernel recorder names such a connect with, whose line is then
// the connect's only one (R7, kernelRecords; enforce-cgroup-observe R5): the resolver exception, the
// entries with their live addresses, the resolved-address check and the entries the runtime adds (the
// capture listener) are this loop's, never a second matcher's. proto is "tcp", "udp" or "raw". Safe for
// any number of goroutines.
func (l *Loop) ContinuedNet(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool) {
	c := l.table.Load()
	if c == nil || !c.netOpen || c.guard != nil || !ap.IsValid() {
		return "", "", "", false
	}
	dec := continuedOf(l.decideInet(c, ap, proto))
	return dec.rule, dec.host, record.VerdictAllow, true
}

// decideInet is decideDest for an IP destination: the resolver exception first (R14), then the entries.
func (l *Loop) decideInet(c *compiled, ap netip.AddrPort, proto string) verdictOf {
	if l.isResolver(c, ap, proto) {
		return verdictOf{rule: ruleResolver, host: ap.Addr().String(), allowed: true}
	}
	return c.admitResolved(ap, proto, c.pol.Resolver.Match(ap, proto))
}

// decideGuarded applies the forwarder boundary before the ordinary network policy. Synthetic capture
// grants remain reachable; known model addresses and local aliases stay refused. Unknown destinations on
// named model ports require an explicit, safely resolved net.allow entry. Other ports follow net: normally.
// Every admitted IP operation is relayed, holding the address against a sibling-thread rewrite (R7).
// With no net: section (netOpen) the contract itself admits every destination, so the port reservation
// does not apply there and only the model's own addresses and local aliases are refused (SEMANTICS §1,
// amended 2026-10-05): from 2026-10-01 such a run refused every HTTPS host on a named model's port.
func (l *Loop) decideGuarded(c *compiled, d dest, proto string, connectOp bool) verdictOf {
	switch {
	case d.isInet():
		if l.isResolver(c, d.ap, proto) {
			return verdictOf{rule: ruleResolver, host: d.ap.Addr().String(), allowed: true}
		}
		m := c.pol.Resolver.Match(d.ap, proto)
		dec := c.admitResolved(d.ap, proto, m)
		if dec.allowed && agent.IsRuntimeRule(dec.rule) {
			return dec
		}
		if guarded, ok := c.guard.matchAllowed(d.ap, dec.allowed || c.netOpen); ok {
			return guarded
		}
		if m != nil || !c.netOpen {
			return dec
		}
		return verdictOf{rule: ruleUnmatched, allowed: true}
	case d.isUnspec() && connectOp:
		return verdictOf{rule: ruleUnspec, allowed: true}
	}
	return refuse(ruleUnmatched)
}

// decideDest is decide against the declared entries alone.
func (l *Loop) decideDest(c *compiled, r *reader, d dest, proto string, connectOp bool) verdictOf {
	switch {
	case !d.decidable(connectOp):
		// Outside connect(2) an AF_UNSPEC address is an address after all — udp_sendmsg and raw_sendmsg
		// accept sin_family AF_UNSPEC as a spelling of AF_INET ("if (usin->sin_family != AF_INET) { if
		// (usin->sin_family != AF_UNSPEC) return -EAFNOSUPPORT; }") and send to what follows it — so it
		// matches nothing, like every family this tier does not parse (R4, E4). resolveTarget refuses both
		// before this is reached when refusesUndecidable says so; handleSendMMsg reaches it for each
		// message of a batch, and under no net: for an unrecognised family that decide then admits.
		return refuse(ruleUnmatched)
	case d.isInet():
		return l.decideInet(c, d.ap, proto)
	case d.isUnix():
		return l.decideUnix(c, r, d, connectOp)
	case d.isUnspec():
		// connect(2)'s disassociation names nowhere, sends nothing and can only narrow what the socket may
		// reach; whatever the socket does next is trapped and decided on its own. There is nothing for R7
		// to match, so refusing it would be a refusal of no destination — and under a net: section the
		// syscall is still relayed on the duplicate rather than continued, so no other thread can swap a
		// real address in first. Under no net: it is continued like every connect there (decide), since
		// any address swapped in is one that contract admits, unless a live net block narrows it (t.ipLive).
		return verdictOf{rule: ruleUnspec, allowed: true}
	}
	return refuse(ruleUnmatched)
}

// isResolver reports whether the destination is one of the machine's DNS resolvers on port 53, allowed on
// UDP and TCP alike and ungated by net.allow (R14, SEMANTICS §5 — glibc falls back to TCP on truncation).
// An empty resolver list matches nothing and DNS falls through to ordinary matching (E32). The lookup is
// decide.IsResolver, the one compile --test answers a resolver row with.
func (l *Loop) isResolver(c *compiled, ap netip.AddrPort, proto string) bool {
	return decide.IsResolver(c.pol.Resolver.ResolverAddrs(), ap, proto)
}

// decideUnix matches a unix destination (R11): an abstract name by its raw bytes, a pathname twice. First its
// cleaned absolute form, with a relative sun_path resolved against /proc/<pid>/cwd, against the declared entries
// and the nearest write entry: a name nothing admits is refused there, as the run's kernel programs refuse it.
// What that admits is a candidate only, since a name can be a symlink, a ".." after one, or a magic link to
// anywhere: the pathname is then decided on the socket it reaches when the task's own lookup resolves it
// (unixWalk), matched by that socket's place against each declared entry's resolved path and the write entries'
// (decideResolved), and through a write entry only when a process of the run bound that very socket (R11a,
// boundByRun), which is what makes multiprocessing, Ray and local MCP servers work while a socket there that
// existed before the run, or that a process outside it made, is refused unix-foreign. For a connect (connectOp)
// that second decision is the relay's, on the inode it then connects to (relayUnix); a connect whose name reaches a
// net.ask unix: scope's place is not admitted by the first at all, whatever entry its spelling lies under, and is
// asked (unixScopeOf, askUnix, R11c). A datagram is never relayed
// (R13b), so it is made here (decideLanded); the kernel then looks the name up again when it sends, which is
// R13b's stated limit. Under a contract with no net: section nothing is decided (decide), and the name is not
// looked up.
func (l *Loop) decideUnix(c *compiled, r *reader, d dest, connectOp bool) verdictOf {
	if d.unnamed {
		return refuse(ruleUnmatched)
	}
	if len(d.abstract) > 0 {
		for _, u := range c.unix {
			if len(u.abstract) > 0 && string(u.abstract) == string(d.abstract) {
				return verdictOf{rule: u.name, allowed: true}
			}
		}
		return refuse(ruleUnmatched)
	}
	p := d.unixPath
	if p == "" {
		return refuse(ruleUnmatched) // no pathname and no abstract name: nothing a rule can name
	}
	if strings.HasPrefix(p, "/") {
		p = cleanPath(p)
	} else {
		p = r.resolve(atFDCWD, p)
	}
	if p == "" {
		return refuse(noteOr(r, ruleUnmatched))
	}
	if !strings.HasPrefix(p, "/") {
		// The cwd could not be read, and R6 left the path relative: no entry can be matched against it,
		// and the refusal says why rather than blaming the policy (R11).
		return refuse(noteOr(r, rulePathUnreliable))
	}
	var scoped func() bool
	if connectOp && r.n != nil {
		scoped = func() bool { return l.unixScopeOf(r.n, c, d, p) != nil }
	}
	dec := c.decideUnixName(p, scoped)
	if dec.allowed && !connectOp && (!c.netOpen || c.hostSockets) {
		dec = l.decideLanded(c, r.n, unixQuery{tid: r.n.pid, path: d.unixPath, joined: p})
	}
	if dec.sockPath == "" {
		dec.sockPath = p // the name, where no walk said what it reached (landedVerdict)
	}
	return dec
}

// decideUnixName is decideUnix's first decision, on the name: the cleaned absolute pathname p matched against the
// declared unix: entries' paths, else against the nearest filesystem entry when that is a write entry. A connect's
// name that reaches a net.ask unix: scope's place (scoped, nil for a datagram and for compile's question) is not
// admitted by a write entry at all, whatever entry its spelling lies under: it is asked (unixScopeOf, askUnix, R11c).
func (c *compiled) decideUnixName(p string, scoped func() bool) verdictOf {
	for _, u := range c.unix {
		if u.path != "" && u.path == p {
			return verdictOf{rule: u.name, allowed: true}
		}
	}
	if scoped != nil && scoped() {
		return refuse(ruleUnmatched) // its name reaches a net.ask unix: scope's place: asked (askUnix), never admitted by a write entry
	}
	if fr := c.nearestFS(p); fr != nil && fr.Write {
		return verdictOf{rule: fr.Name, allowed: true}
	}
	return refuse(ruleUnmatched)
}

// decideLanded decides an addressed unix datagram on what its name reaches in the task's view (R11, R11a), the
// unixTarget walk's answer as landedVerdict decides it, with R11a's question asked of this run (boundByRun).
func (l *Loop) decideLanded(c *compiled, n *notif, q unixQuery) verdictOf {
	place, err := l.unixTarget(n, q)
	return c.landedVerdict(place, err, func(f unixFile, dec verdictOf) verdictOf {
		return l.boundByRun(n, f, dec, needDatagram)
	})
}

// landedVerdict is a datagram's decision on what its name's walk reached (R11, R11a): the file there, matched by its
// place against the declared entries' resolved paths and the write entries' (decideResolved), and through a write entry
// only when bound says the run bound that very socket (boundByRun), which a directory or a file that is no socket never
// is. A name the walk cannot resolve is refused (unixLandedRefusal). The decision is marked landed: its refusal is this
// loop's own. compile --test's property test asks it of the tree it makes (TestCompileLandsWhereTheRunLands).
func (c *compiled) landedVerdict(place unixPlace, err error, bound func(unixFile, verdictOf) verdictOf) verdictOf {
	if err != nil {
		return unixLandedRefusal(err)
	}
	dec, implicit := c.decideResolved(place.at)
	if implicit {
		dec = bound(place.file, dec)
	}
	dec.landed = true
	dec.sockPath = place.at // the socket the walk reached, which the refused line's what is read from (ADR 0070 Decision 4)
	return dec
}

// duplicate takes a duplicate of the target's socket (R9, E31): the pidfd is opened fresh per
// notification and the notification re-validated between the open and the duplicate, so a pid this loop
// no longer has a live notification for is never touched. The duplicate shares the target's open file
// description, so O_NONBLOCK and every other fcntl state carries over and the connect really happens on
// the run's own socket (I6). The credentials it happens with are this process's, except for a unix
// connect, which is made on a thread holding the trapping task's (relayUnix, R11).
//
// Its error is the errno of the step that failed, or ESRCH when the notification is no longer live, so the
// caller can tell this process's own descriptor exhaustion from a race (fdExhausted).
func (l *Loop) duplicate(n *notif, sockfd int) (int, error) {
	if sockfd < 0 {
		return -1, unix.EBADF
	}
	if !l.valid(n) {
		return -1, unix.ESRCH
	}
	pidfd, err := l.openTargetPidFD(n)
	if err != nil {
		l.log.Debug("supervisor: pidfd_open failed", "tid", n.pid, "err", err)
		return -1, err
	}
	defer l.closeDup(pidfd)
	if !l.valid(n) {
		return -1, unix.ESRCH
	}
	dup, err := l.k.GetFD(pidfd, sockfd)
	if err != nil {
		l.log.Debug("supervisor: pidfd_getfd failed", "pid", n.pid, "fd", sockfd, "err", err)
		return -1, err
	}
	return dup, nil
}

// dupFailure is the rule a failed duplicate's refusal names (§7 "pidfd_getfd fails"): fd-exhausted when this process
// or the system had no descriptor for it (fdExhausted), fd-unreadable when the descriptor cannot be taken from this
// task for a lasting reason, and fd-raced for every other failure, the descriptor closed or the task gone between the
// trap and the duplicate. The lasting reasons: pidfd_getfd's ptrace access check refused it (EPERM: at tier 1 a target
// that made itself non-dumpable; kcmp's own access check answers the same); below 6.9, a secondary thread whose
// descriptor table is not its leader's (openTargetPidFD's errOwnFDTable: cloned without CLONE_FILES, or unshared),
// or a kernel whose kcmp cannot tell (ENOSYS, no CONFIG_KCMP). None is a race, and each refuses every such call of
// the task alike.
func (l *Loop) dupFailure(err error) string {
	switch {
	case l.fdExhausted(err):
		return ruleFDExhausted
	case errors.Is(err, unix.EPERM), errors.Is(err, errOwnFDTable), errors.Is(err, unix.ENOSYS):
		return ruleFDUnreadable
	}
	return ruleFDRaced
}

// fdWarnEvery bounds how often descriptor exhaustion is logged at Warn: once per run is too few for an operator
// who raises the limit mid-run, and once per refused connect floods the log.
const fdWarnEvery = 10 * time.Second

// fdExhausted reports whether err is this process's or the system's descriptor table being full (EMFILE,
// ENFILE), and logs it at Warn, at most once per fdWarnEvery: every connect and Fast-Open send under a net:
// section is then refused until descriptors free up, and at the default level nothing else would say why.
func (l *Loop) fdExhausted(err error) bool {
	if !errors.Is(err, unix.EMFILE) && !errors.Is(err, unix.ENFILE) {
		return false
	}
	now := time.Now().UnixNano()
	if last := l.fdWarnAt.Load(); now-last >= int64(fdWarnEvery) && l.fdWarnAt.CompareAndSwap(last, now) {
		l.log.Warn("supervisor: out of file descriptors; sockets cannot be duplicated and are refused as fd-exhausted",
			"err", err)
	}
	return true
}

// openTargetPidFD opens a pidfd for the task that trapped.
//
// The notification's Pid is a thread id: the kernel fills it with task_pid_vnr(current), which this
// package documents in two other places and execIdentity already converts before building an exec id.
// pidfd_open without PIDFD_THREAD requires a thread-group leader, so passing the tid straight through
// is refused for every notification raised by a secondary thread — and a failed duplicate is a
// refusal, so a threaded agent had every connect from a worker refused with EACCES against a contract
// that allowed the host. OpenPidFD is sys.PidfdOpenThread, which asks for the PIDFD_THREAD form (Linux
// 6.9) that names the trapping task exactly and, when that fails, retries the plain form itself. Below
// 6.9 the retry is what runs: it succeeds for a thread-group leader and refuses any other tid (EINVAL
// there; this 6.17 box answers ENOENT, which is why the fallback below keys on no particular errno). That
// refusal is the case served here: resolve the thread group and take a process-scoped pidfd for its
// leader instead.
//
// The tgid fallback is correct only while the worker shares its leader's file-descriptor table
// (CLONE_FILES): pidfd_getfd against the leader then returns the same open file description the worker is
// connecting on. A thread created without CLONE_FILES, or one that has called unshare(CLONE_FILES), has a
// table of its own, and pidfd_getfd against the leader succeeds whenever the leader has any file under the
// same number — the decision, the duplicate and a relay would then run on a socket the worker never named.
// So the fallback asks the kernel whether the two tasks share one table (kcmp KCMP_FILES) and refuses the
// pidfd when they do not, or when kcmp cannot answer (ENOSYS without CONFIG_KCMP): the caller then refuses
// the call, the fail-closed direction, as fd-unreadable (dupFailure), since neither is a race. The answer is stable until the duplicate is taken, since
// the worker is blocked in the trapped syscall and only it can unshare its table, and duplicate's ID_VALID
// check after this returns covers the tid having been reused in between.
func (l *Loop) openTargetPidFD(n *notif) (int, error) {
	fd, err := l.k.OpenPidFD(n.pid)
	if err == nil {
		return fd, nil
	}
	tgid, terr := l.k.Tgid(n.pid)
	if terr != nil || tgid == n.pid {
		return -1, err // the leader's own tid already failed, or the target is gone
	}
	pidfd, err := l.k.OpenPidFDProcess(tgid)
	if err != nil {
		return -1, err
	}
	if same, err := l.k.SameFiles(n.pid, tgid); err != nil || !same {
		l.closeDup(pidfd)
		if err == nil {
			err = errOwnFDTable
		}
		return -1, err
	}
	return pidfd, nil
}

// errOwnFDTable is a secondary thread whose descriptor table is not its leader's, which the tgid fallback
// of openTargetPidFD cannot duplicate from.
var errOwnFDTable = errors.New("the trapping thread does not share its thread group leader's descriptor table")

// closeDup closes a descriptor this loop owns. Every duplicate is closed by the notification that took
// it — inside the handler, or, once relay has taken ownership, by the goroutine still inside the syscall,
// which may outlive the handler and Run itself. A handler holds at most one at a time — three for a unix
// connect, whose task's root and cwd travel with the duplicate (relayUnix) — and at most
// Workers+maxStandby handlers run at once; relay goroutines, which keep theirs after their handler has
// gone, are at most relayCeiling. That sum is what bounds the outstanding descriptors, so a run at a high
// notification or signal rate cannot exhaust this process's descriptors (E28).
func (l *Loop) closeDup(fd int) {
	if fd < 0 {
		return
	}
	if err := l.k.CloseFD(fd); err != nil {
		l.log.Warn("supervisor: closing a duplicate", "fd", fd, "err", err)
	}
}

// protoOf names the protocol of the socket the duplicate is: a unix destination is always unix and a raw
// socket raw. Any other socket is named by its protocol, as the tier-2 kernel recorder names the connect it
// records from sk_protocol (observe's protoName), so the two lines for one continued connect agree: TCP (and
// MPTCP, whose sk_protocol the recorder reads truncated to TCP's number) is tcp, UDP udp, and anything else
// raw: a ping socket (SOCK_DGRAM, IPPROTO_ICMP or ICMPV6), SCTP, UDP-Lite. With no protocol read (0) the socket
// type decides: a datagram socket udp, everything else tcp.
func protoOf(sockType, sockProto int, d dest) string {
	if d.isUnix() {
		return protoUnix
	}
	if sockType == unix.SOCK_RAW {
		return protoRaw
	}
	switch sockProto {
	case 0:
		if sockType == unix.SOCK_DGRAM {
			return protoUDP
		}
		return protoTCP
	case unix.IPPROTO_TCP, unix.IPPROTO_MPTCP:
		return protoTCP
	case unix.IPPROTO_UDP:
		return protoUDP
	}
	return protoRaw
}

// ProtoOfSocket is protoOf for an IP socket of sockType whose SO_PROTOCOL is protocol: the proto this package
// records a connect on it with, which the kernel recorder's must equal (observe's cross-check).
func ProtoOfSocket(sockType, protocol int) string {
	return protoOf(sockType, protocol, dest{family: unix.AF_INET})
}

// socklen reads a socklen_t argument: unsigned 32 bits, so a value with the top bit set is a very large
// length and not a negative one. The reader clamps it to sockaddr_storage either way (R3, E4).
func socklen(arg uint64) int64 { return int64(uint32(arg)) }

// noteOr is the reader's own marker, or the fallback when it recorded none.
func noteOr(r *reader, fallback string) string {
	if r != nil && r.note != "" {
		return r.note
	}
	return fallback
}
