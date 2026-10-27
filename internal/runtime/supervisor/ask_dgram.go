// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// maxDgramApprovals bounds the socket approvals one run keeps (dgramApproved). A socket's cookie is never reused
// while the system runs, so a closed socket's entry admits nothing; past the bound an approval is not kept, and the
// socket's next datagram to that destination is asked again, never admitted unasked.
const maxDgramApprovals = 1024

// dgramApproval is one UDP destination a person approved for one socket (askDatagram): the socket's SO_COOKIE, the
// destination as this loop read it, the net.ask scope it reached and, under a net gate, the verdict, score and rule
// the gate gave the datagram the person saw (scored). A person decides a scored request in the light of its score
// (the broker never keeps one as a standing answer), so a later datagram the gate scores otherwise, the gate's hosts
// for that address having changed during the run, is asked again rather than admitted by an approval given at
// another score.
type dgramApproval struct {
	cookie uint64
	dst    netip.AddrPort
	rule   string
	scored gate.Decision
}

// askInetTarget is what a person reads, and a standing answer is kept under, for an IP destination: a TCP one by its
// address, as before UDP approval existed, and a UDP one prefixed udp://, so an "always" given for one transport
// never answers the other.
func askInetTarget(d dest, proto string) string {
	if proto == protoUDP {
		return "udp://" + d.String()
	}
	return d.String()
}

// askDatagram holds an addressed UDP datagram whose destination nothing admits and a net.ask udp:// or bare host:port
// scope reaches (R13d), and reports whether it answered. The datagram's address and payload are copied first, and
// what a relay cannot reproduce exactly is refused before anyone is asked, as relayDatagram refuses it: ancillary
// data, a payload not read whole, MSG_ZEROCOPY, a source-routed socket, a corked socket (frameFree, read again just
// before the relay); a length or payload the kernel itself refuses gets the kernel's answer. MSG_MORE never reaches
// here: refusesFrame refused it first. Then a person decides (ADR 0008; ask.timeout, ask.on_timeout and --always are the
// broker's, under op send and target udp://ip:port), and an approval sends the copied payload on the duplicate to the
// copied address, so a sibling thread that rewrites either during the wait changes nothing that leaves. At tiers 2
// and 3 the run's sendmsg4/6 refuses that send unless granted, so the approval first grants the socket one datagram
// to that destination (grantDatagram), withdrawn when the relay returns. An approval covers the socket's later
// datagrams to the same destination under the same scope, and under a net gate at the same score (dgramApproved), as
// a TCP approval covers the stream its connect opens; another socket, or a datagram scored otherwise, is asked again,
// and a live block naming the destination (its address or the scope's host) refuses each datagram and drops the approval. A denial, a timeout or a broker that cannot answer refuses with that
// reason and sends nothing.
func (l *Loop) askDatagram(n *notif, c *compiled, t *target, d dest, raw []byte, control bool, prepare func() (sendArgs, bool)) bool {
	if len(c.pol.Rules.NetAsk) == 0 || !d.isInet() || !d.ok || t.dec.rule != ruleUnmatched || l.askResolver == nil ||
		t.sockType != unix.SOCK_DGRAM || t.sockProto != unix.IPPROTO_UDP || t.proto != protoUDP {
		return false
	}
	m := l.askResolver.Match(d.ap, protoUDP)
	if m == nil {
		return false
	}
	admitted := c.admitResolved(d.ap, protoUDP, m)
	if !admitted.allowed {
		return false
	}
	// A live block naming the destination's address or the scope's declared host refuses it before anyone is asked,
	// whether or not this socket's datagrams there were approved before the block landed, and takes that approval back
	// (liveInetAsked). liveNet, which decided the datagram, knows no host for a destination nothing admits, so it
	// matches a host block only where the launcher's lookup of the host holds this address: a round-robin or CDN
	// host's other addresses, QUIC's usual traffic, would otherwise leave on an approval the block outranks.
	if l.refuseLiveInet(n, d, t.proto, m.Host) {
		l.forgetDgramDst(t, d.ap)
		return true
	}
	dec, g := l.gateNet(c, n.r, d, t.proto, admitted, gate.Ask)
	if g != nil && g.Verdict == gate.Refused {
		l.refuseNet(n, d, t.proto, dec)
		return true
	}
	rt := c.pol.Rules
	rootTier := rt.Tier == backend.TierCgroup || rt.Tier == backend.TierBPFLSM
	if rt.AskConfig == nil || rt.AskConfig.Hold != agent.AskHoldConnect || rootTier && l.grantDatagram == nil {
		l.refuseAskConnect(n, d, t.proto, m.Rule, m.Host, ask.ReasonUnavailable, g)
		return true
	}
	if control {
		l.refuseNet(n, d, t.proto, refuse(ruleAncillary))
		return true
	}
	args, ready := prepare()
	if !ready {
		return true // R19: the target died while its payload was being read
	}
	if err := args.addrErr; err != nil || args.sendErr != nil {
		if err == nil {
			err = args.sendErr
		}
		l.respond(n, respResult(0, err)) // the kernel's own answer, before any prompt: nothing is sent
		return true
	}
	switch {
	case !args.whole:
		l.refuseNet(n, d, t.proto, refuse(ruleDatagramSize))
		return true
	case zeroCopy(args.flags):
		l.refuseNet(n, d, t.proto, refuse(ruleZeroCopy))
		return true
	case l.sourceRouted(t):
		l.refuseNet(n, d, t.proto, refuse(ruleSourceRouted))
		return true
	case !l.frameFree(t, args.flags):
		l.refuseNet(n, d, t.proto, refuse(ruleCorked))
		return true
	}
	id, err := l.k.SocketID(t.dup)
	if err != nil || id.cookie == 0 {
		l.refuseAskConnect(n, d, t.proto, m.Rule, m.Host, ask.ReasonUnavailable, g)
		return true
	}
	key := dgramApproval{cookie: id.cookie, dst: d.ap, rule: m.Rule}
	if g != nil {
		key.scored = *g
	}
	if !l.dgramWasApproved(key) {
		req := ask.Request{Op: "send", Target: askInetTarget(d, protoUDP), Rule: m.Rule, Hold: string(agent.AskHoldConnect), PID: l.tgidOf(n.pid), TID: n.pid}
		if g != nil {
			req.Score, req.GateRule = &g.Score, g.Rule
		}
		// A live block naming the destination withdraws the request when it lands while the person decides (liveInetAsked);
		// one in force once the answer is back is refused below, whatever the answer.
		decision, err := l.askHeldUnless(n, req, l.liveInetBlocked(d.ap, m.Host))
		if n.gone {
			return true
		}
		if err != nil && l.refuseLiveInet(n, d, t.proto, m.Host) {
			return true
		}
		if err != nil || !decision.Approved {
			l.refuseAskConnect(n, d, t.proto, m.Rule, m.Host, askReason(decision, err), g)
			return true
		}
		l.rememberDgram(key)
	}
	if !l.valid(n) {
		return true
	}
	// Every datagram, newly approved or sent on a remembered approval, is put to the live Set once more before its
	// grant and relay: a block that landed since the check above (or while the person decided) refuses it under the
	// block's rule, and the socket's approval there is dropped, so a block lifted later does not bring it back unasked.
	if l.refuseLiveInet(n, d, t.proto, m.Host) {
		l.forgetDgram(key)
		return true
	}
	var revoke Revoke
	if l.grantDatagram != nil {
		// Granted by the socket's identity, the cookie and domain read from the duplicate of a socket checked to be
		// UDP above, never by its descriptor number here (ADR 0023 F8).
		granted, err := l.grantDatagramOf(n, t, id.cookie, d.ap)
		if err != nil {
			l.log.Warn("supervisor: grant an approved datagram", "err", err)
			l.refuseAskConnect(n, d, t.proto, m.Rule, m.Host, ask.ReasonUnavailable, g)
			return true
		}
		revoke = revokeOnce(granted) // read once the relay returns (creditTaken), and withdrawn on every other path
		defer l.withdraw(revoke)
	}
	if !l.valid(n) {
		return true
	}
	if !l.frameFree(t, args.flags) {
		// The socket was corked while a person decided (one the run was handed: the run cannot cork one, R13), and
		// the relay would join the frame it holds.
		l.refuseNet(n, d, t.proto, refuse(ruleCorked))
		return true
	}
	t.dec = verdictOf{rule: m.Rule, host: m.Host, allowed: true, gate: g, human: true}
	res, out := l.relay(n, t, func(dup int) resp {
		sent, err := l.k.SendToRaw(dup, args.payload, args.flags, raw)
		return respResult(sent, err)
	})
	switch out {
	case relayDone:
		l.respond(n, res)
		// The run's sendmsg4/6 decides the relayed datagram too: a refusal there (the grant lapsed) is the kernel's
		// line, as for a relayed connect (kernelDecided), never a person's allow of a datagram that did not leave.
		kdec, v := l.kernelDecided(n, d, t.proto, res, t.dec)
		if v == record.VerdictAllow && revoke != nil && res.errno == 0 {
			v = l.creditTaken(revoke)
		}
		l.emitNet(n, c, d, t.proto, kdec, v, l.answeredMarks(n))
	case relayOrphaned:
		l.emitNet(n, c, d, t.proto, t.dec, record.VerdictAllow, netMarks{resultUnknown: true})
	case relayLimited:
		l.refuseNet(n, d, t.proto, refuse(ruleRelayLimit))
	}
	// relayCancelled: the run is ending with the send in flight; nothing honest to answer (I3).
	return true
}

// grantDatagramOf has the run's kernel admit one datagram of t's socket, whose SO_COOKIE is cookie, to dst
// (grantDatagram), with the socket's SO_DOMAIN read from the duplicate where resolveSocket did not read it. Two
// threads' datagrams to an approved destination take their credits one after the other: the granter holds the
// kernel row from the grant to its revoke (Options.GrantConnect says how).
func (l *Loop) grantDatagramOf(n *notif, t *target, cookie uint64, dst netip.AddrPort) (Revoke, error) {
	if t.domain == 0 {
		domain, err := l.k.SockDomain(t.dup)
		if err != nil {
			return nil, err
		}
		t.domain = domain
	}
	return l.grantDatagram(n.done, cookie, t.domain, dst)
}

// creditTaken is the verdict of an approved datagram the run's kernel answered with success at tiers 2 and 3 (R13d),
// once its credit is withdrawn: the person's allow when sendmsg4/6 took the credit, which it does only for that
// socket's datagram to that destination, so the relayed bytes left as their own datagram to the address the line
// names. A credit left in the map means the hook never took it: the datagram joined a frame pending on the socket (a
// socket the run was handed, or one a sibling thread raced the supervisor's read on, R13's pending frames), which
// udp_sendmsg and udpv6_sendmsg append to before they run the hook, and its bytes went to that frame's destination; or
// a refresh admitted the destination by an ordinary row while a person decided, which the hook lets through with the
// credit untouched. No breadcrumb tells the two apart (the kernel recorder names connects), so the line is observed,
// under the person's authority and the scope's rule, which says nothing the kernel did not: never an allow of a
// destination the bytes may not have reached. A revoke that fails leaves the verdict as the kernel's answer made it.
func (l *Loop) creditTaken(revoke Revoke) record.Verdict {
	if untaken, err := revoke(); err == nil && untaken {
		return record.VerdictObserved
	}
	return record.VerdictAllow
}

// revokeOnce is r called at most once, every later call answering the first's result.
func revokeOnce(r Revoke) Revoke {
	var once sync.Once
	var untaken bool
	var err error
	return func() (bool, error) {
		once.Do(func() { untaken, err = r() })
		return untaken, err
	}
}

// withdraw revokes a credit once its relay returned, logging a revoke the kernel refused.
func (l *Loop) withdraw(revoke Revoke) {
	if _, err := revoke(); err != nil {
		l.log.Warn("supervisor: revoke an approval credit", "err", err)
	}
}

// dgramWasApproved reports whether a person approved key's destination for key's socket under key's scope.
func (l *Loop) dgramWasApproved(key dgramApproval) bool {
	l.dgramMu.Lock()
	defer l.dgramMu.Unlock()
	_, ok := l.dgramApproved[key]
	return ok
}

// forgetDgram drops a person's approval of key, if one is kept.
func (l *Loop) forgetDgram(key dgramApproval) {
	l.dgramMu.Lock()
	defer l.dgramMu.Unlock()
	delete(l.dgramApproved, key)
}

// forgetDgramDst drops every approval kept for t's socket to dst, under any scope and score: a live block naming dst
// outranks them all. A socket whose identity cannot be read keeps nothing to drop that a later datagram could use
// unchecked, since every datagram is put to the live Set before it is relayed (askDatagram).
func (l *Loop) forgetDgramDst(t *target, dst netip.AddrPort) {
	id, err := l.k.SocketID(t.dup)
	if err != nil || id.cookie == 0 {
		return
	}
	l.dgramMu.Lock()
	defer l.dgramMu.Unlock()
	for key := range l.dgramApproved {
		if key.cookie == id.cookie && key.dst == dst {
			delete(l.dgramApproved, key)
		}
	}
}

// rememberDgram keeps a person's approval of key, unless maxDgramApprovals are kept already.
func (l *Loop) rememberDgram(key dgramApproval) {
	l.dgramMu.Lock()
	defer l.dgramMu.Unlock()
	if l.dgramApproved == nil {
		l.dgramApproved = make(map[dgramApproval]struct{})
	}
	if len(l.dgramApproved) < maxDgramApprovals {
		l.dgramApproved[key] = struct{}{}
	}
}
