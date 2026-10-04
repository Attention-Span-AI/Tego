// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func (l *Loop) refuseAskConnect(n *notif, d dest, proto, rule, host, reason string, g *gate.Decision) {
	l.respond(n, respErrno(refusalErrno))
	ev := action(l.event(n, record.KindNet, record.SourceSupervisor), rule, record.VerdictRefused, record.Reason(reason))
	if g != nil {
		ev.Authority = record.AuthorityGate
	}
	l.emitFor(n, ev, netPayload{NetPayload: record.NetPayload{Proto: proto, Dst: d.String(), Host: host}, GateFields: gatePayload(g, false)})
}

// liveInetBlocked is askHeldUnless's blocked for a held IP connect or datagram to ap, admitted under host: whether a
// live block names it now (liveInetAsked), the Set loaded at each call, so it is safe on the hold's watcher.
func (l *Loop) liveInetBlocked(ap netip.AddrPort, host string) func() bool {
	return func() bool { _, hit := l.table.Load().liveInetAsked(ap, host); return hit }
}

// liveInetRule is the first-write relay's refused for a connect to ap admitted under host: the rule of the live block
// naming it now, "" when none (liveInetAsked), the Set loaded at each call.
func (l *Loop) liveInetRule(ap netip.AddrPort, host string) func() string {
	return func() string { v, _ := l.table.Load().liveInetAsked(ap, host); return v.rule }
}

// refuseLiveInet refuses a held IP connect or datagram to d that a live block names now, as liveNet's refusal of it
// would have been made had the block been in force when it was decided: EACCES and a refused net line under the
// block's rule, never the ask's or the gate's. It reports whether it refused.
func (l *Loop) refuseLiveInet(n *notif, d dest, proto, host string) bool {
	v, hit := l.table.Load().liveInetAsked(d.ap, host)
	if hit {
		l.refuseNet(n, d, proto, v)
	}
	return hit
}

// askConnect runs only after ordinary grants and unconditional address/model
// guards. Its address bytes and socket OFD were captured before the human wait.
func (l *Loop) askConnect(n *notif, c *compiled, t *target, d dest, raw []byte) bool {
	if d.isUnix() {
		return l.askUnix(n, c, t, d, raw)
	}
	// This lookup is solely for declared ask scopes. Gate-only escalation of
	// an already admitted connect reaches performAskConnect independently.
	if len(c.pol.Rules.NetAsk) == 0 || !d.isInet() || !d.ok || t.dec.rule != ruleUnmatched || l.askResolver == nil {
		return false
	}
	m := l.askResolver.Match(d.ap, t.proto)
	if m == nil {
		return false
	}
	admitted := c.admitResolved(d.ap, t.proto, m)
	if !admitted.allowed {
		return false
	}
	// A live block naming the scope's declared host refuses the connect before the gate scores it or anyone is asked
	// (liveInetAsked): liveNet knows no host for a destination nothing admits, so it matches a host block only where the
	// launcher's lookup of the host holds this address.
	if l.refuseLiveInet(n, d, t.proto, m.Host) {
		return true
	}
	dec, g := l.gateNet(c, n.r, d, t.proto, admitted, gate.Ask)
	if g != nil && g.Verdict == gate.Refused {
		l.refuseNet(n, d, t.proto, dec)
		return true
	}
	t.dec.gate = g
	return l.performAskConnect(n, c, t, d, raw, m.Rule, m.Host, true)
}

// performAskConnect holds an IP connect while a person decides and relays it once approved. scoped says the
// connect reached a net.ask scope (askConnect): then a UDP socket's connect is held too (R13d), whose approval is the
// socket's exchange with that peer; one a gate's ask range raised on an admitted destination is a TCP connect's
// alone (gate.md R4).
func (l *Loop) performAskConnect(n *notif, c *compiled, t *target, d dest, raw []byte, rule, host string, scoped bool) bool {
	if !d.isInet() || !d.ok {
		if t.dec.gate != nil {
			t.dec.allowed = false
			t.dec.continued = false
			t.dec.rule = rule
			t.dec.kernelReason = record.ReasonNetGate
			t.dec.unsupported = true
			l.refuseNet(n, d, t.proto, t.dec)
			return true
		}
		return false
	}
	// A live block in force now refuses the connect before anyone is asked or a first-write relay is reserved: the
	// broker would otherwise post a card the hold's first tick takes back, and under first_write the agent's connect to
	// the relay would be allowed and logged, and only its first write refused (liveInetAsked).
	if l.refuseLiveInet(n, d, t.proto, host) {
		return true
	}
	rt := c.pol.Rules
	if rt.AskConfig == nil {
		l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
		return true
	}
	// The generic recorder classifies MPTCP as TCP, but approval is scoped to
	// one ordinary TCP or UDP socket. Subflow identities and unreadable protocols
	// cannot inherit a grant or be transparently converted by the relay.
	tcp := t.sockType == unix.SOCK_STREAM && t.sockProto == unix.IPPROTO_TCP
	udp := scoped && t.sockType == unix.SOCK_DGRAM && t.sockProto == unix.IPPROTO_UDP && t.proto == protoUDP
	if !tcp && !udp {
		if t.dec.gate != nil {
			t.dec.allowed = false
			t.dec.continued = false
			t.dec.rule = rule
			t.dec.kernelReason = record.ReasonNetGate
			t.dec.unsupported = true
			l.refuseNet(n, d, t.proto, t.dec)
			return true
		}
		l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
		return true
	}
	rootTier := rt.Tier == backend.TierCgroup || rt.Tier == backend.TierBPFLSM
	if udp && rootTier && d.ap.Addr().Unmap().Is4() && l.socketDomainIs(t, unix.AF_INET6) {
		// An AF_INET6 UDP socket connected to an IPv4 peer sends each datagram through udp_sendmsg with that peer as
		// its address (udpv6_sendmsg), so the run's sendmsg4 decides every send after the connect, and refuses each
		// one, which no row admits: an approved connect would carry no datagram. Refused before anyone is asked;
		// the socket's unconnected datagrams are asked one destination at a time (askDatagram).
		l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
		return true
	}
	// The kernel's own answer to the address, given before it touches the socket and so before any prompt:
	// EINVAL for an addrlen past 128, EFAULT for one the read came up short on (shortAddrErr, R3, I3).
	if err := shortAddrErr(addrlenErr(socklen(n.args[2])), raw, socklen(n.args[2])); err != nil {
		l.respond(n, respResult(0, err))
		return true
	}
	req := ask.Request{Op: "connect", Target: askInetTarget(d, t.proto), Rule: rule, Hold: string(rt.AskConfig.Hold), PID: l.tgidOf(n.pid), TID: n.pid}
	if t.dec.gate != nil {
		req.Score = &t.dec.gate.Score
		req.GateRule = t.dec.gate.Rule
	}
	connectRawBytes := append([]byte(nil), raw...)
	connectDst := d.ap
	var release func()
	firstWrite := rt.AskConfig.Hold == agent.AskHoldFirstWrite
	if firstWrite {
		if t.proto != protoTCP || t.sockType != unix.SOCK_STREAM || l.firstWrite == nil {
			l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
			return true
		}
		if !l.valid(n) {
			return true
		}
		var err error
		// The person is asked by the relay once the agent writes, long after this connect: the relay puts the
		// destination to the live Set then, while they decide and once the answer is back (Reserve's refused).
		connectDst, release, err = l.firstWrite(context.Background(), req, d.ap, d.family == unix.AF_INET6, t.dup, l.liveInetRule(d.ap, host))
		if err != nil {
			l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
			return true
		}
		connectRawBytes = relaySockaddr(connectDst, d.family)
	} else {
		// HTTP request holds are performed by the cooperating forwarder. A
		// direct raw/TLS socket never masquerades as an inspected request.
		if rt.AskConfig.Hold != agent.AskHoldConnect {
			l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
			return true
		}
		// A live block naming the destination that lands while the person decides withdraws the request, and one in
		// force once the answer is back refuses the connect whatever the answer, under the block's rule, before
		// anything is granted or connected (liveInetAsked).
		decision, err := l.askHeldUnless(n, req, l.liveInetBlocked(d.ap, host))
		if n.gone {
			return true
		}
		// A request withdrawn for a block (or cut short otherwise) names the block now in force; a person's denial and
		// a timeout keep their own reason.
		if err != nil && l.refuseLiveInet(n, d, t.proto, host) {
			return true
		}
		if err != nil || !decision.Approved {
			l.refuseAskConnect(n, d, t.proto, rule, host, askReason(decision, err), t.dec.gate)
			return true
		}
		if l.valid(n) && l.refuseLiveInet(n, d, t.proto, host) {
			return true
		}
	}
	keepRelay := false
	if release != nil {
		defer func() {
			if !keepRelay {
				release()
			}
		}()
	}
	if !l.valid(n) {
		return true
	}
	if rootTier && l.grantConnect == nil {
		l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
		return true
	}
	if l.grantConnect != nil {
		// Two connects of one socket to one destination, or a UDP socket's connect and datagram there, take their
		// credits one after the other: the granter holds the kernel row from the grant to its revoke.
		revoke, err := l.grantConnect(n.done, t.dup, connectDst, t.proto)
		if err != nil {
			l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
			return true
		}
		if revoke != nil {
			defer l.withdraw(revoke)
		}
	}
	if !l.valid(n) {
		return true
	}
	res, out := l.relay(n, t, func(fd int) resp { return respResult(0, l.k.ConnectRaw(fd, connectRawBytes)) })
	switch out {
	case relayDone:
		l.respond(n, res)
		keepRelay = firstWrite && !n.gone && (res.errno == 0 || res.errno == -int32(unix.EINPROGRESS))
		dec := verdictOf{rule: rule, host: host, allowed: true, gate: t.dec.gate}
		if firstWrite {
			ev := action(l.event(n, record.KindNet, record.SourceSupervisor), rule, record.VerdictAllow, "")
			if t.dec.gate != nil {
				ev.Authority = record.AuthorityGate
			}
			l.emitFor(n, ev, struct {
				record.NetPayload
				GateFields
				Hold              string `json:"hold"`
				RelayDst          string `json:"relay_dst"`
				UpstreamConnected bool   `json:"upstream_connected"`
			}{record.NetPayload{Proto: t.proto, Dst: d.String(), Host: host}, gatePayload(t.dec.gate, false), "first_write", connectDst.String(), false})
		} else if kdec, v := l.kernelDecided(n, d, t.proto, res, verdictOf{rule: rule, host: host, allowed: true, gate: t.dec.gate, human: true}); v != record.VerdictAllow {
			// The run's connect4/6 refused the relayed connect (the grant lapsed, or a row refuses it): the line is the
			// kernel's, as for every relayed connect, not a person's allow of a connect that did not happen.
			l.emitNet(n, c, d, t.proto, kdec, v, l.answeredMarks(n))
		} else {
			l.emitApprovedAskConnect(n, c, d, t.proto, dec, l.answeredMarks(n))
		}
	case relayOrphaned:
		dec := verdictOf{rule: rule, host: host, allowed: true, gate: t.dec.gate}
		if firstWrite {
			l.emitNet(n, c, d, t.proto, dec, record.VerdictAllow, netMarks{resultUnknown: true})
		} else {
			l.emitApprovedAskConnect(n, c, d, t.proto, dec, netMarks{resultUnknown: true})
		}
	case relayLimited:
		l.refuseAskConnect(n, d, t.proto, rule, host, ask.ReasonUnavailable, t.dec.gate)
	}
	return true
}

// askUnix holds a unix connect whose name reaches a net.ask unix: scope's place and that nothing else admits
// (SEMANTICS §5, R11c; unixScopeOf): the connect stays trapped while a person decides (ADR 0008), and an approval is
// carried out by the R11 relay, as the task, admitted at the scope's place only (relayUnix with the scope), so the
// approval connects where a person was asked about and never to an inode the agent repointed the name at during the
// wait. A denial, a timeout or a broker that cannot answer refuses with that reason and connects nothing;
// ask.on_timeout and --always are the broker's, as for any held connect. What cannot carry an approval refuses before
// anyone is asked: a hold other than connect, and an abstract name at a root tier whose kernel cannot take the
// one-connect grant (grantUnix). It reports whether it answered.
func (l *Loop) askUnix(n *notif, c *compiled, t *target, d dest, raw []byte) bool {
	if len(c.unixAsk) == 0 || !d.ok || t.dec.rule != ruleUnmatched || t.ipGated || c.netOpen {
		return false
	}
	joined := unixJoined(n.r, d)
	u := l.unixScopeOf(n, c, d, joined)
	if u == nil {
		return false
	}
	// A live block naming the scope's place, the name as spelled or the abstract name refuses the connect before anyone
	// is asked (liveUnixAsked); the same names are put to the live Set while the person decides and once the answer is
	// back.
	names := []string{u.path, u.resolved, joined}
	live := func() (verdictOf, bool) { return l.table.Load().liveUnixAsked(d.abstract, names...) }
	if v, hit := live(); hit {
		l.refuseNet(n, d, t.proto, v)
		return true
	}
	dec, g := l.gateNet(c, n.r, d, t.proto, verdictOf{rule: u.name, allowed: true}, gate.Ask)
	if g != nil && g.Verdict == gate.Refused {
		l.refuseNet(n, d, t.proto, dec)
		return true
	}
	rt := c.pol.Rules
	abstract := len(d.abstract) > 0
	rootTier := rt.Tier == backend.TierCgroup || rt.Tier == backend.TierBPFLSM
	if rt.AskConfig == nil || rt.AskConfig.Hold != agent.AskHoldConnect || abstract && rootTier && l.grantUnix == nil {
		l.refuseAskConnect(n, d, t.proto, u.name, "", ask.ReasonUnavailable, g)
		return true
	}
	// The kernel's own answer to the address, before any prompt (performAskConnect).
	if err := shortAddrErr(addrlenErr(socklen(n.args[2])), raw, socklen(n.args[2])); err != nil {
		l.respond(n, respResult(0, err))
		return true
	}
	// The target a person reads, and a standing answer is kept under, is the scope's own name: the name the task passed
	// reaches the scope's place only from its cwd and through the links it met.
	target := d.String()
	if u.path != "" {
		target = "unix:" + u.path
	}
	req := ask.Request{Op: "connect", Target: target, Rule: u.name, Hold: string(agent.AskHoldConnect), PID: l.tgidOf(n.pid), TID: n.pid}
	if g != nil {
		req.Score, req.GateRule = &g.Score, g.Rule
	}
	// A live block naming the scope's place, the name as spelled or the abstract name that lands while the person
	// decides withdraws the request (liveUnixAsked); one in force once the answer is back refuses the connect whatever
	// the answer, and the relay's walk is matched again where it lands (liveUnixLanded).
	decision, err := l.askHeldUnless(n, req, func() bool { _, hit := live(); return hit })
	if n.gone {
		return true
	}
	if err != nil {
		// Withdrawn for a block (or cut short otherwise): the refusal names the block now in force.
		if v, hit := live(); hit {
			l.refuseNet(n, d, t.proto, v)
			return true
		}
	}
	if err != nil || !decision.Approved {
		l.refuseAskConnect(n, d, t.proto, u.name, "", askReason(decision, err), g)
		return true
	}
	if !l.valid(n) {
		return true
	}
	// An approval that came back after a block landed but before the hold's next tick (a standing answer, or Allow
	// clicked inside the tick): liveUnixLanded matches only the resolved place of a pathname and nothing of an abstract
	// name, so the names the person was asked about are matched here, before any grant or relay.
	if v, hit := live(); hit {
		l.refuseNet(n, d, t.proto, v)
		return true
	}
	if abstract && l.grantUnix != nil {
		revoke, err := l.grantUnixName(n, t.dup, d.abstract)
		if err != nil {
			l.log.Warn("supervisor: grant an approved unix name", "err", err)
			l.refuseAskConnect(n, d, t.proto, u.name, "", ask.ReasonUnavailable, g)
			return true
		}
		// Withdrawn once the relay returns: its connect consumed the grant or never will. An orphaned relay may still
		// be connecting then; its connect then fails closed in the kernel, which its result_unknown line allows for.
		defer l.withdraw(revoke)
	}
	t.dec = verdictOf{rule: u.name, allowed: true, gate: g, human: true}
	l.relayUnix(n, c, t, d, raw, u)
	return true
}

// grantUnixName has the run's kernel admit one connect of the socket dup duplicates to the approved abstract name
// (grantUnix): it checks that the socket is AF_UNIX and grants by its SO_COOKIE, the identity the kernel's programs
// read, so the grant names the socket and never its descriptor number here (ADR 0023 F8). The kernel keeps one row per
// socket, whatever name it grants, and the granter holds it from the grant to its revoke, so two approved connects of
// one socket take their credits one after the other.
func (l *Loop) grantUnixName(n *notif, dup int, name []byte) (Revoke, error) {
	domain, err := l.k.SockDomain(dup)
	if err != nil {
		return nil, err
	}
	if domain != unix.AF_UNIX {
		return nil, errors.New("one-shot unix approval socket is not AF_UNIX")
	}
	id, err := l.k.SocketID(dup)
	if err != nil {
		return nil, err
	}
	return l.grantUnix(n.done, id.cookie, name)
}

// unixJoined is R6's cleaned absolute spelling of a pathname destination, a relative one joined to the task's cwd
// (decideUnix's), "" for an abstract or unnamed one.
func unixJoined(r *reader, d dest) string {
	p := d.unixPath
	switch {
	case p == "" || d.unnamed:
		return ""
	case strings.HasPrefix(p, "/"):
		return cleanPath(p)
	}
	return r.resolve(atFDCWD, p)
}

// unixScopeOf is the net.ask unix: scope a connect's destination reaches (R11c), nil when none: an abstract name by its
// bytes, and a pathname by the place its name reaches in the task's view, never by its spelling. That place is where
// the loop's walk of the name lands (unixTarget, as the relay's walk lands, a final symlink followed); for a name
// whose last component names nothing yet, the directory the walk reaches with that component, and for one whose last
// component is a symlink that leads nowhere yet, where that link leads, placed as a scope is (resolveUnixDeclared,
// Before, the link's own path, so the write entry around it admitted the scope's own name with
// nobody asked); and the name is the scope's when the place is the one the scope resolved to when the loop was built
// (unixAskAt). So the scope's own spelling, a relative name from any cwd, the canonical spelling getcwd gives, a
// symlink or a symlinked directory the agent made are all the scope when they reach its place, whoever bound the
// socket there, and a hard link or a rename of that socket elsewhere is not: it is decided at the place it is reached
// at, as any connect is (decideResolved), the run's own socket there admitted by the write entry around it (R11a) and
// any other refused. A name whose directory does not exist yet reaches no place, and its connect fails ENOENT or
// ENOTDIR unless the run makes the directory meanwhile; it is the scope's when it spells the scope, as declared or as
// placed, or when it is placed at the scope's place as a scope is placed: walked uncleaned, an absolute name as the
// task passed it and a relative one from the task's cwd, so a symlinked directory before the missing one and a ".."
// after it are followed as the kernel's lookup follows them (a relative name was placed from R6's lexically cleaned
// spelling, the ".." applied before the link). Such a name is asked as a connect to
// a host port is asked before anyone knows whether it listens: an approval still connects only at the scope's place
// (relayUnix). A name the walk cannot place — a magic link, procfs, another root or view — is no scope's: the relay
// refuses it path-unreliable, and nobody is asked; so is one whose placement takes more names than
// agent.ResolveUnixPlace walks, which bounds what an agent's chain of dangling links costs this worker: it is
// decided at the place it reaches, as any connect is. joined is unixJoined's
// spelling of the name.
func (l *Loop) unixScopeOf(n *notif, c *compiled, d dest, joined string) *unixRule {
	if len(d.abstract) > 0 {
		for i := range c.unixAsk {
			if u := &c.unixAsk[i]; len(u.abstract) > 0 && string(u.abstract) == string(d.abstract) {
				return u
			}
		}
		return nil
	}
	if !c.unixAskPaths || d.unnamed || d.unixPath == "" || !strings.HasPrefix(joined, "/") {
		return nil
	}
	q := unixQuery{tid: n.pid, path: d.unixPath, joined: joined}
	place, err := l.unixTarget(n, q)
	if err == nil {
		return c.unixAskAt(place.at)
	}
	if !namesNothing(err) {
		return nil
	}
	q.parent = true
	dir, err := l.unixTarget(n, q)
	switch {
	case err == nil:
		// The last component names nothing, or is a symlink that leads nowhere yet: placed as a scope is placed
		// (resolveUnixDeclared), the link followed to where the kernel's lookup lands once that is made.
		at := path.Join(dir.at, bindBase(d.unixPath))
		if u := c.unixAskAt(at); u != nil {
			return u
		}
		return c.unixAskPlaced(l.k, at)
	case !namesNothing(err):
		return nil
	}
	for i := range c.unixAsk {
		if u := &c.unixAsk[i]; u.path != "" && (u.path == joined || u.resolved == joined) {
			return u
		}
	}
	raw := d.unixPath
	if !strings.HasPrefix(raw, "/") {
		if n.r == nil || n.r.cwd == "" {
			return nil // no cwd read for it: its spelling was compared above
		}
		raw = n.r.cwd + "/" + raw
	}
	return c.unixAskPlaced(l.k, raw)
}

// unixAskPlaced is the net.ask unix: scope whose place p is placed at as a scope is placed (resolveUnixDeclared), nil
// when that is none's or p cannot be placed.
func (c *compiled) unixAskPlaced(k kernel, p string) *unixRule {
	at, ok := resolveUnixDeclared(k, p)
	if !ok {
		return nil
	}
	return c.unixAskAt(at)
}

// namesNothing reports whether a walk failed because its name names nothing (yet): ENOENT or ENOTDIR, the kernel's
// own lookup's answer too.
func namesNothing(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)
}

// unixAskAt is the net.ask unix: scope whose place, the path it resolved to when the loop was built, is at, or nil.
func (c *compiled) unixAskAt(at string) *unixRule {
	for i := range c.unixAsk {
		if u := &c.unixAsk[i]; u.path != "" && u.resolved == at {
			return u
		}
	}
	return nil
}

func (l *Loop) emitApprovedAskConnect(n *notif, c *compiled, d dest, proto string, dec verdictOf, marks netMarks) {
	if !c.recording() {
		return
	}
	ev := action(l.event(n, record.KindNet, record.SourceSupervisor), dec.rule, record.VerdictAllow, "")
	ev.Authority = record.AuthorityHuman
	p := netPayload{NetPayload: record.NetPayload{Proto: proto, Dst: d.String(), Host: dec.host}, ResultUnknown: marks.resultUnknown, GateFields: gatePayload(dec.gate, false)}
	if marks.resultUnknown {
		l.awaitPrev(n)
		l.emit(ev, p)
	} else {
		l.emitFor(n, ev, p)
	}
}

func relaySockaddr(ap netip.AddrPort, family uint16) []byte {
	if family == unix.AF_INET6 {
		b := make([]byte, unix.SizeofSockaddrInet6)
		binary.NativeEndian.PutUint16(b, uint16(unix.AF_INET6))
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a := ap.Addr().As16()
		copy(b[8:], a[:])
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet4)
	binary.NativeEndian.PutUint16(b, uint16(unix.AF_INET))
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As4()
	copy(b[4:], a[:])
	return b
}
