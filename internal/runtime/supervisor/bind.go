// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"strings"
	"unsafe"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// bindKernel is a separate syscall seam so a custom kernel implementation
// cannot silently continue a bind it has no way to perform on the owned socket.
type bindKernel interface{ BindRaw(fd int, sa []byte) error }

func (sysKernel) BindRaw(fd int, sa []byte) error {
	if len(sa) == 0 {
		return unix.EINVAL
	}
	_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
	if errno != 0 {
		return errno
	}
	return nil
}

// handleBind freezes the address and socket for IP binds. Unix pathname binds
// remain in the task's Landlock domain; a selected decision plane additionally
// checks copied abstract names and the actual filesystem socket creation.
//
// Every pathname unix bind of the run is also recorded, by the identity of the socket it names, before it is
// answered (R11a, recordRunSocket): the implicit admit of a socket under a write entry holds only for a socket a
// process of the run bound. Under a net: section with no listener policy the filter notifies bind for that record
// alone (enforce-landlock R11c), and the bind is continued as before, with no line: the kernel decides it, as it
// did when bind was not notified. An observe run's filter carries the same arm, and its binds are continued the
// same way, listener policy or not: before it, an observe run's filter did not notify bind at all.
func handleBind(l *Loop, n *notif) {
	if c := l.table.Load(); c.pol.Rules.Builtins != nil && !c.pol.Observe {
		if l.builtinBind(n, c) {
			return
		}
	}
	if c := l.table.Load(); c.pol.Rules.Listen == nil && c.pol.Rules.Builtins == nil || c.pol.Observe {
		r := l.newReader(n)
		raw := r.sockaddr(n.args[1], socklen(n.args[2]))
		if n.gone {
			return
		}
		switch d := parseSockaddr(raw); {
		case !r.ok():
			// The address could not be read — at tier landlock, a non-dumpable task's (ssh-agent) — so whether
			// this binds a pathname socket, which one, and where, is unknown: remembered as an unrecorded bind at no
			// known path (R11a), which only names a refusal and never admits.
			l.runSockets.lost("")
		case d.isUnix() && d.unixPath != "":
			l.recordRunSocket(n, d, l.boundPath(r, d))
		case d.isUnix() && len(d.abstract) > 0 && (c.hostSockets || c.pol.Rules.Builtins != nil):
			l.recordRunAbstract(n)
		}
		l.respond(n, respContinue())
		return
	}
	if l.bindHandoffReady() {
		l.beginBindHandover(n)
	}
	r := l.newReader(n)
	raw := r.sockaddr(n.args[1], socklen(n.args[2]))
	if n.gone {
		return
	}
	d := parseSockaddr(raw)
	c := l.table.Load()
	dec := refuse(ruleUnmatched)
	if r.ok() && l.bindRoute(n, c, d, raw) {
		return
	}
	if !r.ok() || !d.ok {
		l.finishBind(n, c, d, protoRaw, refuse(noteOr(r, ruleArgsUnreadable)), nil, false)
		return
	}
	if d.isUnix() {
		if d.unixPath != "" {
			l.recordRunSocket(n, d, l.boundPath(r, d)) // R11a; a bind the listener policy refuses binds nothing
		} else if len(d.abstract) > 0 && (c.hostSockets || c.pol.Rules.Builtins != nil) {
			l.recordRunAbstract(n)
		}
		if l.bindHandoffReady() {
			l.saveBindNaming(n, d, "", false)
			if l.valid(n) {
				l.respond(n, respContinue())
			}
			return
		}
		l.bindUnix(n, c, r, d)
		return
	}
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if !n.gone {
			l.finishBind(n, c, d, protoRaw, refuse(why), nil, false)
		}
		return
	}
	defer l.closeDup(t.dup)
	proto := protoOf(t.sockType, t.sockProto, d)
	if d.isInet() {
		if match, allowed := agent.MatchBind(c.pol.Rules.Listen, d.ap, proto); allowed {
			dec = verdictOf{rule: match.RuleName(), allowed: true}
			if c.pol.Rules.Listen == nil {
				dec.rule = ruleUnmatched
			}
		}
	}
	// The relay runs outside the task's Landlock domain. Preserve its
	// withheld BIND_TCP right when a net section declares no listeners.
	if d.isInet() && proto == protoTCP && !c.netOpen && c.pol.Rules.Listen == nil {
		dec = refuse(ruleUnmatched)
	}
	if rule := c.builtinNet(d, proto); rule != "" {
		dec = refuse(rule)
	}
	if !dec.allowed {
		l.finishBind(n, c, d, proto, dec, nil, false)
		return
	}
	binder, ok := l.k.(bindKernel)
	if !ok {
		l.finishBind(n, c, d, proto, refuse(ruleArgsUnreadable), nil, false)
		return
	}
	if !l.valid(n) {
		return
	}
	// The kernel's own answers, in its order: move_addr_to_kernel fails a length past 128 EINVAL and a copy
	// that faults EFAULT (shortAddrErr), then the protocol fails a length short of its family's EINVAL.
	err := shortAddrErr(addrlenErr(socklen(n.args[2])), raw, socklen(n.args[2]))
	if err == nil && socklen(n.args[2]) < kernelAddrMin(d.family) {
		err = unix.EINVAL
	}
	if err == nil {
		err = binder.BindRaw(t.dup, raw)
	}
	if err == nil {
		l.rememberListenerBind(t.dup, d, proto, dec.rule)
	}
	l.finishBind(n, c, d, proto, dec, err, false)
}

// bindRoute answers a bind under a listener policy that names the netlink family on a NETLINK_ROUTE socket with no
// multicast group, and reports whether it did (ADR 0128). glibc's getifaddrs and getaddrinfo, Go's net.Interfaces and
// iproute2 bind before their query, so refusing it refused the query under a contract with a net.listen key, where
// every bind is notified. It is no listener: it names a port id in the kernel's netlink table, which no socket outside
// the kernel can reach unless the run sends to it, and nothing is received but the replies to what the socket asked.
// It is made on the duplicate, from the copy, as an IP bind is, since a CONTINUE would hand the descriptor and address
// back to a sibling that swaps a TCP socket and a port in. A socket nothing named gets this process's pid as its port
// id, and glibc, Go and iproute2 read it back with getsockname. A multicast group is no part of it: a bind to one is
// checked against the caller's capability for some groups (rtnetlink_bind), and at a root tier this process would pass
// where the task does not, so it goes on to handleBind's refusal.
func (l *Loop) bindRoute(n *notif, c *compiled, d dest, raw []byte) bool {
	if d.family != unix.AF_NETLINK || (len(raw) >= sizeofSockaddrNL && binary.NativeEndian.Uint32(raw[8:]) != 0) {
		return false
	}
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if !n.gone {
			l.finishBind(n, c, d, protoRaw, refuse(why), nil, false)
		}
		return true
	}
	defer l.closeDup(t.dup)
	binder, ok := l.k.(bindKernel)
	if !ok || !l.routeSocket(&t) {
		return false
	}
	if !l.valid(n) {
		return true
	}
	// The kernel's own answers, in its order, as in handleBind's IP bind: netlink_bind fails a short name EINVAL.
	err := shortAddrErr(addrlenErr(socklen(n.args[2])), raw, socklen(n.args[2]))
	if err == nil && socklen(n.args[2]) < sizeofSockaddrNL {
		err = unix.EINVAL
	}
	if err == nil {
		err = binder.BindRaw(t.dup, raw)
	}
	l.finishBind(n, c, d, protoRaw, verdictOf{rule: ruleRouteQuery, allowed: true}, err, false)
	return true
}

// boundPath is R6's spelling of the path a pathname unix bind names: an absolute sun_path cleaned, a relative one
// joined to the task's cwd; "" when the cwd cannot be read. R11a records no bind's name or directory: a bind it
// cannot record is remembered at the path the task's own lookup reaches (lostBind, unixWalk), never at this
// spelling, which a ".." after a symlink or a magic link makes name another place; the fake kernel keys its walks on
// it.
func (l *Loop) boundPath(r *reader, d dest) string {
	if strings.HasPrefix(d.unixPath, "/") {
		return cleanPath(d.unixPath)
	}
	if p := r.resolve(atFDCWD, d.unixPath); strings.HasPrefix(p, "/") {
		return p
	}
	return ""
}

func (l *Loop) bindUnix(n *notif, c *compiled, r *reader, d dest) {
	rules := c.pol.Rules.Listen
	dec := refuse(ruleUnmatched)
	if rules == nil {
		dec = verdictOf{rule: ruleUnmatched, allowed: true}
	}
	switch {
	case len(d.abstract) > 0:
		for _, rule := range rules {
			if rule.Proto == agent.ProtoUnix && rule.Abstract && rule.UnixPath == string(d.abstract) {
				dec = verdictOf{rule: rule.RuleName(), allowed: true}
				break
			}
		}
	case d.unixPath != "":
		path := r.resolve(atFDCWD, d.unixPath)
		query := pathQuery{tid: n.pid, dirfd: atFDCWD, path: d.unixPath, joined: path}.as(agent.LookupParent)
		actual, err := l.fsTarget(n, query)
		if n.gone {
			return
		}
		if err != nil || !strings.HasPrefix(actual, "/") {
			dec = refuse(rulePathUnreliable)
		} else {
			for _, rule := range rules {
				if rule.Proto == agent.ProtoUnix && !rule.Abstract && rule.UnixPath == actual {
					dec = verdictOf{rule: rule.RuleName(), allowed: true}
					break
				}
			}
			_, v, _ := c.fsVerdictIn(c.fsResolved, actual, record.FSMkdir, 0, false)
			if v != record.VerdictAllow {
				dec = refuse(ruleUnmatched)
			}
		}
	default:
		dec = refuse(ruleUnmatched)
	}
	l.finishBind(n, c, d, protoUnix, dec, nil, true)
}

type bindPayload struct {
	record.NetPayload
	BestEffort bool `json:"best_effort,omitempty"`
}

func (l *Loop) finishBind(n *notif, c *compiled, d dest, proto string, dec verdictOf, err error, continued bool) {
	l.finishListenerOp(n, c, d, proto, dec, err, continued, "bind")
}

// A frozen pathname lookup can fail before the task enters socket_bind. Own
// that completion so its unmarked sys_exit_bind cannot become a second line
// claiming kernel authority. No policy allow or refusal decided this error.
func (l *Loop) finishBindLookupFailure(n *notif, c *compiled, d dest, err error) {
	if l.bindHandoffReady() {
		l.saveBindNaming(n, d, ruleUnmatched, true)
		if n.gone {
			return
		}
	}
	l.respond(n, respResult(0, err))
	if !c.recording() {
		return
	}
	var errno unix.Errno
	if !errors.As(err, &errno) {
		errno = unix.EIO
	}
	ev := action(l.event(n, record.KindNet, record.SourceSupervisor), ruleUnmatched, record.VerdictObserved, "")
	l.emitFor(n, ev, bindPayload{NetPayload: record.NetPayload{Proto: protoUnix, Dst: d.String(), Op: "bind",
		SyscallRet: -int64(errno), SyscallErrno: int(errno)}})
}

func (l *Loop) finishListenerOp(n *notif, c *compiled, d dest, proto string, dec verdictOf, err error, continued bool, op string) {
	if n.gone {
		return
	}
	if op == "bind" && l.bindHandoffReady() {
		l.saveBindNaming(n, d, dec.rule, true)
		if n.gone {
			return
		}
	}
	if op == "listen" && l.listenHandoffReady() {
		l.saveListenNaming(n, d, dec.rule, true)
		if n.gone {
			return
		}
	}
	switch {
	case !dec.allowed:
		l.respond(n, respErrno(refusalErrno))
	case continued:
		l.respond(n, respContinue())
	default:
		l.respond(n, respResult(0, err))
	}
	v := record.VerdictRefused
	reason := record.ReasonNetNotAllowed
	if dec.allowed {
		v, reason = record.VerdictAllow, ""
	}
	if dec.allowed && !c.recording() {
		return
	}
	ev := action(l.event(n, record.KindNet, record.SourceSupervisor), dec.rule, v, reason)
	var errno unix.Errno
	if err != nil && !errors.As(err, &errno) {
		errno = unix.EIO
	}
	if !dec.allowed && !c.pol.Observe {
		errno = refusalErrno
	}
	ret := int64(0)
	if errno != 0 {
		ret = -int64(errno)
	}
	l.emitFor(n, ev, bindPayload{NetPayload: record.NetPayload{Proto: proto, Dst: d.String(), Op: op, SyscallRet: ret, SyscallErrno: int(errno)}, BestEffort: continued || !dec.allowed && c.pol.Observe})
}

// recordRunAbstract remembers the socket a task of the run is binding to an abstract name in the unix-only state (ADR
// 0070): the socket object, as recordRunSocket remembers a pathname one, never the name, which runSockets.holdsAbstract
// asks the kernel for when a connect or a datagram names one. A socket that cannot be read, one bound already (this
// bind fails EINVAL and binds nothing), or one past abstractMax is not remembered, and the names it holds stay refused.
func (l *Loop) recordRunAbstract(n *notif) {
	dup, err := l.duplicate(n, int(int32(n.args[0])))
	if err != nil {
		return
	}
	defer l.closeDup(dup)
	id, err := l.k.SocketID(dup)
	if err != nil {
		return
	}
	if b, err := l.k.UnixBound(id); err == nil && b.bound {
		return // bound to a file already: this bind fails EINVAL
	}
	if name, err := l.k.UnixAbstractName(id); err == nil && name != "" {
		return // bound to an abstract name already
	}
	if !l.runSockets.addAbstract(l.k, id) {
		l.log.Warn("supervisor: the run holds more abstract unix sockets than ADR 0070 remembers; a name bound past them is refused",
			"max", abstractMax)
	}
}
