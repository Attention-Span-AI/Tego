// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"unsafe"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

type listenKernel interface {
	SocketNameRaw(fd int) ([]byte, error)
	ListenRaw(fd, backlog int) error
}

func (sysKernel) SocketNameRaw(fd int) ([]byte, error) {
	var raw [sockaddrMax]byte
	length := uint32(len(raw))
	_, _, errno := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&length)))
	if errno != 0 {
		return nil, errno
	}
	if length > uint32(len(raw)) {
		return nil, unix.EOVERFLOW
	}
	return raw[:length], nil
}

func (sysKernel) ListenRaw(fd, backlog int) error { return unix.Listen(fd, backlog) }

// handleListen covers implicit autobind as well as sockets explicitly bound
// earlier. A fixed-port grant never authorizes an unbound port-zero socket.
// The operation runs on the duplicated socket, never a later fd-number lookup.
//
// Under a net: section with no listener policy a TCP listen is refused whatever
// port the socket shows (enforce-landlock R6). Landlock withholds BIND_TCP there,
// but listen() on an unbound socket takes its port through the kernel's autobind,
// which never reaches security_socket_bind, so this is the only refusal. It is not
// keyed on port zero: a connect a sibling has in flight gives the socket a port its
// failure takes back, and between getsockname and ListenRaw that socket autobinds
// all the same. A unix listen stays on the duplicate in that state too, because
// the filter cannot tell it from a TCP one: continued, it is a descriptor number a
// sibling's dup2 points at a TCP socket.
func handleListen(l *Loop, n *notif) {
	if l.listenHandoffReady() {
		l.beginListenHandover(n)
	}
	c := l.table.Load()
	t, why, ok := l.resolveSocket(n, c, int(int32(n.args[0])))
	if !ok {
		if !n.gone {
			l.finishListenerOp(n, c, dest{}, protoRaw, refuse(why), nil, false, "listen")
		}
		return
	}
	defer l.closeDup(t.dup)
	k, ok := l.k.(listenKernel)
	if !ok {
		l.finishListenerOp(n, c, dest{}, protoRaw, refuse(ruleArgsUnreadable), nil, false, "listen")
		return
	}
	if !l.valid(n) {
		return
	}
	raw, err := k.SocketNameRaw(t.dup)
	if !l.valid(n) {
		return
	}
	d := parseSockaddr(raw)
	proto := protoOf(t.sockType, t.sockProto, d)
	dec := refuse(ruleUnmatched)
	if err == nil && d.ok {
		if d.isInet() {
			if rule, allowed := agent.MatchBind(c.pol.Rules.Listen, d.ap, proto); allowed {
				switch {
				case c.pol.Rules.Listen != nil:
					dec = verdictOf{allowed: true, rule: rule.RuleName()}
				case proto != protoTCP:
					dec = verdictOf{allowed: true, rule: ruleUnmatched} // a UDP listen is the kernel's EOPNOTSUPP
				}
			}
			if !dec.allowed {
				if cookies, ok := l.k.(listenerCookieKernel); ok {
					if cookie, err := cookies.SocketCookie(t.dup); err == nil {
						if rule, matched := l.listenerBindings.match(cookie, d.ap, proto); matched {
							original, active := agent.MatchBind(c.pol.Rules.Listen, netip.AddrPortFrom(d.ap.Addr(), 0), proto)
							if active && original.RuleName() == rule {
								dec = verdictOf{allowed: true, rule: rule}
							}
						}
					}
				}
			}
		} else if d.isUnix() {
			if l.listenHandoffReady() {
				// getsockname retains the original relative or symlinked
				// spelling. Only the kernel can verify the actual bound
				// socket's dentry after chdir, rename, or descriptor races.
				l.saveListenNaming(n, d, "", false)
				if l.valid(n) {
					l.respond(n, respContinue())
				}
				return
			}
			if c.pol.Rules.Listen == nil {
				dec = verdictOf{allowed: true, rule: ruleUnmatched}
			}
			for _, rule := range c.pol.Rules.Listen {
				if rule.Proto != agent.ProtoUnix {
					continue
				}
				if rule.Abstract && len(d.abstract) > 0 && rule.UnixPath == string(d.abstract) || !rule.Abstract && d.unixPath != "" && rule.UnixPath == d.unixPath {
					dec = verdictOf{allowed: true, rule: rule.RuleName()}
					break
				}
			}
		}
	}
	if !dec.allowed {
		l.finishListenerOp(n, c, d, proto, dec, nil, false, "listen")
		return
	}
	if !l.valid(n) {
		return
	}
	err = k.ListenRaw(t.dup, int(int32(n.args[1])))
	if c.pol.Rules.Listen == nil {
		l.respond(n, respResult(0, err)) // no line: no rule decided this, as when the kernel took it (R11c)
		return
	}
	l.finishListenerOp(n, c, d, proto, dec, err, false, "listen")
}
