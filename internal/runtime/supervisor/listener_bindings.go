// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

const maxListenerBindings = 65536

type listenerBinding struct {
	address     netip.AddrPort
	proto, rule string
}

// A successful bind to port zero must retain its original declaration after
// the kernel allocates a port. These proofs are socket-cookie scoped, never fd
// numbers, and match the actual bound address again before listen is relayed.
// A proof is never consumed, since a listening socket may listen again to
// change its backlog, and nothing says when its socket closes; a cookie is
// never reused, so a closed socket's proof is simply never matched again.
// A full cache therefore evicts its oldest proof (amended 2026-10-05,
// races-1: it dropped the newest, so after maxListenerBindings port-0 binds
// in one run every later port-0 listen was refused). Only a socket left bound
// and unlistened across that many later port-0 binds loses its proof, and a
// lost proof only narrows admission.
type listenerBindings struct {
	mu       sync.Mutex
	byCookie map[uint64]listenerBinding
	// order holds byCookie's cookies in insertion order, a ring once full:
	// oldest is the index of the next one to evict.
	order  []uint64
	oldest int
}

func (b *listenerBindings) remember(cookie uint64, address netip.AddrPort, proto, rule string) {
	if cookie == 0 || !address.IsValid() || address.Port() == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byCookie == nil {
		b.byCookie = make(map[uint64]listenerBinding)
	}
	if _, exists := b.byCookie[cookie]; !exists {
		if len(b.order) < maxListenerBindings {
			b.order = append(b.order, cookie)
		} else {
			delete(b.byCookie, b.order[b.oldest])
			b.order[b.oldest] = cookie
			b.oldest = (b.oldest + 1) % maxListenerBindings
		}
	}
	b.byCookie[cookie] = listenerBinding{address: address, proto: proto, rule: rule}
}

func (b *listenerBindings) match(cookie uint64, address netip.AddrPort, proto string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.byCookie[cookie]
	return p.rule, ok && cookie != 0 && p.address == address && p.proto == proto
}

func (b *listenerBindings) clear() {
	b.mu.Lock()
	b.byCookie, b.order, b.oldest = nil, nil, 0
	b.mu.Unlock()
}

type listenerCookieKernel interface{ SocketCookie(fd int) (uint64, error) }

func (sysKernel) SocketCookie(fd int) (uint64, error) {
	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
}

func (l *Loop) rememberListenerBind(fd int, requested dest, proto, rule string) {
	if !requested.isInet() || requested.ap.Port() != 0 {
		return
	}
	namer, ok := l.k.(listenKernel)
	if !ok {
		return
	}
	cookies, ok := l.k.(listenerCookieKernel)
	if !ok {
		return
	}
	raw, err := namer.SocketNameRaw(fd)
	if err != nil {
		return
	}
	actual := parseSockaddr(raw)
	if !actual.isInet() || !actual.ok || actual.ap.Addr() != requested.ap.Addr() {
		return
	}
	cookie, err := cookies.SocketCookie(fd)
	if err != nil {
		return
	}
	l.listenerBindings.remember(cookie, actual.ap, proto, rule)
}
