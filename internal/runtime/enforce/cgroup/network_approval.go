// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const connectApprovalLifetime = time.Second

// grantWait bounds how long a grant waits for another grant's credit of the same row to be withdrawn (creditRows). An
// approved datagram's relay returns in microseconds; a connect's relay can take as long as the connect does, so a
// second connect of one socket to one destination, which the kernel would refuse EALREADY or EISCONN anyway, is refused
// after this rather than holding the supervisor's worker for it.
const grantWait = time.Second

// ErrGrantBusy is a grant's refusal when another grant held the same row past grantWait, or the caller's done closed
// while it waited: nothing was written and the caller sends nothing.
var ErrGrantBusy = errors.New("another approved operation holds the kernel credit row this one needs")

// Revoke withdraws one credit a grant wrote, once the relay it admitted has returned, whatever came of it, and lets
// the next grant of that row write its own. untaken reports that the credit was still in the map, so the run's hook
// never took it: a relay the kernel answered with success then did not pass connect4/6, sendmsg4/6 or connect_unix as
// the operation the credit names (an approved datagram's caller reads it, supervisor R13d). Calls after the first
// return the first's result.
type Revoke = func() (untaken bool, err error)

// creditMap is the part of a one-shot approval map a grant uses: *ebpf.Map's own methods, behind an interface so a
// unit test stands in a map with the kernel's UpdateNoExist and delete-by-key semantics.
type creditMap interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// creditStore is a kernel that holds the approval maps (bpfKernel).
type creditStore interface {
	creditMap(name string) creditMap
}

// creditMap is the named approval map, nil when the build has none.
func (k *bpfKernel) creditMap(name string) creditMap {
	if m := k.maps[name]; m != nil {
		return m
	}
	return nil
}

// creditRows serializes the grants of each one-shot approval row by the row's own map key: the value the grant writes
// with UpdateNoExist and its revoke deletes. A map takes one row per key and a revoke deletes by key, so two grants of
// one key at once had the second fail EEXIST (an approved operation refused), or the first's revoke delete the
// second's live credit (its relay then refused by the kernel). Held from the grant to its revoke, a key admits one
// credit at a time, and because the key is the map's own, every field the kernel keys a row by (slot, generation,
// cookie, family, protocol, address, port; a unix row's cookie alone) is in it and nothing the kernel drops, an IPv6
// zone or an abstract name, is (a serializing key the supervisor built apart from the map's drifted from it twice).
// Keys of the two maps are distinct types and never meet.
type creditRows struct {
	mu   sync.Mutex
	held map[any]chan struct{}
}

// hold waits until no grant holds key, at most wait and never past done, then holds it until release is called.
func (c *creditRows) hold(done <-chan struct{}, key any, wait time.Duration) (release func(), err error) {
	var timeout <-chan time.Time
	for {
		c.mu.Lock()
		busy, held := c.held[key]
		if !held {
			if c.held == nil {
				c.held = make(map[any]chan struct{})
			}
			mine := make(chan struct{})
			c.held[key] = mine
			c.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					c.mu.Lock()
					delete(c.held, key)
					c.mu.Unlock()
					close(mine)
				})
			}, nil
		}
		c.mu.Unlock()
		if timeout == nil {
			t := time.NewTimer(wait)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case <-busy:
		case <-done:
			return nil, ErrGrantBusy
		case <-timeout:
			return nil, ErrGrantBusy
		}
	}
}

// GrantConnect authorizes one refused connect on the exact duplicated agent socket: a TCP connect (proto tcp, an
// ordinary TCP socket) or a UDP one (proto udp, a UDP socket; supervisor R13d). The caller revokes it on every relay
// outcome. Socket cookies prevent fd-number reuse; slot generations prevent dead-run aliasing. A grant waits while
// another of the same row is held (creditRows), at most grantWait and never past done.
func (h *Handle) GrantConnect(done <-chan struct{}, fd int, dst netip.AddrPort, proto string) (Revoke, error) {
	want := unix.IPPROTO_TCP
	switch proto {
	case agent.ProtoTCP:
	case agent.ProtoUDP:
		want = unix.IPPROTO_UDP
	default:
		return nil, fmt.Errorf("one-shot connect approvals require a TCP or UDP connect")
	}
	protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("one-shot approval socket protocol: %w", err)
	}
	if protocol != want {
		return nil, fmt.Errorf("one-shot %s approvals require an ordinary %s socket; protocol %d is unsupported", proto, proto, protocol)
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return nil, fmt.Errorf("one-shot approval socket domain: %w", err)
	}
	cookie, err := socketCookie(fd)
	if err != nil {
		return nil, err
	}
	return h.grantCredit(done, cookie, domain, dst, proto, false)
}

// GrantDatagram authorizes one refused addressed UDP datagram to dst, which a person approved (supervisor R13d), on
// the agent's UDP socket whose SO_COOKIE is cookie and whose SO_DOMAIN is domain: the run's sendmsg4/6 admits the
// first datagram of that socket to dst within connectApprovalLifetime, once. The caller reads both from its duplicate
// of the socket, having checked that it is a UDP socket: the API takes the socket's identity, never its descriptor
// number (ADR 0023 F8), as GrantUnix does. The caller revokes the grant when the relay returns, whatever came of it,
// and reads from the revoke whether the hook took the credit. Two datagrams of one socket to one destination take
// their credits one after the other (creditRows).
func (h *Handle) GrantDatagram(done <-chan struct{}, cookie uint64, domain int, dst netip.AddrPort) (Revoke, error) {
	return h.grantCredit(done, cookie, domain, dst, agent.ProtoUDP, true)
}

// grantCredit writes one credit for the socket whose cookie is cookie, keyed as the hook that will take it reads the
// destination. connect6 reads an IPv4 destination of an AF_INET6 socket in its mapped form; an addressed datagram to
// one runs sendmsg4 instead, with the IPv4 address (udpv6_sendmsg hands a v4-mapped datagram to udp_sendmsg), so its
// credit is keyed AF_INET.
func (h *Handle) grantCredit(done <-chan struct{}, cookie uint64, domain int, dst netip.AddrPort, proto string, datagram bool) (Revoke, error) {
	if !dst.IsValid() || dst.Port() == 0 || dst.Addr().IsUnspecified() {
		return nil, fmt.Errorf("one-shot approvals require a concrete destination")
	}
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return nil, fmt.Errorf("one-shot approval socket is not IP")
	}
	switch {
	case domain == unix.AF_INET6 && datagram && dst.Addr().Is4In6():
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	case domain == unix.AF_INET6 && !datagram && dst.Addr().Is4():
		dst = netip.AddrPortFrom(netip.AddrFrom16(dst.Addr().As16()), dst.Port())
	}
	h.netMu.Lock()
	slot, gen, err := h.grantable()
	h.netMu.Unlock()
	if err != nil {
		return nil, err
	}
	key, err := connectApprovalKey(slot, gen, cookie, dst, proto)
	if err != nil {
		return nil, err
	}
	return h.grantRow(done, bpf.MapConnectApprovals, gen, key, func(deadline uint64) any {
		return bpf.ConnectCredit{Credit: 1, DeadlineNS: deadline}
	})
}

// GrantUnix authorizes one connect of the agent's unix socket whose SO_COOKIE is cookie to the abstract name name,
// which a person approved (supervisor R11c): connect_unix (6.7+) and the plane's socket_connect (below 6.7) admit it
// once, for this run's gen, within connectApprovalLifetime, and only on that socket. The caller reads the cookie from
// its duplicate of the socket, having checked that the socket is AF_UNIX: the API takes the socket's identity, never
// its descriptor number (ADR 0023 F8). The caller revokes the grant when the relay returns, whatever came of it. A
// pathname needs no grant: the relay names the inode it resolved, which those programs admit from the launcher's
// cgroup alone. The row is the socket's whatever name it grants, so two approved connects of one socket take their
// credits one after the other, to one name or two (creditRows).
func (h *Handle) GrantUnix(done <-chan struct{}, cookie uint64, name []byte) (Revoke, error) {
	h.netMu.Lock()
	slot, gen, err := h.grantable()
	h.netMu.Unlock()
	if err != nil {
		return nil, err
	}
	key, credit, err := bpf.UnixApproval(slot, gen, cookie, name, 0)
	if err != nil {
		return nil, err
	}
	return h.grantRow(done, bpf.MapUnixApprovals, gen, key, func(deadline uint64) any {
		c := credit
		c.DeadlineNS = deadline
		return c
	})
}

// grantable is the slot and generation a grant keys its row by, or why this handle grants nothing: it is not
// prepared, or it is detached or closed. The caller holds netMu.
func (h *Handle) grantable() (slot, gen uint32, err error) {
	if !h.prepared || h.detached || h.closed || h.gen == 0 {
		return 0, 0, ErrNotPrepared
	}
	return h.slot, h.gen, nil
}

// grantRow writes one credit, credit(deadline), under key into the approval map name, once no other grant holds key
// (creditRows: at most grantWait, never past done), and returns the Revoke that deletes it and releases the key. The
// handle's state is checked again under netMu after the wait, and a generation that changed meanwhile grants nothing:
// key names the run it was built for.
func (h *Handle) grantRow(done <-chan struct{}, name string, gen uint32, key any, credit func(deadline uint64) any) (Revoke, error) {
	release, err := h.credits.hold(done, key, grantWait)
	if err != nil {
		return nil, err
	}
	m, err := h.writeCredit(name, gen, key, credit)
	if err != nil {
		release()
		return nil, err
	}
	var once sync.Once
	var untaken bool
	var revokeErr error
	return func() (bool, error) {
		once.Do(func() {
			defer release()
			h.netMu.Lock()
			defer h.netMu.Unlock()
			switch err := m.Delete(key); {
			case err == nil:
				untaken = true
			case !errors.Is(err, ebpf.ErrKeyNotExist):
				revokeErr = err
			}
		})
		return untaken, revokeErr
	}, nil
}

// writeCredit writes key's credit under netMu, with the deadline taken then, and returns the map it wrote.
func (h *Handle) writeCredit(name string, gen uint32, key any, credit func(deadline uint64) any) (creditMap, error) {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if _, now, err := h.grantable(); err != nil || now != gen {
		return nil, ErrNotPrepared
	}
	store, ok := h.kern.(creditStore)
	var m creditMap
	if ok {
		m = store.creditMap(name)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: kernel one-shot approvals unavailable (%s)", ErrProgramLoad, name)
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, err
	}
	if err := m.Update(key, credit(uint64(ts.Nano())+uint64(connectApprovalLifetime)), ebpf.UpdateNoExist); err != nil {
		return nil, mapFull(name, err)
	}
	return m, nil
}

func socketCookie(fd int) (uint64, error) {
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("socket cookie: %w", err)
	}
	if cookie == 0 {
		return 0, fmt.Errorf("socket has no usable kernel cookie")
	}
	return cookie, nil
}

func connectApprovalKey(slot, gen uint32, cookie uint64, dst netip.AddrPort, proto string) (bpf.ConnectApprovalKey, error) {
	var out bpf.ConnectApprovalKey
	p := bpf.ProtoTCP
	if proto == agent.ProtoUDP {
		p = bpf.ProtoUDP
	}
	if slot >= bpf.MaxSlots || gen == 0 || cookie == 0 || !dst.IsValid() || proto != agent.ProtoTCP && proto != agent.ProtoUDP || dst.Port() == 0 || dst.Addr().IsUnspecified() {
		return out, fmt.Errorf("invalid exact socket approval identity")
	}
	// Retain the actual socket address family. The supervisor relays precisely
	// these frozen bytes; unmapping here would authorize a different hook key.
	addr, family, err := bpf.Addr16(dst.Addr().WithZone(""))
	if err != nil {
		return out, err
	}
	return bpf.ConnectApprovalKey{RunIdx: slot, Gen: gen, Cookie: cookie, Family: family, Proto: p, Port: dst.Port(), Addr: addr}, nil
}
