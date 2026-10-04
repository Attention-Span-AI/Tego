// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// MaxRelays bounds a run's first-write relays in all, unanswered and
// established. Each established relay holds two sockets, two goroutines and
// their buffers for as long as the agent keeps its connection.
const MaxRelays = 256

// RelayPool bounds TCP first-delivery holds. The agent connects to a private
// loopback listener on its original socket. No upstream connection or byte is
// delivered until the first buffered bytes receive approval. Its peer address
// consequently names the relay; the original send may enter kernel buffers.
//
// max (ask.max_pending) bounds the unanswered relays only, from reservation
// until approved delivery: an established relay is no longer pending, and
// counting it let long-lived approved connections refuse every later ask
// before a human saw it (agent-contract R22). maxRelays bounds them all.
type RelayPool struct {
	mu          sync.Mutex
	closed      bool
	max         int
	maxRelays   int
	established int
	timeout     time.Duration
	request     func(context.Context, Request) (Decision, error)
	delivered   func(Delivery)
	active      map[*firstRelay]struct{}
	wg          sync.WaitGroup
}

type firstRelay struct {
	pool             *RelayPool
	ctx              context.Context
	cancel           context.CancelFunc
	listener         *net.TCPListener
	mu               sync.Mutex
	closed           bool
	established      bool // guarded by pool.mu
	client, upstream *net.TCPConn
	req              Request
	dst              netip.AddrPort
	agentFD          int
	// refused names the live block refusing dst now, "" when none (Reserve); nil refuses nothing.
	refused func() string
}

// Delivery is how a relay ended once it read the agent's first bytes: the
// request's decision and error (Err is non-nil whenever no answer line was
// accepted, so no denial mirror exists), and for an approval whether the
// upstream connection and the first delivery succeeded. Blocked is the rule of
// the live block that refused the delivery (Reserve's refused), whatever the
// decision: nothing was asked, the request was withdrawn, or the approval came
// back after the block landed; nothing was connected or delivered then.
type Delivery struct {
	Request              Request
	Decision             Decision
	Err                  error
	Connected, Delivered bool
	Blocked              string
}

// NewRelayPool requires delivered, called exactly once and synchronously for
// every relay that read first bytes: the supervisor recorded only the connect
// into the relay, so the delivery's end is the caller's to record.
func NewRelayPool(max int, timeout time.Duration, request func(context.Context, Request) (Decision, error), delivered func(Delivery)) (*RelayPool, error) {
	if max < 1 || max > DefaultMaxPending || timeout <= 0 || request == nil || delivered == nil {
		return nil, ErrUnavailable
	}
	return &RelayPool{max: max, maxRelays: MaxRelays, timeout: timeout, request: request, delivered: delivered, active: make(map[*firstRelay]struct{})}, nil
}

// Reserve binds a single-accept loopback listener. Release closes it and any
// accepted sockets; call it if the target connect failed or was abandoned.
//
// The run's live blocks outrank the delivery (supervisor liveInetAsked):
// refused names the block refusing dst now, "" when
// none. A block in force when the first bytes arrive refuses the delivery
// before anyone is asked; one landing while the
// person decides withdraws the request at the next tick (the broker answers it
// ask-unavailable by cancelled); one in force when the answer is back refuses
// it whatever the answer, before the upstream dial, and again once the dial
// connects, before the first bytes are written. Delivery.Blocked names it.
// refused runs on the relay's goroutines, so it must be safe there and must not
// block; nil refuses nothing.
func (p *RelayPool) Reserve(ctx context.Context, req Request, dst netip.AddrPort, ipv6 bool, socketFD int, refused func() string) (netip.AddrPort, func(), error) {
	if !validRequest(req) || req.Hold != "first_write" || !dst.IsValid() || dst.Port() == 0 {
		return netip.AddrPort{}, nil, ErrProtocol
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.active)-p.established >= p.max || len(p.active) >= p.maxRelays {
		return netip.AddrPort{}, nil, ErrUnavailable
	}
	agentFD, err := unix.FcntlInt(uintptr(socketFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	network, host := "tcp4", "127.0.0.1:0"
	if ipv6 {
		network, host = "tcp6", "[::1]:0"
	}
	l, err := net.ListenTCP(network, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(host)))
	if err != nil {
		_ = unix.Close(agentFD)
		return netip.AddrPort{}, nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	r := &firstRelay{pool: p, ctx: cctx, cancel: cancel, listener: l, req: req, dst: dst, agentFD: agentFD, refused: refused}
	p.active[r] = struct{}{}
	p.wg.Add(1)
	go r.run()
	return l.Addr().(*net.TCPAddr).AddrPort(), r.close, nil
}

func (r *firstRelay) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.agentFD >= 0 {
		_ = unix.Close(r.agentFD)
		r.agentFD = -1
	}
	r.cancel()
	_ = r.listener.Close()
	if r.client != nil {
		_ = r.client.SetLinger(0)
		_ = r.client.Close()
	}
	if r.upstream != nil {
		_ = r.upstream.Close()
	}
}

func (r *firstRelay) own(c *net.TCPConn, upstream bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = c.Close()
		return false
	}
	if upstream {
		r.upstream = c
	} else {
		r.client = c
	}
	return true
}

func (r *firstRelay) run() {
	defer r.pool.wg.Done()
	defer func() {
		r.close()
		r.pool.mu.Lock()
		delete(r.pool.active, r)
		if r.established {
			r.pool.established--
		}
		r.pool.mu.Unlock()
	}()
	stop := context.AfterFunc(r.ctx, r.close)
	defer stop()
	_ = r.listener.SetDeadline(time.Now().Add(r.pool.timeout))
	var client *net.TCPConn
	for tries := 0; tries < maxClients; tries++ {
		var err error
		client, err = r.listener.AcceptTCP()
		if err != nil {
			return
		}
		// Authenticate the accepted peer against the held target socket OFD,
		// rather than trust anybody able to guess a loopback listener port.
		r.mu.Lock()
		valid := !r.closed && relayPeerMatches(r.agentFD, client.RemoteAddr())
		r.mu.Unlock()
		if valid {
			break
		}
		_ = client.Close()
		client = nil
	}
	if client == nil {
		return
	}
	_ = r.listener.Close()
	if !r.own(client, false) {
		return
	}
	r.mu.Lock()
	if r.agentFD >= 0 {
		_ = unix.Close(r.agentFD)
		r.agentFD = -1
	}
	r.mu.Unlock()
	_ = client.SetReadDeadline(time.Now().Add(r.pool.timeout))
	buf := make([]byte, 32<<10)
	n, err := client.Read(buf)
	if n == 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return
	}
	var (
		d       Decision
		reqErr  error
		blocked = r.blocked()
	)
	report := func(connected, delivered bool) {
		r.pool.delivered(Delivery{Request: r.req, Decision: d, Err: reqErr, Connected: connected, Delivered: delivered, Blocked: blocked})
	}
	if blocked != "" {
		report(false, false) // a block in force already: nobody is asked about a delivery no answer could complete
		return
	}
	d, reqErr = r.ask()
	if blocked = r.blocked(); blocked != "" || reqErr != nil || !d.Approved || r.ctx.Err() != nil {
		report(false, false)
		return
	}
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(r.ctx, "tcp", r.dst.String())
	if err != nil {
		report(false, false)
		return
	}
	// The dial may take up to its 30 s timeout, and a block that landed during the handshake outranks the approval as
	// much as one that landed while the person decided: the agent's first bytes are never written to the blocked host.
	if blocked = r.blocked(); blocked != "" {
		_ = conn.Close() // nothing was written on it; its close error changes nothing the line says
		report(true, false)
		return
	}
	upstream := conn.(*net.TCPConn)
	if !r.own(upstream, true) {
		report(true, false)
		return
	}
	_ = client.SetReadDeadline(time.Time{})
	if _, err = upstream.Write(buf[:n]); err != nil {
		report(true, false)
		return
	}
	report(true, true)
	// Delivered: the relay leaves max_pending's count and lives as long as
	// the agent's connection, with no idle timeout a direct one lacks.
	r.pool.mu.Lock()
	r.established = true
	r.pool.established++
	r.pool.mu.Unlock()
	// Explicit bounded buffers avoid optional ReaderFrom/WriterTo paths. Half
	// close preserves protocols that finish their request with a write EOF.
	done := make(chan struct{}, 2)
	go func() { copyStream(upstream, client); _ = upstream.CloseWrite(); done <- struct{}{} }()
	go func() { copyStream(client, upstream); _ = client.CloseWrite(); done <- struct{}{} }()
	<-done
	select {
	case <-done:
	case <-r.ctx.Done():
		r.close()
		<-done
	}
}

// blocked is the live block refusing the relay's destination now, "" when none.
func (r *firstRelay) blocked() string {
	if r.refused == nil {
		return ""
	}
	return r.refused()
}

// ask asks the person about the first delivery, and takes the request back once a live block refusing the destination
// lands (refused, looked at every 50 ms, as the supervisor's hold looks): the broker then answers it ask-unavailable by
// cancelled, so the dashboard's card and `tego ask` drop it.
func (r *firstRelay) ask() (Decision, error) {
	if r.refused == nil {
		return r.pool.request(r.ctx, r.req)
	}
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if r.refused() != "" {
					cancel()
					return
				}
			}
		}
	}()
	d, err := r.pool.request(ctx, r.req)
	cancel()
	<-watchDone
	return d, err
}

func relayPeerMatches(fd int, peer net.Addr) bool {
	if fd < 0 {
		return false
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	var ap netip.AddrPort
	switch s := sa.(type) {
	case *unix.SockaddrInet4:
		ap = netip.AddrPortFrom(netip.AddrFrom4(s.Addr), uint16(s.Port))
	case *unix.SockaddrInet6:
		ap = netip.AddrPortFrom(netip.AddrFrom16(s.Addr).Unmap(), uint16(s.Port))
	default:
		return false
	}
	p, ok := peer.(*net.TCPAddr)
	if !ok {
		return false
	}
	actual := p.AddrPort()
	return ap.Port() != 0 && ap.Port() == actual.Port() && ap.Addr().Unmap() == actual.Addr().Unmap()
}

func copyStream(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			sent := 0
			for sent < n {
				w, e := dst.Write(buf[sent:n])
				sent += w
				if e != nil || w == 0 {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *RelayPool) Close() error {
	p.mu.Lock()
	p.closed = true
	relays := make([]*firstRelay, 0, len(p.active))
	for r := range p.active {
		relays = append(relays, r)
	}
	p.mu.Unlock()
	for _, r := range relays {
		r.close()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(clientTimeout):
		return fmt.Errorf("%w: first-write relays did not stop", ErrUnavailable)
	}
}
