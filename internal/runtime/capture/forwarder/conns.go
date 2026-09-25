// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultIdleTimeout is how long a keep-alive connection may sit between requests before the listener closes it
// (R27). net/http holds an idle connection, its goroutine, its descriptor and its buffers until the peer
// closes it when the server sets no IdleTimeout (and no ReadTimeout, which R27 rules out), so 2000 connections
// that each sent one request and went quiet stayed open for as long as their peer liked. Two minutes is longer
// than the idle expiry of every client pool an agent brings — httpx's 5 s (the Anthropic and OpenAI Python
// SDKs), undici's 4 s (Node's fetch), Go's Transport's 90 s — so the client always gives up a connection first
// and the listener never closes one a client still counts as reusable, which would fail a POST the client is
// just then writing on it.
const DefaultIdleTimeout = 2 * time.Minute

// DefaultMaxConns is how many connections one listener holds open at once; the one past it is closed as soon as
// it is accepted (R27). No cgroup covers the launcher (budget's doc), and each connection costs it a
// goroutine, a descriptor and about 12 KB of buffers and state (measured: 4000 connections, 4001 goroutines,
// 4000 descriptors, ~50 MB), so the number an agent may open is bounded here, as the capture budget bounds the
// bytes; what anything else on the host, which can reach a loopback port too (R19a), may hold is bounded apart
// (capListener), so that it cannot take these slots. 2048 is twice the largest
// pool an SDK opens by default (the Anthropic Python SDK's httpx limit is 1000 connections per client), which
// leaves a second process of the run, or a pool not yet drained of its idle connections, room as well; at the
// cap it is about 25 MB of the launcher's heap.
const DefaultMaxConns = 2048

// DefaultMaxOutsiders is how many connections from peers R19a refused one listener holds at once, each waiting to
// send the request its 403 answers; one refused past it is closed as soon as its peer is known.
const DefaultMaxOutsiders = 64

// capListener is the listener's accept side with DefaultMaxConns applied to the run's own connections: one the
// run's process opens while max of the run's are open is closed at once and counted, rather than left to wait in
// the kernel's backlog (which is what golang.org/x/net/netutil.LimitListener does). A connection waiting there has
// no deadline and nothing records it: the agent's call hangs without a word in the run's record, where a refusal
// fails the call and is a gap.
//
// Whose connection it is is decided before it takes a slot (R19a). The cap was once taken at accept, ahead of the
// admission a connection's first request made, so any process on the host could hold every slot with idle
// loopback connections: the agent's own were then closed at accept, and each was a gap why=size-cap in the run's
// record that a process outside the run had put there. Now a connection is admitted as net/http first reads it,
// on its own goroutine and before any byte of it is read, and each of the three kinds is bounded apart:
//
//   - pending, accepted and not yet placed: at most max. Placing one is a sock_diag lookup and a few descriptor
//     links, done in microseconds to milliseconds, so this fills only under a connect flood; one accepted past it
//     is placed on the accept goroutine itself, which makes the flood wait in the backlog rather than hold a slot
//     or be refused unplaced;
//   - the run's, at most max: one past it is closed before a byte is read and is refuse's size-cap gap;
//   - outsiders, peers R19a refused, at most maxOutsiders: each is kept only to read the request its 403
//     answers, after which ServeHTTP closes it, and one past the bound is closed at once and counted as a
//     refusal (turnAway), never a gap.
//
// So everything the listener holds open is at most 2·max + maxOutsiders connections, and nothing outside the run
// can close the run's connections or write the run's gap report.
type capListener struct {
	net.Listener
	max          int64
	maxOutsiders int64
	pending      atomic.Int64
	open         atomic.Int64
	outsiders    atomic.Int64
	// resolve places a connection's peer: its pid and nil for the run's, an error for anything else (R19a).
	resolve  func(net.Conn) (int, error)
	refuse   func()                // counts one of the run's connections refused at the cap
	turnAway func(net.Conn, error) // counts one outsider closed past maxOutsiders
	closed   func(net.Conn)        // is told of each accepted connection's close
}

// Accept returns the next connection, placed or to be placed on its first read.
func (c *capListener) Accept() (net.Conn, error) {
	for {
		conn, err := c.Listener.Accept()
		if err != nil {
			return nil, err
		}
		cc := &cappedConn{Conn: conn, l: c, verdict: new(peerVerdict)}
		if c.pending.Add(1) <= c.max {
			cc.slot = slotPending
			return cc, nil
		}
		c.pending.Add(-1)
		if err := cc.admit(); err != nil {
			_ = cc.Close()
			continue
		}
		return cc, nil
	}
}

// slot is which of capListener's bounds a connection is counted under.
type slot int

const (
	slotNone slot = iota
	slotPending
	slotRun
	slotOutsider
	slotClosed
)

// cappedConn is one accepted connection and the slot it holds, which it gives back when it closes.
type cappedConn struct {
	net.Conn
	l       *capListener
	verdict *peerVerdict // R19a's decision, shared with the connection's requests by ConnContext

	admitOnce sync.Once
	admitErr  error

	mu        sync.Mutex
	slot      slot
	closeOnce sync.Once
}

// admit places the connection's peer and moves it from pending to the run's slots or an outsider's; an error is
// the connection closed at one of the bounds, before a byte of it is read.
func (c *cappedConn) admit() error {
	c.admitOnce.Do(func() {
		v := c.verdict
		if c.l.resolve != nil {
			v.once.Do(func() { v.pid, v.err = c.l.resolve(c.Conn) })
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.slot == slotClosed {
			c.admitErr = net.ErrClosed
			return
		}
		c.release()
		switch {
		case v.err == nil && c.l.open.Add(1) > c.l.max:
			c.l.open.Add(-1)
			c.l.refuse() // counted before the close, so a gap report read once the client sees it includes it
			c.admitErr = errOverCap
		case v.err == nil:
			c.slot = slotRun
		case c.l.outsiders.Add(1) > c.l.maxOutsiders:
			c.l.outsiders.Add(-1)
			if c.l.turnAway != nil {
				c.l.turnAway(c.Conn, v.err)
			}
			c.admitErr = errOverCap
		default:
			c.slot = slotOutsider // served only as far as ServeHTTP's 403
		}
	})
	return c.admitErr
}

// errOverCap is a connection closed at one of capListener's bounds.
var errOverCap = errors.New("forwarder: connection closed at the listener's connection cap")

// release gives back the slot the connection holds; c.mu is held.
func (c *cappedConn) release() {
	switch c.slot {
	case slotPending:
		c.l.pending.Add(-1)
	case slotRun:
		c.l.open.Add(-1)
	case slotOutsider:
		c.l.outsiders.Add(-1)
	case slotNone, slotClosed: // no slot held
	}
	c.slot = slotNone
}

// Read admits the connection before its first byte is read (R19a), then reads. A connection closed at a bound
// reads as its end: net/http answers any other read error with a 400 written to the peer, and this one is closed
// before a byte of it is read or a byte written to it.
func (c *cappedConn) Read(p []byte) (int, error) {
	if c.admit() != nil {
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}

// Close closes the connection and frees its slot, once however often it is called.
func (c *cappedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.release()
		c.slot = slotClosed
		c.mu.Unlock()
		if c.l.closed != nil {
			c.l.closed(c.Conn)
		}
	})
	return err
}

// CloseWrite half-closes the connection when the one underneath can: net/http's server shuts the write side and
// waits before closing a connection whose request body it did not read, so the client reads the response rather
// than a reset, and it finds that by asking the connection it was handed for this method.
func (c *cappedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// turnAwayOutsider counts an outsider closed past DefaultMaxOutsiders as a refusal, like refusePeer's and for its
// reason: not a gap, and logged at warn level only the first time.
func (l *Listener) turnAwayOutsider(c net.Conn, err error) {
	n := l.refused.Add(1)
	args := []any{"run", l.runRef().ID, "host", l.model.Host, "peer", c.RemoteAddr().String(), "refused", n,
		"err", err}
	if n == 1 {
		l.opts.Logger.Warn("forwarder: refused a peer outside the run", args...)
	} else {
		l.opts.Logger.Debug("forwarder: refused a peer outside the run", args...)
	}
}

// refuseOverCap records a connection closed at the cap as one gap why=size-cap: a cap this component set, as R37
// defines the value, and a shortfall of capture if it was the agent's (I4). It is counted for the run's gap report
// rather than written as a line of its own, since whoever opens connections chooses how many are refused. It
// reports nothing unmetered (docs/p0/limits-check-doctor-cli.md R1): the connection was closed before a byte of
// it was read, so nothing of it reached the model host to be spent on. Only the first is logged at warn level,
// for the reason refusePeer gives.
func (l *Listener) refuseOverCap() {
	l.note(GapSizeCap, 1)
	n := l.overCap.Add(1)
	args := []any{"run", l.runRef().ID, "host", l.model.Host, "max", l.opts.MaxConns, "refused", n}
	if n == 1 {
		l.opts.Logger.Warn("forwarder: closed a connection over the listener's connection cap", args...)
	} else {
		l.opts.Logger.Debug("forwarder: closed a connection over the listener's connection cap", args...)
	}
}

// connClosed passes a closed connection's two ends to the peer admitter, whose memory of where the peer's socket
// was is then out of date (procAdmitter.forget).
func (l *Listener) connClosed(c net.Conn) {
	if l.forgetPeer == nil {
		return
	}
	peer, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	local, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}
	l.forgetPeer(unmapped(peer), unmapped(local))
}
