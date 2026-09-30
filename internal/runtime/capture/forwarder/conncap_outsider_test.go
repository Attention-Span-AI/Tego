// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// outsiderAddr is the source address the outsiders below dial from: loopback, and refused by outsiderAdmitter.
var outsiderAddr = netip.MustParseAddr("127.0.0.2")

// outsiderAdmitter admits every peer but those dialling from outsiderAddr, as R19a admits the run's processes and
// refuses the rest of the host.
func outsiderAdmitter(peer, _ netip.AddrPort, _ uint64) (int, error) {
	if peer.Addr() == outsiderAddr {
		return 0, fmt.Errorf("%w: an outsider", ErrPeer)
	}
	return 0, nil
}

// newCappedListener is a listener at the given connection cap, admitting by outsiderAdmitter.
func newCappedListener(t *testing.T, maxConns int) *Listener {
	t.Helper()
	l, err := NewListener(
		agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		Options{Clock: newClock(), Rand: &countingRand{}, MaxConns: maxConns,
			Transport: &cannedTransport{status: http.StatusOK, body: `{}`}})
	if err != nil {
		t.Fatal(err)
	}
	l.peers = outsiderAdmitter
	l.Bind(testRun, &fakeSink{})
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		<-served
	})
	return l
}

// dialOutsider opens a connection from outsiderAddr and sends nothing on it.
func dialOutsider(t *testing.T, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: outsiderAddr.AsSlice()}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skipf("cannot dial from %s on this machine: %v", outsiderAddr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The connection cap was taken at accept, before admission, so processes outside the run could hold
// every slot with idle loopback connections: the agent's own connections were then closed at accept and its model
// calls failed, and each one refused was a gap why=size-cap in the run's record, fed by processes R19a keeps out of
// it. Admission now runs as a connection is first read, and only the run's connections count against the cap: the
// outsiders hold none of it, those past their own small cap are closed as refusals, and none is a gap.
func TestOutsidersDoNotTakeTheRunsConnectionSlots(t *testing.T) {
	const maxConns = 2
	l := newCappedListener(t, maxConns)
	addr := l.Addr().String()
	for range DefaultMaxOutsiders + 4 {
		dialOutsider(t, addr)
	}
	// The outsiders past DefaultMaxOutsiders are refused as they are read, which the server does asynchronously.
	deadline := time.Now().Add(5 * time.Second)
	for l.refused.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := l.refused.Load(); n != 4 {
		t.Errorf("refused = %d, want the 4 outsiders past DefaultMaxOutsiders (%d)", n, DefaultMaxOutsiders)
	}
	for i := range maxConns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := fmt.Fprintf(c, "HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n", HelloPath); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("the run's connection %d, beside %d idle outsiders, was not served: %v", i,
				DefaultMaxOutsiders+4, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("the run's connection %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	for _, why := range []string{GapSizeCap, GapMalformed} {
		if n := gapCount(l, why); n != 0 {
			t.Errorf("gap why=%s = %d: an outsider is not a gap what=capture (R19a)", why, n)
		}
	}
}

// A refused peer is answered 403 and its connection closed, so it gives back its outsider slot rather than
// being kept alive to ask again.
func TestARefusedPeerIsClosedAfterItsAnswer(t *testing.T) {
	l := newCappedListener(t, 2)
	c := dialOutsider(t, l.Addr().String())
	if _, err := fmt.Fprintf(c, "HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n", HelloPath); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	if !closedWithin(c, br, 3*time.Second) {
		t.Error("a refused peer's connection was kept open")
	}
}

// With max connections already being placed (a connect flood), the next is placed on the accept goroutine before
// Accept returns it, counted under the run's bound or closed, and never refused unplaced.
func TestAcceptPlacesAConnectionPastThePendingBound(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var resolved, refused int
	cl := &capListener{Listener: ln, max: 1, maxOutsiders: 1,
		resolve: func(net.Conn) (int, error) { resolved++; return 0, nil },
		refuse:  func() { refused++ }}
	defer func() { _ = cl.Close() }()
	cl.pending.Store(1) // one connection is being placed
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	got, err := cl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Close() }()
	if resolved != 1 || refused != 0 || cl.open.Load() != 1 || cl.pending.Load() != 1 {
		t.Errorf("resolved %d refused %d open %d pending %d, want the connection placed and counted as the run's",
			resolved, refused, cl.open.Load(), cl.pending.Load())
	}
	_ = got.Close()
	if cl.open.Load() != 0 {
		t.Errorf("open %d after the close, want its slot back", cl.open.Load())
	}
}
