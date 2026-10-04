// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func relaySocket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func relayClient(t *testing.T, fd int, ap netip.AddrPort) net.Conn {
	t.Helper()
	if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}); err != nil {
		t.Fatal(err)
	}
	copyFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(copyFD), "relay-client")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}

func TestFirstWriteNoUpstreamBeforeApprovedDelivery(t *testing.T) {
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	dst := up.Addr().(*net.TCPAddr).AddrPort()
	accepted := make(chan struct{}, 1)
	delivered := make(chan string, 1)
	go func() {
		c, e := up.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 5)
		if _, e = io.ReadFull(c, b); e == nil {
			delivered <- string(b)
			_, _ = c.Write(b)
		}
	}()
	requested, approve := make(chan Request, 1), make(chan struct{})
	pool, err := NewRelayPool(1, time.Second, func(ctx context.Context, r Request) (Decision, error) {
		requested <- r
		select {
		case <-approve:
			return Decision{Approved: true}, nil
		case <-ctx.Done():
			return Decision{}, ctx.Err()
		}
	}, func(Delivery) {})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	fd := relaySocket(t)
	req := Request{Op: "connect", Target: dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	ap, release, err := pool.Reserve(context.Background(), req, dst, false, fd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// An unrelated socket able to guess the private port cannot trigger ask.
	outsider, err := net.DialTimeout("tcp", ap.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = outsider.Write([]byte("wrong"))
	_ = outsider.Close()
	c := relayClient(t, fd, ap)
	select {
	case <-requested:
		t.Fatal("connect or outsider prompted before first write")
	case <-time.After(30 * time.Millisecond):
	}
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-requested:
		if r.Target != dst.String() {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("first write did not ask")
	}
	select {
	case <-accepted:
		t.Fatal("upstream opened before approval")
	case <-time.After(30 * time.Millisecond):
	}
	close(approve)
	b := make([]byte, 5)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("echo %q: %v", b, err)
	}
	select {
	case got := <-delivered:
		if got != "hello" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("approved delivery absent")
	}
	_ = c.Close()
	if err = pool.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFirstWriteDenialCapacityAndShutdown(t *testing.T) {
	requested := make(chan struct{}, 1)
	pool, err := NewRelayPool(1, time.Second, func(context.Context, Request) (Decision, error) {
		requested <- struct{}{}
		return Decision{Reason: ReasonDenied}, nil
	}, func(Delivery) {})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	fd := relaySocket(t)
	req := Request{Op: "connect", Target: "127.0.0.1:9", Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	ap, release, err := pool.Reserve(context.Background(), req, netip.MustParseAddrPort(req.Target), false, fd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, _, err = pool.Reserve(context.Background(), req, netip.MustParseAddrPort(req.Target), false, fd, nil); err != ErrUnavailable {
		t.Fatalf("capacity: %v", err)
	}
	c := relayClient(t, fd, ap)
	_, _ = c.Write([]byte("denied"))
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("no ask")
	}
	b := make([]byte, 1)
	if n, e := c.Read(b); n != 0 || e == nil {
		t.Fatalf("denied connection n=%d err=%v", n, e)
	}
	if err = pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = pool.Reserve(context.Background(), req, netip.MustParseAddrPort(req.Target), false, fd, nil); err != ErrUnavailable {
		t.Fatalf("closed: %v", err)
	}
}

// echoUpstream accepts connections and echoes them until the test ends.
func echoUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	go func() {
		for {
			c, e := up.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return up.Addr().(*net.TCPAddr).AddrPort()
}

// establishRelay reserves a relay to dst, writes its first bytes and waits for
// the approved echo, leaving the connection open and idle.
func establishRelay(t *testing.T, pool *RelayPool, dst netip.AddrPort) net.Conn {
	t.Helper()
	fd := relaySocket(t)
	req := Request{Op: "connect", Target: dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	ap, _, err := pool.Reserve(context.Background(), req, dst, false, fd, nil)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	c := relayClient(t, fd, ap)
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("echo %q: %v", b, err)
	}
	return c
}

// ask.max_pending bounds unanswered asks (agent-contract R22). An approved,
// established relay is no longer pending: a keep-alive connection must not hold
// a max_pending slot for its whole life and refuse every later first_write
// connect before a human sees it.
func TestFirstWriteEstablishedRelayLeavesPendingBound(t *testing.T) {
	dst := echoUpstream(t)
	pool, err := NewRelayPool(1, time.Second, func(context.Context, Request) (Decision, error) {
		return Decision{Approved: true}, nil
	}, func(Delivery) {})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.maxRelays = 3
	establishRelay(t, pool, dst)
	// The first relay is open and idle with no ask pending; max_pending is 1.
	establishRelay(t, pool, dst)
	// One unanswered reservation still fills max_pending.
	req := Request{Op: "connect", Target: dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	if _, _, err = pool.Reserve(context.Background(), req, dst, false, relaySocket(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err = pool.Reserve(context.Background(), req, dst, false, relaySocket(t), nil); err != ErrUnavailable {
		t.Fatalf("second unanswered relay with max_pending 1: %v", err)
	}
	if err = pool.Close(); err != nil {
		t.Fatal(err)
	}
	// Relays in all keep their own bound: two established reach maxRelays 2.
	pool, err = NewRelayPool(2, time.Second, func(context.Context, Request) (Decision, error) {
		return Decision{Approved: true}, nil
	}, func(Delivery) {})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.maxRelays = 2
	establishRelay(t, pool, dst)
	establishRelay(t, pool, dst)
	if _, _, err = pool.Reserve(context.Background(), req, dst, false, relaySocket(t), nil); err != ErrUnavailable {
		t.Fatalf("relay beyond the total bound: %v", err)
	}
	if err = pool.Close(); err != nil {
		t.Fatal(err)
	}
}

// Every relay that read first bytes reports its end exactly once, before the
// agent's connection is reset or relayed: a request error, a denial, and an
// approval whose upstream dial failed or whose delivery succeeded.
func TestFirstWriteReportsEveryDelivery(t *testing.T) {
	refused, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedDst := refused.Addr().(*net.TCPAddr).AddrPort()
	_ = refused.Close()
	for _, tc := range []struct {
		name     string
		decision Decision
		reqErr   error
		dst      netip.AddrPort
		want     Delivery
	}{
		{"request error", Decision{Reason: ReasonUnavailable}, ErrUnavailable, closedDst, Delivery{Decision: Decision{Reason: ReasonUnavailable}, Err: ErrUnavailable}},
		{"denied", Decision{Reason: ReasonDenied}, nil, closedDst, Delivery{Decision: Decision{Reason: ReasonDenied}}},
		{"approved, dial refused", Decision{Approved: true}, nil, closedDst, Delivery{Decision: Decision{Approved: true}}},
		{"approved and delivered", Decision{Approved: true}, nil, echoUpstream(t), Delivery{Decision: Decision{Approved: true}, Connected: true, Delivered: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan Delivery, 2)
			pool, err := NewRelayPool(1, time.Second, func(context.Context, Request) (Decision, error) {
				return tc.decision, tc.reqErr
			}, func(d Delivery) { got <- d })
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			fd := relaySocket(t)
			req := Request{Op: "connect", Target: tc.dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
			ap, release, err := pool.Reserve(context.Background(), req, tc.dst, false, fd, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			c := relayClient(t, fd, ap)
			if _, err = c.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			var d Delivery
			select {
			case d = <-got:
			case <-time.After(3 * time.Second):
				t.Fatal("no delivery reported")
			}
			tc.want.Request = req
			if d != tc.want {
				t.Fatalf("delivery %+v, want %+v", d, tc.want)
			}
			if err = pool.Close(); err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatalf("second report %+v", <-got)
			}
		})
	}
}
