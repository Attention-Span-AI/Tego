// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestFirstWriteLiveBlockOutranksTheAnswer is the first-write half for net: a live block naming the
// relay's destination (Reserve's refused) refuses the delivery and names itself in Delivery.Blocked, and no
// upstream is dialed, whether it was in force when the agent first wrote (nobody is asked), landed while the person
// decided (the request is taken back: its context ends, as the broker's does for a withdrawn request), or landed
// before an approval came back. Before, an approval given after the block dialed the blocked destination.
func TestFirstWriteLiveBlockOutranksTheAnswer(t *testing.T) {
	const rule = "live.block[net:api.example.com]"
	for _, tc := range []struct {
		name      string
		before    bool // the block is in force when the agent first writes
		withdrawn bool // the person never answers: only the block's withdrawal ends the request
		asks      int32
	}{
		{"in force at the first write", true, false, 0},
		{"lands while the person decides", false, true, 1},
		{"lands before the approval comes back", false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer up.Close()
			dialed := make(chan struct{}, 1)
			go func() {
				for {
					c, e := up.Accept()
					if e != nil {
						return
					}
					select {
					case dialed <- struct{}{}:
					default:
					}
					_ = c.Close()
				}
			}()
			dst := up.Addr().(*net.TCPAddr).AddrPort()
			var blocked atomic.Bool
			blocked.Store(tc.before)
			refused := func() string {
				if blocked.Load() {
					return rule
				}
				return ""
			}
			var asks atomic.Int32
			cancelled := make(chan struct{}, 1)
			got := make(chan Delivery, 2)
			pool, err := NewRelayPool(1, time.Minute, func(ctx context.Context, r Request) (Decision, error) {
				asks.Add(1)
				blocked.Store(true) // lands while the person decides
				if !tc.withdrawn {
					return Decision{AskID: "q-1", Approved: true, By: "uid:1 pid:2"}, nil
				}
				select {
				case <-ctx.Done():
					cancelled <- struct{}{}
					return Decision{AskID: "q-1", Reason: ReasonUnavailable, By: "cancelled"}, nil
				case <-time.After(5 * time.Second): // the person, still shown the card, answers Allow once
					return Decision{AskID: "q-1", Approved: true, By: "uid:1 pid:2"}, nil
				}
			}, func(d Delivery) { got <- d })
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			fd := relaySocket(t)
			req := Request{Op: "connect", Target: dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
			ap, release, err := pool.Reserve(context.Background(), req, dst, false, fd, refused)
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
				t.Fatal("no delivery reported 3 s after the block")
			}
			if d.Blocked != rule || d.Connected || d.Delivered {
				t.Fatalf("delivery %+v: want refused by %s, nothing connected", d, rule)
			}
			if n := asks.Load(); n != tc.asks {
				t.Fatalf("asked %d times, want %d", n, tc.asks)
			}
			if tc.withdrawn && len(cancelled) != 1 {
				t.Fatal("the pending request was never taken back")
			}
			select {
			case <-dialed:
				t.Fatal("the blocked destination was dialed")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestFirstWriteLiveBlockDuringTheDial: a block that lands while the approved relay dials its upstream (up to 30 s
// for a slow handshake) refuses the delivery once the dial connects, before the agent's first bytes are written, and
// names itself in Delivery.Blocked. Before, refused was looked at only before the dial, so a block landing during
// the handshake still had the first bytes delivered to the blocked host.
func TestFirstWriteLiveBlockDuringTheDial(t *testing.T) {
	const rule = "live.block[net:api.example.com]"
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	received := make(chan int, 1)
	go func() {
		c, e := up.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := c.Read(buf)
		received <- n
	}()
	dst := up.Addr().(*net.TCPAddr).AddrPort()
	// refused is looked at when the first bytes arrive, once the answer is back, and once the dial connects: the block
	// lands between the second look and the third, as one landing during the handshake does.
	var looks atomic.Int32
	refused := func() string {
		if looks.Add(1) >= 3 {
			return rule
		}
		return ""
	}
	got := make(chan Delivery, 2)
	pool, err := NewRelayPool(1, time.Minute, func(context.Context, Request) (Decision, error) {
		return Decision{AskID: "q-1", Approved: true, By: "uid:1 pid:2"}, nil
	}, func(d Delivery) { got <- d })
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	fd := relaySocket(t)
	req := Request{Op: "connect", Target: dst.String(), Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	ap, release, err := pool.Reserve(context.Background(), req, dst, false, fd, refused)
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
		t.Fatal("no delivery reported 3 s after the block")
	}
	if d.Blocked != rule || d.Delivered {
		t.Fatalf("delivery %+v: want refused by %s, nothing delivered", d, rule)
	}
	select {
	case n := <-received:
		if n != 0 {
			t.Fatalf("the blocked upstream received %d bytes, want none", n)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the upstream connection was neither closed nor written")
	}
}
