// SPDX-License-Identifier: Apache-2.0

package ask_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
)

// TestBrokerNeverServesRawTarget: the broker's list and detail show every client a held request's target in its
// ledger form, the one the ask line records (askclient.LedgerTarget, record-ledger R9a), so an http_request's path
// and query, which may carry a token, never leave the run (threat G-08). Only an http_request
// differs: a connect's destination and an open's path stay exact, and the list still cuts a long target that detail
// serves whole.
func TestBrokerNeverServesRawTarget(t *testing.T) {
	w := newWireBroker(t, nil)
	const canary = "CANARY-7f3a"
	longPath := "/srv/data/" + strings.Repeat("d", 200) + "/report.csv"
	cases := []struct {
		req  ask.Request
		want string
	}{
		{ask.Request{Op: "http_request", Target: "api.example.com POST /v1/messages?token=" + canary + "&x=1", Rule: "net.ask[0]", Hold: "request", PID: 4242, TID: 4243},
			"api.example.com POST /v1/messages?redacted"},
		{ask.Request{Op: "http_request", Target: "api.example.com GET /v1/private/" + canary + "?q=" + canary, Rule: "net.ask[1]", Hold: "request", PID: 4242, TID: 4243},
			"api.example.com GET /redacted?redacted"},
		{connectReq("10.0.0.7:443"), "10.0.0.7:443"},
		{ask.Request{Op: "open", Target: longPath, Rule: "fs.ask[0]", Hold: ask.HoldOpen, PID: 4242, TID: 4243}, longPath},
	}
	ids := map[string]string{} // ask id -> the target clients are shown
	var dones []<-chan ask.Decision
	for _, c := range cases {
		id, done := w.hold(t, c.req)
		ids[id] = c.want
		dones = append(dones, done)
	}
	var phases []wirePhase
	ctx := context.Background()
	w.tap.record(&phases, "list", nil, func() (any, error) { return ask.ListFor(ctx, w.tap.dir, os.Getpid()) })
	for id := range ids {
		w.tap.record(&phases, "detail "+id, nil, func() (any, error) { return ask.DetailFor(ctx, w.tap.dir, os.Getpid(), id) })
	}
	for _, p := range phases {
		for _, f := range p.Frames {
			if strings.Contains(f.Data, canary) {
				t.Fatalf("%s: the broker sent %s, which holds the raw target", p.Name, f.Data)
			}
		}
	}
	list, err := ask.ListFor(ctx, w.dir, os.Getpid())
	if err != nil || len(list) != len(cases) {
		t.Fatalf("list %v %v", list, err)
	}
	for _, s := range list {
		want := ids[s.AskID]
		if s.TargetTruncated != (len(want) > 128) || !strings.HasPrefix(want, s.Target) || (!s.TargetTruncated && s.Target != want) {
			t.Errorf("listed %s as %q (truncated %v); want %q", s.AskID, s.Target, s.TargetTruncated, want)
		}
		d, err := ask.DetailFor(ctx, w.dir, os.Getpid(), s.AskID)
		if err != nil || d.Target != want {
			t.Errorf("detail of %s: %q %v; want %q", s.AskID, d.Target, err, want)
		}
	}
	for id := range ids {
		if _, err := ask.AnswerFor(ctx, w.dir, os.Getpid(), id, false, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range dones {
		settle(t, d)
	}
}

// TestBrokerReadsThePeerAtThePacket: Authorize is given the peer as peer.Identify read it, its cgroup and cgroup
// namespace with its pid and uid, once at the connect and again once the packet is in, so a process that moved after
// its connect is judged where it is. The test stands in for the packet's reading (ask.SwapIdentify): a cgroup that
// differs from the connect's must be the one Authorize sees there, and a different start time, another process
// under the writer's pid, is refused before Authorize. Every refusal at the packet leaves the ask pending. Reusing
// the connect's reading at the packet fails both.
func TestBrokerReadsThePeerAtThePacket(t *testing.T) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	self, err := runscope.Unified(b)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &st); err != nil {
		t.Fatal(err)
	}
	moved := strings.TrimSuffix(self, "/") + "/moved-after-connect.scope"
	var mu sync.Mutex
	var seen []ask.Peer
	refuseAt := 0                                       // the Authorize call that refuses, 0 for none
	identified := 0                                     // identify calls in this exchange
	var alter func(ask.Peer, uint64) (ask.Peer, uint64) // what the packet's reading (the second) becomes, nil for as read
	// Registered before the broker is made, so it runs after the broker's close has stopped its handlers.
	t.Cleanup(ask.SwapIdentify(func(real ask.IdentifyFunc) ask.IdentifyFunc {
		return func(c *net.UnixConn) (ask.Peer, uint64, error) {
			p, started, err := real(c)
			mu.Lock()
			defer mu.Unlock()
			identified++
			if identified == 2 && alter != nil && err == nil {
				p, started = alter(p, started)
			}
			return p, started, err
		}
	}))
	w := newWireBroker(t, func(o *ask.Options) {
		o.Authorize = func(p ask.Peer) error {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, p)
			if len(seen) == refuseAt || p.Cgroup == moved {
				return errors.New("refused by the test")
			}
			return nil
		}
	})
	id, done := w.hold(t, connectReq("10.0.0.8:443"))
	// exchange answers id once with the packet's reading changed by change and returns every peer Authorize saw.
	exchange := func(change func(ask.Peer, uint64) (ask.Peer, uint64), refuse int) ([]ask.Peer, error) {
		mu.Lock()
		seen, refuseAt, identified, alter = nil, refuse, 0, change
		mu.Unlock()
		_, err := ask.AnswerFor(context.Background(), w.dir, os.Getpid(), id, true, false)
		mu.Lock()
		defer mu.Unlock()
		got := append([]ask.Peer(nil), seen...)
		seen, refuseAt, identified, alter = nil, 0, 0, nil
		return got, err
	}
	stillPending := func(after string) {
		t.Helper()
		list, err := ask.ListFor(context.Background(), w.dir, os.Getpid())
		if err != nil || len(list) != 1 || list[0].AskID != id {
			t.Fatalf("after %s the broker lists %v %v; want %s still pending", after, list, err, id)
		}
	}
	wantPeer := func(i int, p ask.Peer, cgroup string) {
		t.Helper()
		if p.PID != os.Getpid() || p.UID != uint32(os.Getuid()) || p.Cgroup != cgroup || p.CgroupNS != st.Ino {
			t.Errorf("call %d had peer %+v; want pid %d uid %d cgroup %q namespace %d", i, p, os.Getpid(), os.Getuid(), cgroup, st.Ino)
		}
	}

	got, err := exchange(nil, 2)
	if !errors.Is(err, ask.ErrUnauthorized) {
		t.Fatalf("an answer refused at its packet came to %v; want unauthorized", err)
	}
	if len(got) != 2 {
		t.Fatalf("Authorize was called %d times for one exchange; want at the connect and at the packet: %+v", len(got), got)
	}
	for i, p := range got {
		wantPeer(i, p, self)
	}
	stillPending("an answer refused at its packet")

	got, err = exchange(func(p ask.Peer, started uint64) (ask.Peer, uint64) { p.Cgroup = moved; return p, started }, 0)
	if !errors.Is(err, ask.ErrUnauthorized) {
		t.Fatalf("an answer from a writer that moved to %s after its connect came to %v; want unauthorized", moved, err)
	}
	if len(got) != 2 {
		t.Fatalf("Authorize was called %d times for a writer that moved; want 2: %+v", len(got), got)
	}
	wantPeer(0, got[0], self)
	wantPeer(1, got[1], moved) // the connect's reading here means the packet was not read again
	stillPending("an answer from a writer that moved")

	got, err = exchange(func(p ask.Peer, started uint64) (ask.Peer, uint64) { return p, started + 1 }, 0)
	if !errors.Is(err, ask.ErrUnauthorized) {
		t.Fatalf("an answer whose writer's pid has a new start time at the packet came to %v; want unauthorized", err)
	}
	if len(got) != 1 {
		t.Fatalf("Authorize was called %d times for a writer with a new start time; want only at the connect: %+v", len(got), got)
	}
	stillPending("an answer from a new process under the writer's pid")

	if _, err := exchange(nil, 0); err != nil {
		t.Fatal(err)
	}
	settle(t, done)
}
