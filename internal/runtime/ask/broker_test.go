// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testBroker(t *testing.T, mutate func(*Options)) (*Broker, string) {
	t.Helper()
	dir := t.TempDir()
	opts := Options{UID: uint32(os.Getuid()), Timeout: time.Second, Authorize: func(Peer) error { return nil }, Emit: func(Event) error { return nil }}
	if mutate != nil {
		mutate(&opts)
	}
	b, err := New(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	return b, dir
}
func testRequest() Request {
	return Request{Op: "connect", Target: "127.0.0.1:443", Rule: "net.ask[0]", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()}
}
func waitAsk(t *testing.T, dir string) Summary {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		items, err := ListFor(context.Background(), dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 1 {
			return items[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request not published")
	return Summary{}
}
func TestBrokerRecordsBeforeApprovalAndSingleWinner(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	b, dir := testBroker(t, func(o *Options) {
		o.Emit = func(e Event) error { mu.Lock(); events = append(events, e); mu.Unlock(); return nil }
	})
	done := make(chan Decision, 1)
	go func() {
		d, e := b.Request(context.Background(), testRequest())
		if e != nil {
			t.Error(e)
		}
		done <- d
	}()
	id := waitAsk(t, dir).AskID
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			d, e := AnswerFor(context.Background(), dir, os.Getpid(), id, true, false)
			if e == nil && d.Approved {
				winners.Add(1)
			} else if !errors.Is(e, ErrNotPending) {
				t.Errorf("answer: %v", e)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
	if d := <-done; !d.Approved || d.AskID != id {
		t.Fatalf("decision %+v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0].Kind != "ask" || events[1].Kind != "answer" || !events[1].Decision.Approved {
		t.Fatalf("events %+v", events)
	}
}
func TestBrokerTimeoutCancelCloseAndQueue(t *testing.T) {
	for _, which := range []string{"timeout", "cancel", "close"} {
		t.Run(which, func(t *testing.T) {
			b, dir := testBroker(t, func(o *Options) { o.Timeout = 50 * time.Millisecond; o.MaxPending = 1 })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan Decision, 1)
			go func() {
				d, e := b.Request(ctx, testRequest())
				if e != nil {
					t.Error(e)
				}
				done <- d
			}()
			waitAsk(t, dir)
			if _, e := b.Request(ctx, testRequest()); !errors.Is(e, ErrUnavailable) {
				t.Fatalf("queue admission: %v", e)
			}
			switch which {
			case "cancel":
				cancel()
			case "close":
				if e := b.Close(); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case d := <-done:
				if d.Approved || d.Reason == "" {
					t.Fatalf("decision %+v", d)
				}
				if which == "timeout" && d.Reason != ReasonTimeout {
					t.Fatalf("reason %s", d.Reason)
				}
			case <-time.After(time.Second):
				t.Fatal("held request did not finish")
			}
		})
	}
}

func TestBrokerOwnerDeadlineRecordsTimeout(t *testing.T) {
	var mu sync.Mutex
	var answer Event
	b, dir := testBroker(t, func(o *Options) {
		o.Timeout = time.Minute
		o.Emit = func(e Event) error {
			if e.Kind == "answer" {
				mu.Lock()
				answer = e
				mu.Unlock()
			}
			return nil
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	type result struct {
		d Decision
		e error
	}
	done := make(chan result, 1)
	go func() { d, e := b.Request(ctx, testRequest()); done <- result{d, e} }()
	id := waitAsk(t, dir).AskID
	select {
	case got := <-done:
		if got.e != nil || got.d.Approved || got.d.AskID != id || got.d.Reason != ReasonTimeout || got.d.By != "timeout" {
			t.Fatalf("owner deadline: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("owner deadline left request held")
	}
	mu.Lock()
	defer mu.Unlock()
	if answer.Decision.AskID != id || answer.Decision.Reason != ReasonTimeout || answer.Decision.By != "timeout" || answer.Decision.Approved {
		t.Fatalf("recorded owner deadline: %+v", answer)
	}
}
func TestBrokerRecordingFailuresNeverAllow(t *testing.T) {
	for _, kind := range []string{"ask", "answer"} {
		t.Run(kind, func(t *testing.T) {
			boom := errors.New("ledger unavailable")
			b, dir := testBroker(t, func(o *Options) {
				o.Emit = func(e Event) error {
					if e.Kind == kind {
						return boom
					}
					return nil
				}
			})
			type result struct {
				d Decision
				e error
			}
			done := make(chan result, 1)
			go func() { d, e := b.Request(context.Background(), testRequest()); done <- result{d, e} }()
			if kind == "answer" {
				id := waitAsk(t, dir).AskID
				if d, e := AnswerFor(context.Background(), dir, os.Getpid(), id, true, false); e == nil || d.Approved {
					t.Fatalf("record failure answered approval: %+v %v", d, e)
				}
			}
			r := <-done
			if r.d.Approved || !errors.Is(r.e, boom) {
				t.Fatalf("result %+v", r)
			}
		})
	}
}

func TestBrokerLostListenerReleasesPendingAndRefusesNewRequests(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = time.Minute })
	done := make(chan Decision, 1)
	go func() {
		d, err := b.Request(t.Context(), testRequest())
		if err != nil {
			t.Error(err)
		}
		done <- d
	}()
	waitAsk(t, dir)
	// Close only the actual listening socket: exercise an accept failure,
	// rather than invoking Broker.Close's explicit shutdown path.
	if err := b.server.listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-done:
		if d.Approved || d.Reason != ReasonUnavailable || d.By != "shutdown" {
			t.Fatalf("lost listener decision %+v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("lost approval listener left the operation held")
	}
	if d, err := b.Request(t.Context(), testRequest()); d.Approved || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost listener accepted new request %+v: %v", d, err)
	}
}
func TestBrokerStrictProtocolAndServerIdentity(t *testing.T) {
	b, dir := testBroker(t, nil)
	_ = b
	if _, e := ListFor(context.Background(), dir, os.Getpid()+1000000); !errors.Is(e, ErrUnauthorized) {
		t.Fatalf("server identity: %v", e)
	}
	for _, data := range []string{`{"action":"list","action":"answer"}`, `{"action":"list","approve":null}`, `{"action":"list","bogus":1}`, `{"action":"answer","ask_id":"q-00000000000000000000000000000000"}`, `{"action":"list"} {}`, `{"action":"list","ask_id":null}`} {
		data = strings.Replace(data, "{", `{"nonce":"00000000000000000000000000000000",`, 1)
		if _, e := decodeCommand([]byte(data)); !errors.Is(e, ErrProtocol) {
			t.Errorf("accepted %s", data)
		}
	}
}
func TestBrokerLongDirectoryAndSocketOwnership(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("a", 80), strings.Repeat("b", 80))
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	opts := Options{UID: uint32(os.Getuid()), Authorize: func(Peer) error { return nil }, Emit: func(Event) error { return nil }}
	b, e := New(dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ListFor(context.Background(), dir, os.Getpid()); e != nil {
		t.Fatal(e)
	}
	if st, e := os.Stat(filepath.Join(dir, SocketName)); e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %v %v", st, e)
	}
	if _, e = New(dir, opts); e == nil {
		t.Fatal("overwrote live socket")
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(filepath.Join(dir, SocketName)); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("socket remains %v", e)
	}
}
func TestBrokerTransferredConnectionAuthenticatesActualWriter(t *testing.T) {
	if os.Getenv("TEGO_ASK_WRITER_CHILD") == "1" {
		f := os.NewFile(3, "inherited-client")
		conn, e := net.FileConn(f)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		_ = f.Close()
		barrier := os.NewFile(4, "barrier")
		var x [1]byte
		if _, e = barrier.Read(x[:]); e != nil {
			t.Fatal(e)
		}
		_ = barrier.Close()
		c := conn.(*net.UnixConn)
		_ = c.SetDeadline(time.Now().Add(time.Second))
		data, _ := json.Marshal(command{Action: "list", Nonce: os.Getenv("TEGO_ASK_WRITER_NONCE")})
		if _, e = c.Write(data); e != nil {
			t.Fatal(e)
		}
		var buf [1024]byte
		n, e := c.Read(buf[:])
		if e != nil {
			t.Fatal(e)
		}
		var r response
		if e = json.Unmarshal(buf[:n], &r); e != nil || r.Code != "unauthorized" {
			t.Fatalf("transferred writer accepted: %s %v", buf[:n], e)
		}
		return
	}
	var forbidden atomic.Int64
	b, dir := testBroker(t, func(o *Options) {
		o.Authorize = func(p Peer) error {
			if int64(p.PID) == forbidden.Load() {
				return ErrUnauthorized
			}
			return nil
		}
	})
	_ = b
	f, path, e := socketDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	ready, e := readResponse(c)
	if e != nil {
		t.Fatal(e)
	}
	passed, e := c.File()
	if e != nil {
		t.Fatal(e)
	}
	defer passed.Close()
	rd, wr, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer rd.Close()
	defer wr.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrokerTransferredConnectionAuthenticatesActualWriter$")
	cmd.Env = append(os.Environ(), "TEGO_ASK_WRITER_CHILD=1", "TEGO_ASK_WRITER_NONCE="+ready.Ready)
	cmd.ExtraFiles = []*os.File{passed, rd}
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	forbidden.Store(int64(cmd.Process.Pid))
	if _, e = wr.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Wait(); e != nil {
		t.Fatalf("child: %v\n%s", e, output.String())
	}
}
func TestBrokerRejectsRightsAndPacketTruncation(t *testing.T) {
	b, dir := testBroker(t, nil)
	_ = b
	f, path, e := socketDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, which := range []string{"rights", "oversized"} {
		t.Run(which, func(t *testing.T) {
			c, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			ready, e := readResponse(c)
			if e != nil {
				t.Fatal(e)
			}
			data, _ := json.Marshal(command{Action: "list", Nonce: ready.Ready})
			var oob []byte
			if which == "rights" {
				rd, wr, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer rd.Close()
				defer wr.Close()
				oob = unix.UnixRights(int(rd.Fd()))
			} else {
				data = []byte(strings.Repeat("x", maxPacket+1))
			}
			if _, _, e = c.WriteMsgUnix(data, oob, nil); e != nil {
				t.Fatal(e)
			}
			var buf [1024]byte
			n, e := c.Read(buf[:])
			if e != nil {
				t.Fatal(e)
			}
			var r response
			if e = json.Unmarshal(buf[:n], &r); e != nil || r.Code != "protocol" {
				t.Fatalf("accepted %s: %s %v", which, buf[:n], e)
			}
		})
	}
}
func TestBrokerMissingCallbacksAndInvalidRequest(t *testing.T) {
	if _, e := New(t.TempDir(), Options{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	b, _ := testBroker(t, nil)
	r := testRequest()
	r.Hold = "bogus"
	if _, e := b.Request(context.Background(), r); !errors.Is(e, ErrProtocol) {
		t.Fatal(e)
	}
	if _, _, e := packetPeer(unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid())}), unix.MSG_CTRUNC); !errors.Is(e, ErrProtocol) {
		t.Fatal(e)
	}
}

// TestValidRequestPairsTheOpenHoldWithAnOpen pins ask-4 at the broker: a file-open approval is held as an
// open (HoldOpen) and only an open is, so neither a file open labelled with a network hold nor a network op
// labelled as an open reaches an approver.
func TestValidRequestPairsTheOpenHoldWithAnOpen(t *testing.T) {
	for _, tc := range []struct {
		op, hold string
		want     bool
	}{
		{"open", HoldOpen, true},
		{"open", "connect", false},
		{"open", "first_write", false},
		{"connect", HoldOpen, false},
		{"connect", "connect", true},
		{"connect", "first_write", true},
		{"http_request", "request", true},
	} {
		r := testRequest()
		r.Op, r.Hold = tc.op, tc.hold
		if got := validRequest(r); got != tc.want {
			t.Errorf("validRequest(op %q, hold %q) = %v, want %v", tc.op, tc.hold, got, tc.want)
		}
	}
}

// TestBrokerAnswerIsRepliedWhenTheRunEndsOnIt is the person's side of a run that ends on its answer: the held
// operation gets the decision, the agent exits, and the run closes the broker at once, before the handler that took
// the answer wrote its reply. The person's `tego deny` must still be told the decision it made, not EOF on a closed
// socket (the flake TestIntegrationTegoInsideADenyListRun showed under load on 2026-10-25), nor the server's
// cancellation when the decision was already taken.
func TestBrokerAnswerIsRepliedWhenTheRunEndsOnIt(t *testing.T) {
	for i := range 50 {
		b, dir := testBroker(t, func(o *Options) { o.Timeout = time.Minute })
		got := make(chan Decision, 1)
		go func() {
			d, _ := b.Request(context.Background(), testRequest())
			_ = b.Close() // the run ends on the decision, as the agent's exit does
			got <- d
		}()
		id := waitAsk(t, dir).AskID
		d, err := AnswerFor(context.Background(), dir, os.Getpid(), id, false, false)
		if err != nil || d.AskID != id || d.Approved || d.Reason != ReasonDenied {
			t.Fatalf("iteration %d: the person's deny was told %+v, %v; want its own refusal of %s", i, d, err, id)
		}
		if held := <-got; held.Approved || held.Reason != ReasonDenied {
			t.Fatalf("iteration %d: the held operation got %+v", i, held)
		}
	}
}
