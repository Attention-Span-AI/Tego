// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func testQuery(t *testing.T, name string, typ dnsmessage.Type, id uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func testResponse(raw []byte, tc bool) []byte {
	var q dnsmessage.Message
	if q.Unpack(raw) != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, Truncated: tc}, Questions: q.Questions}
	if !tc {
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 17}}}}
	}
	b, _ := m.Pack()
	return b
}

type fixture struct {
	address  netip.AddrPort
	udp      *net.UDPConn
	tcp      *net.TCPListener
	calls    atomic.Int32
	tcpCalls atomic.Int32
	wg       sync.WaitGroup
}

func newFixture(t *testing.T, reply func([]byte) [][]byte) *fixture {
	t.Helper()
	var u *net.UDPConn
	var tcp *net.TCPListener
	var err error
	// TCP and UDP have independent port namespaces. Reserve TCP first so old
	// TCP TIME_WAITs cannot collide with a UDP-selected ephemeral port; a UDP
	// collision still requires a fresh pair rather than weakening fallback.
	for i := 0; i < 32; i++ {
		tcp, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		u, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcp.Addr().(*net.TCPAddr).Port})
		if err == nil {
			break
		}
		_ = tcp.Close()
		if !errors.Is(err, unix.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	if err != nil {
		t.Fatalf("reserve a shared TCP/UDP fixture port: %v", err)
	}
	f := &fixture{address: u.LocalAddr().(*net.UDPAddr).AddrPort(), udp: u, tcp: tcp}
	f.wg.Add(2)
	go func() {
		defer f.wg.Done()
		for {
			raw := make([]byte, MaxPacket+1)
			n, from, e := u.ReadFromUDP(raw)
			if e != nil {
				return
			}
			f.calls.Add(1)
			for _, out := range reply(raw[:n]) {
				_, _ = u.WriteToUDP(out, from)
			}
		}
	}()
	go func() {
		defer f.wg.Done()
		for {
			c, e := tcp.AcceptTCP()
			if e != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var header [2]byte
				if _, e := io.ReadFull(c, header[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header[:]))
				if n > MaxPacket {
					return
				}
				raw := make([]byte, n)
				if _, e := io.ReadFull(c, raw); e != nil {
					return
				}
				f.tcpCalls.Add(1)
				out := testResponse(raw, false)
				binary.BigEndian.PutUint16(header[:], uint16(len(out)))
				_, _ = c.Write(append(header[:], out...))
			}()
		}
	}()
	t.Cleanup(func() { u.Close(); tcp.Close(); f.wg.Wait() })
	return f
}
func testBroker(t *testing.T, f *fixture, mutate func(*Options)) (*Broker, string) {
	t.Helper()
	policy, err := dnspolicy.Compile([]string{"allowed.example"}, []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{UID: uint32(os.Geteuid()), Policy: policy, Upstreams: []netip.AddrPort{f.address}, MaxParallel: 2, Cache: 8, Timeout: time.Second, Authorize: func(p Peer) error {
		if p.PID != os.Getpid() {
			return ErrUnauthorized
		}
		return nil
	}}
	if mutate != nil {
		mutate(&opts)
	}
	dir := t.TempDir()
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

// Use the held-directory spelling used by Exchange, including with long TMPDIRs.
func dialTestBroker(dirName string) (*net.UnixConn, error) {
	dir, path, err := openSocketDir(dirName)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
}

func TestBrokerLedgerDecisionFailureDoesNotDispatch(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	_, dir := testBroker(t, f, func(o *Options) {
		o.Emit = func(Event) error { return errors.New("ledger unavailable") }
	})
	if _, err := Exchange(context.Background(), dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)); err == nil {
		t.Fatal("unrecorded decision answered")
	}
	if f.calls.Load() != 0 {
		t.Fatalf("unrecorded decision dispatched %d upstream queries", f.calls.Load())
	}
}

func TestBrokerLedgerCompletionFailureWithholdsAlreadyDispatchedReply(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	var decisions, completions atomic.Int32
	_, dir := testBroker(t, f, func(o *Options) {
		o.Emit = func(e Event) error {
			if e.Phase == PhaseDecision {
				decisions.Add(1)
				return nil
			}
			completions.Add(1)
			return errors.New("ledger unavailable after dispatch")
		}
	})
	if _, err := Exchange(context.Background(), dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)); err == nil {
		t.Fatal("unrecorded completion answered")
	}
	if f.calls.Load() != 1 || decisions.Load() != 1 || completions.Load() != 1 {
		t.Fatalf("dispatch/decision/completion=%d/%d/%d", f.calls.Load(), decisions.Load(), completions.Load())
	}
}

func TestActualBrokerPolicyAuthenticationAndCache(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	var events []Event
	var mu sync.Mutex
	b, dir := testBroker(t, f, func(o *Options) {
		o.Emit = func(e Event) error { mu.Lock(); events = append(events, e); mu.Unlock(); return nil }
	})
	query := testQuery(t, "allowed.example.", dnsmessage.TypeA, 0x1234)
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint16(query, uint16(i+10))
		raw, err := Exchange(context.Background(), dir, os.Getpid(), query)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if m.Unpack(raw) != nil || m.ID != uint16(i+10) || len(m.Answers) != 1 {
			t.Fatalf("wrong real response %+v", m)
		}
	}
	if f.calls.Load() != 1 {
		t.Fatalf("cache did not suppress second upstream: %d", f.calls.Load())
	}
	for _, q := range [][]byte{testQuery(t, "forbidden.example.", dnsmessage.TypeA, 50), testQuery(t, "allowed.example.", dnsmessage.TypeTXT, 51)} {
		raw, err := Exchange(context.Background(), dir, os.Getpid(), q)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		_ = m.Unpack(raw)
		if m.RCode != dnsmessage.RCodeRefused {
			t.Fatalf("query policy reply=%+v", m)
		}
	}
	if f.calls.Load() != 1 {
		t.Fatal("denied query reached upstream")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 6 || events[0].Phase != PhaseDecision || events[1].Phase != PhaseCompletion || !events[0].Allowed || events[1].Cached || !events[3].Cached || events[4].Allowed || events[5].Allowed || events[0].Peer.PID != os.Getpid() {
		t.Fatalf("event identity/verdict mismatch %+v", events)
	}
	st, err := os.Lstat(b.Endpoint())
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions %v %v", st, err)
	}
}

func TestBrokerRejectsSameUIDWrongGovernedPeerAndWrongServer(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	_, dir := testBroker(t, f, func(o *Options) { o.Authorize = func(Peer) error { return ErrUnauthorized } })
	q := testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)
	if _, err := Exchange(context.Background(), dir, os.Getpid(), q); err == nil {
		t.Fatal("same UID bypassed governed callback")
	}
	if _, err := Exchange(context.Background(), dir, os.Getpid()+1, q); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong server PID admitted: %v", err)
	}
	if f.calls.Load() != 0 {
		t.Fatal("unauthorized query delivered")
	}
}

func TestBrokerVerifiesUpstreamIDQuestionAndTCPFallback(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte {
		wrongID := testResponse(raw, false)
		binary.BigEndian.PutUint16(wrongID, binary.BigEndian.Uint16(raw)+1)
		wrongQuestion := testQuery(t, "foreign.example.", dnsmessage.TypeA, binary.BigEndian.Uint16(raw))
		wrongQuestion = testResponse(wrongQuestion, false)
		return [][]byte{wrongID, wrongQuestion, testResponse(raw, true)}
	})
	_, dir := testBroker(t, f, nil)
	raw, err := Exchange(context.Background(), dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 93))
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	_ = m.Unpack(raw)
	if m.ID != 93 || m.Truncated || len(m.Answers) != 1 || f.tcpCalls.Load() != 1 {
		t.Fatalf("unverified/fallback response %+v tcp=%d", m, f.tcpCalls.Load())
	}
}

func TestBrokerRejectsAmbiguousOversizedAndRightsPackets(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	_, dir := testBroker(t, f, nil)
	query := testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, tc := range []struct {
		label    string
		raw, oob []byte
	}{{"trailing", append(append([]byte(nil), query...), 0), nil}, {"oversized", make([]byte, MaxPacket+1), nil}, {"rights", query, unix.UnixRights(int(file.Fd()))}} {
		t.Run(tc.label, func(t *testing.T) {
			c, err := dialTestBroker(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			if _, _, err = c.WriteMsgUnix(tc.raw, tc.oob, nil); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, MaxPacket)
			if n, _, _, _, err := c.ReadMsgUnix(buf, nil); err == nil && n != 0 {
				t.Fatalf("bad packet answered %q", buf[:n])
			}
		})
	}
	if f.calls.Load() != 0 {
		t.Fatal("bad packet delivered upstream")
	}
}

func TestBrokerPassedConnectedClientCannotImpersonateConnector(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	_, dir := testBroker(t, f, func(o *Options) { o.Authorize = func(Peer) error { return nil } })
	c, err := dialTestBroker(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fd, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPassedDNSClientHelper$")
	cmd.ExtraFiles = []*os.File{fd}
	cmd.Env = append(os.Environ(), "TEGO_PASSED_DNS_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child writer: %v %s", err, out)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, MaxPacket)
	if n, err := c.Read(buf); err == nil && n != 0 {
		t.Fatalf("passed client answer %q", buf[:n])
	}
	if f.calls.Load() != 0 {
		t.Fatal("later socket writer inherited connector credentials")
	}
}
func TestPassedDNSClientHelper(t *testing.T) {
	if os.Getenv("TEGO_PASSED_DNS_HELPER") != "1" {
		return
	}
	_, err := unix.Write(3, testQuery(t, "allowed.example.", dnsmessage.TypeA, 1))
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestBrokerParallelBoundAndCloseCancel(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseUpstream()
	f := newFixture(t, func(raw []byte) [][]byte { close(entered); <-release; return [][]byte{testResponse(raw, false)} })
	b, dir := testBroker(t, f, func(o *Options) { o.MaxParallel = 1; o.Cache = 0 })
	first := make(chan error, 1)
	firstQuery := testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)
	go func() {
		_, e := Exchange(context.Background(), dir, os.Getpid(), firstQuery)
		first <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first query not delivered")
	}
	raw, err := Exchange(context.Background(), dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 2))
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	_ = m.Unpack(raw)
	if m.RCode != dnsmessage.RCodeServerFailure || f.calls.Load() != 1 {
		t.Fatal("parallel ceiling not enforced")
	}
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel outstanding upstream")
	}
	releaseUpstream()
	if err := <-first; err == nil {
		t.Fatal("cancelled query succeeded")
	}
	if _, err := os.Lstat(filepath.Join(dir, SocketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed: %v", err)
	}
}

func TestBrokerCacheAgesTTLAndExpires(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	b, dir := testBroker(t, f, nil)
	query := testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)
	if _, err := Exchange(context.Background(), dir, os.Getpid(), query); err != nil {
		t.Fatal(err)
	}
	key := string(query[2:])
	b.mu.Lock()
	entry := b.cache[key]
	entry.stored = time.Now().Add(-1500 * time.Millisecond)
	b.cache[key] = entry
	b.mu.Unlock()
	raw, err := Exchange(context.Background(), dir, os.Getpid(), query)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	_ = m.Unpack(raw)
	if m.Answers[0].Header.TTL > 28 || f.calls.Load() != 1 {
		t.Fatalf("cached TTL did not age: %+v", m.Answers)
	}
	b.mu.Lock()
	entry = b.cache[key]
	entry.expires = time.Now().Add(-time.Millisecond)
	b.cache[key] = entry
	b.mu.Unlock()
	if _, err := Exchange(context.Background(), dir, os.Getpid(), query); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 2 {
		t.Fatal("expired cache remained active")
	}
}

func TestBrokerPreservesReplacementSocketPathOnClose(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	b, dir := testBroker(t, f, nil)
	path := filepath.Join(dir, SocketName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "replacement" {
		t.Fatalf("foreign replacement changed %q %v", raw, err)
	}
}

func TestBrokerRequiresAuthenticationAndRejectsMalformedQuestions(t *testing.T) {
	policy, _ := dnspolicy.Compile(nil, nil)
	if _, err := New(t.TempDir(), Options{Policy: policy, Upstreams: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}}); err == nil {
		t.Fatal("missing governed authorization accepted")
	}
	q := testQuery(t, "allowed.example.", dnsmessage.TypeA, 1)
	for i, raw := range [][]byte{append(append([]byte(nil), q...), 0), q[:11], make([]byte, MaxPacket+1)} {
		if _, err := queryMessage(raw); !errors.Is(err, ErrProtocol) {
			t.Fatal(strconv.Itoa(i), err)
		}
	}
	var m dnsmessage.Message
	_ = m.Unpack(q)
	m.Questions = append(m.Questions, m.Questions[0])
	raw, _ := m.Pack()
	if _, err := queryMessage(raw); err == nil {
		t.Fatal("multiple questions accepted")
	}
	m.Questions = m.Questions[:1]
	m.Questions[0].Class = dnsmessage.ClassCHAOS
	raw, _ = m.Pack()
	if _, err := queryMessage(raw); err == nil {
		t.Fatal("non-IN query accepted")
	}
	reserved := append([]byte(nil), q...)
	reserved[3] |= 0x40
	if _, err := queryMessage(reserved); err == nil {
		t.Fatal("reserved header flag accepted")
	}
}

func TestBrokerBoundedTimeoutAndResolverFailover(t *testing.T) {
	silent := newFixture(t, func([]byte) [][]byte { return nil })
	healthy := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	_, dir := testBroker(t, healthy, func(o *Options) {
		o.Upstreams = []netip.AddrPort{silent.address, healthy.address}
		o.Timeout = 200 * time.Millisecond
		o.Cache = 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := Exchange(ctx, dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 1))
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	_ = m.Unpack(raw)
	if len(m.Answers) != 1 || silent.calls.Load() != 1 || healthy.calls.Load() != 1 {
		t.Fatalf("resolver fallback missing: %+v calls%d/%d", m, silent.calls.Load(), healthy.calls.Load())
	}
	_, deadDir := testBroker(t, silent, func(o *Options) { o.Timeout = 50 * time.Millisecond; o.Cache = 0 })
	start := time.Now()
	raw, err = Exchange(ctx, deadDir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 2))
	m = dnsmessage.Message{}
	if err != nil || m.Unpack(raw) != nil || m.RCode != dnsmessage.RCodeServerFailure || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("silent upstream was not bounded by a SERVFAIL: %v rcode %v elapsed%v", err, m.RCode, time.Since(start))
	}
}

// One deadline bounds a request from the handler's start: an upstream that does not answer within it gets the
// client a SERVFAIL, not a dropped connection, and what the completion event records is what the client
// receives. The exchange used to get a fresh Timeout after the decision was recorded while the connection kept
// the one set at the handler's start, so a silent upstream left the client with EOF, and an answer arriving
// past the connection's deadline was recorded as completed but never written.
func TestBrokerUpstreamTimeoutRepliesWithinOneRequestDeadline(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision time.Duration // how long recording the decision takes
		answer   time.Duration // how long the upstream takes; < 0: never
	}{{"silent upstream", 0, -1}, {"answer past the handler's deadline", 150 * time.Millisecond, 100 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(raw []byte) [][]byte {
				if tc.answer < 0 {
					return nil
				}
				time.Sleep(tc.answer)
				return [][]byte{testResponse(raw, false)}
			})
			var mu sync.Mutex
			var completion *Event
			_, dir := testBroker(t, f, func(o *Options) {
				o.Timeout, o.Cache = 200*time.Millisecond, 0
				o.Emit = func(e Event) error {
					if e.Phase == PhaseDecision {
						time.Sleep(tc.decision)
						return nil
					}
					mu.Lock()
					completion = &e
					mu.Unlock()
					return nil
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			raw, err := Exchange(ctx, dir, os.Getpid(), testQuery(t, "allowed.example.", dnsmessage.TypeA, 7))
			if err != nil {
				t.Fatalf("no reply after %v: %v", time.Since(start), err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("reply not bounded: %v", elapsed)
			}
			var m dnsmessage.Message
			if err := m.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if completion == nil || (completion.Error == "") != (m.RCode == dnsmessage.RCodeSuccess) {
				t.Fatalf("completion %+v recorded, client received rcode %v", completion, m.RCode)
			}
			if m.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("answer outside the request's deadline delivered: rcode %v", m.RCode)
			}
		})
	}
}

// No descriptor is not a live process: poll(2) skips a negative fd and reports nothing ready, which read as
// alive, so with RelayPID 0 (relayPIDFD -1) the relay exception admitted a peer whose credentials read pid 0
// as far as pidfd_open.
func TestPidfdAliveRefusesNoDescriptor(t *testing.T) {
	if pidfdAlive(-1) {
		t.Fatal("pidfdAlive(-1) reports a live process")
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	defer unix.Close(fd)
	if !pidfdAlive(fd) {
		t.Fatal("pidfdAlive reports this live process dead")
	}
}

func TestBrokerListenerLossIsRuntimeFailure(t *testing.T) {
	f := newFixture(t, func(raw []byte) [][]byte { return [][]byte{testResponse(raw, false)} })
	b, _ := testBroker(t, f, nil)
	if err := b.listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Run(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost listener stayed active: %v", err)
	}
}
