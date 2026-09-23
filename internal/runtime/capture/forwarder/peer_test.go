// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// anyPeer is the admission a case uses when its subject is not admission: the golden line freezes a
// cgroup id no process is in, and a benchmark measures the forwarding path. Everything else dials from a
// process the harness places in the run, so R19a's real admitter runs on it.
func anyPeer(_, _ netip.AddrPort, _ uint64) (int, error) { return 0, nil }

// serveDirect drives the handler for a request that has no connection behind it, with R19a's admission
// already decided in its favour. A direct ServeHTTP call presents no peer — httptest.NewRequest invents a
// RemoteAddr and there is no accepted socket to read a local address from — so a case about what the
// handler does after the door has to say that the door was open. The verdict is the one the server's own
// ConnContext would have attached, resolved to "admitted". It returns once what the handler emitted has
// reached the sink, which the listener's emit queue does off the handler's path (I1).
func serveDirect(l *Listener, w http.ResponseWriter, r *http.Request) {
	v := &peerVerdict{}
	v.once.Do(func() {}) // decided, and decided nil: this peer is the run's
	l.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerVerdictKey{}, v)))
	l.emitq.flush(5 * time.Second)
}

// foreignCgroupID is larger than any kernfs inode number a cgroup directory is given, so a run carrying
// it is a run no process on this machine is in.
const foreignCgroupID = uint64(1) << 62

// liveCgroupID is the cgroup the test process itself is in — the one a connection opened from this
// process has to be placed in for R19a to admit it.
func liveCgroupID() (uint64, error) {
	mount, err := cgroup2Mount()
	if err != nil {
		return 0, err
	}
	p, err := procCgroupPath(os.Getpid())
	if err != nil {
		return 0, err
	}
	return cgroupIDOf(mount + p)
}

// newPeerListener is one listener serving a run whose cgroup the caller chooses, with R19a's admission in
// place unless peers replaces it. Only the upstream is faked: the connection, the kernel's tcp table and
// the cgroup walk are real, because they are what is under test. An admitter is passed in rather than
// assigned afterwards because Serve is already reading it by then.
func newPeerListener(t *testing.T, run source.RunRef, peers peerAdmitter) (*Listener, *fakeSink) {
	t.Helper()
	l, err := NewListener(
		agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		Options{
			Clock: newClock(),
			Rand:  &countingRand{},
			Transport: &cannedTransport{status: http.StatusOK, body: `{"ok":true}`,
				header: http.Header{"Content-Type": {"application/json"}}},
			Bodies: true,
		})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	if peers != nil {
		l.peers = peers
	}
	sink := &fakeSink{}
	l.Bind(run, sink)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return l, sink
}

// A process that is not in the run's cgroup is refused, and nothing it sent reaches the run's
// ledger or the upstream (R19a). This is the CVE-2025-52882 shape: the port is loopback, so any process
// on the host — and any page in the developer's browser, by a POST that is never preflighted — can reach
// it, and before this check every one of them could append an ssl_request the agent never made.
func TestForwarderRefusesAPeerOutsideTheRunCgroup(t *testing.T) {
	run := testRun
	run.CgroupID = foreignCgroupID
	l, sink := newPeerListener(t, run, nil)

	resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-5","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a peer outside the run (R19a)", resp.StatusCode)
	}
	if got := sink.of(record.KindSSLRequest); len(got) != 0 {
		t.Errorf("%d ssl_request events from a peer outside the run: the ledger is authenticated as to"+
			" ordering, not as to origin, so a forged line stays forged", len(got))
	}
	if n := l.refused.Load(); n != 1 {
		t.Errorf("refused = %d, want 1", n)
	}
}

// The health check R22 answers locally is behind the same door. It contacts no upstream, but it
// is still the listener telling a caller it does not know that the run exists and is alive.
func TestForwarderRefusesAForeignPeerOnTheHealthCheck(t *testing.T) {
	run := testRun
	run.CgroupID = foreignCgroupID
	l, _ := newPeerListener(t, run, nil)

	req, err := http.NewRequest(http.MethodHead, l.BaseURL()+HelloPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (R19a before R22)", resp.StatusCode)
	}
}

// A run whose cgroup id is unknown can place no peer in it, so it serves none. The listener
// fails closed: an admission that cannot be decided is a refusal, never a pass.
func TestForwarderRefusesEveryPeerWhenTheRunHasNoCgroup(t *testing.T) {
	run := testRun
	run.CgroupID = 0
	l, _ := newPeerListener(t, run, nil)

	resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when the run has no cgroup id to place a peer in", resp.StatusCode)
	}
}

// The other half of the rule — a process that is in the run's cgroup is served. Without it the
// refusal above would be satisfied by a check that refuses everything, which would take the run's own
// agent with it.
func TestForwarderServesAPeerInTheRunCgroup(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	run := testRun
	run.CgroupID = id
	l, sink := newPeerListener(t, run, nil)

	resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-5","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the test process is in the run's cgroup", resp.StatusCode)
	}
	if n := l.refused.Load(); n != 0 {
		t.Errorf("refused = %d, want 0", n)
	}
	sink.waitFor(t, record.KindSSLRequest, 1)
}

// A refusal is not a capture gap. Nothing of the agent's own traffic was missed, and the run's
// gap report is coverage — the mirror of R38, where a forwarder bypass is enforce's refusal rather than
// capture's shortfall.
func TestRefusedPeerIsNotACaptureGap(t *testing.T) {
	run := testRun
	run.CgroupID = foreignCgroupID
	l, sink := newPeerListener(t, run, nil)

	resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if gaps := l.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: a peer turned away is not lost coverage", gaps)
	}
	if got := sink.of(record.KindGap); len(got) != 0 {
		t.Errorf("%d gap events for a refused peer, want none", len(got))
	}
}

// Admission is decided once per connection, not once per request. The walk reads /proc, and a
// keep-alive connection carries a whole conversation.
func TestPeerAdmissionIsDecidedOncePerConnection(t *testing.T) {
	var calls atomic.Int64
	l, _ := newPeerListener(t, testRun, func(_, _ netip.AddrPort, _ uint64) (int, error) {
		calls.Add(1)
		return 0, nil
	})
	client := &http.Client{}
	for i := range 3 {
		resp, err := client.Post(l.BaseURL()+"/v1/messages", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		// The body has to be read to EOF and closed for the connection to go back to the pool; a new
		// connection per request would make this assertion meaningless.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d admissions for 3 requests on one connection, want 1", n)
	}
}

// A handler reached without the server's accept path has no cached verdict and must still be
// asked, never waved through.
func TestPeerAdmissionWithoutAConnectionVerdict(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com"}, Options{})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.Bind(testRun, &fakeSink{})
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:1/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:34567"
	if _, err := l.admitPeer(req); !errors.Is(err, ErrPeer) {
		t.Errorf("err = %v, want ErrPeer for a request with no connection behind it", err)
	}
}

// The kernel's tcp table is read the way the kernel writes it. The rows are real ones from this
// machine's /proc/net/tcp and /proc/net/tcp6: the address is the in-memory image of a __be32 printed with
// %08X, so 0100007F is 127.0.0.1 and the v6 groups are four such words in order; the port is big-endian.
func TestParseProcAddrPort(t *testing.T) {
	tests := []struct {
		cell string
		want string
		ok   bool
	}{
		{"0100007F:0277", "127.0.0.1:631", true},
		{"0100007F:A515", "127.0.0.1:42261", true},
		{"00000000:0000", "0.0.0.0:0", true},
		{"3500007F:0035", "127.0.0.53:53", true},
		{"00000000000000000000000001000000:0277", "[::1]:631", true},
		{"0000000000000000FFFF00000100007F:01BB", "127.0.0.1:443", true}, // v4-mapped, unwrapped
		{"0100007F", "", false},                                          // no port
		{"0100007:0277", "", false},                                      // truncated address
		{"zzzzzzzz:0277", "", false},
		{"0100007F:zzzz", "", false},
	}
	for _, tc := range tests {
		got, ok := parseProcAddrPort(tc.cell)
		if ok != tc.ok {
			t.Errorf("parseProcAddrPort(%q) ok = %v, want %v", tc.cell, ok, tc.ok)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("parseProcAddrPort(%q) = %s, want %s", tc.cell, got, tc.want)
		}
	}
}

// The peer's row is the one whose local address is the peer and whose remote address is the
// listener. The listener's own accepted socket is the same pair reversed, and picking it would name this
// process as the peer of every connection — which would admit everything.
func TestScanTCPTablePicksThePeerSide(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A515 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:A515 0100007F:C0DE 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C0DE 0100007F:A515 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 100 0 0 10 0
`
	listener := netip.MustParseAddrPort("127.0.0.1:42261") // A515
	peer := netip.MustParseAddrPort("127.0.0.1:49374")     // C0DE
	inode, found, err := scanTCPTable(strings.NewReader(table), peer, listener)
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	if inode != 333 {
		t.Errorf("inode = %d, want 333 (the peer's own socket, not the listener's)", inode)
	}
	if _, found, err := scanTCPTable(strings.NewReader(table), listener, peer); err != nil {
		t.Fatalf("err = %v", err)
	} else if !found {
		t.Error("the reversed pair is the listener's own row and should still be found by its own key")
	}
	absent := netip.MustParseAddrPort("127.0.0.1:1")
	if _, found, err := scanTCPTable(strings.NewReader(table), absent, listener); err != nil || found {
		t.Errorf("found = %v, err = %v for a connection that is not in the table", found, err)
	}
}

// The cgroup2 mount point comes from the fixed columns on the left of mountinfo's " - "
// separator, because the optional fields before it are variable in number; the filesystem type comes from
// the right of it. A mount point with a space in it is octal-escaped by the kernel.
func TestParseCgroup2Mount(t *testing.T) {
	const mountinfo = `25 30 0:24 / /sys/fs/cgroup/unified rw,nosuid - cgroup rw,name=systemd
8:44 42 0:29 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate
`
	got, ok := parseCgroup2Mount(mountinfo)
	if !ok || got != "/sys/fs/cgroup" {
		t.Errorf("parseCgroup2Mount = %q, %v, want /sys/fs/cgroup", got, ok)
	}
	if _, ok := parseCgroup2Mount("25 30 0:24 / /proc rw - proc proc rw\n"); ok {
		t.Error("a machine with no cgroup2 mount reported one")
	}
	const escaped = `8:44 42 0:29 / /sys/fs/my\040cgroup rw shared:7 - cgroup2 cgroup2 rw
`
	if got, _ := parseCgroup2Mount(escaped); got != "/sys/fs/my cgroup" {
		t.Errorf("escaped mount point = %q", got)
	}
}

// BenchmarkPeerAdmission measures what R19a costs one new connection, with the run already holding sockets=N
// others open: the verdict is cached for the life of a connection, which is why it is measured on its own rather
// than folded into BenchmarkForward's per-request number (§9 Benchmarks). Each iteration is a connection of its
// own — dialled, admitted, closed — so a descriptor number the kernel hands out again is part of what is measured.
func BenchmarkPeerAdmission(b *testing.B) {
	id, err := liveCgroupID()
	if err != nil {
		b.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	for _, open := range []int{0, 1000, 4000} {
		b.Run("sockets="+strconv.Itoa(open), func(b *testing.B) {
			ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			held := make([]net.Conn, 0, 2*open)
			defer func() {
				for _, c := range held {
					_ = c.Close()
				}
			}()
			pair := func() (net.Conn, net.Conn) {
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				accepted, err := ln.Accept()
				if err != nil {
					b.Fatal(err)
				}
				return conn, accepted
			}
			for range open {
				c, a := pair()
				held = append(held, c, a)
			}
			admit := newProcAdmitter()
			b.ReportAllocs()
			for b.Loop() {
				conn, accepted := pair()
				peer := netip.MustParseAddrPort(accepted.RemoteAddr().String())
				local := netip.MustParseAddrPort(accepted.LocalAddr().String())
				if _, err := admit.admit(peer, local, id); err != nil {
					b.Fatalf("the peer of a live connection from this process was refused: %v", err)
				}
				admit.forget(peer, local)
				_ = conn.Close()
				_ = accepted.Close()
			}
		})
	}
}
