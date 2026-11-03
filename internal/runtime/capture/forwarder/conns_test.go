// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// helloOn sends one health check on a raw connection and reads its answer, leaving the connection idle and open.
func helloOn(t *testing.T, c net.Conn) *bufio.Reader {
	t.Helper()
	if _, err := fmt.Fprintf(c, "HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n", HelloPath); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hello status = %d", resp.StatusCode)
	}
	return br
}

// closedWithin reports whether the server closes c within d: a read that ends in EOF or a reset, not a timeout.
func closedWithin(c net.Conn, br *bufio.Reader, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := br.ReadByte()
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// H1: net/http holds a keep-alive connection that has gone quiet until its peer closes it unless the server sets
// IdleTimeout; the listener set none, and 2000 such connections stayed open indefinitely.
func TestIdleKeepAliveConnectionIsClosed(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{IdleTimeout: 200 * time.Millisecond})
	c, err := net.Dial("tcp", h.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	br := helloOn(t, c)
	if !closedWithin(c, br, 3*time.Second) {
		t.Error("an idle keep-alive connection was still open 3 s past a 200 ms IdleTimeout")
	}
}

// H1: the default is set, and is the named constant.
func TestListenerDefaultsBoundConnections(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if l.srv.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want DefaultIdleTimeout (%v)", l.srv.IdleTimeout, DefaultIdleTimeout)
	}
	cl, ok := l.ln.(*capListener)
	if !ok || cl.max != DefaultMaxConns {
		t.Errorf("listener = %T, want a capListener at DefaultMaxConns", l.ln)
	}
}

// H1: past the cap a connection is closed as it is accepted and counted as one gap why=size-cap; the ones under
// it are served, and a slot a connection gives back by closing is served again.
func TestConnectionCapRefusesTheOneOverAndRecordsAGap(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{MaxConns: 2})
	m := meter(h)
	addr := h.listener.Addr().String()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		helloOn(t, c)
	}
	over, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	held = append(held, over)
	_, _ = fmt.Fprintf(over, "HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n", HelloPath)
	if !closedWithin(over, bufio.NewReader(over), 3*time.Second) {
		t.Fatal("the connection over the cap was served or left open")
	}
	if n := gapCount(h.listener, GapSizeCap); n != 1 {
		t.Errorf("size-cap gaps = %d, want 1 for the connection refused at the cap", n)
	}
	if got := m.reported(); len(got) != 0 {
		t.Errorf("unmetered reports %v for a connection closed before a byte of it was read (limits R1)", got)
	}
	// A slot comes back when a connection closes, which the server sees asynchronously.
	_ = held[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		_, _ = fmt.Fprintf(c, "HEAD %s HTTP/1.1\r\nHost: x\r\n\r\n", HelloPath)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a slot freed by a closed connection was never served again")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// truncationDeriver records whether each response derive is handed was cut, by the request's path.
type truncationDeriver struct {
	mu  sync.Mutex
	cut map[string][]bool
}

func (d *truncationDeriver) Handle(req, resp *derive.Message, _ derive.Meta) (derive.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if resp != nil {
		d.cut[req.Path] = append(d.cut[req.Path], resp.Truncated)
	}
	return derive.Result{}, nil
}

func (d *truncationDeriver) of(path string) []bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]bool(nil), d.cut[path]...)
}

// L3: R27 leaves the response to the client without a deadline, and a client that stopped reading held its
// relay's record copy with it. Five such responses held the whole of a budget sized for five, and the next
// exchange, from a client reading normally, was recorded cut. The stalled copies now go back once their write has
// made no progress for WriteStallTimeout, and the relays still deliver every byte once their clients read again.
func TestStalledClientGivesItsCaptureBack(t *testing.T) {
	const (
		maxBody  = 16 << 10
		stalled  = exchangeBuffers // a budget at its floor holds this many stalled copies of MaxBody
		stallLen = 12 << 20        // past loopback's send and receive buffers together
	)
	chunk := strings.Repeat("x", 32<<10)
	var started atomic.Int64
	d := &truncationDeriver{cut: map[string][]bool{}}
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path == "/v1/small" {
			_, _ = io.WriteString(w, strings.Repeat("s", 4<<10))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(stallLen))
		started.Add(1)
		for sent := 0; sent < stallLen; sent += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}, Options{MaxBody: maxBody, MaxCaptureBytes: 1, WriteStallTimeout: 100 * time.Millisecond, Deriver: d})

	dialer := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		// A small receive window, so the relay's writes to this client block early.
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4096)
		}); err != nil {
			return err
		}
		return serr
	}}
	conns := make([]net.Conn, 0, stalled)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range stalled {
		c, err := dialer.Dial("tcp", h.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_, _ = fmt.Fprintf(c, "POST /v1/stall HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
	}
	deadline := time.Now().Add(5 * time.Second)
	for started.Load() < stalled && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Past the stall timeout several times over: every stalled relay is blocked on its client by now, and has
	// given its copy back.
	time.Sleep(time.Second)
	if used := h.listener.budget.used.Load(); used >= maxBody {
		t.Errorf("budget in use %d with every response stalled on its client, want under one body (%d): the"+
			" stalled copies still hold it", used, maxBody)
	}

	resp := h.post("/v1/small", []byte(`{}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	deadline = time.Now().Add(3 * time.Second)
	for len(d.of("/v1/small")) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := d.of("/v1/small"); len(got) != 1 || got[0] {
		t.Errorf("the exchange beside the stalled ones was recorded cut=%v, want one whole copy", got)
	}

	// The relay was never cut; every stalled client gets its whole response once it reads.
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Go(func() {
			_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Errorf("stalled client %d: %v", i, err)
				return
			}
			n, err := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil || n != stallLen {
				t.Errorf("stalled client %d read %d bytes (%v), want all %d", i, n, err, stallLen)
			}
		})
	}
	wg.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for len(d.of("/v1/stall")) < stalled && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for i, cut := range d.of("/v1/stall") {
		if !cut {
			t.Errorf("stalled exchange %d recorded whole; its copy was given back and has to be marked cut", i)
		}
	}
	h.sink.waitFor(t, record.KindSSLResponse, stalled+1)
	if n := gapCount(h.listener, GapSizeCap); n != stalled {
		t.Errorf("size-cap gaps = %d, want %d: a copy given back is cut as a full budget cuts it", n, stalled)
	}
}

// L3, the guard alone: a write that returns in time keeps the copy, one that does not gives it back once, and a
// guard that is stopped never fires.
func TestStallGuard(t *testing.T) {
	b := newBudget(0, 1024)
	h := b.hold(1024)
	h.write(make([]byte, 512))
	g := stallGuard{after: 30 * time.Millisecond, captured: h}
	g.arm()
	if g.disarm() {
		t.Fatal("a write that returned at once gave its copy back")
	}
	g.arm()
	time.Sleep(150 * time.Millisecond)
	if !g.disarm() {
		t.Fatal("a write stalled past the timeout kept its copy")
	}
	if b.used.Load() != 0 || h.reserved() != 0 {
		t.Errorf("budget in use %d, copy holds %d after the release, want 0 and 0", b.used.Load(), h.reserved())
	}
	g.arm() // a released guard arms nothing
	time.Sleep(60 * time.Millisecond)
	if !g.disarm() {
		t.Error("a released guard forgot it was released")
	}
	g.stop()
}

// livePair is one loopback connection from this process: its two ends and the peer's view of the tuple.
func livePair(t testing.TB, ln net.Listener) (client, server net.Conn, peer, local netip.AddrPort) {
	t.Helper()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return client, server, netip.MustParseAddrPort(server.RemoteAddr().String()),
		netip.MustParseAddrPort(server.LocalAddr().String())
}

// M1: the exact sock_diag lookup names the same socket the tcp table does.
func TestSockDiagMatchesTheTCPTable(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, s, peer, local := livePair(t, ln)
	defer func() { _ = c.Close(); _ = s.Close() }()
	want, err := peerSocketInode(peer, local)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sockDiagInode(peer, local)
	if err != nil {
		t.Fatalf("sock_diag: %v", err)
	}
	if got != want {
		t.Errorf("sock_diag inode %d, tcp table %d", got, want)
	}
	// The reverse tuple is the listener's own accepted socket, a different one.
	if rev, err := sockDiagInode(local, peer); err != nil || rev == want {
		t.Errorf("reversed tuple: inode %d err %v, want the accepted socket's own", rev, err)
	}
	if _, err := sockDiagInode(netip.MustParseAddrPort("127.0.0.1:1"), local); !errors.Is(err, errSockDiagMiss) {
		t.Errorf("a tuple no socket has: err %v, want errSockDiagMiss", err)
	}
}

// M1: a reply naming another socket, or an error reply, is never taken for this connection's inode.
func TestParseSockDiagReply(t *testing.T) {
	peer, local := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:50000")
	reply := func(src, dst netip.AddrPort, ino uint32) []byte {
		msg := make([]byte, nlmsgHdrLen+inetDiagMsgLen)
		ne := binary.NativeEndian
		ne.PutUint32(msg[0:], uint32(len(msg)))
		ne.PutUint16(msg[4:], unix.SOCK_DIAG_BY_FAMILY)
		msg[nlmsgHdrLen] = unix.AF_INET
		putSockID(msg[nlmsgHdrLen+4:], unix.AF_INET, src, dst)
		ne.PutUint32(msg[nlmsgHdrLen+inetDiagInodeOff:], ino)
		return msg
	}
	if ino, err := parseSockDiagReply(reply(peer, local, 77), unix.AF_INET, peer, local); err != nil || ino != 77 {
		t.Errorf("matching reply: %d, %v", ino, err)
	}
	if _, err := parseSockDiagReply(reply(local, peer, 77), unix.AF_INET, peer, local); err == nil {
		t.Error("a reply for the reversed tuple was accepted")
	}
	if _, err := parseSockDiagReply(reply(peer, local, 0), unix.AF_INET, peer, local); !errors.Is(err, errSockDiagMiss) {
		t.Errorf("an inode-less socket: %v, want a miss", err)
	}
	e := make([]byte, nlmsgHdrLen+4)
	binary.NativeEndian.PutUint16(e[4:], nlmsgErrorType)
	errno := -int32(unix.ENOENT)
	binary.NativeEndian.PutUint32(e[nlmsgHdrLen:], uint32(errno))
	if _, err := parseSockDiagReply(e, unix.AF_INET, peer, local); !errors.Is(err, errSockDiagMiss) {
		t.Errorf("ENOENT: %v, want a miss", err)
	}
}

// admitterCostChildEnv makes this test binary, re-executed by TestProcAdmitterCostDoesNotGrowWithOpenSockets, take the
// measurement in the re-executed process.
const admitterCostChildEnv = "TEGO_FORWARDER_ADMITTER_COST_CHILD"

// M1: with a thousand other connections open, admitting one more reads a handful of descriptor links, not one per
// open socket; a connection whose descriptor number was closed and reused unseen is still found; and a failed
// sock_diag falls back to the tcp table.
//
// The measurement runs in a process of its own: this binary re-executed for this test alone. Its bounds count on the
// kernel giving each new socket the lowest number free, where the admitter probes, so they hold only while nothing
// else in the process frees a descriptor below the test's sockets. In the package's process, earlier tests leave
// descriptors that close later. One is the pipe pair io.Copy between two TCP connections splices through: the Go
// runtime keeps it in a pool (internal/poll), and a runtime cleanup closes it once the pool has dropped it, two
// collections after its last use, wherever the collector's pace puts that. The race job's unit step failed this test
// with connection 0 and kept connection 1 each missing the probe and searching the tables of every process in the
// job's cgroup (57 and 55 links read), which is the pattern one pair of descriptors freed between the warm-up and
// connection 0 gives. In that run's order a duplex CONNECT test leaves such a pipe four tests before this one; with the
// collector's pace moved, it closes here and fails the test with those two lines, and at the default pace on a quiet
// machine it closes a test earlier.
func TestProcAdmitterCostDoesNotGrowWithOpenSockets(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	if os.Getenv(admitterCostChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcAdmitterCostDoesNotGrowWithOpenSockets$", "-test.count=1",
			"-test.v", "-test.timeout=5m")
		cmd.Env = append(os.Environ(), admitterCostChildEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the measurement, in a process of its own: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "--- PASS: TestProcAdmitterCostDoesNotGrowWithOpenSockets") {
			t.Fatalf("the measurement, in a process of its own, did not pass:\n%s", out)
		}
		return
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for range 1000 {
		c, s, _, _ := livePair(t, ln)
		open = append(open, c, s)
	}
	a := newProcAdmitter()
	admit := func(what string) (net.Conn, net.Conn, netip.AddrPort, netip.AddrPort, int) {
		t.Helper()
		c, s, peer, local := livePair(t, ln)
		before := a.links.Load()
		if _, err := a.admit(peer, local, id); err != nil {
			t.Fatalf("%s: the peer of a live connection from this process was refused: %v", what, err)
		}
		return c, s, peer, local, int(a.links.Load() - before)
	}
	// descriptor is c's number, which a failure names: one below the sockets this test opened is a number something
	// else in the process freed.
	descriptor := func(c net.Conn) int {
		n := -1
		if rc, err := c.(syscall.Conn).SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) { n = int(fd) })
		}
		return n
	}
	// The first admission lists every table; the ones after it do not.
	c, s, peer, local, _ := admit("warm-up")
	a.forget(peer, local)
	_ = c.Close()
	_ = s.Close()
	for i := range 20 {
		c, s, peer, local, links := admit("next")
		if links > 20 {
			t.Errorf("connection %d (descriptor %d) read %d descriptor links with %d sockets open; the cost grows with them",
				i, descriptor(c), links, len(open))
		}
		a.forget(peer, local)
		_ = c.Close()
		_ = s.Close()
	}
	// Kept open, with a file opened and closed between two connections, as an agent's pool and its other work do:
	// the next socket lands past the last one, not past the file.
	for i := range 20 {
		if f, err := os.Open("/proc/self/fd"); err == nil {
			_ = f.Close()
		}
		c, s, _, _, links := admit("kept")
		open = append(open, c, s)
		if links > 8 {
			t.Errorf("kept connection %d (descriptor %d) read %d descriptor links", i, descriptor(c), links)
		}
	}
	// Closed without the admitter being told: the number is reused and remembered with its old socket.
	c, s, _, _, _ = admit("unseen close")
	_ = c.Close()
	_ = s.Close()
	c, s, _, _, _ = admit("after an unseen close")
	_ = c.Close()
	_ = s.Close()

	a.diag = func(netip.AddrPort, netip.AddrPort) (uint64, error) { return 0, errors.New("no inet_diag") }
	c, s, _, _, _ = admit("without sock_diag")
	_ = c.Close()
	_ = s.Close()

	if _, err := a.admit(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort(ln.Addr().String()),
		id); !errors.Is(err, ErrPeer) {
		t.Errorf("a tuple no socket has: err %v, want ErrPeer", err)
	}
}

// M1: a socket held only outside the run's cgroup is refused by the cached admitter as by the walk.
func TestProcAdmitterRefusesAForeignCgroup(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, s, peer, local := livePair(t, ln)
	defer func() { _ = c.Close(); _ = s.Close() }()
	a := newProcAdmitter()
	a.fallback = func(netip.AddrPort, netip.AddrPort, uint64) (int, error) { return 0, ErrPeer }
	if _, err := a.admit(peer, local, foreignCgroupID); !errors.Is(err, ErrPeer) {
		t.Errorf("err = %v, want ErrPeer for a run no process is in", err)
	}
}

// A peer outside the run misses every cache and costs a read of each run process's descriptor table, and a
// local process chooses how many of those happen. That search held the admitter's mutex, so the run's own
// connections queued behind every refusal. It now runs outside the mutex: an admission the cache answers completes
// while a refusal's search is still reading, and each descriptor is read once per search, not twice.
func TestARefusalsSearchDoesNotHoldBackAnAdmission(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	// A descriptor below this test's sockets that closes after the warm-up, as one of an earlier test of this binary
	// does when a goroutine of that test closes its connection late or a finalizer closes a file it leaked.
	late, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	a := newProcAdmitter()
	c, s, peer, local := livePair(t, ln)
	defer func() { _ = c.Close(); _ = s.Close() }()
	// The connection admitted while the refusal searches is open before the warm-up, whose table search reads every
	// descriptor of this process and so remembers where its socket is: its admission is one the memory answers (held,
	// a single link read), whatever descriptor number it got. One opened after the warm-up is answered by the memory
	// only at a number probe reads (one it saw freed, or just past the highest socket), while it gets the lowest free
	// number, late's once late has closed: its find then rightly waits for the next table search, which this test holds
	// until release.
	c2, s2, peer2, local2 := livePair(t, ln)
	defer func() { _ = c2.Close(); _ = s2.Close() }()
	if _, err := a.admit(peer, local, id); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	_ = late.Close()
	// An outsider: a socket inode no run process holds.
	outsider := netip.MustParseAddrPort("127.0.0.1:1")
	a.diag = func(p, l netip.AddrPort) (uint64, error) {
		if p == outsider {
			return 1 << 62, nil
		}
		return sockDiagInode(p, l)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.searching = func() { once.Do(func() { close(entered); <-release }) }
	refused := make(chan error, 1)
	go func() { _, err := a.admit(outsider, local, id); refused <- err }()
	<-entered

	admitted := make(chan error, 1)
	go func() { _, err := a.admit(peer2, local2, id); admitted <- err }()
	select {
	case err := <-admitted:
		if err != nil {
			t.Errorf("the run's own connection was refused: %v", err)
		}
	// The refusal's search is held until release, and no other search starts before it ends (searchLoop runs one
	// at a time), so an admission waiting behind it never completes: a long bound loses nothing.
	case <-time.After(time.Minute):
		close(release)
		t.Fatal("the run's own connection waited behind a refusal's descriptor search")
	}
	close(release)
	if err := <-refused; !errors.Is(err, ErrPeer) {
		t.Errorf("the outsider: err %v, want ErrPeer", err)
	}

	// Cold, every descriptor of the run's processes is read once for a refusal, not once per pass. The run here
	// is the cgroup this test process is in, which may hold other processes too.
	for range 64 {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
	}
	cold := newProcAdmitter()
	cold.diag = func(netip.AddrPort, netip.AddrPort) (uint64, error) { return 1 << 62, nil }
	// Only this process's own links are counted: the cgroup's other processes open and close descriptors while
	// the search runs, which under load moved a whole-cgroup count past any fixed slack.
	self := os.Getpid()
	var own atomic.Int64
	cold.linked = func(pid int) {
		if pid == self {
			own.Add(1)
		}
	}
	fds, _ := os.ReadDir("/proc/self/fd")
	open := len(fds)
	if _, err := cold.admit(outsider, local, id); !errors.Is(err, ErrPeer) {
		t.Fatalf("the outsider: err %v, want ErrPeer", err)
	}
	if n := own.Load(); n < 64 {
		t.Errorf("a refusal read only %d of this process's descriptor links: the search did not reach them", n)
	}
	if n := own.Load(); n > int64(open)+16 {
		t.Errorf("a refusal read %d of this process's descriptor links with about %d open: each is read more than once",
			n, open)
	}
}
