// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A peer outside the run misses every cache and costs a search of every run process's descriptor table,
// and a local process chooses how often that happens. Each outsider once had a search of its own, and up to
// MaxConns of them could run at once, so a connect loop kept a core of the launcher reading /proc. Now the finds
// waiting while a search runs share the next one, and a search that leaves a socket unfound holds the next back
// for searchPace times as long as it took.
func TestOutsiderSearchesAreSharedAndPaced(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	local := netip.MustParseAddrPort(ln.Addr().String())
	a := newProcAdmitter()
	// Each outsider is a socket inode no run process holds, one per source port.
	a.diag = func(p, _ netip.AddrPort) (uint64, error) { return 1<<62 + uint64(p.Port()), nil }
	// A clock a millisecond on at each reading, so a search takes time however fast it ran.
	var clockMu sync.Mutex
	clock := time.Unix(1_000_000, 0)
	a.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(time.Millisecond)
		return clock
	}
	var pauses []time.Duration
	a.pause = func(d time.Duration) { pauses = append(pauses, d) } // called only on searchLoop's goroutine
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.searching = func() { once.Do(func() { close(entered); <-release }) }

	const outsiders = 32
	refused := make(chan error, outsiders+1)
	outsider := func(port uint16) {
		_, err := a.admit(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), local, id)
		refused <- err
	}
	go outsider(1)
	<-entered
	for i := range outsiders {
		go outsider(uint16(2 + i))
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.mu.Lock()
		n := len(a.wait)
		a.mu.Unlock()
		if n == outsiders {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("%d of %d outsiders are waiting for a search", n, outsiders)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for range outsiders + 1 {
		if err := <-refused; !errors.Is(err, ErrPeer) {
			t.Errorf("an outsider: err %v, want ErrPeer", err)
		}
	}
	if n := a.searches.Load(); n != 2 {
		t.Errorf("%d outsiders ran %d table searches, want 2: the one in progress and one for all that waited on it",
			outsiders+1, n)
	}
	if len(pauses) != 1 || pauses[0] <= 0 {
		t.Errorf("pauses before the second search: %v, want one: a search that found nothing holds the next back",
			pauses)
	}
}

// BenchmarkOutsiderAdmission measures what R19a costs a peer outside the run, with the run holding sockets=N open:
// each iteration is a refusal, a full search of the run's descriptor tables, back to back as a connect loop makes
// them. Its time per operation includes searchPace's pause, so it is about searchPace+1 times the search's own, and
// the searches take about a quarter of that wall time in CPU.
func BenchmarkOutsiderAdmission(b *testing.B) {
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
			for range open {
				c, s, _, _ := livePair(b, ln)
				held = append(held, c, s)
			}
			local := netip.MustParseAddrPort(ln.Addr().String())
			outsider := netip.MustParseAddrPort("127.0.0.1:1")
			a := newProcAdmitter()
			var ino uint64 = 1 << 62
			a.diag = func(netip.AddrPort, netip.AddrPort) (uint64, error) { ino++; return ino, nil }
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.admit(outsider, local, id); !errors.Is(err, ErrPeer) {
					b.Fatalf("an outsider: err %v, want ErrPeer", err)
				}
			}
			b.ReportMetric(float64(a.links.Load())/float64(b.N), "links/op")
		})
	}
}
