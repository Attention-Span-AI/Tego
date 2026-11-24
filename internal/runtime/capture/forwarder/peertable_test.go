// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syntheticTable writes a /proc/net/tcp-shaped file of other rows other sockets and the listed peers' rows (each
// peer port p is the local end of a connection to listener, inode 1000+p), and returns its path. The other rows
// are spread through the file, the wanted ones last: the worst place for a reader that stops at its match.
func syntheticTable(tb testing.TB, others int, ports []int, listener netip.AddrPort) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i := range others {
		fmt.Fprintf(&b, "%4d: 0100007F:%04X 0100007F:%04X 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n",
			i, 20000+i%40000, 9000+i%1000, 5_000_000+i)
	}
	for i, p := range ports {
		fmt.Fprintf(&b, "%4d: 0100007F:%04X 0100007F:%04X 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n",
			others+i, p, listener.Port(), 1000+p)
	}
	path := filepath.Join(tb.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// scanTCPTable is the table scan for one connection (scanTCPTableSet's, with one want): the inode of the row that is
// the peer's side of the connection, whether there was one, and the row's error (no inode).
func scanTCPTable(r io.Reader, peer, local netip.AddrPort) (uint64, bool, error) {
	w := &tcpWant{}
	if _, err := scanTCPTableSet(r, map[connKey]*tcpWant{{peer: peer, local: local}: w}); err != nil {
		return 0, false, err
	}
	return w.inode, w.found, w.err
}

// useTables points the reader at the synthetic tables for the test and restores it after.
func useTables(tb testing.TB, names ...string) {
	tb.Helper()
	old := procNetTCP
	procNetTCP = names
	tb.Cleanup(func() { procNetTCP = old; tcpTableOpened = nil })
}

// TestLookupsOfOneBurstShareTheTableReads: Each connection's lookup read the whole /proc/net/tcp, so n
// connections accepted together read it n times, on the accepting goroutines. Now lookups share reads: the first
// goes alone (it is the one that finds no read running), and the other 63, which register while it reads, are
// answered by one more read. Each is answered with its own inode, from a read that began after it registered.
func TestLookupsOfOneBurstShareTheTableReads(t *testing.T) {
	const n = 64
	listener := netip.MustParseAddrPort("127.0.0.1:8080")
	ports := make([]int, n)
	for i := range ports {
		ports[i] = 40000 + i
	}
	table := syntheticTable(t, 5000, ports, listener)
	useTables(t, table, filepath.Join(t.TempDir(), "no-tcp6"))
	var reads atomic.Int64
	release := make(chan struct{})
	tcpTableOpened = func(name string) {
		if name != table {
			return
		}
		if reads.Add(1) == 1 {
			<-release // the first read waits until the rest of the burst has registered
		}
	}
	var wg sync.WaitGroup
	got := make([]uint64, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = peerSocketInode(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ports[i])), listener)
		}()
		if i == 0 {
			for reads.Load() == 0 { // the first lookup is reading before the rest arrive
				time.Sleep(time.Millisecond)
			}
		}
	}
	for stop := time.Now().Add(5 * time.Second); time.Now().Before(stop); { // all of the others are waiting in the next batch
		tcpTables.mu.Lock()
		waiting := 0
		if b := tcpTables.next; b != nil {
			waiting = len(b.wants)
		}
		tcpTables.mu.Unlock()
		if waiting == n-1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	for i := range n {
		if errs[i] != nil || got[i] != uint64(1000+ports[i]) {
			t.Errorf("lookup %d: inode %d, err %v; want %d", i, got[i], errs[i], 1000+ports[i])
		}
	}
	if r := reads.Load(); r != 2 {
		t.Errorf("%d connections read the table %d times, want 2 (one alone, one shared)", n, r)
	}
}

// TestALookupAfterTheTableChangedSeesTheNewRow: nothing is kept between reads, so a connection made after an earlier
// lookup is never answered from the table as that lookup saw it.
func TestALookupAfterTheTableChangedSeesTheNewRow(t *testing.T) {
	listener := netip.MustParseAddrPort("127.0.0.1:8080")
	first := netip.MustParseAddrPort("127.0.0.1:40001")
	second := netip.MustParseAddrPort("127.0.0.1:40002")
	table := syntheticTable(t, 10, []int{40001}, listener)
	useTables(t, table)
	if ino, err := peerSocketInode(first, listener); err != nil || ino != 41001 {
		t.Fatalf("first lookup: %d, %v", ino, err)
	}
	if _, err := peerSocketInode(second, listener); err == nil {
		t.Fatal("a connection not in the table was found")
	}
	table2 := syntheticTable(t, 10, []int{40001, 40002}, listener)
	b, err := os.ReadFile(table2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(table, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ino, err := peerSocketInode(second, listener); err != nil || ino != 41002 {
		t.Fatalf("the connection made after the first lookup: %d, %v; want 41002", ino, err)
	}
}

// BenchmarkLookupBurst is 64 connections' lookups arriving together against a table of 100,000 other sockets.
func BenchmarkLookupBurst(b *testing.B) {
	const n = 64
	listener := netip.MustParseAddrPort("127.0.0.1:8080")
	ports := make([]int, n)
	for i := range ports {
		ports[i] = 40000 + i
	}
	useTables(b, syntheticTable(b, 100_000, ports, listener))
	var reads atomic.Int64
	tcpTableOpened = func(string) { reads.Add(1) }
	for b.Loop() {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := peerSocketInode(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ports[i])), listener); err != nil {
					b.Error(err)
				}
			}()
		}
		wg.Wait()
	}
	b.ReportMetric(float64(reads.Load())/float64(b.N), "reads/burst")
}
