// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// A row whose inode is 0 is an orphaned socket, one its process has closed. No process holds it, so the table
// refuses it rather than hand back 0, which every descriptor that is not a socket also reads as.
func TestScanTCPTableRefusesInodeZero(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:C0DE 0100007F:A515 05 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 100 0 0 10 0
`
	listener := netip.MustParseAddrPort("127.0.0.1:42261") // A515
	peer := netip.MustParseAddrPort("127.0.0.1:49374")     // C0DE
	inode, found, err := scanTCPTable(strings.NewReader(table), peer, listener)
	if !errors.Is(err, ErrPeer) {
		t.Errorf("inode %d, found %v, err %v: an orphaned row must be refused with ErrPeer", inode, found, err)
	}
}

// Inode 0 names no socket. Every descriptor that is not a socket (a file, a pipe, /dev/null) reads as 0, so a
// search for it must find nothing rather than the first such descriptor of a run process.
func TestProcAdmitterFindRefusesInodeZero(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	a := newProcAdmitter()
	pid := os.Getpid()
	if _, found := a.search(map[uint64]bool{0: true}, []int{pid}, nil); len(found) != 0 {
		t.Errorf("search matched inode 0 at %v", found)
	}
	// Every descriptor remembered as a socket, so the second pass reads them all again.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	remembered := map[string]uint64{}
	for _, e := range entries {
		remembered[e.Name()] = 1
	}
	known := map[int]map[string]uint64{pid: remembered}
	if _, found := a.search(map[uint64]bool{0: true}, []int{pid}, known); len(found) != 0 {
		t.Errorf("search of a remembered table matched inode 0 at %v", found)
	}
	if ref, ok := a.find(0, []int{os.Getpid()}); ok {
		t.Errorf("find(0) matched pid %d fd %s: a descriptor that is not a socket was taken for the peer", ref.pid,
			ref.fd)
	}
}

// A peer that writes its request and closes without waiting leaves an orphaned socket with inode 0 in the tcp
// table and none for sock_diag. It must be refused, not admitted as whichever run process has a non-socket fd.
func TestProcAdmitterRefusesAnOrphanedPeer(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, s, peer, local := livePair(t, ln)
	defer func() { _ = s.Close() }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Wait for the close to reach the tcp table: the peer's row turns orphaned (inode 0) once its descriptor is gone.
	deadline := time.Now().Add(5 * time.Second)
	for {
		inode, err := peerSocketInode(peer, local)
		if err != nil || inode == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Skipf("the closed peer socket still reports inode %d", inode)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a := newProcAdmitter()
	a.fallback = func(netip.AddrPort, netip.AddrPort, uint64) (int, error) { return 0, ErrPeer }
	if pid, err := a.admit(peer, local, id); !errors.Is(err, ErrPeer) {
		t.Errorf("an orphaned peer socket was admitted as pid %d (err %v), want ErrPeer", pid, err)
	}
}
