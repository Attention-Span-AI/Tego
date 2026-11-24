// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The helpers C205 and C206 add, on the real kernel: sock_diag's inode, /proc's view of a process that hides its
// descriptors, the run's cgroup subtree.

// TestPeerSocketInodeOfARealConnection: sock_diag's inode for a real loopback pair is the inode of the descriptor the
// client holds, with no read of the kernel's tables.
func TestPeerSocketInodeOfARealConnection(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	client := netip.MustParseAddrPort(c.LocalAddr().String())
	server := netip.MustParseAddrPort(c.RemoteAddr().String())
	if _, err := peer.TCPSocketInfo(client, server); err != nil {
		t.Skipf("this kernel answers no socket lookup over sock_diag: %v", err)
	}
	opened := 0
	tcpTableOpened = func(string) { opened++ }
	t.Cleanup(func() { tcpTableOpened = nil })
	ino, err := peerSocketInode(client, server)
	if err != nil || opened != 0 {
		t.Fatalf("inode %d, error %v, %d table reads", ino, err, opened)
	}
	if !holdsSocket(os.Getpid(), ino) {
		t.Fatalf("this process does not hold a socket of inode %d", ino)
	}
	tableIno, err := tableSocketInode(client, server)
	if err != nil || tableIno != ino {
		t.Fatalf("the table says %d (%v), the exact lookup %d", tableIno, err, ino)
	}
}

// ---- the real /proc

// TestHolderHelper is the child of TestRealProcsTellAHiddenProcessFromOneThatHoldsNothing: it holds its inherited socket
// (fd 3), sets or leaves its dumpable flag as its mode says, says it is ready, and waits to be killed.
func TestHolderHelper(t *testing.T) {
	mode := os.Getenv("TEGO_HOLDER_HELPER")
	if mode == "" {
		t.Skip("a helper of the tests below")
	}
	if mode == "hidden" {
		if err := sys.SetDumpable(false); err != nil {
			os.Stdout.WriteString("setdumpable: " + err.Error() + "\n")
			os.Exit(2)
		}
	}
	os.Stdout.WriteString("ready\n")
	select {}
}

func TestRealProcsTellAHiddenProcessFromOneThatHoldsNothing(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	tc, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	f, err := tc.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || !strings.HasPrefix(link, "socket:[") {
		t.Fatalf("link %q: %v", link, err)
	}
	inode, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
	for _, mode := range []string{"visible", "hidden"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestHolderHelper$")
			cmd.Env = append(os.Environ(), "TEGO_HOLDER_HELPER="+mode)
			cmd.ExtraFiles = []*os.File{f}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			sc := bufio.NewScanner(out)
			for sc.Scan() && sc.Text() != "ready" {
				if strings.HasPrefix(sc.Text(), "setdumpable") {
					t.Skipf("the child could not set its dumpable flag: %s", sc.Text())
				}
			}
			holds, state := realProcs{}.Holds(cmd.Process.Pid, inode)
			switch mode {
			case "visible":
				if !holds || state != fdsRead {
					t.Fatalf("a process that holds the socket and can be read: holds %v, state %v", holds, state)
				}
			case "hidden":
				if holds || state != fdsHidden {
					t.Fatalf("a process that is not dumpable: holds %v, state %v, want hidden (not 'holds nothing')", holds, state)
				}
			}
			if _, ok := (realProcs{}).Start(cmd.Process.Pid); !ok {
				t.Fatal("the start time of a live process was not read")
			}
		})
	}
	if holds, state := (realProcs{}).Holds(1<<22+12345, inode); holds || state != fdsRead {
		t.Fatalf("a process that does not exist holds nothing: %v %v", holds, state)
	}
}

func TestRealProcsListTheProcessesOfACgroup(t *testing.T) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	cg, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "0::")
	if !ok || cg == "" {
		t.Skipf("no unified cgroup line: %q", b)
	}
	dir := filepath.Join("/sys/fs/cgroup", cg)
	if _, err := os.Stat(dir); err != nil {
		t.Skip(err)
	}
	found := false
	for _, pid := range (realProcs{}).Pids(dir) {
		if pid == os.Getpid() {
			found = true
		}
	}
	if !found {
		t.Fatalf("this process is not among the processes of its own cgroup %s", dir)
	}
}

// TestCgroupBelowKeepsAYes: a descendant of the run's cgroup is found by one walk of the run's subtree and remembered; the
// run's parent is not below it.
func TestCgroupBelowKeepsAYes(t *testing.T) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	cg, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "0::")
	if !ok || cg == "" || cg == "/" {
		t.Skipf("no cgroup path to take a parent of: %q", b)
	}
	own, parent := filepath.Join("/sys/fs/cgroup", cg), filepath.Dir(filepath.Join("/sys/fs/cgroup", cg))
	ino := func(p string) uint64 {
		fi, err := os.Stat(p)
		if err != nil {
			t.Skip(err)
		}
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	ownID, parentID := ino(own), ino(parent)
	if !cgroupBelow(parentID, ownID) {
		t.Fatal("this process's cgroup is not below its parent's")
	}
	cgDirMu.Lock()
	kept := cgBelow[[2]uint64{parentID, ownID}]
	cgDirMu.Unlock()
	if !kept {
		t.Fatal("a yes was not kept")
	}
	if cgroupBelow(ownID, parentID) {
		t.Fatal("a cgroup's parent is below it")
	}
	if cgroupBelow(parentID, 1<<62) {
		t.Fatal("a cgroup that does not exist is below the run's")
	}
}

// TestSocketInRunAdmitsByTheSocketsCgroup: the lookup's cgroup is the run's or below it; an outsider's, a failed lookup
// and a run without a cgroup are refused.
func TestSocketInRunAdmitsByTheSocketsCgroup(t *testing.T) {
	remote, local := netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2")
	look := func(id uint64, err error) func(netip.AddrPort, netip.AddrPort) (peer.SocketInfo, error) {
		return func(netip.AddrPort, netip.AddrPort) (peer.SocketInfo, error) {
			return peer.SocketInfo{CgroupID: id, Inode: 9}, err
		}
	}
	if info, err := socketInRun(look(7, nil), remote, local, 7); err != nil || info.Inode != 9 {
		t.Fatalf("the run's own cgroup: %+v %v", info, err)
	}
	if _, err := socketInRun(look(8, nil), remote, local, 7); !errors.Is(err, ErrPeer) {
		t.Fatalf("an outsider: %v", err)
	}
	if _, err := socketInRun(look(0, errors.New("sock_diag")), remote, local, 7); !errors.Is(err, ErrPeer) {
		t.Fatalf("a failed lookup: %v", err)
	}
	if _, err := socketInRun(look(7, nil), remote, local, 0); !errors.Is(err, ErrPeer) {
		t.Fatalf("a run with no cgroup: %v", err)
	}
}
