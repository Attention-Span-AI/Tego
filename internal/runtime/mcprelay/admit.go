// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// ErrPeer is a control connection the service does not admit.
var ErrPeer = errors.New("mcprelay: peer not admitted")

// admission is what admitting a control connection proved, kept for the gate (Relayed): a pid alone names whichever
// process holds the number by then, and the socket says which connection the proof was about.
type admission struct {
	pid   int
	inode uint64 // the socket on the peer's end of the connection
	start uint64 // the process's start, /proc/<pid>/stat field 22
}

// admitter places a control connection's peer: it returns the shim holding the connection, or an error that refuses
// it. The hello's PID is the shim's claim; the admitter proves it.
type admitter func(c net.Conn, claimedPID int, runCgroup uint64) (admission, error)

// shimCheck is the gate's look at an admitted shim, at the moment its server's start is asked about.
type shimCheck func(admission) bool

// procAdmit is the admitter of a real run (ADR 0126 §4 "Stdio shim"): the claimed process holds the socket on the
// other end of this connection (its inode from the kernel's TCP table, found among the process's descriptors), it
// is in the run's cgroup subtree, its image is this launcher's own executable (device and inode of /proc/self/exe),
// and its command line is `… mcp relay …`. Copied from the forwarder's approach (internal/runtime/capture/forwarder
// peer.go), not imported: the capture package is not this one's to link.
//
// This proves a process holds the socket, not that it wrote the hello: an agent can dial, start a real shim with the
// descriptor inherited and its relay variable naming a listener of its own, and write the hello itself. At hello time
// such a shim may not have dialled yet, so what tells the two apart is checked at the gate (procStillShim).
func procAdmit(c net.Conn, pid int, runCgroup uint64) (admission, error) {
	if pid <= 0 {
		return admission{}, fmt.Errorf("%w: hello names no pid", ErrPeer)
	}
	if runCgroup == 0 {
		return admission{}, fmt.Errorf("%w: the run has no cgroup id to place a peer in", ErrPeer)
	}
	peer, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return admission{}, fmt.Errorf("%w: peer address: %w", ErrPeer, err)
	}
	local, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return admission{}, fmt.Errorf("%w: local address: %w", ErrPeer, err)
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	inode, err := peerSocketInode(peer, local)
	if err != nil {
		return admission{}, err
	}
	start, err := startOf(pid)
	if err != nil {
		return admission{}, fmt.Errorf("%w: process %d: %w", ErrPeer, pid, err)
	}
	if !holdsSocket(pid, inode) {
		return admission{}, fmt.Errorf("%w: process %d does not hold the connection's socket", ErrPeer, pid)
	}
	mount, err := cgroup2Mount()
	if err != nil {
		return admission{}, err
	}
	cg, err := procCgroupPath(pid)
	if err != nil || !cgroupInSubtree(mount, cg, runCgroup) {
		return admission{}, fmt.Errorf("%w: process %d is not in the run's cgroup", ErrPeer, pid)
	}
	if err := shimImage(pid); err != nil {
		return admission{}, err
	}
	// The socket and the start are read again: a pid that exited and was reissued between the reads holds a different one.
	if !holdsSocket(pid, inode) {
		return admission{}, fmt.Errorf("%w: process %d no longer holds the connection's socket", ErrPeer, pid)
	}
	if now, err := startOf(pid); err != nil || now != start {
		return admission{}, fmt.Errorf("%w: process %d is another process now", ErrPeer, pid)
	}
	return admission{pid: pid, inode: inode, start: start}, nil
}

// shimImage proves pid is this launcher's own executable running `tego mcp relay`.
func shimImage(pid int) error {
	var self, img unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &self); err != nil {
		return fmt.Errorf("%w: stat own image: %w", ErrPeer, err)
	}
	if err := unix.Stat("/proc/"+strconv.Itoa(pid)+"/exe", &img); err != nil || img.Dev != self.Dev || img.Ino != self.Ino {
		return fmt.Errorf("%w: process %d is not this launcher's tego image", ErrPeer, pid)
	}
	argv, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || !isShimArgv(strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")) {
		return fmt.Errorf("%w: process %d is not `tego mcp relay`", ErrPeer, pid)
	}
	return nil
}

// procStillShim is the gate's check of an admitted shim (ADR 0126 §4 "The gate"), asked as its server starts. The pid
// is the process that was admitted, by its start time: an agent keeping the connection open keeps the pending start
// after the shim dies, and the number can be reissued to a process of its own. It is still tego's image and shim
// command line. And the admitted socket is the only TCP socket it holds: a shim dials exactly one connection before it
// starts a server, so a second TCP socket is the relay it really dialled, and the admitted one is a descriptor it
// inherited, the hello written by someone else. The admitted descriptor must also have CLOEXEC: net.Dial creates it
// that way, while a socket inherited across the shim's exec cannot retain that flag. This refuses a forged child
// registration before the shim has dialled its real connection, when there is no second TCP socket yet (SEC06).
// Only TCP is counted: a client may hand the shim socket stdio, and the
// server's own channels are AF_UNIX. The table read is the process's own network namespace, since a socket dialled in
// another one is in no table of the launcher's. Any read that fails says no.
func procStillShim(a admission) bool {
	if start, err := startOf(a.pid); err != nil || start != a.start || shimImage(a.pid) != nil {
		return false
	}
	if !socketCloexec(a.pid, a.inode) {
		return false
	}
	held, ok := socketsOf(a.pid)
	if !ok || !held[a.inode] {
		return false
	}
	tcp, ok := tcpInodes(a.pid)
	if !ok {
		return false
	}
	for ino := range held {
		if ino != a.inode && tcp[ino] {
			return false
		}
	}
	start, err := startOf(a.pid)
	return err == nil && start == a.start
}

// socketCloexec requires a close-on-exec descriptor on the admitted socket in the shim itself. The flag is per
// descriptor: a duplicate in the agent cannot change it after exec unshares the shim's descriptor table.
func socketCloexec(pid int, inode uint64) bool {
	dir := "/proc/" + strconv.Itoa(pid)
	ents, err := os.ReadDir(dir + "/fd")
	if err != nil {
		return false
	}
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	for _, e := range ents {
		if link, err := os.Readlink(dir + "/fd/" + e.Name()); err != nil || link != want {
			continue
		}
		info, err := os.ReadFile(dir + "/fdinfo/" + e.Name())
		if err != nil {
			return false
		}
		for line := range strings.SplitSeq(string(info), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "flags:" {
				flags, err := strconv.ParseUint(f[1], 8, 64)
				if err == nil && flags&unix.O_CLOEXEC != 0 {
					return true
				}
			}
		}
	}
	return false
}

// isShimArgv reports whether argv is `<tego> mcp relay …`, the shim's own command line, up to its "--".
func isShimArgv(argv []string) bool {
	if i := slices.Index(argv, "--"); i >= 0 {
		argv = argv[:i]
	}
	return len(argv) >= 3 && argv[1] == "mcp" && argv[2] == "relay"
}

// holdsSocket reports whether pid has a descriptor on socket inode.
func holdsSocket(pid int, inode uint64) bool {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	for _, e := range ents {
		if l, err := os.Readlink(dir + "/" + e.Name()); err == nil && l == want {
			return true
		}
	}
	return false
}

// socketsOf is the socket inodes among pid's descriptors. ok is false when they cannot be listed.
func socketsOf(pid int) (map[uint64]bool, bool) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	out := map[uint64]bool{}
	for _, e := range ents {
		l, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		s, found := strings.CutPrefix(l, "socket:[")
		if !found {
			continue
		}
		if ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
			out[ino] = true
		}
	}
	return out, true
}

// tcpInodes is every TCP socket's inode in pid's network namespace. ok is false when its table cannot be read; a kernel
// with no IPv6 has no tcp6 table, and that is not a failure.
func tcpInodes(pid int) (map[uint64]bool, bool) {
	out := map[uint64]bool{}
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/net/" + name)
		if err != nil {
			if name == "tcp6" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, false
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // the header
		for sc.Scan() {
			if c := strings.Fields(sc.Text()); len(c) >= 10 {
				if ino, err := strconv.ParseUint(c[9], 10, 64); err == nil {
					out[ino] = true
				}
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return nil, false
		}
	}
	return out, true
}

// peerSocketInode finds the inode of the socket on the peer's end of this connection: the row of the kernel's TCP
// table whose local address is the peer and whose remote address is this listener.
func peerSocketInode(peer, local netip.AddrPort) (uint64, error) {
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		ino, found := scanTCPTable(bufio.NewScanner(f), peer, local)
		_ = f.Close()
		if found {
			if ino == 0 {
				return 0, fmt.Errorf("%w: the peer's socket has no inode", ErrPeer)
			}
			return ino, nil
		}
	}
	return 0, fmt.Errorf("%w: no socket for %s -> %s in the kernel's tcp table", ErrPeer, peer, local)
}

// scanTCPTable reads /proc/net/tcp{,6} rows: sl local rem st queues timer retr uid timeout inode.
func scanTCPTable(sc *bufio.Scanner, peer, local netip.AddrPort) (uint64, bool) {
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		l, ok1 := parseHexAddr(f[1])
		r, ok2 := parseHexAddr(f[2])
		if !ok1 || !ok2 || l != peer || r != local {
			continue
		}
		ino, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		return ino, true
	}
	return 0, false
}

// parseHexAddr reads one "ADDR:PORT" column: the address in the kernel's host-order 32-bit words.
func parseHexAddr(s string) (netip.AddrPort, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var raw []byte
	for i := 0; i+8 <= len(a); i += 8 {
		w, err := strconv.ParseUint(a[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		// Each 32-bit word is printed in host order; this is a little-endian reading (amd64, arm64).
		raw = append(raw, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	var addr netip.Addr
	switch len(raw) {
	case 4:
		addr = netip.AddrFrom4([4]byte(raw))
	case 16:
		addr = netip.AddrFrom16([16]byte(raw)).Unmap()
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(port)), true
}

// cgroupInSubtree reports whether cgPath (a unified hierarchy path) is the cgroup whose id is runCgroup or below it.
func cgroupInSubtree(mount, cgPath string, runCgroup uint64) bool {
	for p := cgPath; ; p = path.Dir(p) {
		var st unix.Stat_t
		if unix.Stat(mount+p, &st) == nil && st.Ino == runCgroup {
			return true
		}
		if p == "/" || p == "." || p == "" {
			return false
		}
	}
}

// procCgroupPath is the unified hierarchy's path of pid ("0::/path").
func procCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok && strings.HasPrefix(p, "/") {
			return strings.TrimSuffix(p, " (deleted)"), nil
		}
	}
	return "", fmt.Errorf("%w: /proc/%d/cgroup has no unified line", ErrPeer, pid)
}

// cgroup2Mount is where the unified hierarchy is mounted.
var cgroup2Mount = sync.OnceValues(func() (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("%w: read mountinfo: %w", ErrPeer, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		if pf, qf := strings.Fields(pre), strings.Fields(post); len(pf) >= 5 && len(qf) >= 1 && qf[0] == "cgroup2" {
			return pf[4], nil
		}
	}
	return "", fmt.Errorf("%w: no cgroup2 mount in mountinfo", ErrPeer)
})

// startOf is pid's start time from /proc/<pid>/stat, in USER_HZ ticks: with the pid, what names one process over time.
func startOf(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	st, err := proc.ParseStat(b)
	if err != nil {
		return 0, err
	}
	return st.StartTicks, nil
}

// ppidOf is pid's parent from /proc/<pid>/stat, 0 when it cannot be read.
func ppidOf(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// The comm field may hold spaces and parentheses: the fields after the last ')' are state, ppid, ...
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return 0
	}
	return n
}
