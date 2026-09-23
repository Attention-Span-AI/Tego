// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Peer admission (R19a).
//
// A loopback TCP socket has no owner. Every process on the host — any uid, any cgroup, and a page in the
// developer's browser by way of a cross-origin POST that is never preflighted — can open
// http://127.0.0.1:<port> and be served. That is the shape of CVE-2025-52882 (Claude Code's IDE
// extensions accepted WebSocket connections from any origin, CWE-1385, CVSS 8.8) and of CVE-2025-49596
// (MCP Inspector's proxy accepted unauthenticated requests that launched MCP commands, CWE-306, CVSS
// 9.4). The run's Landlock ruleset and cgroup rules bind the agent; they say nothing about the rest of
// the machine, so they do not answer this. Left unanswered it is worse here than for an ordinary proxy,
// because the ledger is the product: an unauthenticated writer can append an ssl_request the agent never
// made to a hash chain that is authenticated as to ordering and not as to origin, and can hold the run's
// whole capture budget (§3) so that the agent's own exchanges record truncated.
//
// docs/p0/capture-derive.md §11 resolves the listener to TCP only, so the peer is identified after the
// fact rather than by a unix socket's SO_PEERCRED. Three kernel interfaces answer it, and all three are
// readable by an unprivileged process for its own descendants:
//
//   - /proc/net/tcp and /proc/net/tcp6 map the connection's 4-tuple to the peer socket's inode (proc(5)), and
//     so does one exact sock_diag lookup, which procAdmitter asks first (sockdiag.go);
//   - /proc/<pid>/fd holds a "socket:[<inode>]" symlink for every socket a process owns (proc(5));
//   - /proc/<pid>/cgroup names the unified-hierarchy cgroup of a process (cgroups(7)).
//
// The agent is cloned directly into the run's cgroup (CLONE_INTO_CGROUP, docs/p0/runtime-launch.md §6)
// and has no write access to the cgroup tree, so it cannot leave it: "holds this socket and is in the
// run's cgroup subtree" is exactly "belongs to this run".
//
// The check is an allow-list walk, not a search: only processes already in the run's cgroup are asked
// whether they hold the socket, so a refusal never depends on being able to read another user's
// /proc/<pid>/fd, and every failure to answer the question refuses the connection.

// peerAdmitter reports whether the process that opened a connection belongs to the run, returning its pid
// and nil when it does. The pid is what the connection's lines are stamped with (R34); 0 is a peer the
// admitter admitted without naming it (a test's). It is a field on Listener so a test can serve a peer this
// machine cannot place in a run's cgroup; production has exactly one implementation, procPeerAdmitter.
type peerAdmitter func(peer, local netip.AddrPort, runCgroup uint64) (int, error)

// peerVerdict is one connection's admission decision. It is resolved as the connection is first read, before
// its first request (capListener, which counts the connection under the run's bound or an outsider's by it),
// and reused for the rest of it: the walk reads /proc, and a keep-alive connection carrying a whole
// conversation must pay for that once rather than per call (R19a, §9 Benchmarks).
type peerVerdict struct {
	once sync.Once
	pid  int
	err  error
}

// peerVerdictKey is the context key ConnContext stores the verdict under.
type peerVerdictKey struct{}

// admitPeer is the check ServeHTTP makes before anything else, including R22's local health answer: a
// connection this listener cannot place in the run is served nothing at all. It returns the pid of the run's
// process that holds the connection, which its lines carry.
func (l *Listener) admitPeer(r *http.Request) (int, error) {
	v, _ := r.Context().Value(peerVerdictKey{}).(*peerVerdict)
	if v == nil {
		// A handler reached without going through the server's accept path (a direct ServeHTTP call)
		// has no per-connection state to cache in; the question is still asked.
		return l.resolvePeer(r)
	}
	v.once.Do(func() { v.pid, v.err = l.resolvePeer(r) })
	return v.pid, v.err
}

// resolvePeer names the two endpoints of this connection and asks the admitter about them. Both come
// from net/http rather than from a header: RemoteAddr and LocalAddrContextKey are filled in from the
// accepted socket itself, so nothing the client sends can move them.
func (l *Listener) resolvePeer(r *http.Request) (int, error) {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return l.resolveAddrs(r.RemoteAddr, la)
}

// resolveConn is resolvePeer for an accepted connection, before any request has been read from it (capListener):
// the same two endpoints, from the socket itself.
func (l *Listener) resolveConn(c net.Conn) (int, error) {
	return l.resolveAddrs(c.RemoteAddr().String(), c.LocalAddr())
}

// resolveAddrs places the peer at remote, connected to la, in the run or refuses it.
func (l *Listener) resolveAddrs(remote string, la net.Addr) (int, error) {
	peer, err := netip.ParseAddrPort(remote)
	if err != nil {
		return 0, fmt.Errorf("%w: peer address %q: %w", ErrPeer, remote, err)
	}
	if la == nil {
		return 0, fmt.Errorf("%w: the connection from %s has no local address", ErrPeer, peer)
	}
	local, err := netip.ParseAddrPort(la.String())
	if err != nil {
		return 0, fmt.Errorf("%w: local address %q: %w", ErrPeer, la, err)
	}
	run := l.runRef()
	if run.CgroupID == 0 {
		// Nothing can be placed in a cgroup the run does not know the id of. createCgroup fails the
		// run when the cgroup itself cannot be made (docs/p0/runtime-launch.md §4.1 step 2), so this
		// is the narrow case of a run whose cgroup exists but whose id could not be read — and a
		// listener that cannot authenticate is one that serves nobody, never one that serves anyone.
		return 0, fmt.Errorf("%w: the run has no cgroup id to place a peer in", ErrPeer)
	}
	return l.peers(unmapped(peer), unmapped(local), run.CgroupID)
}

// unmapped strips the v4-in-v6 wrapper a v4 address can carry when it is read back through a dual-stack
// socket, so the two sides of the comparison against the kernel's table are in one form (the same
// normalization AddrPort makes).
func unmapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// refusePeer answers a connection that is not the run's and records that it happened.
//
// It is deliberately not a gap what=capture: nothing of the agent's own traffic was missed, and the run's
// gap report is coverage, not an intrusion log — the same reasoning R38 applies in the other direction,
// where a forwarder bypass is enforce's refusal rather than capture's gap. The ledger has no event shape
// for "a process outside the run was turned away at the forwarder" in spec/record/v1: `gap why` is closed
// to R37's six values and `refused` is the supervisor's own shape, whose reason set and last-refusal.json
// both describe the agent. So the refusal is counted and logged here, and the missing record shape is
// written down as a limitation in docs/p0/capture-derive.md §11 rather than borrowed from a value that
// would misdescribe it.
//
// Only the first refusal of a listener is logged at warn level: the port is reachable by anything on the
// host, so an attacker chooses how many refusals happen and must not be able to choose how much the run's
// log grows.
func (l *Listener) refusePeer(w http.ResponseWriter, r *http.Request, err error) {
	n := l.refused.Add(1)
	args := []any{"run", l.runRef().ID, "host", l.model.Host, "peer", r.RemoteAddr,
		"method", r.Method, "refused", n, "err", err}
	if n == 1 {
		l.opts.Logger.Warn("forwarder: refused a peer outside the run", args...)
	} else {
		l.opts.Logger.Debug("forwarder: refused a peer outside the run", args...)
	}
	// Identity admission belongs to the entire physical connection. No later
	// stream can become authorized; close it after the answer and reclaim its
	// outsider slot even when it keeps sending refused HTTP/2 requests.
	closeHTTPConnection(w)
	http.Error(w, "this listener serves only the run it was bound for", http.StatusForbidden)
}

// procPeerAdmitter is the admitter as it was before the sock_diag lookup, and what procAdmitter falls back to: the
// peer's socket inode from the kernel's TCP table, then every process on the host read for its cgroup and each of
// the run's asked whether it holds the socket.
func procPeerAdmitter(peer, local netip.AddrPort, runCgroup uint64) (int, error) {
	inode, err := peerSocketInode(peer, local)
	if err != nil {
		return 0, err
	}
	return socketHeldByCgroup(inode, runCgroup)
}

// procNetTCP are the tables a loopback connection can appear in: a v4 connection in the first, a v6 or
// v4-mapped one in the second. Both are scanned because Options.Listen may name either family.
var procNetTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// peerSocketInode finds the inode of the socket on the other end of this connection: the row whose local
// address is the peer and whose remote address is this listener. Both endpoints of a loopback connection
// are in the table — the listener's own accepted socket is the row with those two reversed — so the pair
// has to match in that order, not as an unordered set.
func peerSocketInode(peer, local netip.AddrPort) (uint64, error) {
	for _, name := range procNetTCP {
		f, err := os.Open(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // a kernel built without IPv6 has no tcp6 table
			}
			return 0, fmt.Errorf("%w: open %s: %w", ErrPeer, name, err)
		}
		inode, found, err := scanTCPTable(f, peer, local)
		_ = f.Close()
		if err != nil {
			return 0, err
		}
		if found {
			return inode, nil
		}
	}
	return 0, fmt.Errorf("%w: no socket for %s -> %s in the kernel's tcp table", ErrPeer, peer, local)
}

// tcpTableInodeField is the index of the inode column in a /proc/net/tcp row, counting the leading "sl:"
// as column 0: sl, local_address, rem_address, st, tx_queue:rx_queue, tr:tm->when, retrnsmt, uid,
// timeout, inode (proc(5), net/ipv4/tcp_ipv4.c get_tcp4_sock).
const tcpTableInodeField = 9

// scanTCPTable reads one /proc/net/tcp-shaped table, returning the inode of the row that is the peer's
// side of this connection.
func scanTCPTable(r io.Reader, peer, local netip.AddrPort) (uint64, bool, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	sc.Scan() // the column header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= tcpTableInodeField {
			continue
		}
		rowLocal, ok := parseProcAddrPort(fields[1])
		if !ok {
			continue
		}
		rowRemote, ok := parseProcAddrPort(fields[2])
		if !ok {
			continue
		}
		if rowLocal != peer || rowRemote != local {
			continue
		}
		inode, err := strconv.ParseUint(fields[tcpTableInodeField], 10, 64)
		if err != nil {
			return 0, false, fmt.Errorf("%w: tcp table inode %q: %w", ErrPeer, fields[tcpTableInodeField], err)
		}
		if inode == 0 {
			// An orphaned socket, closed by its process and lingering in FIN_WAIT2 or TIME_WAIT, has no inode. No
			// process holds it, and every descriptor that is not a socket also reads as inode 0, so 0 would match
			// any process of the run.
			return 0, false, fmt.Errorf("%w: the socket for %s -> %s has no inode: no process holds it", ErrPeer,
				peer, local)
		}
		return inode, true, nil
	}
	if err := sc.Err(); err != nil {
		return 0, false, fmt.Errorf("%w: read tcp table: %w", ErrPeer, err)
	}
	return 0, false, nil
}

// parseProcAddrPort reads one "address:port" cell of a /proc/net/tcp row.
//
// The kernel prints the address with %08X straight off the in-memory __be32 (four of them for v6), so on
// a little-endian host each group of eight hex digits reads back as a little-endian u32 whose four bytes
// are the address in network order: 0100007F is 127.0.0.1. Tego releases amd64 and arm64
// (.goreleaser.yaml), both little-endian; on a big-endian host every cell would read back byte-reversed,
// no row would match, and every peer would be refused — the safe direction for a check whose failure
// closes the listener rather than opening it. The port is printed big-endian and needs no swap.
func parseProcAddrPort(cell string) (netip.AddrPort, bool) {
	host, portText, ok := strings.Cut(cell, ":")
	if !ok || len(host) == 0 || len(host)%8 != 0 || len(host) > 32 {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw := make([]byte, 0, len(host)/2)
	for i := 0; i < len(host); i += 8 {
		word, err := strconv.ParseUint(host[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		raw = append(raw, byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, false
	}
	// A v4-mapped v6 row and a v4 row name the same peer; the caller's addresses are unmapped too.
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// socketHeldByCgroup reports whether any process in the run's cgroup subtree holds this socket, and returns
// the first that does, in /proc's order: a socket a process shares with the children it forked is named by the
// lowest pid holding it, usually the parent that opened it.
//
// The walk is over the run's processes rather than over the socket's owner: asking "who holds inode N"
// means reading every process's /proc/<pid>/fd, which for another user's process is a permission error
// that would have to be interpreted, and interpreting it is how a check like this ends up fail-open.
// Asking "does one of ours hold it" reads only directories this process may read, and anything it cannot
// establish is a refusal.
func socketHeldByCgroup(inode, runCgroup uint64) (int, error) {
	mount, err := cgroup2Mount()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("%w: read /proc: %w", ErrPeer, err)
	}
	link := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	// Processes of one run share a cgroup path, and every process on the host shares its ancestors, so
	// the subtree answer is memoized per path for the length of one walk.
	inRun := make(map[string]bool)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // /proc has more than processes in it
		}
		cgPath, err := procCgroupPath(pid)
		if err != nil {
			continue // exited between the listing and the read, or not ours to read
		}
		member, known := inRun[cgPath]
		if !known {
			member = cgroupInSubtree(mount, cgPath, runCgroup)
			inRun[cgPath] = member
		}
		if member && holdsSocket(pid, link) {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("%w: socket inode %d is held by no process in cgroup %d", ErrPeer, inode, runCgroup)
}

// holdsSocket reports whether a process's fd table contains this socket. Any error is a no: a process
// that cannot be read is not evidence of membership.
func holdsSocket(pid int, link string) bool {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		target, err := os.Readlink(dir + "/" + e.Name())
		if err == nil && target == link {
			return true
		}
	}
	return false
}

// cgroupInSubtree reports whether a /proc/<pid>/cgroup path is the run's own cgroup or one nested beneath
// it, by the id the run carries: on cgroup2 a cgroup's id is its directory's inode number, which is what
// RunRef.CgroupID holds (internal/runtime/enforce/cgroup's cgroupIDOfPath, and what
// bpf_get_current_cgroup_id() reports). The path is walked upward because membership is of the subtree,
// the same test the fanotify listener makes on the enforcement side.
func cgroupInSubtree(mount, cgPath string, runCgroup uint64) bool {
	for p := cgPath; ; p = path.Dir(p) {
		if id, err := cgroupIDOf(mount + p); err == nil && id == runCgroup {
			return true
		}
		if p == "/" || p == "." || p == "" {
			return false
		}
	}
}

// cgroupIDOf is the inode number of one cgroup directory.
func cgroupIDOf(dir string) (uint64, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%w: %s has no stat", ErrPeer, dir)
	}
	return st.Ino, nil
}

// procCgroupPath is the unified hierarchy's path for one process: the line with hierarchy id 0 and an
// empty controller list ("0::/path"). v1 lines are ignored, and the file is parsed defensively because it
// is read for a process the run does not control (cgroups(7)).
func procCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(strings.TrimRight(string(data), "\n"), "\n") {
		id, rest, ok := strings.Cut(line, ":")
		if !ok || id != "0" {
			continue
		}
		controllers, p, ok := strings.Cut(rest, ":")
		if !ok || controllers != "" || !strings.HasPrefix(p, "/") {
			continue
		}
		// The kernel appends " (deleted)" for a removed cgroup a task is still in.
		return strings.TrimSuffix(p, " (deleted)"), nil
	}
	return "", fmt.Errorf("%w: /proc/%d/cgroup has no unified line", ErrPeer, pid)
}

// cgroup2Mount is where the unified hierarchy is mounted, read once per process: it is a property of the
// machine, and a run that outlives a remount of /sys/fs/cgroup has larger problems than its forwarder.
var cgroup2Mount = sync.OnceValues(func() (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("%w: read mountinfo: %w", ErrPeer, err)
	}
	if mount, ok := parseCgroup2Mount(string(data)); ok {
		return mount, nil
	}
	return "", fmt.Errorf("%w: no cgroup2 mount in mountinfo", ErrPeer)
})

// parseCgroup2Mount finds the cgroup2 mount point in a mountinfo file. The optional fields before the
// " - " separator are variable in number, which is why the filesystem type is read from the right of it
// and the mount point from the fixed left-hand columns (proc(5) "/proc/[pid]/mountinfo").
func parseCgroup2Mount(mountinfo string) (string, bool) {
	for line := range strings.SplitSeq(mountinfo, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		if fs := strings.Fields(right); len(fs) == 0 || fs[0] != "cgroup2" {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) < 5 {
			continue
		}
		return unescapeMountPath(fields[4]), true
	}
	return "", false
}

// unescapeMountPath undoes the octal escaping mountinfo applies to space, tab, newline and backslash in a
// mount point.
func unescapeMountPath(p string) string {
	if !strings.Contains(p, `\`) {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+3 < len(p) {
			if v, err := strconv.ParseUint(p[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}
