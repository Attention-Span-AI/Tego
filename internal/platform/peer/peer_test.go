// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil"
)

const (
	testRun = "r-0a1b2c3d-0123456789abc-xyz123"
	userApp = "/user.slice/user-1000.slice/user@1000.service/app.slice"
	// The /proc/<pid>/cgroup files the fixtures give a pid: the person's terminal, a real run's scope, and a
	// look-alike the person made in their own delegated subtree.
	terminalCgroup  = "0::" + userApp + "/app-term.scope\n"
	runCgroup       = "0::/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-" + testRun + ".scope\n"
	lookAlikeCgroup = "0::" + userApp + "/tego.slice/tego-x.slice/adopt-anything.scope\n"
)

// codeOf is the bracketed code of a Refusal, "" for nil or another error.
func codeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// TestRefuseCodes: Refuse's order and codes over identified peers: another uid first, then any run's or adoption's
// scope or a look-alike, then another, unreadable or out-of-reach cgroup namespace; a peer that was never identified
// is refused before any of them.
func TestRefuseCodes(t *testing.T) {
	const owner, ns = 1000, 4026531835
	ok := Peer{UID: owner, PID: 42, Cgroup: userApp + "/app-term.scope", CgroupNS: ns, StartBootNS: 1}
	with := func(f func(*Peer)) Peer { p := ok; f(&p); return p }
	for _, c := range []struct {
		name string
		p    Peer
		err  error
		want string
	}{
		{"the person's own terminal", ok, nil, ""},
		{"a pid-fallback peer is served, and disclosed by its caller", with(func(p *Peer) { p.PidfdFallback = true }), nil, ""},
		{"another uid", with(func(p *Peer) { p.UID = 1001 }), nil, CodeUnmappedUID},
		{"root", with(func(p *Peer) { p.UID = 0 }), nil, CodeUnmappedUID},
		{"another uid inside a run", with(func(p *Peer) { p.UID = 1001; p.Cgroup = runCgroup[3 : len(runCgroup)-1] }), nil, CodeUnmappedUID},
		{"a run's agent", with(func(p *Peer) { p.Cgroup = runCgroup[3 : len(runCgroup)-1] }), nil, CodeRunMember},
		{"below a run's scope", with(func(p *Peer) { p.Cgroup = runCgroup[3:len(runCgroup)-1] + "/x.scope" }), nil, CodeRunMember},
		{"an adoption", with(func(p *Peer) { p.Cgroup = "/tego.slice/tego-a.slice/adopt-" + testRun + ".scope" }), nil, CodeRunMember},
		{"a Docker run", with(func(p *Peer) { p.Cgroup = "/tego/a/" + testRun + "/c1" }), nil, CodeRunMember},
		{"a look-alike in the person's own subtree", with(func(p *Peer) { p.Cgroup = lookAlikeCgroup[3 : len(lookAlikeCgroup)-1] }), nil, CodeRunMember},
		{"systemd-run's run-*.scope is the person's", with(func(p *Peer) { p.Cgroup = userApp + "/run-r3f2b1c.scope" }), nil, ""},
		{"another cgroup namespace", with(func(p *Peer) { p.CgroupNS = ns + 1 }), nil, CodeCgroupNS},
		{"an unreadable cgroup namespace", with(func(p *Peer) { p.CgroupNS = 0 }), nil, CodeCgroupNS},
		{"above this namespace's root", with(func(p *Peer) { p.Cgroup = "/../../user.slice/x.scope" }), nil, CodeCgroupNS},
		{"this process's namespace unreadable", ok, os.ErrPermission, CodeCgroupNS},
		{"no pid", with(func(p *Peer) { p.PID = 0 }), nil, CodeUnidentified},
		{"no cgroup", Peer{UID: owner, PID: 42, CgroupNS: ns}, nil, CodeUnidentified},
	} {
		err := refuse(c.p, owner, ns, c.err)
		if got := codeOf(err); got != c.want || (err == nil) != (c.want == "") {
			t.Errorf("%s: refuse = %v, want code %q", c.name, err, c.want)
		}
	}
	if err := refuse(ok, owner, 0, nil); codeOf(err) != CodeCgroupNS {
		t.Errorf("refuse with this process's namespace inode 0 = %v, want [%s]", err, CodeCgroupNS)
	}
	// This process in a cgroup namespace of its own (a container's, or one an agent unshared inside its run's
	// scope): every path it reads starts at that namespace's root, so a peer sharing the namespace at its root reads
	// "/", and a run's scope above that root would not show. It is refused, wherever the root is.
	const containerNS = ns + 0x10000001
	for _, cg := range []string{"/", userApp + "/app-term.scope"} {
		p := with(func(p *Peer) { p.Cgroup, p.CgroupNS = cg, containerNS })
		if err := refuse(p, owner, containerNS, nil); codeOf(err) != CodeCgroupNS {
			t.Errorf("refuse of %q with this process and the peer in cgroup namespace %d = %v, want [%s]", cg, containerNS, err, CodeCgroupNS)
		}
	}
	if runscope.InitCgroupNS != ns {
		t.Errorf("runscope.InitCgroupNS = %d, want %d (PROC_CGROUP_INIT_INO)", runscope.InitCgroupNS, uint64(ns))
	}
	if err := refuse(Peer{UID: owner, PID: 1, Cgroup: "/x", CgroupNS: ns}, owner, ns, nil); err != nil {
		t.Errorf("refuse of a plain peer = %v", err)
	}
	r := &Refusal{Code: CodeRunMember, Detail: "pid 7 is inside a run", Err: os.ErrClosed}
	if got, want := r.Error(), "peer refused: pid 7 is inside a run: "+os.ErrClosed.Error()+" ["+CodeRunMember+"]"; got != want || !errors.Is(r, os.ErrClosed) {
		t.Errorf("Refusal.Error() = %q, want %q, wrapping its cause", got, want)
	}
}

// listen serves a unix socket in a fresh directory of the test's.
func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// t.TempDir includes the test's name, which can exhaust sockaddr_un even under a modest TMPDIR.
	dir, err := os.MkdirTemp("", "peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, path
}

// accept takes the next connection and its client's one byte, so the client has connected and written when it
// returns.
func accept(t *testing.T, ln *net.UnixListener) *net.UnixConn {
	t.Helper()
	if err := ln.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return c
}

// selfConn is a connection this process made to itself: the server's end, whose peer is this process, and the
// client's.
func selfConn(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	ln, path := listen(t)
	cl, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	if _, err := cl.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	return accept(t, ln), cl
}

// selfFacts is what this process's own /proc says, as Identify reads it.
func selfFacts(t *testing.T) Peer {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	cg, err := runscope.Unified(b)
	if err != nil {
		t.Skipf("this process has no single cgroup v2 path: %v", err)
	}
	ns, err := selfCgroupNS()
	if err != nil {
		t.Fatal(err)
	}
	st, err := proc.New().Stat(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return Peer{UID: os.Geteuid(), PID: os.Getpid(), Cgroup: cg, CgroupNS: ns, StartBootNS: st.StartBootNS()}
}

// rowEnv is the kernel-matrix row test/vm/root-suites.sh boots the suites on (its TEGO_VM_ROW, forwarded into the guest).
const rowEnv = "TEGO_VM_ROW"

// rowsWithoutPeerPidfd are the kernel-matrix rows whose kernels are below Linux 6.5 (test/vm/fetch-kernel.py: rhel-9's
// 5.14, al2023's 6.1) and so answer SO_PEERPIDFD with ENOPROTOOPT. The nightly runs this package as root on every row
// (vm-matrix.yml), and on these rows Identify takes the pidfd_open fallback against the old kernel's own pidfd_open,
// fdinfo Pid: line and poll, where TestPeerCheckFallbackWithoutPeerPidfd simulates only the getsockopt's answer. On
// such a row a kernel that answers SO_PEERPIDFD (a backport, a row moved to a newer series) fails
// TestIdentifyReadsThePeer rather than passing while the fallback ran on no real kernel.
var rowsWithoutPeerPidfd = map[string]bool{"rhel-9": true, "al2023": true}

// hasPeerPidfd reports whether this kernel answers SO_PEERPIDFD (Linux 6.5).
func hasPeerPidfd(t *testing.T, c *net.UnixConn) bool {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	p, pidfdErr := sys.PeerPidfdFD(raw)
	if pidfdErr == nil {
		_ = p.Close()
	}
	if pidfdErr != nil && !errors.Is(pidfdErr, unix.ENOPROTOOPT) {
		t.Fatalf("SO_PEERPIDFD: %v", pidfdErr)
	}
	return pidfdErr == nil
}

// TestIdentifyReadsThePeer: a connection this process made to itself is identified as this process, with this
// process's uid, pid, cgroup, cgroup namespace and start time, through SO_PEERPIDFD where the kernel has it and
// through the fallback on a row meant to lack it (rowsWithoutPeerPidfd); Refuse serves it unless the test itself
// runs inside a run.
func TestIdentifyReadsThePeer(t *testing.T) {
	noFDLeak(t)
	server, _ := selfConn(t)
	want := selfFacts(t)
	want.PidfdFallback = !hasPeerPidfd(t, server)
	if row := os.Getenv(rowEnv); rowsWithoutPeerPidfd[row] && !want.PidfdFallback {
		t.Fatalf("the %s row is meant to lack SO_PEERPIDFD (below Linux 6.5, test/vm/fetch-kernel.py) so that the fallback runs on its kernel, and this kernel answers it", row)
	}
	got, err := Identify(server)
	if err != nil || got != want {
		t.Fatalf("Identify = %+v, %v; want %+v", got, err, want)
	}
	in, inErr := runscope.InRun()
	if err := Refuse(got, os.Geteuid()); (err == nil) != (!in && inErr == nil) {
		t.Errorf("Refuse(this process) = %v; this process in a run: %v, %v", err, in, inErr)
	}
	if err := Refuse(got, os.Geteuid()+1); codeOf(err) != CodeUnmappedUID {
		t.Errorf("Refuse(this process, another owner) = %v, want [%s]", err, CodeUnmappedUID)
	}
}

// statLine is a /proc/<pid>/stat line with the given start time, in ticks.
func statLine(pid int, startTicks uint64) string {
	return fmt.Sprintf("%d (peer test) S 1 %d %d 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n", pid, pid, pid, startTicks)
}

// fixtureProc is a proc tree holding pid alone, with the given cgroup file and start time and a cgroup namespace
// file; it returns the tree and that file's inode, which Identify reads as the namespace's. Its self is this process's
// own, so the pidfd's fdinfo read through it is the kernel's: the pid it shows is the connector's in this process's
// pid namespace.
func fixtureProc(t *testing.T, pid int, cgroup string, startTicks uint64) (dirFS, uint64) {
	t.Helper()
	root := t.TempDir()
	if err := os.Symlink("/proc/self", filepath.Join(root, "self")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"cgroup": cgroup, "stat": statLine(pid, startTicks), "ns/cgroup": ""} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(dir, "ns", "cgroup"), &st); err != nil {
		t.Fatal(err)
	}
	return dirFS(root), st.Ino
}

// TestIdentifyReadsFixtureCgroups: Identify reads the cgroup, its namespace and the start time from the proc tree it
// is given, needs exactly one 0:: line there, and refuses a pid whose files are missing; Refuse then judges the
// cgroup read (a run's scope and a look-alike are [run-member]).
func TestIdentifyReadsFixtureCgroups(t *testing.T) {
	server, _ := selfConn(t)
	pid := os.Getpid()
	for _, c := range []struct {
		name, cgroup, wantCg, code string
	}{
		{"the person's terminal", terminalCgroup, userApp + "/app-term.scope", ""},
		{"a run's agent", runCgroup, runCgroup[3 : len(runCgroup)-1], CodeRunMember},
		{"a look-alike", lookAlikeCgroup, lookAlikeCgroup[3 : len(lookAlikeCgroup)-1], CodeRunMember},
		{"a hybrid host", "12:pids:/a\n1:name=systemd:/a\n" + terminalCgroup, userApp + "/app-term.scope", ""},
		{"two 0:: lines", terminalCgroup + runCgroup, "", CodeUnidentified},
		{"no 0:: line", "1:name=systemd:/a\n", "", CodeUnidentified},
		{"a relative path", "0::a/b\n", "", CodeUnidentified},
	} {
		fs, ino := fixtureProc(t, pid, c.cgroup, 77)
		h := kernel
		h.proc = fs
		got, err := h.identify(server)
		if c.wantCg == "" {
			if codeOf(err) != c.code {
				t.Errorf("%s: identify = %+v, %v; want [%s]", c.name, got, err, c.code)
			}
			continue
		}
		if err != nil || got.Cgroup != c.wantCg || got.CgroupNS != ino || got.StartBootNS != 77*proc.NanosPerTick || got.PID != pid {
			t.Errorf("%s: identify = %+v, %v; want cgroup %q, namespace %d, start 77 ticks", c.name, got, err, c.wantCg, ino)
			continue
		}
		// The fixture's namespace file is no namespace: judge the cgroup read as a server in the initial cgroup
		// namespace would, with the peer in it too.
		got.CgroupNS = runscope.InitCgroupNS
		if err := refuse(got, got.UID, runscope.InitCgroupNS, nil); codeOf(err) != c.code {
			t.Errorf("%s: refuse = %v, want code %q", c.name, err, c.code)
		}
	}
	h := kernel
	h.proc = dirFS(t.TempDir()) // the pid has no directory: gone, or never visible here
	if _, err := h.identify(server); codeOf(err) != CodeUnidentified {
		t.Errorf("identify over an empty proc tree = %v, want [%s]", err, CodeUnidentified)
	}
}

// startClient starts this test binary as a client of the socket at path.
func startClient(t *testing.T, mode, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], clientArg, mode, path)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// waitZombie waits until pid has exited, as a pidfd tells it, and is not yet reaped. Its state reads Z earlier: a
// leader whose other threads are still exiting is a zombie in /proc, and not exited to a pidfd until the last of them
// is gone (pidfd_poll's delay_group_leader), and Identify asks the pidfd.
func waitZombie(t *testing.T, pid int) {
	t.Helper()
	pidfd, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pidfd.Close() }()
	if exited, err := sys.PollPidfdFD(pidfd, 30000); err != nil || !exited {
		t.Fatalf("pid %d did not exit within 30 s: %v, %v", pid, exited, err)
	}
	if st, err := proc.New().Stat(pid); err != nil || st.State != 'Z' {
		t.Fatalf("pid %d exited but is no zombie: %+v, %v", pid, st, err)
	}
}

// TestPeerPidReuseRefused: once the process that connected has exited, nothing read under its pid is taken for it,
// even when /proc shows a live process outside every run there (the pid reused). The connector here exits right
// after its connect: still a zombie, and again once reaped, its pid free for anyone, with the proc tree showing
// another process of the same uid in the person's terminal under it. Through SO_PEERPIDFD the pidfd names the
// connector itself and its exit refuses the connection (ErrExited); on the fallback the connection it closed does.
func TestPeerPidReuseRefused(t *testing.T) {
	ln, path := listen(t)
	cmd := startClient(t, "exit", path)
	server := accept(t, ln)
	pid := cmd.Process.Pid
	waitZombie(t, pid)
	pidfd := hasPeerPidfd(t, server)

	if p, err := Identify(server); codeOf(err) != CodeUnidentified {
		t.Errorf("Identify of a connector that exited (a zombie) = %+v, %v; want [%s]", p, err, CodeUnidentified)
	}
	reused, _ := fixtureProc(t, pid, terminalCgroup, 99) // the pid as another process holding it would show it
	h := kernel
	h.proc = reused
	p, err := h.identify(server)
	switch {
	case codeOf(err) != CodeUnidentified:
		t.Errorf("identify of a zombie connector whose pid shows another process = %+v, %v; want [%s]", p, err, CodeUnidentified)
	case pidfd && !errors.Is(err, ErrExited):
		t.Errorf("identify with SO_PEERPIDFD = %v; want the connector's exit (ErrExited) to refuse it", err)
	case !pidfd && !errors.Is(err, errHungUp):
		t.Errorf("identify on the fallback = %v; want the closed connection (errHungUp) to refuse it", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("client: %v", err)
	}
	if p, err := h.identify(server); codeOf(err) != CodeUnidentified {
		t.Errorf("identify of a reaped connector whose pid shows another process = %+v, %v; want [%s]", p, err, CodeUnidentified)
	}
}

// reusedAfterOpen is a proc tree in which another process takes the pid between Identify's first and second read of
// its start time: what a pid reused after the fallback's pidfd_open looks like.
type reusedAfterOpen struct {
	dirFS
	reads int
}

func (r *reusedAfterOpen) startBootNS(pid int) (uint64, error) {
	r.reads++
	ns, err := r.dirFS.startBootNS(pid)
	return ns + uint64(r.reads-1)*proc.NanosPerTick, err
}

// ownedBy is a proc tree whose pid belongs to another uid.
type ownedBy struct {
	dirFS
	uid int
}

func (o ownedBy) owner(int) (int, error) { return o.uid, nil }

// TestPeerCheckFallbackWithoutPeerPidfd: on a kernel without SO_PEERPIDFD (below Linux 6.5) Identify opens a pidfd on
// the SO_PEERCRED pid instead and says so (PidfdFallback, which a caller discloses as WarnPidfdFallback), and it then
// re-checks what ADR 0042 (vii) names: a pid now held by another uid, a start time that changed while it read, and a
// connection the peer has closed are each refused. The kernel's answer is simulated here; the rhel-9 and al2023 rows
// give it for real.
func TestPeerCheckFallbackWithoutPeerPidfd(t *testing.T) {
	noFDLeak(t)
	noPeerPidfd := kernel
	noPeerPidfd.noPeerPidfd = true
	server, client := selfConn(t)
	want := selfFacts(t)
	want.PidfdFallback = true
	got, err := noPeerPidfd.identify(server)
	if err != nil || got != want {
		t.Fatalf("identify on the fallback = %+v, %v; want %+v", got, err, want)
	}
	if WarnPidfdFallback != "peer-pidfd-fallback" {
		t.Errorf("WarnPidfdFallback = %q, the name ADR 0100 gives the warning", WarnPidfdFallback)
	}

	pid := os.Getpid()
	fs, _ := fixtureProc(t, pid, terminalCgroup, 5)
	for _, c := range []struct {
		name string
		proc procFS
		want string
	}{
		{"the pid taken by another process after the open", &reusedAfterOpen{dirFS: fs}, "taken by another process"},
		{"the pid held by another uid", ownedBy{dirFS: fs, uid: os.Geteuid() + 1}, "held by uid"},
	} {
		h := noPeerPidfd
		h.proc = c.proc
		if p, err := h.identify(server); codeOf(err) != CodeUnidentified || !containsDetail(err, c.want) {
			t.Errorf("%s: identify = %+v, %v; want [%s] saying %q", c.name, p, err, CodeUnidentified, c.want)
		}
	}
	// A connector reaped before the open: its pid names no process, and pidfd_open says so.
	ln, path := listen(t)
	cmd := startClient(t, "exit", path)
	gone := accept(t, ln)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := noPeerPidfd.identify(gone); codeOf(err) != CodeUnidentified || !errors.Is(err, unix.ESRCH) {
		t.Errorf("identify when pidfd_open finds no process = %v, want [%s] with ESRCH", err, CodeUnidentified)
	}
	// A client that sends its request and then shuts down its writing side (nc -N, a one-shot client) is alive and
	// still reads the reply: it is identified there as through SO_PEERPIDFD, and refused once it closes the socket.
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := noPeerPidfd.identify(server); err != nil || got != want {
		t.Errorf("identify of a connection whose peer shut down its writing side = %+v, %v; want %+v", got, err, want)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := noPeerPidfd.identify(server); !errors.Is(err, errHungUp) {
		t.Errorf("identify of a connection whose peer closed it = %v, want errHungUp", err)
	}
}

// shownAs is a proc tree that shows the pidfd's process under another pid than the connector's.
type shownAs struct {
	dirFS
	pid int
}

func (s shownAs) pidfdPID(*sys.FD) (int, error) { return s.pid, nil }

// TestIdentifyBindsProcToThePidfd: whatever the tree holds under the SO_PEERCRED pid, Identify reads it only when
// the tree shows the pidfd's process as that pid; another pid (a /proc of another pid namespace), 0 (no pid there) and
// -1 (reaped) are each [peer-unidentified], through SO_PEERPIDFD and on the fallback, and so is a tree with no self.
func TestIdentifyBindsProcToThePidfd(t *testing.T) {
	server, _ := selfConn(t)
	pid := os.Getpid()
	fs, _ := fixtureProc(t, pid, terminalCgroup, 5)
	for _, fallback := range []bool{false, true} {
		h := kernel
		h.noPeerPidfd = fallback
		for _, shown := range []int{pid + 1, 1, 0, -1} {
			h.proc = shownAs{dirFS: fs, pid: shown}
			if p, err := h.identify(server); codeOf(err) != CodeUnidentified || !containsDetail(err, "pid namespace") {
				t.Errorf("fallback %v, the pidfd's process shown as pid %d: identify = %+v, %v; want [%s]", fallback, shown, p, err, CodeUnidentified)
			}
		}
		h.proc = fs
		if _, err := h.identify(server); err != nil {
			t.Errorf("fallback %v, the pidfd's process shown as its own pid: identify = %v", fallback, err)
		}
		if err := os.Remove(filepath.Join(string(fs), "self")); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if _, err := h.identify(server); codeOf(err) != CodeUnidentified {
			t.Errorf("fallback %v, a tree with no self: identify = %v; want [%s]", fallback, err, CodeUnidentified)
		}
		if err := os.Symlink("/proc/self", filepath.Join(string(fs), "self")); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIdentifyForeignProcRefused: a server in a pid namespace of its own whose /proc is still its parent's (entered
// without remounting /proc) would read /proc/<SO_PEERCRED pid> as another process: the connector is pid 1 there, and
// /proc/1 is the host's init. Identify proves the /proc it reads is the connector's own: the pid that /proc shows for
// the pidfd's process (its fdinfo) must be the SO_PEERCRED pid. Here it is not, so the peer is [peer-unidentified],
// through SO_PEERPIDFD and on the fallback alike.
func TestIdentifyForeignProcRefused(t *testing.T) {
	cmd := exec.Command(os.Args[0], clientArg, "identify-self", filepath.Join(t.TempDir(), "s"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		// The clone was refused: no user namespace here, so the child never ran.
		t.Skipf("no user and pid namespace to start the child in: %v", err)
	}
	if err != nil {
		t.Fatalf("child: %v\n%s%s", err, out, stderr.Bytes())
	}
	seen := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, identifyReport+" ")
		if !ok {
			continue
		}
		seen++
		if !strings.Contains(rest, " code="+CodeUnidentified+" ") || !strings.Contains(rest, " pid=1 ") ||
			!strings.Contains(rest, "pid namespace") {
			t.Errorf("Identify of pid 1 in a pid namespace whose /proc is its parent's: %s; want [%s], naming the pid namespace",
				rest, CodeUnidentified)
		}
	}
	if seen != 2 {
		t.Fatalf("the child printed %d reports, want 2:\n%s%s", seen, out, stderr.Bytes())
	}
}

// containsDetail reports whether err is a Refusal whose detail holds s.
func containsDetail(err error, s string) bool {
	var r *Refusal
	return errors.As(err, &r) && strings.Contains(r.Detail, s)
}

// noFDLeak is testutil.NoFDLeak once the network poller exists: its descriptors are made on the process's first
// socket, whichever test that is, and are no test's leak.
func noFDLeak(t *testing.T) {
	t.Helper()
	ln, _ := listen(t)
	_ = ln.Close()
	testutil.NoFDLeak(t)
}
