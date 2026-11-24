// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// ownNamespaces is this test process's cgroup and user namespace inodes, by stat: what the rule must agree with.
func ownNamespaces(t *testing.T) (cgroup, user uint64) {
	t.Helper()
	var c, u unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &c); err != nil {
		t.Skipf("no /proc/self/ns/cgroup here: %v", err)
	}
	if err := unix.Stat("/proc/self/ns/user", &u); err != nil {
		t.Skipf("no /proc/self/ns/user here: %v", err)
	}
	return c.Ino, u.Ino
}

// TestSelfOnThisMachine: Self agrees with this process's own files. In the kernel's first cgroup namespace it is the
// path's answer alone (outside unless the tests themselves run inside a run); in any other it is never inside for a
// clean path and says why it is not outside. It leaves no descriptor open, and asking twice gives one answer.
func TestSelfOnThisMachine(t *testing.T) {
	noFDLeak(t)
	ns, _ := ownNamespaces(t)
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no /proc/self/cgroup here: %v", err)
	}
	cg, uerr := runscope.Unified(b)
	a := Self()
	t.Logf("cgroup namespace %d, path %q: %s %q (%v)", ns, cg, runscope.Describe(a).Verdict, runscope.Describe(a).Cause, runscope.Describe(a).Err)
	switch {
	case uerr != nil:
		if runscope.Describe(a).Verdict != runscope.Inside || runscope.Describe(a).Cause != runscope.CausePathMalformed {
			t.Errorf("a cgroup file that names no single path: %s %q; want inside, path-malformed", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
		}
	case runscope.LooksGoverned(cg):
		if !runscope.SaysGoverned(a) {
			t.Errorf("a governed path %q: %s %q; want inside, governed", cg, runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
		}
	case ns == runscope.InitCgroupNS:
		if !a.Outside() {
			t.Errorf("the first cgroup namespace, path %q: %s %q (%v); want outside", cg, runscope.Describe(a).Verdict, runscope.Describe(a).Cause, runscope.Describe(a).Err)
		}
	case runscope.Describe(a).Verdict == runscope.Inside || !a.Outside() && runscope.Describe(a).Cause == "":
		t.Errorf("another cgroup namespace, clean path %q: %s %q; want outside, or unknown with a cause", cg, runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
	if b := Self(); runscope.Describe(b).Verdict != runscope.Describe(a).Verdict || runscope.Describe(b).Cause != runscope.Describe(a).Cause {
		t.Errorf("asked again: %s %q, first %s %q", runscope.Describe(b).Verdict, runscope.Describe(b).Cause, runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
}

// TestOpenNamespaceVerifies: the namespace's identity is taken from a descriptor fstatfs shows to be a kernel
// namespace file. A regular file, whatever its inode, a directory and a missing path are errors, so a file made to
// carry the first namespace's inode number cannot route a process into the unchanged branch.
func TestOpenNamespaceVerifies(t *testing.T) {
	noFDLeak(t)
	want, _ := ownNamespaces(t)
	fd, ns, err := openNamespace("/proc/self/ns/cgroup")
	if err != nil || ns.Ino != want {
		t.Fatalf("openNamespace of this process's cgroup namespace = %+v, %v; want inode %d", ns, err, want)
	}
	if ty, err := fd.NamespaceType(); err != nil || ty != unix.CLONE_NEWCGROUP {
		t.Errorf("NS_GET_NSTYPE = %#x, %v; want CLONE_NEWCGROUP", ty, err)
	}
	if runscope.CgroupNSType != unix.CLONE_NEWCGROUP {
		t.Errorf("runscope.CgroupNSType = %#x; want CLONE_NEWCGROUP (%#x)", runscope.CgroupNSType, unix.CLONE_NEWCGROUP)
	}
	_ = fd.Close()
	if got, err := selfCgroupNS(); err != nil || got != want {
		t.Errorf("selfCgroupNS = %d, %v; want %d", got, err, want)
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plain, dir, filepath.Join(dir, "missing"), "/proc/self/cgroup"} {
		if fd, ns, err := openNamespace(path); err == nil {
			_ = fd.Close()
			t.Errorf("openNamespace(%s) = %+v; want an error: it is no namespace file", path, ns)
		}
	}
	if _, _, err := openNamespace(plain); !errors.Is(err, errNotNSFS) {
		t.Errorf("openNamespace of a regular file = %v; want errNotNSFS", err)
	}
	k := &selfReads{host: machine}
	k.host.selfNS = plain
	defer k.close()
	if a := runscope.Decide(k); runscope.Describe(a).Verdict != runscope.Unknown && runscope.Describe(a).Verdict != runscope.Inside || a.Outside() {
		t.Errorf("Decide over a namespace file that is a regular file = %s %q; want it refused", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	} else if runscope.Describe(a).Verdict == runscope.Unknown && runscope.Describe(a).Cause != runscope.CauseNSUnreadable {
		t.Errorf("Decide over a namespace file that is a regular file = unknown %q; want ns-unreadable", runscope.Describe(a).Cause)
	}
}

// TestAnchorProc: the rule's /proc descriptor must be the root of a procfs. A directory of another filesystem, a
// procfs directory that is not its root, a symlink and a missing path are each unanchored.
func TestAnchorProc(t *testing.T) {
	noFDLeak(t)
	fd, err := anchorProc("/proc")
	if err != nil {
		t.Skipf("no procfs at /proc here: %v", err)
	}
	defer func() { _ = fd.Close() }()
	for _, path := range []string{t.TempDir(), "/proc/sys", "/proc/1", "/proc/self", "/proc/self/cgroup", "/nonexistent-proc"} {
		got, err := anchorProc(path)
		if err == nil {
			_ = got.Close()
		}
		if !errors.Is(err, runscope.ErrUnanchored) {
			t.Errorf("anchorProc(%s) = %v; want ErrUnanchored", path, err)
		}
	}
	k := &selfReads{host: machine}
	k.host.proc = "/proc/sys"
	defer k.close()
	if _, err := k.AnchoredCgroup(); !errors.Is(err, runscope.ErrUnanchored) {
		t.Errorf("AnchoredCgroup over a /proc that is not a procfs root = %v; want ErrUnanchored", err)
	}
}

// TestAnchoredRead: a read beneath the anchor returns the file; a path that leaves the tree, follows a link the
// kernel resolves elsewhere (a magic link) or names nothing fails at the open, as unanchored, and nothing longer
// than the cap is returned.
func TestAnchoredRead(t *testing.T) {
	noFDLeak(t)
	fd, err := anchorProc("/proc")
	if err != nil {
		t.Skipf("no procfs at /proc here: %v", err)
	}
	defer func() { _ = fd.Close() }()
	want, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"self/cgroup", strconv.Itoa(os.Getpid()) + "/cgroup"} {
		if got, err := anchoredRead(fd, rel); err != nil || !bytes.Equal(got, want) {
			t.Errorf("anchoredRead(%s) = %q, %v; want %q", rel, got, err, want)
		}
	}
	if b, err := anchoredRead(fd, "1/cgroup"); err != nil {
		t.Logf("pid 1's cgroup cannot be read here (hidepid?): %v", err)
	} else if _, err := runscope.Unified(b); err != nil {
		t.Logf("pid 1's cgroup file names no single cgroup v2 path here: %v", err)
	}
	for _, c := range []struct {
		rel   string
		errno error
	}{
		{"self/ns/cgroup", unix.ELOOP},     // a magic link
		{"self/root/etc/hostname", nil},    // a magic link out of the tree
		{"self/cwd", nil},                  // a magic link
		{"../etc/hostname", unix.EXDEV},    // above the anchor
		{"/proc/self/cgroup", unix.EXDEV},  // an absolute path
		{"0/cgroup", unix.ENOENT},          // no such process
		{"self/no-such-file", unix.ENOENT}, // no such file
		{"self/cgroup/x", unix.ENOTDIR},    // through a file
		{"thread-self/../../etc", nil},     // above the anchor through a link
	} {
		b, err := anchoredRead(fd, c.rel)
		if !errors.Is(err, runscope.ErrUnanchored) || c.errno != nil && !errors.Is(err, c.errno) {
			t.Errorf("anchoredRead(%s) = %q, %v; want ErrUnanchored with %v", c.rel, b, err, c.errno)
		}
	}
	// A file longer than the cap is an error, not a truncated read.
	if b, err := anchoredRead(fd, "kallsyms"); err == nil {
		t.Errorf("anchoredRead of a file longer than the cap returned %d bytes", len(b))
	} else if !errors.Is(err, sys.ErrTooLong) && !errors.Is(err, runscope.ErrUnanchored) {
		t.Errorf("anchoredRead(kallsyms) = %v; want ErrTooLong", err)
	}
	// A mount laid over part of /proc is not crossed. binfmt_misc is one on most machines.
	var over, root unix.Stat_t
	if unix.Stat("/proc/sys/fs/binfmt_misc/status", &over) == nil && unix.Stat("/proc", &root) == nil && over.Dev != root.Dev {
		if b, err := anchoredRead(fd, "sys/fs/binfmt_misc/status"); !errors.Is(err, unix.EXDEV) || !errors.Is(err, runscope.ErrUnanchored) {
			t.Errorf("anchoredRead across a mount = %q, %v; want EXDEV, unanchored", b, err)
		}
	} else {
		t.Log("no separate mount beneath /proc here to cross")
	}
}

// probeFor is a probe of this process over the kernel, with its own descriptors, aimed at socket.
func probeFor(t *testing.T, socket string) (*selfProbe, runscope.Namespace) {
	t.Helper()
	nsfd, ns, err := openNamespace("/proc/self/ns/cgroup")
	if err != nil {
		t.Skipf("this process's cgroup namespace: %v", err)
	}
	procfd, err := anchorProc("/proc")
	if err != nil {
		_ = nsfd.Close()
		t.Skipf("no procfs at /proc here: %v", err)
	}
	p := &selfProbe{host: machine, nsfd: nsfd, procfd: procfd, socket: socket,
		connectBy: time.Now().Add(ProbeLimit - connectReserve), now: time.Now, sleep: time.Sleep}
	t.Cleanup(p.close)
	return p, ns
}

// TestProbeFactA: on the real namespace file NS_GET_NSTYPE says cgroup, and NS_GET_USERNS gives a namespace file of
// the same device whose inode is this process's own user namespace's when that is the first one (the kernel answers
// the owner only to a caller in it or above it). The descriptor the ioctl returns is closed on every path: a real
// owner, a result that is no namespace file, and an error.
func TestProbeFactA(t *testing.T) {
	noFDLeak(t)
	_, user := ownNamespaces(t)
	p, ns := probeFor(t, "")
	if ty, err := p.NSType(); err != nil || ty != runscope.CgroupNSType {
		t.Errorf("NSType = %#x, %v", ty, err)
	}
	o, err := p.Owner()
	switch {
	case user == runscope.InitUserNS && ns.Ino == runscope.InitCgroupNS:
		if err != nil || !o.NSFS || o.Ino != runscope.InitUserNS || o.Dev != ns.Dev {
			t.Errorf("Owner in the first user namespace = %+v, %v; want the first user namespace (inode %#x) on device %d",
				o, err, runscope.InitUserNS, ns.Dev)
		}
	case err == nil && o.Ino == runscope.InitUserNS && user != runscope.InitUserNS:
		t.Errorf("Owner = %+v from a process in user namespace %d: the kernel must not answer the first one there", o, user)
	default:
		t.Logf("in user namespace %d, cgroup namespace %d: Owner = %+v, %v", user, ns.Ino, o, err)
	}

	var handed *sys.FD
	plain := filepath.Join(t.TempDir(), "user")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	closed := func(name string) {
		t.Helper()
		if handed == nil {
			return
		}
		if err := handed.Borrow(func(int) error { return nil }); !errors.Is(err, sys.ErrClosed) {
			t.Errorf("%s: the descriptor NS_GET_USERNS returned is still open after Owner (%v)", name, err)
			_ = handed.Close()
		}
		handed = nil
	}
	p.host.nsOwner = func(*sys.FD) (*sys.FD, error) {
		var err error
		handed, err = sys.Own(unix.Open(plain, unix.O_RDONLY|unix.O_CLOEXEC, 0))
		return handed, err
	}
	if o, err := p.Owner(); err != nil || o.NSFS {
		t.Errorf("Owner over a result that is a regular file = %+v, %v; want not a namespace file", o, err)
	}
	closed("a regular file")
	p.host.nsOwner = func(*sys.FD) (*sys.FD, error) {
		var err error
		handed, _, err = openNamespace("/proc/self/ns/user")
		return handed, err
	}
	if o, err := p.Owner(); err != nil || !o.NSFS || o.Ino != user {
		t.Errorf("Owner over this process's own user namespace = %+v, %v; want inode %d", o, err, user)
	}
	closed("a namespace file")
	p.host.nsOwner = func(*sys.FD) (*sys.FD, error) { return nil, unix.EPERM }
	if o, err := p.Owner(); !errors.Is(err, unix.EPERM) || o.NSFS {
		t.Errorf("Owner when the ioctl is refused = %+v, %v; want EPERM", o, err)
	}
	if a := runscope.Prove(p, ns, os.Getuid()); runscope.Describe(a).Cause != runscope.CauseUserNamespace || a.Outside() {
		t.Errorf("Prove with NS_GET_USERNS refused = %s %q; want unknown, user-namespace", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
}

// rawListener is a listening unix socket nobody accepts on, with the given backlog.
func rawListener(t *testing.T, path string, backlog int) *sys.FD {
	t.Helper()
	fd, err := sys.Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	if err := fd.Borrow(func(n int) error {
		if err := unix.Bind(n, &unix.SockaddrUnix{Name: path}); err != nil {
			return err
		}
		return unix.Listen(n, backlog)
	}); err != nil {
		t.Fatal(err)
	}
	return fd
}

// socketDir is a short directory for a test's socket (a unix socket's path is at most 107 bytes).
func socketDir(t *testing.T) string {
	t.Helper()
	ln, path := listen(t)
	_ = ln.Close()
	_ = os.Remove(path)
	return filepath.Dir(path)
}

// TestProbeConnect: the probe's one connect against real sockets. A missing socket or folder is no-user-manager, a
// socket file nobody listens on is manager-not-listening, a folder the caller may not search is socket-refused, and
// a queue that stays full is retried every 20 ms and ends as manager-busy before the caller's own limit. Each ends
// with every descriptor of the probe closed.
func TestProbeConnect(t *testing.T) {
	noFDLeak(t)
	dir := socketDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "stale")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	closedDir := filepath.Join(dir, "closed")
	if err := os.Mkdir(closedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rawListener(t, filepath.Join(closedDir, "s"), 8)
	if err := os.Chmod(closedDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closedDir, 0o700) })

	cases := []struct {
		name, path string
		errno      error
		cause      runscope.Cause
	}{
		{"no socket", filepath.Join(dir, "missing"), unix.ENOENT, runscope.CauseNoUserManager},
		{"no folder", filepath.Join(dir, "no", "such", "private"), unix.ENOENT, runscope.CauseNoUserManager},
		{"a file where the folder should be", filepath.Join(file, "private"), unix.ENOTDIR, runscope.CauseNoUserManager},
		{"a socket file nobody listens on", stale, unix.ECONNREFUSED, runscope.CauseManagerNotListening},
	}
	if os.Geteuid() != 0 {
		cases = append(cases, struct {
			name, path string
			errno      error
			cause      runscope.Cause
		}{"a folder that may not be searched", filepath.Join(closedDir, "s"), unix.EACCES, runscope.CauseSocketRefused})
	}
	for _, c := range cases {
		p, _ := probeFor(t, c.path)
		err := p.Connect()
		if !errors.Is(err, c.errno) {
			t.Errorf("%s: Connect = %v; want %v", c.name, err, c.errno)
		}
		// The cause is the rule's for that errno, whatever (a) and (b) say on this machine.
		q := &connectOnly{Prober: p, err: err}
		if a := runscope.Prove(q, runscope.Namespace{Dev: 1}, os.Getuid()); runscope.Describe(a).Cause != c.cause {
			t.Errorf("%s: cause %q; want %q", c.name, runscope.Describe(a).Cause, c.cause)
		}
		p.close()
	}

	// A full accept queue: backlog 0 holds one connection nobody accepts; the next non-blocking connect is EAGAIN.
	busy := filepath.Join(dir, "busy")
	rawListener(t, busy, 0)
	first, err := net.Dial("unix", busy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	p, _ := probeFor(t, busy)
	clock := time.Unix(1000, 0)
	p.now = func() time.Time { return clock }
	sleeps := 0
	p.sleep = func(d time.Duration) {
		if d != connectEvery {
			t.Errorf("the probe slept %v between connects; want %v", d, connectEvery)
		}
		sleeps++
		clock = clock.Add(d)
	}
	p.connectBy = clock.Add(ProbeLimit - connectReserve)
	if err := p.Connect(); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("Connect to a full queue = %v; want EAGAIN at the deadline", err)
	}
	if want := int((ProbeLimit-connectReserve)/connectEvery) - 1; sleeps != want {
		t.Errorf("the probe retried %d times; want %d (every %v until %v)", sleeps, want, connectEvery, ProbeLimit-connectReserve)
	}
	if spent := clock.Sub(time.Unix(1000, 0)); spent >= ProbeLimit {
		t.Errorf("the retries took %v of the caller's %v: a full queue would read as probe-timeout", spent, ProbeLimit)
	}
	p.close()
}

// connectOnly is a Prober whose facts (a) and (b) hold and whose connect already failed with err: it lets a test
// read the cause the rule gives one real connect error on a machine where (a) or (b) would fail first.
type connectOnly struct {
	runscope.Prober
	err error
}

func (c *connectOnly) NSType() (int, error) { return runscope.CgroupNSType, nil }
func (c *connectOnly) Owner() (runscope.Owner, error) {
	return runscope.Owner{NSFS: true, Dev: 1, Ino: runscope.InitUserNS}, nil
}
func (c *connectOnly) InitCgroup() ([]byte, error) { return []byte("0::/init.scope\n"), nil }
func (c *connectOnly) Connect() error              { return c.err }

// afterAB is a Prober whose facts (a) and (b) hold and whose (c') is the kernel's.
type afterAB struct{ *selfProbe }

func (afterAB) NSType() (int, error) { return runscope.CgroupNSType, nil }
func (a afterAB) Owner() (runscope.Owner, error) {
	return runscope.Owner{NSFS: true, Dev: 1, Ino: runscope.InitUserNS}, nil
}
func (afterAB) InitCgroup() ([]byte, error) { return []byte("0::/init.scope\n"), nil }

// TestProbeListener: fact (c') against real listeners. A live listener of this uid outside the manager's cgroup
// (this test process) is identified, read through the anchored /proc, and answered peer-elsewhere; the probe sends
// it nothing and has closed its end by the time it returns. A listener that handed its socket to a child and was
// reaped is not identified: the kernel still names its pid, and the pidfd shows that no process holds it.
func TestProbeListener(t *testing.T) {
	noFDLeak(t)
	// Below Linux 6.5 there is no SO_PEERPIDFD, and the rule's answer for this listener is no-peer-pidfd (no fallback),
	// which is what the old-kernel row exists to show: the wanted cause follows the kernel, asked on a socket pair of
	// this test's own, so the listener still sees exactly one connection.
	want := runscope.CausePeerElsewhere
	if !kernelHasPeerPidfd(t) {
		want = runscope.CauseNoPeerPidfd
	}
	ln, path := listen(t)
	p, _ := probeFor(t, path)
	a := runscope.Prove(afterAB{p}, runscope.Namespace{Dev: 1}, os.Getuid())
	p.close()
	if runscope.Describe(a).Cause != want {
		t.Errorf("a listener in this test's own cgroup: %s %q (%v); want unknown, %s", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, runscope.Describe(a).Err, want)
	}
	// What the listener saw: one connection, closed, with nothing in it.
	if err := ln.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(make([]byte, 16)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("the listener read %d bytes, %v from the probe's connection; want none and the end of the stream", n, err)
	}

	// The probe's own reads of that listener, one by one.
	p, _ = probeFor(t, path)
	if err := p.Connect(); err != nil {
		t.Fatal(err)
	}
	uid, pid, err := p.PeerCred()
	if err != nil || uid != os.Geteuid() || pid != os.Getpid() {
		t.Errorf("PeerCred = %d, %d, %v; want this process", uid, pid, err)
	}
	if err := p.PeerPidfd(); errors.Is(err, unix.ENOPROTOOPT) {
		// The rule's whole answer on this kernel, from a probe of its own: a probe makes one connection (Connect is
		// the rule's step c'), so the one this test connected by hand above is closed first. Proving on it would
		// connect a second time and replace p.sock without closing the first, which noFDLeak reported on a 5.14
		// kernel (the guest row L-ROOT-PEER-OLD-KERNEL: "3 open before, 4 after; new: socket"). The product never
		// does that: Proof makes a fresh probe for every proof, TestRepeatedProbesKeepDescriptorsFlat holds it.
		p.close()
		p, _ = probeFor(t, path)
		if a := runscope.Prove(afterAB{p}, runscope.Namespace{Dev: 1}, os.Getuid()); runscope.Describe(a).Cause != runscope.CauseNoPeerPidfd {
			t.Errorf("a kernel without SO_PEERPIDFD: %s %q; want unknown, no-peer-pidfd", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
		}
		p.close() // before the skip: noFDLeak counts this probe's socket
		t.Skip("this kernel has no SO_PEERPIDFD (below Linux 6.5): the rule answers unknown, with no fallback")
	} else if err != nil {
		t.Fatal(err)
	}
	if shown, err := p.PidfdPID(); err != nil || shown != os.Getpid() {
		t.Errorf("PidfdPID = %d, %v; want %d", shown, err, os.Getpid())
	}
	own, _ := os.ReadFile("/proc/self/cgroup")
	if b, err := p.PeerCgroup(pid); err != nil || !bytes.Equal(b, own) {
		t.Errorf("PeerCgroup = %q, %v; want %q", b, err, own)
	}
	if exited, err := p.PeerExited(); err != nil || exited {
		t.Errorf("PeerExited = %v, %v", exited, err)
	}
	p.close()

	// A reaped listener.
	gone := filepath.Join(filepath.Dir(path), "gone")
	defer func() { _ = os.Remove(gone) }() // the holder exits when the socket's file is gone
	cmd := exec.Command(os.Args[0], clientArg, handoffMode, gone)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output() // waits for the listener, and reaps it
	if err != nil || !strings.Contains(string(out), "handed off") {
		t.Fatalf("the listener that hands its socket on: %v: %s", err, out)
	}
	p, _ = probeFor(t, gone)
	a = runscope.Prove(afterAB{p}, runscope.Namespace{Dev: 1}, os.Getuid())
	p.close()
	if runscope.Describe(a).Cause != runscope.CausePeerUnidentified || a.Outside() {
		t.Errorf("a listener that was reaped: %s %q (%v); want unknown, peer-unidentified", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, runscope.Describe(a).Err)
	}
}

// TestRepeatedProbesKeepDescriptorsFlat: a long-lived process that proves its membership again and again (the
// dashboard's helpers, `tego contracts` runs, a relay that checks every connection) keeps its descriptor count where
// it was, whatever the kernel: each proof makes a probe of its own, which makes one connection, and closes every
// descriptor it holds, the socket and the pidfd included, whether the proof ends in a refusal (the listener here is
// this process, in no manager's cgroup: peer-elsewhere, or no-peer-pidfd on a kernel below 6.5, the answer that
// leaked in this package's own test on the 5.14 guest) or earlier. The analysis of the report that this package leaks
// on such a kernel found the test, not the product: it connected a probe by hand and then proved on the same probe.
func TestRepeatedProbesKeepDescriptorsFlat(t *testing.T) {
	noFDLeak(t)
	_, path := listen(t)
	v, _ := testProver()
	v.backoff = 0 // every call probes, none is answered from a failure's memory
	host := machine
	host.socket = func(int) string { return path }
	k := &selfReads{host: host, prover: v}
	t.Cleanup(k.close)
	ns, err := k.CgroupNS()
	if err != nil {
		t.Skipf("this process's cgroup namespace: %v", err)
	}
	if _, err := k.AnchoredCgroup(); err != nil {
		t.Skipf("no procfs at /proc here: %v", err)
	}
	for i := 0; i < 40; i++ {
		if a := k.Proof(ns, os.Getuid()); a.Outside() {
			t.Fatalf("proof %d: a listener in this test's own cgroup was taken for the user's manager", i)
		}
	}
}

// TestProbeTheRealUserManager: where this machine has a user manager for the test's uid, the probe's fact (c') holds
// for it and for nothing else: the listener on its private socket is a live process of this uid in exactly the
// manager's cgroup. Whether it should hold is read independently first (the socket's SO_PEERCRED pid and that pid's
// cgroup file by path); the probe must agree. It connects once and sends nothing.
func TestProbeTheRealUserManager(t *testing.T) {
	noFDLeak(t)
	uid := os.Getuid()
	socket := runscope.ManagerSocket(uid)
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Skipf("no user manager to connect to at %s: %v", socket, err)
	}
	raw, _ := c.SyscallConn()
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) { cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	hasPidfd := false
	if p, perr := sys.PeerPidfdFD(raw); perr == nil {
		hasPidfd = true
		_ = p.Close()
	}
	_ = c.Close()
	if err != nil || cred.Pid <= 0 {
		t.Skipf("the manager's socket names no process here: %+v, %v", cred, err)
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(cred.Pid)), "cgroup"))
	if err != nil {
		t.Skipf("the listener's cgroup cannot be read here: %v", err)
	}
	cg, _ := runscope.Unified(b)
	expect := int(cred.Uid) == uid && cg == runscope.ManagerCgroup(uid) && hasPidfd
	p, _ := probeFor(t, socket)
	a := runscope.Prove(afterAB{p}, runscope.Namespace{Dev: 1}, uid)
	p.close()
	t.Logf("listener pid %d uid %d cgroup %q, SO_PEERPIDFD %v: %s %q (%v)", cred.Pid, cred.Uid, cg, hasPidfd, runscope.Describe(a).Verdict, runscope.Describe(a).Cause, runscope.Describe(a).Err)
	if a.Outside() != expect {
		t.Errorf("fact (c') for the user manager = %s %q; an independent read says it should hold: %v", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, expect)
	}
}

// fakeClock is a prover's clock and timers under a test's hand.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []chan time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) after(time.Duration) (<-chan time.Time, func()) {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.timers = append(c.timers, ch)
	c.mu.Unlock()
	return ch, func() {}
}

// expire fires every timer made so far: the callers waiting on them have waited the limit.
func (c *fakeClock) expire() {
	c.mu.Lock()
	for _, ch := range c.timers {
		select {
		case ch <- c.now:
		default:
		}
	}
	c.timers = nil
	c.mu.Unlock()
}

func (c *fakeClock) waiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func testProver() (*prover, *fakeClock) {
	c := &fakeClock{now: time.Unix(5000, 0)}
	v := newProver()
	v.now, v.after, v.sleep = c.Now, c.after, func(time.Duration) {}
	return v, c
}

// counted is a probe starter that counts its starts and answers what answer returns.
func counted(n *int, answer func() runscope.Answer) func() (func() runscope.Answer, error) {
	return func() (func() runscope.Answer, error) {
		*n++
		return answer, nil
	}
}

var (
	proved  = answertest.Outside()
	noProof = runscope.Unproven(runscope.CauseNoUserManager, nil)
)

// TestProverRecordsTheProbeTime: the answer of a probe carries the time the probe took on the prover's clock, and a
// proof held from it keeps that time: tego doctor prints it, and the untraced guest row W-RULE-PROBE-TIME reads it.
func TestProverRecordsTheProbeTime(t *testing.T) {
	v, clock := testProver()
	key := proofKey{dev: 4, ino: 4026532208, uid: 1000}
	slow := func() (func() runscope.Answer, error) {
		return func() runscope.Answer { clock.advance(120 * time.Millisecond); return proved }, nil
	}
	for i := range 2 {
		if a := v.prove(key, slow); !a.Outside() || runscope.Describe(a).Probe != 120*time.Millisecond {
			t.Errorf("call %d: %s; want outside with a probe of 120 ms", i, runscope.Describe(a))
		}
	}
}

// TestProverCache: only a proof is kept, per namespace and uid, for the life of the process. A failure is not kept:
// it is returned as it was for one second without probing again, then the next call probes again. The limits are
// the signed ones.
func TestProverCache(t *testing.T) {
	if ProbeLimit != 500*time.Millisecond || probeBackoff != time.Second || connectEvery != 20*time.Millisecond {
		t.Errorf("limits: probe %v, backoff %v, connect every %v", ProbeLimit, probeBackoff, connectEvery)
	}
	v, _ := testProver()
	key := proofKey{dev: 4, ino: 4026532208, uid: 1000}
	starts := 0
	for i := range 3 {
		if a := v.prove(key, counted(&starts, func() runscope.Answer { return proved })); !a.Outside() || starts != 1 {
			t.Fatalf("call %d: %s %q after %d probes; want outside from one probe", i, runscope.Describe(a).Verdict, runscope.Describe(a).Cause, starts)
		}
	}
	for _, other := range []proofKey{{dev: 4, ino: 4026532209, uid: 1000}, {dev: 4, ino: 4026532208, uid: 1001}, {dev: 5, ino: 4026532208, uid: 1000}} {
		n := 0
		if a := v.prove(other, counted(&n, func() runscope.Answer { return proved })); !a.Outside() || n != 1 {
			t.Errorf("key %+v: %s after %d probes; want its own probe", other, runscope.Describe(a).Verdict, n)
		}
	}

	v, clock := testProver()
	starts = 0
	fail := counted(&starts, func() runscope.Answer { return noProof })
	if a := v.prove(key, fail); runscope.Describe(a).Cause != runscope.CauseNoUserManager || starts != 1 {
		t.Fatalf("a failed probe: %s %q after %d probes", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, starts)
	}
	clock.advance(999 * time.Millisecond)
	if a := v.prove(key, fail); runscope.Describe(a).Cause != runscope.CauseNoUserManager || starts != 1 {
		t.Errorf("within a second of a failure: %s %q after %d probes; want the same unknown and no new probe", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, starts)
	}
	clock.advance(time.Millisecond)
	if a := v.prove(key, counted(&starts, func() runscope.Answer { return proved })); !a.Outside() || starts != 2 {
		t.Errorf("a second after a failure: %s %q after %d probes; want a new probe and its proof", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, starts)
	}
	if a := v.prove(key, fail); !a.Outside() || starts != 2 {
		t.Errorf("after the proof: %s after %d probes; want it held", runscope.Describe(a).Verdict, starts)
	}
	if a := v.prove(key, func() (func() runscope.Answer, error) { return nil, unix.EMFILE }); !a.Outside() {
		t.Errorf("a held proof needs no descriptor: %s", runscope.Describe(a).Verdict)
	}
	v, _ = testProver()
	if a := v.prove(key, func() (func() runscope.Answer, error) { return nil, unix.EMFILE }); runscope.Describe(a).Cause != runscope.CauseProbeError || a.Outside() {
		t.Errorf("a probe that could not start: %s %q; want unknown, probe-error", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
}

// TestProverOneProbeAtATime: many callers at once cause one probe, and all get its result.
func TestProverOneProbeAtATime(t *testing.T) {
	v, _ := testProver()
	key := proofKey{dev: 4, ino: 4026532208, uid: 1000}
	var mu sync.Mutex
	starts := 0
	release := make(chan struct{})
	start := func() (func() runscope.Answer, error) {
		mu.Lock()
		starts++
		mu.Unlock()
		return func() runscope.Answer { <-release; return proved }, nil
	}
	const callers = 32
	answers := make(chan runscope.Answer, callers)
	for range callers {
		go func() { answers <- v.prove(key, start) }()
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		v.mu.Lock()
		running := v.flight != nil
		v.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no probe started")
		}
		time.Sleep(time.Millisecond)
	}
	// A caller of another namespace or uid does not start a second probe while one runs.
	n := 0
	if a := v.prove(proofKey{dev: 4, ino: 1, uid: 1000}, counted(&n, func() runscope.Answer { return proved })); a.Outside() || n != 0 {
		t.Errorf("another key while a probe runs: %s after %d probes; want unknown and no second probe", runscope.Describe(a).Verdict, n)
	}
	close(release)
	for range callers {
		if a := <-answers; !a.Outside() {
			t.Errorf("a waiter got %s %q; want the probe's proof", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if starts != 1 {
		t.Errorf("%d probes for %d callers; want one", starts, callers)
	}
}

// TestProverDeadline: a caller waits at most the limit. A probe still running then is abandoned: the caller is
// answered probe-timeout, the probe's late result is discarded even when it is a proof, and no second probe starts
// while it runs.
func TestProverDeadline(t *testing.T) {
	v, clock := testProver()
	key := proofKey{dev: 4, ino: 4026532208, uid: 1000}
	release := make(chan struct{})
	ended := make(chan struct{})
	starts := 0
	hang := func() (func() runscope.Answer, error) {
		starts++
		return func() runscope.Answer { defer close(ended); <-release; return proved }, nil
	}
	got := make(chan runscope.Answer, 1)
	go func() { got <- v.prove(key, hang) }()
	waitFor(t, "the caller to wait", func() bool { return clock.waiting() == 1 })
	clock.expire() // 500 ms passed
	if a := <-got; runscope.Describe(a).Cause != runscope.CauseProbeTimeout || a.Outside() {
		t.Fatalf("a probe that hangs: %s %q; want unknown, probe-timeout", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
	// Within the back-off the same unknown comes back at once.
	n := 0
	if a := v.prove(key, counted(&n, func() runscope.Answer { return proved })); runscope.Describe(a).Cause != runscope.CauseProbeTimeout || n != 0 {
		t.Errorf("right after a timeout: %s %q after %d new probes", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, n)
	}
	// After it, the hung probe still runs: a caller waits on it and no new probe starts.
	clock.advance(2 * time.Second)
	go func() { got <- v.prove(key, counted(&n, func() runscope.Answer { return proved })) }()
	waitFor(t, "the second caller to wait", func() bool { return clock.waiting() == 1 })
	clock.expire()
	if a := <-got; runscope.Describe(a).Cause != runscope.CauseProbeTimeout || n != 0 || starts != 1 {
		t.Errorf("while the abandoned probe runs: %s %q, %d new probes, %d starts; want probe-timeout and none", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, n, starts)
	}
	// The hung probe ends with a proof: discarded.
	close(release)
	<-ended
	waitFor(t, "the abandoned probe to end", func() bool {
		v.mu.Lock()
		defer v.mu.Unlock()
		return v.flight == nil
	})
	v.mu.Lock()
	_, kept := v.proved[key]
	v.mu.Unlock()
	if kept {
		t.Error("the late result of an abandoned probe was kept as a proof")
	}
	// Only now does a new probe start.
	clock.advance(2 * time.Second)
	if a := v.prove(key, counted(&n, func() runscope.Answer { return proved })); !a.Outside() || n != 1 {
		t.Errorf("after the abandoned probe ended: %s %q after %d new probes; want a new probe's proof", runscope.Describe(a).Verdict, runscope.Describe(a).Cause, n)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// gated is a WSL shell's reads with every fact holding, over a prover that holds no proof yet: what Self reads
// there, with the kernel's part given by a table.
type gated struct {
	*selfReads
	path []byte
	caps uint64
	mode int
	ino  uint64                                  // the cgroup namespace's inode; 0 for one that is not the first
	gate func(first bool) (runscope.Cause, bool) // nil: the host's gate (selfHost.withheld)
}

func (g *gated) Withheld(first bool) (runscope.Cause, bool) {
	if g.gate != nil {
		return g.gate(first)
	}
	return g.selfReads.Withheld(first)
}

func (g *gated) OwnCgroup() ([]byte, error) { return g.path, nil }
func (g *gated) CgroupNS() (runscope.Namespace, error) {
	if g.ino != 0 {
		return runscope.Namespace{Dev: 4, Ino: g.ino}, nil
	}
	return runscope.Namespace{Dev: 4, Ino: 4026532208}, nil
}
func (g *gated) UIDs() (int, int, int)           { return 1000, 1000, 1000 }
func (g *gated) Permitted() (uint64, error)      { return g.caps, nil }
func (g *gated) Seccomp() (int, error)           { return g.mode, nil }
func (g *gated) AnchoredCgroup() ([]byte, error) { return g.path, nil }
func (g *gated) Proof(ns runscope.Namespace, uid int) runscope.Answer {
	return g.prover.prove(proofKey{dev: ns.Dev, ino: ns.Ino, uid: uid}, func() (func() runscope.Answer, error) {
		return func() runscope.Answer { return proved }, nil
	})
}

// TestCachedProofDoesNotCoverThePathOrTheCaller: the proof is of the namespace, and steps 1 to 5 run on every call.
// After a proof is held, a path that now shows a run answers inside, and a capability the process has since gained
// answers unknown; a seccomp filter is recorded on the answer and changes nothing.
func TestCachedProofDoesNotCoverThePathOrTheCaller(t *testing.T) {
	v, _ := testProver()
	host := machine
	host.release = func() (string, error) { return "6.17.0-generic", nil }
	host.exists = func(string) bool { return false }
	g := &gated{selfReads: &selfReads{host: host, prover: v}, path: []byte("0::/non-systemd\n"),
		gate: func(bool) (runscope.Cause, bool) { return "", false }} // the gate is TestGateInThisBuild's
	if a := runscope.Decide(g); !a.Outside() {
		t.Fatalf("every fact holds: %s %q", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
	g.path = []byte("0::/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-r.scope\n")
	if a := runscope.Decide(g); !runscope.SaysGoverned(a) {
		t.Errorf("a path that shows a run, after a proof: %s %q; want inside, governed", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
	g.path = []byte("0::/non-systemd\n")
	g.caps = 1 << unix.CAP_SYS_ADMIN
	if a := runscope.Decide(g); runscope.Describe(a).Cause != runscope.CauseCapabilities {
		t.Errorf("a capability gained after a proof: %s %q; want unknown, capabilities", runscope.Describe(a).Verdict, runscope.Describe(a).Cause)
	}
	g.caps, g.mode = 0, 2
	if a := runscope.Decide(g); !a.Outside() || runscope.Describe(a).Seccomp != "2" {
		t.Errorf("a filter gained after a proof: %s; want outside with the mode recorded (fact 4c is removed)", runscope.Describe(a))
	}
	g.mode = 0
	if a := runscope.Decide(g); !a.Outside() || runscope.Describe(a).Seccomp != "0" {
		t.Errorf("the facts hold again: %s", runscope.Describe(a))
	}
}

// selfChildEnv makes this test binary TestSelfInANamespaceOfItsOwn's child, which prints what Self says.
const selfChildEnv = "TEGO_PEER_SELF_CHILD"

// TestSelfInANamespaceOfItsOwnHelper prints Self's answer and this process's namespaces.
func TestSelfInANamespaceOfItsOwnHelper(t *testing.T) {
	if os.Getenv(selfChildEnv) != "1" {
		t.Skip("helper process for TestSelfInANamespaceOfItsOwn")
	}
	var c, u unix.Stat_t
	_ = unix.Stat("/proc/self/ns/cgroup", &c)
	_ = unix.Stat("/proc/self/ns/user", &u)
	b, _ := os.ReadFile("/proc/self/cgroup")
	a := Self()
	fmt.Printf("self-report verdict=%s cause=%q cgroupns=%d userns=%d uid=%d err=%q cgroup=%q\n",
		runscope.Describe(a).Verdict, runscope.Describe(a).Cause, c.Ino, u.Ino, os.Getuid(), fmt.Sprint(runscope.Describe(a).Err), b)
}

// TestSelfInANamespaceOfItsOwn: a process in a cgroup namespace it made itself, with the user namespace that let it,
// reads its cgroup relative to that namespace's root ("0::/" at the root) and cannot see a run's scope above it: an
// agent that unshares one inside its run reads just that. Self is never outside there. As root of its user namespace
// the cause is root-caller; mapped to an ordinary uid, with no capability left after the exec, the kernel's own
// answer refuses it: NS_GET_USERNS names the user namespace it made, not the first one (user-namespace). A user
// namespace alone leaves the process in its cgroup namespace, and in the first one that is the unchanged branch.
func TestSelfInANamespaceOfItsOwn(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ownNS, _ := ownNamespaces(t)
	root := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	rootGID := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	same := []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}
	sameGID := []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
	// An ordinary uid inside the namespace whoever runs the test: run as root, "its own uid" would be root, whose answer
	// is root-caller (the root suites run this as root), so the namespace's uid is a non-zero one mapped onto it.
	ordinary := []syscall.SysProcIDMap{{ContainerID: 1000, HostID: os.Getuid(), Size: 1}}
	ordinaryGID := []syscall.SysProcIDMap{{ContainerID: 1000, HostID: os.Getgid(), Size: 1}}
	both := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP)
	for _, c := range []struct {
		name   string
		attr   *syscall.SysProcAttr
		causes []runscope.Cause // any of these; nil means the first-namespace branch
	}{
		// ns-unreadable is the answer where an LSM refuses a process in a user namespace of its own the open of its
		// own namespace file (AppArmor's restriction of unprivileged user namespaces does); the rule stops there.
		{"unmapped", &syscall.SysProcAttr{Cloneflags: both},
			[]runscope.Cause{runscope.CauseUserNamespace, runscope.CauseCapabilities, runscope.CauseNSUnreadable}},
		{"root of its user namespace", &syscall.SysProcAttr{Cloneflags: both, UidMappings: root, GidMappings: rootGID},
			[]runscope.Cause{runscope.CauseRootCaller, runscope.CauseNSUnreadable}},
		{"mapped to an ordinary uid", &syscall.SysProcAttr{Cloneflags: both, UidMappings: ordinary, GidMappings: ordinaryGID},
			[]runscope.Cause{runscope.CauseUserNamespace, runscope.CauseCapabilities, runscope.CauseNSUnreadable}},
		{"a user namespace alone", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER, UidMappings: same, GidMappings: sameGID}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestSelfInANamespaceOfItsOwnHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), selfChildEnv+"=1")
			cmd.SysProcAttr = c.attr
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				// The clone or the id maps were refused: no user namespace here, so the child never ran.
				t.Skipf("no user and cgroup namespace to start the child in: %v", err)
			}
			if err != nil {
				t.Fatalf("child: %v\n%s%s", err, out, stderr.Bytes())
			}
			for line := range strings.SplitSeq(string(out), "\n") {
				rest, ok := strings.CutPrefix(line, "self-report ")
				if !ok {
					continue
				}
				t.Log(rest)
				if c.causes == nil {
					if strings.Contains(rest, fmt.Sprintf(" cgroupns=%d ", ownNS)) && ownNS == runscope.InitCgroupNS &&
						!strings.HasPrefix(rest, "verdict=outside ") && !strings.Contains(rest, `cause="governed"`) {
						t.Errorf("a user namespace alone, in the first cgroup namespace: %s; want the unchanged branch's answer", rest)
					}
					return
				}
				if strings.Contains(rest, fmt.Sprintf(" cgroupns=%d ", ownNS)) {
					t.Fatalf("the child is still in this test's cgroup namespace: %s", rest)
				}
				if !strings.Contains(rest, `cgroup="0::/\n"`) {
					t.Errorf("the child's cgroup path is not its new namespace's root: %s", rest)
				}
				if !strings.HasPrefix(rest, "verdict=unknown ") {
					t.Errorf("Self in a cgroup namespace of its own: %s; want unknown", rest)
				}
				for _, cause := range c.causes {
					if strings.Contains(rest, fmt.Sprintf(" cause=%q ", string(cause))) {
						return
					}
				}
				t.Errorf("Self in a cgroup namespace of its own: %s; want one of the causes %q", rest, c.causes)
				return
			}
			t.Fatalf("the child printed no report:\n%s%s", out, stderr.Bytes())
		})
	}
}

// kernelHasPeerPidfd reports whether this kernel answers SO_PEERPIDFD (Linux 6.5 on), asked on a socket pair of the
// test's own; ENOPROTOOPT is the answer of a kernel without it.
func kernelHasPeerPidfd(t *testing.T) bool {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }() // the pair is this test's alone
	pidfd, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	switch {
	case err == nil:
		_ = unix.Close(pidfd) // only whether the kernel answers counts
		return true
	case errors.Is(err, unix.ENOPROTOOPT):
		return false
	}
	t.Fatal(err)
	return false
}
