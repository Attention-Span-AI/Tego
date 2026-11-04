// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestUnixWalkLandsWhereTheKernelDoes is the one walk every unix name takes (unixWalk, R11, R11a) on the real kernel,
// unprivileged, with this process as the task: for a bind, the directory the kernel's own bind of the same name
// creates the socket in, and for a connect or a send the socket the kernel's own lookup reaches, compared each time
// with what the kernel did with the name. A ".." after a symlink climbs from where the symlink leads, which the
// lexical spelling R11a used to stat names as another directory; /proc/self,
// /proc/thread-self and /dev/fd lead through magic links, which are refused rather than resolved as this process; a
// climb out of procfs through ".." lands where the task's does; a name that ends on procfs,
// one through a file and one that names nothing are what the task's lookup would meet; a bind's name with no final
// component binds nothing.
func TestUnixWalkLandsWhereTheKernelDoes(t *testing.T) {
	k := sysKernel{}
	d := shortTempDir(t)
	for _, p := range []string{"a", "b/deep", "x"} {
		if err := os.MkdirAll(filepath.Join(d, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../b/deep", filepath.Join(d, "a", "lnk")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(d, "dlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(d)
	pid := os.Getpid()
	dfd, err := unix.Open(d, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd) //nolint:errcheck // a test descriptor
	devFD := ""
	if st, err := os.Lstat("/dev/fd"); err == nil && st.Mode()&os.ModeSymlink != 0 {
		devFD = "/dev/fd/" + strconv.Itoa(dfd)
	}
	walk := func(name string, parent bool) (unixPlace, error) {
		return k.UnixTarget(unixQuery{tid: pid, path: name, parent: parent})
	}
	same := func(place unixPlace, p string) bool {
		var st unix.Stat_t
		return unix.Stat(p, &st) == nil && place.file.dev == st.Dev && place.file.ino == st.Ino
	}

	t.Run("bind", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			dir  string // where the kernel's bind creates the socket, relative to d; "" when the walk refuses
			err  error
		}{
			{"a/lnk/../s1.sock", "b", nil}, // lexically a/s1.sock
			{d + "/a/lnk/../s2.sock", "b", nil},
			{"s3.sock", ".", nil},
			{"dlink/s4.sock", "b", nil},
			{"/proc/self/../.." + d + "/s5.sock", ".", nil},
			{"/proc/self/cwd/s6.sock", "", unix.ELOOP},
			{"/proc/thread-self/cwd/s7.sock", "", unix.ELOOP},
			{"f/s8.sock", "", unix.ENOTDIR},
			{"nodir/s9.sock", "", unix.ENOENT},
			{"x/", "", errNoFinal},
			{"x/.", "", errNoFinal},
			{"x/..", "", errNoFinal},
		} {
			place, err := walk(tc.name, true)
			if tc.dir == "" {
				if !errors.Is(err, tc.err) {
					t.Errorf("%s: walk = %+v, %v; want %v", tc.name, place, err, tc.err)
				}
				continue
			}
			if err != nil || !same(place, filepath.Join(d, tc.dir)) || place.at != filepath.Clean(filepath.Join(d, tc.dir)) {
				t.Errorf("%s: walk = %+v, %v; want %s", tc.name, place, err, filepath.Join(d, tc.dir))
				continue
			}
			// The kernel's own bind of the name makes the socket in that directory.
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: tc.name}); err != nil {
				t.Fatalf("%s: bind: %v", tc.name, err)
			}
			var st unix.Stat_t
			if err := unix.Stat(filepath.Join(place.at, bindBase(tc.name)), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
				t.Errorf("%s: no socket file where the walk placed it (%v)", tc.name, err)
			}
			_ = unix.Close(fd)
		}
		// The kernel follows the magic links the walk refuses: what it does with them is the task's cwd.
		if devFD != "" {
			if _, err := walk(devFD+"/s10.sock", true); !errors.Is(err, unix.ELOOP) {
				t.Errorf("%s/s10.sock: %v, want ELOOP", devFD, err)
			}
		}
	})

	t.Run("send", func(t *testing.T) {
		target := filepath.Join(d, "b", "r.dg")
		rd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(rd) //nolint:errcheck // a test socket
		if err := unix.Bind(rd, &unix.SockaddrUnix{Name: target}); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("b/r.dg", filepath.Join(d, "c.dg")); err != nil {
			t.Fatal(err)
		}
		bdfd, err := unix.Open(filepath.Join(d, "b"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(bdfd) //nolint:errcheck // a test descriptor
		cases := []struct {
			name  string
			lands bool
			err   error
		}{
			{"a/lnk/../r.dg", true, nil}, // lexically a/r.dg
			{"dlink/r.dg", true, nil},
			{"c.dg", true, nil},
			{"/proc/self/../.." + target, true, nil},
			{"/proc/self/cwd/b/r.dg", false, unix.ELOOP},
			{"/proc/thread-self/cwd/b/r.dg", false, unix.ELOOP},
			{"/proc/self/status", false, errUnixProcfs},
			{"b/absent.dg", false, unix.ENOENT},
			{"b/r.dg/", false, unix.ENOTDIR},
			{"f/r.dg", false, unix.ENOTDIR},
		}
		if devFD != "" {
			cases = append(cases, struct {
				name  string
				lands bool
				err   error
			}{"/dev/fd/" + strconv.Itoa(bdfd) + "/r.dg", false, unix.ELOOP})
		}
		for _, tc := range cases {
			place, err := walk(tc.name, false)
			if !tc.lands {
				if !errors.Is(err, tc.err) {
					t.Errorf("%s: walk = %+v, %v; want %v", tc.name, place, err, tc.err)
				}
				continue
			}
			if err != nil || place.at != target || !same(place, target) {
				t.Errorf("%s: walk = %+v, %v; want %s", tc.name, place, err, target)
				continue
			}
			// The kernel's own send by the name reaches the same socket.
			s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Sendto(s, []byte("x"), 0, &unix.SockaddrUnix{Name: tc.name}); err != nil {
				t.Errorf("%s: the kernel's send: %v", tc.name, err)
			} else if n, _, err := unix.Recvfrom(rd, make([]byte, 4), unix.MSG_DONTWAIT); n != 1 || err != nil {
				t.Errorf("%s: the walk's socket received %d bytes (%v)", tc.name, n, err)
			}
			_ = unix.Close(s)
		}

		// Another process as the task, its cwd b/: a relative name is walked from its cwd, not this process's, and
		// "self" on the way is its pid, which a single openat2 made here would read as this process's (whose task
		// directory has no thread of that id, so it fails ENOENT) and the walk a component at a time answers for it.
		sleeper := exec.Command("sleep", "30")
		sleeper.Dir = filepath.Join(d, "b")
		if err := sleeper.Start(); err != nil {
			t.Skipf("no sleep to stand for another task: %v", err)
		}
		defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
		other := sleeper.Process.Pid
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"r.dg", nil},
			{"/proc/self/task/" + strconv.Itoa(other) + "/../../../.." + target, nil},
			{"/proc/self/cwd/r.dg", unix.ELOOP},
		} {
			place, err := k.UnixTarget(unixQuery{tid: other, path: tc.name})
			switch {
			case tc.err != nil && !errors.Is(err, tc.err):
				t.Errorf("as pid %d, %s: walk = %+v, %v; want %v", other, tc.name, place, err, tc.err)
			case tc.err == nil && (err != nil || place.at != target || !same(place, target)):
				t.Errorf("as pid %d, %s: walk = %+v, %v; want %s", other, tc.name, place, err, target)
			}
		}
		// A relayed connect is made to what the walk reached, so a name only the walk a component at a time resolves,
		// which reads symlinks rather than following them, is refused rather than connected (errWalkedOnly).
		task, err := k.TaskOf(other)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		climb := "/proc/self/task/" + strconv.Itoa(other) + "/../../../.." + target
		out, err := k.ConnectUnixAs(cs, task, unixSockaddr(climb), climb, func(string, unixFile) bool { return true })
		_ = unix.Close(cs)
		_ = unix.Close(task.root)
		_ = unix.Close(task.cwd)
		if out != unixUnreliable || !errors.Is(err, errWalkedOnly) {
			t.Errorf("a relayed connect to %s: %d, %v; want unixUnreliable, errWalkedOnly", climb, out, err)
		}
	})
}

// TestBoundFileIsBornInItsBind is the kernel's half of R11a's identity on the real kernel, unprivileged: a sibling
// thread rewrites a bind's sun_path in memory while the bind runs, as a sibling of the run's can between the loop's
// read and the kernel's copy after CONTINUE, and whichever name the kernel copied, the
// file it made is the one sock_diag reports the socket bound to, born after the moment recordRunSocket takes before
// it answers and within bindBornWithin of it, and the namespace's dump lists the socket under that file's binding. So
// the birth time decides which file a socket of the run's made whatever its name, and the rewrite changes nothing.
func TestBoundFileIsBornInItsBind(t *testing.T) {
	k := sysKernel{}
	if !unixDiagAvailable() {
		t.Skip("no sock_diag for AF_UNIX on this kernel (R11a fails closed there)")
	}
	d := shortTempDir(t)
	// A sockaddr_un in 4-byte words, so the rewrite is one aligned store the race detector accepts.
	var words [(sunPathOff + sunPathMax + 3) / 4]uint32
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*4)
	nameA := d + "/aaaaaaaa.sock"
	if len(nameA) >= sunPathMax-1 {
		t.Skipf("the temporary directory %s is too long for sun_path", d)
	}
	raw[0], raw[1] = byte(unix.AF_UNIX), byte(unix.AF_UNIX>>8)
	copy(raw[sunPathOff:], nameA)
	w := (sunPathOff + len(d) + 1 + 3) &^ 3 // an aligned word inside the eight a's
	valA := atomic.LoadUint32(&words[w/4])
	nb := []byte(nameA)
	copy(nb[w-sunPathOff:], "bbbb")
	var bwords [1]uint32
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&bwords[0])), 4), "bbbb")
	valB := bwords[0]
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			atomic.StoreUint32(&words[w/4], valB)
			atomic.StoreUint32(&words[w/4], valA)
		}
	}()
	defer func() { close(stop); <-done }()
	seen := map[string]int{}
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < 200 && time.Now().Before(deadline); i++ {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := k.SocketID(fd)
		if err != nil {
			t.Fatal(err)
		}
		rs := &runSock{binds: []int64{time.Now().UnixNano()}}
		_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&words[0])), uintptr(sunPathOff+len(nameA)+1))
		if errno != 0 {
			_ = unix.Close(fd)
			t.Fatalf("bind: %v", errno)
		}
		b, err := k.UnixBound(id)
		if err != nil || !b.bound {
			t.Fatalf("UnixBound: %+v, %v", b, err)
		}
		rs.b, rs.seen = b, time.Now().UnixNano()
		// The kernel's copy of sun_path need not be word-atomic, so a bind under the rewrite can make a third, mixed
		// name (GitHub's runner, 2026-11-02): the file the bind made is the one the directory holds, whatever its name.
		ents, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 {
			t.Fatalf("%d files in %s after one bind, want the one it made: %v", len(ents), d, ents)
		}
		made := filepath.Join(d, ents[0].Name())
		f, err := k.UnixFile(made)
		if err != nil {
			t.Fatalf("%s: %v", made, err)
		}
		if o, err := owns(k, b, rs, f); o != ownsFile || err != nil {
			t.Fatalf("%s: the socket's binding %+v does not name the file the bind made, %+v: %d, %v", made, b, f, o, err)
		}
		if fit := rs.birth(f.born); fit != bornInBind {
			t.Fatalf("%s: born %d, the bind answered at %d and seen bound at %d: %d, want bornInBind", made, f.born, rs.binds[0], rs.seen, fit)
		}
		if i%50 == 0 {
			entries, err := dumpWhenCalm(k, unixDumpMax, needConnect(unix.SOCK_STREAM))
			if err != nil {
				t.Fatalf("UnixDump: %v", err)
			}
			if !slices.Contains(entries, unixDumpEntry{id: id, b: b}) {
				t.Fatalf("the namespace's dump does not list the socket %+v under its binding %+v", id, b)
			}
		}
		seen[made]++
		_ = os.Remove(made)
		_ = unix.Close(fd)
	}
	if seen[nameA] == 0 || seen[string(nb)] == 0 {
		t.Logf("the rewrite never landed on one side (%v): the files were checked, the race was not exercised both ways", seen)
	}
}

// dumpCalm is how long the real-kernel dump tests wait out a crowded namespace (dumpWhenCalm).
const dumpCalm = 5 * time.Second

// dumpWhenCalm is k.UnixDump(limit, need), asked again every 50 ms for up to dumpCalm while it answers
// errUnixDumpSplit. These tests share the host's network namespace with every other process, and another test's
// sockets (a parallel run of TestUnixDumpIsOnePassOrRefused binds 4,000) crowd it past one pass of the kernel's walk
// for a while; a dump this host's own sockets keep past one pass still fails after dumpCalm.
func dumpWhenCalm(k sysKernel, limit int, need dumpNeed) ([]unixDumpEntry, error) {
	for deadline := time.Now().Add(dumpCalm); ; time.Sleep(50 * time.Millisecond) {
		entries, err := k.UnixDump(limit, need)
		if !errors.Is(err, errUnixDumpSplit) || time.Now().After(deadline) {
			return entries, err
		}
	}
}

// dumpTestSockets sizes a dump test's bound sockets and its churn burst to the descriptors this process has left,
// keeping 64 for the dumps' own sockets: in root-suites.sh's KVM guest 4,000 bound sockets and a churn of 1,500 took
// the last descriptor a dump needed (sock_diag: socket: EMFILE), and the churn ignores its own EMFILE. It asks for
// bound and burst, or two thirds and one third of what is left, and fails when that leaves fewer than 1,500 bound,
// some two and a half passes of the kernel's walk.
func dumpTestSockets(t *testing.T, bound, burst int) (int, int) {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	left := int(min(lim.Cur, 1<<20)) - len(fds) - 64
	if bound+burst > left {
		bound, burst = left*2/3, left-left*2/3
	}
	if bound < 1500 {
		t.Fatalf("RLIMIT_NOFILE %d with %d open leaves %d descriptors: too few to bind more sockets than one pass of the kernel's dump holds", lim.Cur, len(fds), left)
	}
	return bound, burst
}

// TestUnixDumpListsWhatAConnectCanReach is R11a's dump on the real kernel, unprivileged: a listener, a stream socket
// bound and not yet listening, and a datagram socket are listed under their files' bindings; a connection the
// listener accepted, which reports the listener's file too, is not, nor is a client, a socket bound to no file, or an
// abstract one; and a dump that would read more sockets than its bound fails closed. A datagram socket another one
// connected to reads TCP_ESTABLISHED, as the one that connected does (unix_dgram_connect sets both), and still takes
// datagrams from any socket, so a datagram's dump and a datagram socket's connect list both (dumpNeed.connected),
// and a stream or seqpacket socket's connect, which reaches neither (unix_find_other refuses another type), leaves
// every connected socket out (unixDumpUnconnected).
func TestUnixDumpListsWhatAConnectCanReach(t *testing.T) {
	k := sysKernel{}
	if !unixDiagAvailable() {
		t.Skip("no sock_diag for AF_UNIX on this kernel (R11a fails closed there)")
	}
	d := shortTempDir(t)
	sock := func(typ int) (int, sockID) {
		fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		id, err := k.SocketID(fd)
		if err != nil {
			t.Fatal(err)
		}
		return fd, id
	}
	bindTo := func(fd int, name string) {
		if err := unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	lfd, lid := sock(unix.SOCK_STREAM)
	bindTo(lfd, filepath.Join(d, "l.sock"))
	if err := unix.Listen(lfd, 4); err != nil {
		t.Fatal(err)
	}
	cfd, cid := sock(unix.SOCK_STREAM)
	if err := unix.Connect(cfd, &unix.SockaddrUnix{Name: filepath.Join(d, "l.sock")}); err != nil {
		t.Fatal(err)
	}
	afd, _, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(afd) })
	aid, err := k.SocketID(afd)
	if err != nil {
		t.Fatal(err)
	}
	bfd, bid := sock(unix.SOCK_STREAM)
	bindTo(bfd, filepath.Join(d, "b.sock"))
	gfd, gid := sock(unix.SOCK_DGRAM)
	bindTo(gfd, filepath.Join(d, "g.sock"))
	xfd, xid := sock(unix.SOCK_STREAM)
	bindTo(xfd, "@tego-dump-test-"+strconv.Itoa(os.Getpid()))
	_, uid := sock(unix.SOCK_DGRAM)
	kfd, kid := sock(unix.SOCK_DGRAM)
	bindTo(kfd, filepath.Join(d, "k.sock"))
	if err := unix.Connect(kfd, &unix.SockaddrUnix{Name: filepath.Join(d, "g.sock")}); err != nil {
		t.Fatal(err)
	}
	reachable := map[string]sockID{"l.sock": lid, "b.sock": bid, "g.sock": gid, "k.sock": kid}
	unreachable := map[string]sockID{"the accepted connection": aid, "the client": cid, "the abstract socket": xid, "the unbound socket": uid}
	for _, tc := range []struct {
		name string
		need dumpNeed
		// left are the reachable sockets the need leaves out: g.sock, which k.sock connected to, and k.sock.
		left []string
	}{
		{"a datagram's", needDatagram, nil},
		{"a datagram socket's connect", needConnect(unix.SOCK_DGRAM), nil},
		{"a stream socket's connect", needConnect(unix.SOCK_STREAM), []string{"g.sock", "k.sock"}},
		{"a seqpacket socket's connect", needConnect(unix.SOCK_SEQPACKET), []string{"g.sock", "k.sock"}},
	} {
		dump := k.UnixDump
		if tc.need.onePass && !tc.need.connected {
			dump = func(limit int, need dumpNeed) ([]unixDumpEntry, error) { return dumpWhenCalm(k, limit, need) }
		}
		entries, err := dump(unixDumpMax, tc.need)
		if tc.need.onePass && tc.need.connected && errors.Is(err, errUnixDumpSplit) {
			// Every connected socket of the namespace, a desktop's connected streams among them, in one pass: more
			// than one datagram holds on a busy host, where such a connect is refused unix-origin-unread.
			t.Logf("%s dump: %v (this namespace's sockets do not fit one pass)", tc.name, err)
			continue
		}
		if err != nil {
			t.Fatalf("%s dump: %v", tc.name, err)
		}
		listed := map[sockID]unixBinding{}
		for _, e := range entries {
			listed[e.id] = e.b
		}
		for name, id := range reachable {
			if slices.Contains(tc.left, name) {
				if b, ok := listed[id]; ok {
					t.Errorf("%s dump lists %s, %+v: a connected socket, which that connect cannot reach", tc.name, name, b)
				}
				continue
			}
			want, err := k.UnixBound(id)
			if err != nil || !want.bound {
				t.Fatalf("%s: UnixBound %+v, %v", name, want, err)
			}
			f, err := k.UnixFile(filepath.Join(d, name))
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := listed[id]; !ok || got != want || uint64(got.ino32) != f.ino&0xffffffff {
				t.Errorf("%s dump: %s listed %+v (%t), want its binding %+v of inode %d", tc.name, name, got, ok, want, f.ino)
			}
		}
		for name, id := range unreachable {
			if b, ok := listed[id]; ok {
				t.Errorf("%s dump lists %s, %+v: no connect or datagram reaches it through a file", tc.name, name, b)
			}
		}
		if b, err := k.UnixBound(aid); err != nil || !b.bound || b != listed[lid] {
			t.Errorf("the accepted connection reads %+v, %v: the kernel reports the listener's file for it (%+v), which is why it is left out", b, err, listed[lid])
		}
		if _, err := k.UnixDump(1, tc.need); !errors.Is(err, errUnixDumpCap) {
			t.Fatalf("%s dump bounded at one socket: %v, want errUnixDumpCap", tc.name, err)
		}
	}
}

// TestUnixDumpIsOnePassOrRefused on the real kernel, unprivileged. The kernel
// makes a dump of a namespace's unix sockets one datagram at a time and starts each from a saved index into a hash
// bucket (unix_diag_dump), so a socket that closes in that bucket between two datagrams makes the next one skip a
// socket that stayed bound throughout — and a run closes its own sockets whenever it likes, in the bucket of its own
// colliding socket among others. While a sibling makes unbound sockets and closes them in bursts, a dump a relayed
// connect asks for (one pass, here of the unconnected sockets a stream connect can reach) either lists every socket
// bound throughout or refuses, never a list missing one: with 4,000 sockets bound (at least 1,500 where descriptors
// are short, dumpTestSockets), more than one pass of the kernel's walk holds, it refuses every time; with 60 it lists
// them all. A datagram's dump (needDatagram) is read
// whole however many datagrams it takes: its decision is best effort, R11a's residual (1).
func TestUnixDumpIsOnePassOrRefused(t *testing.T) {
	k := sysKernel{}
	if !unixDiagAvailable() {
		t.Skip("no sock_diag for AF_UNIX on this kernel (R11a fails closed there)")
	}
	d := shortTempDir(t)
	need := needConnect(unix.SOCK_STREAM)
	bound := func(t *testing.T, n int, prefix string) map[sockID]bool {
		ids := make(map[sockID]bool, n)
		for i := range n {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(d, prefix+strconv.Itoa(i))}); err != nil {
				t.Fatal(err)
			}
			id, err := k.SocketID(fd)
			if err != nil {
				t.Fatal(err)
			}
			ids[id] = true
		}
		return ids
	}
	// churn makes burst unbound sockets and closes them, again and again, until stopped: each lands in a bucket of
	// the namespace's table and leaves it again, which shifts the sockets after it there.
	churn := func(burst int) (stop func()) {
		quit, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			fds := make([]int, 0, burst)
			for {
				for range burst {
					if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
						fds = append(fds, fd)
					}
				}
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
				fds = fds[:0]
				select {
				case <-quit:
					return
				default:
				}
			}
		}()
		return func() { close(quit); <-done }
	}
	dumps := func(t *testing.T, want map[sockID]bool, rounds int) (listed, refused int) {
		for round := range rounds {
			entries, err := k.UnixDump(unixDumpMax, need)
			if err != nil {
				if !errors.Is(err, errUnixDumpSplit) {
					t.Fatalf("round %d: UnixDump: %v", round, err)
				}
				refused++
				continue
			}
			listed++
			got := make(map[sockID]bool, len(entries))
			for _, e := range entries {
				got[e.id] = true
			}
			missing := 0
			for id := range want {
				if !got[id] {
					missing++
				}
			}
			if missing > 0 {
				t.Errorf("round %d: the dump listed %d sockets and left out %d of the %d bound throughout it", round, len(entries), missing, len(want))
			}
		}
		return listed, refused
	}
	t.Run("more sockets than one pass holds", func(t *testing.T) {
		n, burst := dumpTestSockets(t, 4000, 1500)
		want := bound(t, n, "m")
		stop := churn(burst)
		listed, refused := dumps(t, want, 40)
		stop()
		if listed != 0 {
			t.Errorf("%d of 40 dumps of a namespace holding %d bound sockets came back as lists (%d refused): no one pass of the kernel's walk holds them", listed, len(want), refused)
		}
		if entries, err := k.UnixDump(unixDumpMax, needDatagram); err != nil || len(entries) < len(want) {
			t.Errorf("a datagram's dump of the same namespace: %d sockets, %v; want the whole list, in as many datagrams as it takes", len(entries), err)
		}
	})
	t.Run("few enough for one pass", func(t *testing.T) {
		want := bound(t, 60, "f")
		stop := churn(150)
		listed, refused := dumps(t, want, 40)
		// Another process's sockets can crowd the shared namespace past one pass for a while (a parallel run of
		// this test binds 4,000): keep dumping, up to dumpCalm, until one lists.
		for deadline := time.Now().Add(dumpCalm); listed == 0 && time.Now().Before(deadline); {
			time.Sleep(50 * time.Millisecond)
			l, r := dumps(t, want, 1)
			listed, refused = listed+l, refused+r
		}
		stop()
		if listed == 0 {
			t.Errorf("every dump of a namespace holding %d bound sockets of this test's was refused (%d): one pass holds them", len(want), refused)
		}
	})
	// The kernel ends a datagram at the first socket whose message does not fit, so one that is nearly full may have
	// ended there, with the rest of the walk lost if the next datagram skips it. UnixDump refuses while there is
	// still a margin: binding one socket at a time, it first refuses while the kernel still sends the whole list in
	// one datagram.
	t.Run("a datagram too full to show that the walk ended", func(t *testing.T) {
		datagrams := func() int {
			fd, err := sockDiagSocket()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fd) }()
			nl := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
			buf := make([]byte, 32<<10)
			if err := unix.Sendto(fd, unixDiagRequest(sockID{}, false), 0, nl); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err := unix.Recvmsg(fd, buf, nil, 0); err != nil {
				t.Fatal(err)
			}
			req := unixDiagRequest(sockID{}, true)
			binary.NativeEndian.PutUint32(req[nlmsgHdrLen+4:], unixDumpUnconnected) // the states need asks for
			if err := unix.Sendto(fd, req, 0, nl); err != nil {
				t.Fatal(err)
			}
			with := 0
			for {
				n, _, _, _, err := unix.Recvmsg(fd, buf, nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				msgs := 0
				done, err := parseUnixDump(buf[:n], func(unixDiagMsg) bool { msgs++; return true })
				if err != nil {
					t.Fatal(err)
				}
				if msgs > 0 {
					with++
				}
				if done {
					return with
				}
			}
		}
		if _, err := dumpWhenCalm(k, unixDumpMax, need); err != nil {
			t.Fatalf("the namespace does not fit one pass before this cell binds anything (%d datagrams): %v", datagrams(), err)
		}
		for i := range 1000 {
			bound(t, 1, "t"+strconv.Itoa(i)+"-")
			_, err := k.UnixDump(unixDumpMax, need)
			if err == nil {
				continue
			}
			if !errors.Is(err, errUnixDumpSplit) {
				t.Fatalf("UnixDump: %v", err)
			}
			n := datagrams()
			if n == 1 {
				return // refused while the kernel still sent the whole list in one datagram: the margin
			}
			// A refusal that does not last, with nothing more bound, was another process's sockets passing through
			// the shared namespace (a parallel run of this test binds 4,000): bind on. One that lasts kept no margin.
			if _, err := dumpWhenCalm(k, unixDumpMax, need); err == nil {
				continue
			}
			t.Errorf("UnixDump first refused after %d more sockets, when the kernel already sent the list in %d datagrams: no margin was kept", i+1, n)
			return
		}
		t.Fatal("1,000 more bound sockets never made the dump refuse")
	})
}

// BenchmarkUnixTarget is the walk a unix datagram's decision and a bind's record pay on the real kernel, once per name
// per notification (unixTarget): the task's root and cwd opened, one openat2, the place read back and walked again in
// this process's view (unixPlaceOf), with this process as the task.
func BenchmarkUnixTarget(b *testing.B) {
	k := sysKernel{}
	d := shortTempDir(b)
	if err := os.Mkdir(filepath.Join(d, "b"), 0o755); err != nil {
		b.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a benchmark socket
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(d, "b", "r.dg")}); err != nil {
		b.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(d, "lnk")); err != nil {
		b.Fatal(err)
	}
	pid := os.Getpid()
	for _, bc := range []struct {
		name string
		q    unixQuery
	}{
		{"absolute", unixQuery{tid: pid, path: filepath.Join(d, "b", "r.dg")}},
		{"through a symlink", unixQuery{tid: pid, path: filepath.Join(d, "lnk", "r.dg")}},
		{"a bind's directory", unixQuery{tid: pid, path: filepath.Join(d, "b", "new.dg"), parent: true}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := k.UnixTarget(bc.q); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
