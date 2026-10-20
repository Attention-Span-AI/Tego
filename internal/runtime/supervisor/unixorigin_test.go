// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUnixBoundNamesTheFileStatNames is R11a's kernel half on this machine, unprivileged: SocketID and an exact
// UNIX_DIAG_VFS lookup name, for a socket bound to a pathname, the file UnixFile names at that path — owns says the
// binding names it — and the superblock device the binding reports is the one mountinfo names for the file's mount
// (MountDev), on the filesystems a write entry commonly lies on (the test's own temporary directory, and tmpfs where
// /dev/shm is one); the file reports its birth time, within the bind. A socket bound to no file has no binding, a
// closed one is gone, and a stale cookie — the inode number reused by another socket — is gone too, so a match is
// never another socket's. btrfs, where st_dev is not the superblock's, is TestUnixBoundOnBtrfs (root, in the KVM
// guest).
func TestUnixBoundNamesTheFileStatNames(t *testing.T) {
	k := sysKernel{}
	dirs := []string{shortTempDir(t)}
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() && unix.Access("/dev/shm", unix.W_OK) == nil {
		d, err := os.MkdirTemp("/dev/shm", "eyv")
		if err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			dirs = append(dirs, d)
		}
	}
	for _, dir := range dirs {
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
			fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			id, err := k.SocketID(fd)
			if err != nil {
				t.Fatalf("SocketID: %v", err)
			}
			if b, err := k.UnixBound(id); err != nil || b.bound {
				t.Fatalf("%s: an unbound socket reads %+v, %v; want no binding", dir, b, err)
			}
			p := filepath.Join(dir, "s.sock")
			_ = os.Remove(p)
			rs := &runSock{binds: []int64{bindNow()}}
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: p}); err != nil {
				t.Fatal(err)
			}
			f, err := k.UnixFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b, err := k.UnixBound(id)
			if err != nil {
				t.Skipf("no sock_diag for AF_UNIX on this kernel (R11a fails closed there): %v", err)
			}
			if o, err := owns(k, b, rs, f); o != ownsFile || err != nil {
				t.Fatalf("%s type %d: UNIX_DIAG_VFS reads %+v, the file %+v: owns = %d, %v", dir, typ, b, f, o, err)
			}
			if fit := rs.birth(f.born); fit != bornInBind {
				t.Fatalf("%s: the socket file's birth time %d is not within its bind at %d", dir, f.born, rs.binds[0])
			}
			if f.mnt == 0 {
				t.Fatalf("%s: statx reported no mount id for %s", dir, p)
			}
			if sb, err := k.MountDev(f.mnt); err != nil || sb != unix.Mkdev(b.major, b.minor) {
				t.Fatalf("%s: mountinfo names %d:%d for mount %d (%v); UNIX_DIAG_VFS's superblock is %d:%d",
					dir, unix.Major(sb), unix.Minor(sb), f.mnt, err, b.major, b.minor)
			}
			other := filepath.Join(dir, "other")
			if err := os.WriteFile(other, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			of, err := k.UnixFile(other)
			if err != nil {
				t.Fatal(err)
			}
			if o, _ := owns(k, b, rs, of); o != ownsNot {
				t.Fatalf("%s: the binding matches another file", dir)
			}
			if _, err := k.UnixBound(sockID{ino: id.ino, cookie: id.cookie + 1}); !errors.Is(err, errSocketGone) {
				t.Fatalf("a stale cookie reads %v, want errSocketGone", err)
			}
			_ = unix.Close(fd)
			if _, err := k.UnixBound(id); !errors.Is(err, errSocketGone) {
				t.Fatalf("a closed socket reads %v, want errSocketGone", err)
			}
			_ = os.Remove(p)
			_ = os.Remove(other)
		}
	}
	// An abstract name is no file.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // test socket
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@tego-r11a-test"}); err != nil {
		t.Fatal(err)
	}
	id, err := k.SocketID(fd)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := k.UnixBound(id); err != nil || b.bound {
		t.Fatalf("an abstract socket reads %+v, %v; want no binding", b, err)
	}
	if _, err := k.SocketID(int(os.Stdin.Fd())); err == nil {
		if st, _ := os.Stdin.Stat(); st != nil && st.Mode()&os.ModeSocket == 0 {
			t.Fatal("SocketID accepted a descriptor that is not a socket")
		}
	}
}

// TestOwns is R11a's comparison of what UNIX_DIAG_VFS reports (the superblock's device, the inode's low 32 bits)
// with the file a name resolves to. On btrfs st_dev is the
// subvolume's anonymous device and never the superblock's, so the superblock is read from the file's mount; where
// st_dev is not the superblock's, two subvolumes repeat their inode numbers, so the pair names a file only when it
// was born while the run's socket was being bound, and is the socket's own only when no socket outside the run
// shares it (ownsIfAlone, decided by alone); a file whose inode is wider than the 32 bits is never admitted.
func TestOwns(t *testing.T) {
	const (
		sb     = 31 // a btrfs superblock's device
		top    = 32 // its top-level subvolume's st_dev
		sub    = 33 // another subvolume's
		upper  = 40 // an overlay's upper layer, which its files can report as st_dev
		ovl    = 41 // the overlay's own superblock
		ext4   = 8<<8 | 1
		wideIn = uint64(1)<<32 | 257
	)
	f := newFake()
	f.sdevs = map[uint64]uint64{top: sb, sub: sb, upper: ovl}
	bind := func(dev, ino uint64) unixBinding {
		s := f.sdevOfLocked(dev)
		return unixBinding{bound: true, major: unix.Major(s), minor: unix.Minor(s), ino32: uint32(ino)}
	}
	at := bindNow()
	rs := &runSock{binds: []int64{at}}
	file := func(dev, ino uint64) unixFile {
		return unixFile{dev: dev, ino: ino, mnt: fakeMountBase + dev, born: at + int64(time.Millisecond)}
	}
	bornAt := func(u unixFile, born int64) unixFile { u.born = born; return u }
	before := at - int64(time.Hour)
	for _, tc := range []struct {
		name   string
		b      unixBinding
		rs     *runSock
		f      unixFile
		mntErr error
		want   ownership
		err    error
	}{
		{"ext4: the file the run bound", bind(ext4, 12), rs, file(ext4, 12), nil, ownsFile, nil},
		{"ext4: its birth time does not decide", bind(ext4, 12), rs, bornAt(file(ext4, 12), before), nil, ownsFile, nil},
		{"ext4: another inode", bind(ext4, 12), rs, file(ext4, 13), nil, ownsNot, nil},
		{"ext4 inode on another filesystem", bind(ext4, 12), rs, file(sub, 12), nil, ownsNot, nil},
		{"btrfs top-level subvolume: st_dev is not the superblock's", bind(top, 257), rs, file(top, 257), nil, ownsIfAlone, nil},
		{"btrfs subvolume", bind(sub, 257), rs, file(sub, 257), nil, ownsIfAlone, nil},
		{"btrfs: a file born before the bind is another subvolume's", bind(top, 257), rs, bornAt(file(sub, 257), before), nil, ownsNot, nil},
		{"btrfs: a file born just before the loop answered, on the coarse clock", bind(top, 257), rs,
			bornAt(file(top, 257), at-int64(bindBornSlack)+1), nil, ownsIfAlone, nil},
		{"btrfs: a file born long after the bind: a bind the loop did not record may have made it", bind(top, 257), rs,
			bornAt(file(sub, 257), at+int64(bindBornWithin)+1), nil, ownsNot, errBornUnaccounted},
		{"btrfs: a file born after the socket was seen bound", bind(top, 257), &runSock{binds: []int64{at}, seen: at + 5},
			bornAt(file(sub, 257), at+6), nil, ownsNot, nil},
		{"btrfs: no birth time reported: cannot tell", bind(top, 257), rs, bornAt(file(top, 257), 0), nil, ownsNot, errNoBirth},
		{"btrfs: born after the binds of a socket bound more times than recorded", bind(top, 257),
			&runSock{binds: []int64{at}, bindsOver: true}, bornAt(file(top, 257), at+int64(bindBornWithin)+1), nil, ownsNot, errBindUnrecorded},
		{"btrfs: born before the first bind of a socket bound more times than recorded", bind(top, 257),
			&runSock{binds: []int64{at}, bindsOver: true}, bornAt(file(top, 257), before), nil, ownsNot, nil},
		{"btrfs: a second bind after a failed one", bind(top, 257), &runSock{binds: []int64{before, at}}, file(top, 257), nil, ownsIfAlone, nil},
		{"overlay: the file reports the upper layer's device", bind(upper, 15), rs, file(upper, 15), nil, ownsIfAlone, nil},
		{"no mount id: cannot tell", bind(top, 257), rs, unixFile{dev: top, ino: 257, born: at}, nil, ownsNot, errNoMount},
		{"mountinfo unreadable: cannot tell", bind(top, 257), rs, file(top, 257), errMountUnknown, ownsNot, errNoMount},
		{"no mount id, but no inode match: foreign", bind(top, 257), rs, unixFile{dev: top, ino: 300}, nil, ownsNot, nil},
		{"a wide inode matching the low 32 bits: cannot tell", bind(ext4, 257), rs, file(ext4, wideIn), nil, ownsNot, errWideInode},
		{"a wide inode not matching them: foreign", bind(ext4, 258), rs, file(ext4, wideIn), nil, ownsNot, nil},
		{"not bound to a file", unixBinding{}, rs, file(ext4, 0), nil, ownsNot, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.mountErr = tc.mntErr
			got, err := owns(f, tc.b, tc.rs, tc.f)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("owns = %d, %v; want %d, %v", got, err, tc.want, tc.err)
			}
		})
	}
	// st_dev equal to the binding's device is the superblock's already: mountinfo is not read for it.
	f.mountErr, f.mountLookups = nil, 0
	if o, _ := owns(f, bind(ext4, 12), rs, file(ext4, 12)); o != ownsFile || f.mountLookups != 0 {
		t.Fatalf("owns = %d with %d mountinfo lookups; want ownsFile with none", o, f.mountLookups)
	}
}

// TestParseMountDevs reads mountinfo's mount id and the superblock's major:minor, skipping a line it cannot read.
func TestParseMountDevs(t *testing.T) {
	got := parseMountDevs([]byte("22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw\n" +
		"61 29 0:31 /home /home rw,relatime shared:31 - btrfs /dev/vda3 rw,subvol=/home\n" +
		"garbage\n" +
		"x 1 0:9 / /bad rw - tmpfs tmpfs rw\n" +
		"70 1 259:2 / /boot rw - ext4 /dev/nvme0n1p2 rw"))
	want := map[uint64]uint64{22: unix.Mkdev(0, 21), 61: unix.Mkdev(0, 31), 70: unix.Mkdev(259, 2)}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for id, dev := range want {
		if got[id] != dev {
			t.Fatalf("mount %d = %d, want %d (all %v)", id, got[id], dev, got)
		}
	}
}

// TestRunSocketsForgetGoneSockets: the set drops a socket the kernel no longer has, matches a socket the run renamed
// (the binding follows the inode, not the name), and past runSocketsMax it prunes the gone ones before refusing to
// remember another.
func TestRunSocketsForgetGoneSockets(t *testing.T) {
	f := newFake()
	var s runSockets
	f.boundFiles = map[sockID]fileID{}
	at := func(p string) unixFile { u, _ := f.UnixFile(p); return u }
	for i := range runSocketsMax {
		id := sockID{ino: uint64(i + 1), cookie: 1}
		name := fmt.Sprintf("/w/%d.sock", i+1)
		if !s.add(f, id, bindNow()) {
			t.Fatalf("add %d refused below the bound", i)
		}
		if i%2 == 0 {
			f.boundFiles[id] = fakeID(name)
		}
	}
	if !s.add(f, sockID{ino: 1 << 20, cookie: 1}, bindNow()) {
		t.Fatal("a full set of half-gone sockets did not prune to make room")
	}
	if len(s.ids) != runSocketsMax/2+1 {
		t.Fatalf("%d remembered after the prune, want %d", len(s.ids), runSocketsMax/2+1)
	}
	if o, _, err := s.boundTo(f, at("/w/3.sock"), newUnixPass()); o != ownsFile || err != nil {
		t.Fatalf("boundTo a live socket's file = %d, %v", o, err)
	}
	// The run renamed its socket: the file is the same, under another name, and still the run's.
	f.statIDs["/w/renamed.sock"] = fakeID("/w/3.sock")
	if o, _, err := s.boundTo(f, at("/w/renamed.sock"), newUnixPass()); o != ownsFile || err != nil {
		t.Fatalf("boundTo a socket the run renamed = %d, %v; want ownsFile", o, err)
	}
	delete(f.boundFiles, sockID{ino: 3, cookie: 1})
	if o, _, err := s.boundTo(f, at("/w/3.sock"), newUnixPass()); o != ownsNot || err != nil {
		t.Fatalf("boundTo a closed socket's file = %d, %v; want ownsNot", o, err)
	}
	for i := 0; len(s.ids) < runSocketsMax; i++ {
		id := sockID{ino: uint64(2<<20 + i), cookie: 1}
		f.boundFiles[id] = fileID{dev: 2, ino: uint64(i)}
		s.add(f, id, bindNow())
	}
	if s.add(f, sockID{ino: 3 << 20, cookie: 1}, bindNow()) {
		t.Fatal("a set full of live sockets remembered one more")
	}
}

// unixDgramLoop is a loop over a contract with a net: section and a write entry at /work, on a fake whose
// descriptors are unix datagram sockets: what R11a's datagram half decides on.
func unixDgramLoop(t *testing.T, f *fakeKernel) (*Loop, *testSink) {
	t.Helper()
	f.sockType, f.sockDomain = unix.SOCK_DGRAM, unix.AF_UNIX
	return newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil,
		[]agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}))
}

// sendUnixDgram has the run sendto a datagram naming p, and returns the answer and the line.
func sendUnixDgram(t *testing.T, f *fakeKernel, l *Loop, sink *testSink, p string) (sysResp, *record.Event) {
	t.Helper()
	sa := sockaddrUn(p)
	before := len(sink.all())
	at := 0x60000 + uint64(before)*0x200 // the fake reads the first region mapped at an address: one per send
	f.put(at, sa)
	l.handle(notifFor(sendToNR(), 4242, 5, 0x50000, 4, 0, at, uint64(len(sa))))
	r, _ := f.lastResp()
	evs := sink.all()
	if len(evs) != before+1 {
		t.Fatalf("%d lines for one datagram", len(evs)-before)
	}
	return r, evs[len(evs)-1]
}

// TestUnixDatagramOnBtrfs is R11a on a filesystem whose st_dev is not its superblock's: on btrfs the
// run's own datagram socket, in the top-level subvolume or another, is admitted, where comparing UNIX_DIAG_VFS's
// device with st_dev refused every one unix-foreign; a socket in another subvolume that repeats the inode number of
// the run's is still refused.
func TestUnixDatagramOnBtrfs(t *testing.T) {
	f := newFake()
	l, sink := unixDgramLoop(t, f)
	f.sdevs = map[uint64]uint64{32: 31, 33: 31}
	f.statIDs["/work"] = fileID{dev: 32, ino: 256}
	f.statIDs["/work/own.dg"] = fileID{dev: 32, ino: 257}
	f.statIDs["/work/sub"] = fileID{dev: 33, ino: 256}
	f.statIDs["/work/sub/own.dg"] = fileID{dev: 33, ino: 258}
	f.statIDs["/work/sub/daemon.dg"] = fileID{dev: 33, ino: 257}
	f.bindsSocket(t, l, sockID{ino: 9300, cookie: 1}, "/work/own.dg")
	f.bindsSocket(t, l, sockID{ino: 9301, cookie: 2}, "/work/sub/own.dg")
	for _, tc := range []struct {
		p       string
		verdict record.Verdict
		rule    string
	}{
		{"/work/own.dg", record.VerdictAllow, "fs.write[/work]"},
		{"/work/sub/own.dg", record.VerdictAllow, "fs.write[/work]"},
		{"/work/sub/daemon.dg", record.VerdictRefused, ruleUnixForeign},
	} {
		r, ev := sendUnixDgram(t, f, l, sink, tc.p)
		if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
			t.Errorf("%s: line %s/%s, want %s/%s", tc.p, ev.Verdict, ev.Rule, tc.verdict, tc.rule)
		}
		if continued := r.Flags != 0; continued != (tc.verdict == record.VerdictAllow) {
			t.Errorf("%s: answer %+v", tc.p, r)
		}
	}
}

// TestUnrecordedBindIsNotCalledForeign is R11a's honesty about binds it could not record: at tier
// landlock a non-dumpable process's bind (ssh-agent) cannot be read or duplicated, so its socket is not the run's
// as far as the loop knows, and a connect to it is refused — but with unix-bind-unrecorded, never unix-foreign,
// which would say no process of the run bound it. A datagram to a name that names nothing is unix-absent, answered
// with the lookup's errno.
func TestUnrecordedBindIsNotCalledForeign(t *testing.T) {
	t.Run("address unread", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		if _, ev := sendUnixDgram(t, f, l, sink, "/work/agent.sock"); ev.Rule != ruleUnixForeign {
			t.Fatalf("before any unrecorded bind: rule %s, want %s", ev.Rule, ruleUnixForeign)
		}
		// bind(fd, addr, len) whose addr the loop cannot read: nothing is mapped at 0x7a000 in the fake.
		handleBind(l, notifFor(connectNR(), 4242, 5, 0x7a000, 20))
		if r, _ := f.lastResp(); r.Flags == 0 {
			t.Fatalf("the unreadable bind was answered %+v, want CONTINUE", r)
		}
		r, ev := sendUnixDgram(t, f, l, sink, "/work/agent.sock")
		if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnixBindUnrecorded || r.Error != -int32(refusalErrno) {
			t.Fatalf("line %s/%s, answer %+v; want refused/%s with R10's errno", ev.Verdict, ev.Rule, r, ruleUnixBindUnrecorded)
		}
	})
	t.Run("socket not duplicated", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		f.dupErr = unix.EPERM
		f.bindsSocket(t, l, sockID{ino: 9400, cookie: 1}, "/work/agent.sock")
		f.dupErr = nil
		if _, ev := sendUnixDgram(t, f, l, sink, "/work/agent.sock"); ev.Rule != ruleUnixBindUnrecorded {
			t.Fatalf("the unrecorded bind's own socket: rule %s, want %s", ev.Rule, ruleUnixBindUnrecorded)
		}
		// Its path is known, so a socket at another name is still called foreign.
		if _, ev := sendUnixDgram(t, f, l, sink, "/work/daemon.sock"); ev.Rule != ruleUnixForeign {
			t.Fatalf("another socket: rule %s, want %s", ev.Rule, ruleUnixForeign)
		}
	})
	t.Run("name absent", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		f.statErrs["/work/gone.dg"] = unix.ENOENT
		r, ev := sendUnixDgram(t, f, l, sink, "/work/gone.dg")
		if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnixAbsent || r.Error != -int32(unix.ENOENT) {
			t.Fatalf("line %s/%s, answer %+v; want refused/%s with ENOENT", ev.Verdict, ev.Rule, r, ruleUnixAbsent)
		}
	})
	t.Run("lost set full", func(t *testing.T) {
		var s runSockets
		for i := range unrecordedMax {
			s.lost(fmt.Sprintf("/w/%d", i))
		}
		if s.lostAny {
			t.Fatal("lostAny set below the bound")
		}
		s.lost("/w/one-more")
		if !s.lostAny || s.unrecorded != nil {
			t.Fatal("past the bound the set still names paths")
		}
	})
}

// noDiagKernel is the fake on a kernel with no sock_diag for AF_UNIX, as the seam's prober says it (diagProber).
type noDiagKernel struct{ *fakeKernel }

func (noDiagKernel) UnixDiagAvailable() bool { return false }

// TestNoUnixDiagWarnsAtStart: a run deciding unix names on a kernel without sock_diag for AF_UNIX warns once, at the
// loop's start, that a socket under a write entry is refused unix-origin-unread; a contract with no
// net: section decides unix names in the unix-only state (ADR 0070) and is warned about too; one with host_sockets:
// true decides no unix name and is not.
func TestNoUnixDiagWarnsAtStart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		net   *agent.NetSection
		hosts bool
		want  bool
	}{{"net section", &agent.NetSection{}, false, true}, {"no net section", nil, false, true}, {"host_sockets: true", nil, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			var buf lockedBuffer
			pol := contractPolicy(&agent.Contract{Net: tc.net, HostSockets: tc.hosts}, nil, []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}})
			if _, err := New(testListener(), pol, &testSink{}, Options{kernel: noDiagKernel{newFake()}, Workers: 1,
				Log: slog.New(slog.NewTextHandler(&buf, nil))}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(buf.String(), "unix-origin-unread"); got != map[bool]int{true: 1, false: 0}[tc.want] {
				t.Fatalf("warned %d times, want %t:\n%s", got, tc.want, buf.String())
			}
		})
	}
}

// BenchmarkUnixBound is one R11a check on the real kernel: the exact UNIX_DIAG_VFS lookup of a bound socket, which
// a decision under a write entry pays once per remembered socket, and once in all for a socket a cache hit names.
func BenchmarkUnixBound(b *testing.B) {
	k := sysKernel{}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // benchmark socket
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(shortTempDir(b), "s")}); err != nil {
		b.Fatal(err)
	}
	id, err := k.SocketID(fd)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := k.UnixBound(id); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnixDump is the dump of this network namespace's unix sockets R11a makes where a file's st_dev is not its
// superblock's (btrfs, overlayfs), on the real kernel: one NLM_F_DUMP, its cost the namespace's socket count. A
// stream connect's is one pass of the unconnected sockets (needConnect), a datagram's every socket in as many
// datagrams as it takes (needDatagram).
func BenchmarkUnixDump(b *testing.B) {
	k := sysKernel{}
	if !unixDiagAvailable() {
		b.Skip("no sock_diag for AF_UNIX on this kernel")
	}
	for _, bc := range []struct {
		name string
		need dumpNeed
	}{{"stream_connect", needConnect(unix.SOCK_STREAM)}, {"datagram", needDatagram}} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				entries, err := k.UnixDump(unixDumpMax, bc.need)
				if err != nil {
					b.Fatal(err)
				}
				n = len(entries)
			}
			b.ReportMetric(float64(n), "listed")
		})
	}
}

// BenchmarkR11aSweepSettles is the settle cost: one pass that first sees
// unixPassUnboundMax of the run's sockets bound, in a set full of sockets bound to nothing with bindRecsMax binds each,
// all under runSockets.mu. A socket is settled by keeping its binding and the moment it was seen (boundLocked) and
// asked about by its binds' times (runSock.birth), so the pass does no work per remembered socket beyond its sweep;
// the cross-socket scan the review measured at about 58 ms per pass is gone.
func BenchmarkR11aSweepSettles(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		f := newFake()
		f.boundFiles, f.unboundSocks = map[sockID]fileID{}, map[sockID]bool{}
		var s runSockets
		at := bindNow()
		for i := range runSocketsMax {
			id := sockID{ino: uint64(1<<20 + i), cookie: 1}
			f.unboundSocks[id] = true
			for range bindRecsMax {
				s.add(f, id, at)
			}
		}
		for i := runSocketsMax - unixPassUnboundMax; i < runSocketsMax; i++ {
			id := sockID{ino: uint64(1<<20 + i), cookie: 1}
			delete(f.unboundSocks, id)
			f.boundFiles[id] = fileID{dev: 1, ino: uint64(1<<21 + i)}
		}
		p := newUnixPass()
		b.StartTimer()
		if o, _, err := s.boundTo(f, unixFile{dev: 1, ino: 99, mnt: fakeMountBase + 1}, p); o != ownsNot || (err != nil && !errors.Is(err, errUnixPassCap)) {
			b.Fatalf("boundTo = %d, %v", o, err)
		}
	}
}

// BenchmarkMountDev is the mountinfo lookup R11a pays where st_dev is not the binding's device (btrfs): a poll of
// the kept file and a map read, the table read again only after the namespace's mounts change.
func BenchmarkMountDev(b *testing.B) {
	k := sysKernel{}
	f, err := k.UnixFile("/")
	if err != nil || f.mnt == 0 {
		b.Skipf("no mount id for /: %+v, %v", f, err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := k.MountDev(f.mnt); err != nil {
			b.Fatal(err)
		}
	}
}

// rememberSockets has the set remember n sockets from ino base, as their binds would: the first bound of them bound
// to files of their own under /work (/work/s<i>), the rest live and bound to nothing. The kernel's lookup count is
// reset after.
func rememberSockets(t *testing.T, f *fakeKernel, l *Loop, base uint64, n, bound int) {
	t.Helper()
	f.mu.Lock()
	if f.boundFiles == nil {
		f.boundFiles = map[sockID]fileID{}
	}
	if f.unboundSocks == nil {
		f.unboundSocks = map[sockID]bool{}
	}
	f.mu.Unlock()
	for i := range n {
		id := sockID{ino: base + uint64(i), cookie: 1}
		name := fmt.Sprintf("/work/s%d", i)
		if !l.runSockets.add(f, id, bindNow()) {
			t.Fatalf("the set refused socket %d below its bound", i)
		}
		f.mu.Lock()
		if i < bound {
			f.boundFiles[id] = fakeID(name)
			f.bornLocked(fakeID(name), bindNow())
		} else {
			f.unboundSocks[id] = true
		}
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.diagLookups = 0
	f.mu.Unlock()
}

// sendUnixBatch has the run sendmmsg a batch of mmsgKernelMax datagrams, alternating between the names a and b, and
// returns the answer, the batch's first line, and the sock_diag lookups the batch made. Each call maps its regions
// at addresses of its own (the fake reads the first region mapped at an address).
func sendUnixBatch(t *testing.T, f *fakeKernel, l *Loop, sink *testSink, a, b string) (sysResp, *record.Event, int) {
	t.Helper()
	nlines := len(sink.all())
	off := uint64(nlines) * 0x10000
	arrayAddr, aAddr, bAddr := 0x1000000+off*2, 0x40000+off, 0x48000+off
	f.put(arrayAddr, mmsgArray(mmsgKernelMax, func(i int) uint64 {
		if i%2 == 1 {
			return bAddr
		}
		return aAddr
	}))
	f.put(aAddr, sockaddrUn(a))
	f.put(bAddr, sockaddrUn(b))
	f.mu.Lock()
	before := f.diagLookups
	f.mu.Unlock()
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgKernelMax, 0))
	r, _ := f.lastResp()
	evs := sink.all()
	if len(evs) <= nlines {
		t.Fatal("the batch has no line")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return r, evs[nlines], f.diagLookups - before
}

// TestR11aWorkIsBoundedPerNotification: a decision about a socket file no remembered socket is
// bound to looked up every remembered socket, once per addressed message of a sendmmsg batch, so a run holding
// thousands of sockets stalled its own loop for seconds per batch. A bound socket's binding is kept now and looked
// up again only when it names the file, a socket bound to nothing is looked up once per notification, and past
// unixPassUnboundMax such lookups the decision fails closed, unix-origin-unread.
func TestR11aWorkIsBoundedPerNotification(t *testing.T) {
	t.Run("many bound elsewhere", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		rememberSockets(t, f, l, 1<<20, runSocketsMax, runSocketsMax)
		// The first batch learns every binding (one lookup per socket in its life); the next makes none.
		if r, ev, n := sendUnixBatch(t, f, l, sink, "/work/fa", "/work/fb"); ev.Rule != ruleUnixForeign || r.Error != -int32(refusalErrno) || n != runSocketsMax {
			t.Fatalf("first batch: rule %s, answer %+v, %d lookups; want %s, refused, %d", ev.Rule, r, n, ruleUnixForeign, runSocketsMax)
		}
		r, ev, n := sendUnixBatch(t, f, l, sink, "/work/fc", "/work/fd")
		if ev.Rule != ruleUnixForeign || r.Error != -int32(refusalErrno) || n != 0 {
			t.Fatalf("second batch: rule %s, answer %+v, %d lookups; want %s, refused, none", ev.Rule, r, n, ruleUnixForeign)
		}
	})
	t.Run("some bound to nothing", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		rememberSockets(t, f, l, 1<<20, 200, 0)
		r, ev, n := sendUnixBatch(t, f, l, sink, "/work/fa", "/work/fb")
		if ev.Rule != ruleUnixForeign || r.Error != -int32(refusalErrno) || n != 200 {
			t.Fatalf("rule %s, answer %+v, %d lookups; want %s, refused, 200 (one per socket)", ev.Rule, r, n, ruleUnixForeign)
		}
	})
	t.Run("more bound to nothing than a pass asks", func(t *testing.T) {
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		rememberSockets(t, f, l, 1<<20, runSocketsMax, 0)
		r, ev, n := sendUnixBatch(t, f, l, sink, "/work/fa", "/work/fb")
		if ev.Rule != ruleUnixOriginUnread || r.Error != -int32(refusalErrno) || n > unixPassUnboundMax {
			t.Fatalf("rule %s, answer %+v, %d lookups; want %s, refused, at most %d", ev.Rule, r, n, ruleUnixOriginUnread, unixPassUnboundMax)
		}
	})
	t.Run("the run's own sockets, never looked up", func(t *testing.T) {
		// 600 binds in a burst, none looked up yet: a lookup that finds a socket bound is not counted against the
		// pass, so the oldest is found, and a batch to two of them looks each up once.
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		rememberSockets(t, f, l, 1<<20, 600, 600)
		if r, ev := sendUnixDgram(t, f, l, sink, "/work/s0"); ev.Verdict != record.VerdictAllow || r.Flags == 0 {
			t.Fatalf("the run's oldest socket: line %s/%s, answer %+v; want allow, continued", ev.Verdict, ev.Rule, r)
		}
		r, ev, n := sendUnixBatch(t, f, l, sink, "/work/s1", "/work/s599")
		if ev.Verdict != record.VerdictAllow || r.Flags == 0 || n != 2 {
			t.Fatalf("a batch to two of the run's sockets: line %s/%s, answer %+v, %d lookups; want allow, continued, 2", ev.Verdict, ev.Rule, r, n)
		}
	})
	t.Run("bound later", func(t *testing.T) {
		// A socket a pass found bound to nothing is asked again by the next notification: its bind may have been
		// in flight.
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		rememberSockets(t, f, l, 1<<20, 1, 0)
		f.statIDs["/work/late"] = fileID{dev: 1, ino: 77}
		if _, ev := sendUnixDgram(t, f, l, sink, "/work/late"); ev.Rule != ruleUnixForeign {
			t.Fatalf("before the bind: rule %s, want %s", ev.Rule, ruleUnixForeign)
		}
		id := sockID{ino: 1 << 20, cookie: 1}
		f.mu.Lock()
		delete(f.unboundSocks, id)
		f.boundFiles[id] = fileID{dev: 1, ino: 77}
		f.mu.Unlock()
		if _, ev := sendUnixDgram(t, f, l, sink, "/work/late"); ev.Verdict != record.VerdictAllow {
			t.Fatalf("after the bind: line %s/%s, want allow", ev.Verdict, ev.Rule)
		}
	})
	t.Run("many bindings share the file's low 32 bits", func(t *testing.T) {
		// btrfs subvolumes repeat inode numbers: 100 of the run's sockets, each in a subvolume of its own, all
		// inode 257, against a foreign socket of inode 257 in another. One decision reads mountinfo once.
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		f.sdevs = map[uint64]uint64{99: 31}
		f.statIDs["/work/daemon.dg"] = fileID{dev: 99, ino: 257}
		f.boundFiles = map[sockID]fileID{}
		for i := range 100 {
			id := sockID{ino: 1<<20 + uint64(i), cookie: 1}
			dev := uint64(100 + i)
			f.sdevs[dev] = 31
			f.boundFiles[id] = fileID{dev: dev, ino: 257}
			if !l.runSockets.add(f, id, bindNow()) {
				t.Fatal("the set refused a socket below its bound")
			}
		}
		for round := range 2 {
			f.mu.Lock()
			f.mountLookups = 0
			f.mu.Unlock()
			if _, ev := sendUnixDgram(t, f, l, sink, "/work/daemon.dg"); ev.Rule != ruleUnixForeign {
				t.Fatalf("round %d: rule %s, want %s", round, ev.Rule, ruleUnixForeign)
			}
			if f.mountLookups > 1 {
				t.Fatalf("round %d: %d mountinfo lookups for one decision, want at most 1", round, f.mountLookups)
			}
		}
	})
	t.Run("unrecorded paths while another worker records binds", func(t *testing.T) {
		// A bind recorded between two messages of the batch moved the set's generation, and the
		// next message stat'ed every unrecorded path again. Each is stat'ed once per notification now.
		f := newFake()
		l, sink := unixDgramLoop(t, f)
		for i := range unrecordedMax - 1 {
			l.runSockets.lost(fmt.Sprintf("/work/d/%d.sock", i))
		}
		f.mu.Lock()
		f.statCountPrefix = "/work/d/"
		f.mu.Unlock()
		stop, started, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for i := uint64(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// A socket bound and closed again: the set's generation moves, and the set stays small.
				id := sockID{ino: 1<<30 + i, cookie: 1}
				l.runSockets.add(f, id, bindNow())
				l.runSockets.mu.Lock()
				l.runSockets.dropLocked(id)
				l.runSockets.compactLocked()
				l.runSockets.mu.Unlock()
				if i == 0 {
					close(started)
				}
			}
		}()
		<-started
		r, ev, _ := sendUnixBatch(t, f, l, sink, "/work/fa", "/work/fb")
		close(stop)
		<-done
		f.mu.Lock()
		n := f.statCounted
		f.mu.Unlock()
		if ev.Rule != ruleUnixForeign || r.Error != -int32(refusalErrno) || n != unrecordedMax-1 {
			t.Fatalf("rule %s, answer %+v, %d stats of unrecorded paths; want %s, refused, %d (each once)",
				ev.Rule, r, n, ruleUnixForeign, unrecordedMax-1)
		}
	})
	t.Run("a full set is pruned at most once a second", func(t *testing.T) {
		f := newFake()
		var s runSockets
		f.boundFiles = map[sockID]fileID{}
		for i := range runSocketsMax {
			id := sockID{ino: uint64(i + 1), cookie: 1}
			f.boundFiles[id] = fileID{dev: 1, ino: uint64(i + 1)}
			s.add(f, id, bindNow())
		}
		if s.add(f, sockID{ino: 1 << 20, cookie: 1}, bindNow()) {
			t.Fatal("a set full of live sockets remembered one more")
		}
		f.mu.Lock()
		f.diagLookups = 0
		f.mu.Unlock()
		if s.add(f, sockID{ino: 1<<20 + 1, cookie: 1}, bindNow()) {
			t.Fatal("a set full of live sockets remembered one more")
		}
		if f.diagLookups != 0 {
			t.Fatalf("a bind just after a prune looked up %d sockets, want none", f.diagLookups)
		}
	})
}

// TestUnrecordedPathsAreStatedOncePerNotification: the paths of binds R11a could not record were
// stat'ed again by every question of a pass whenever the set's generation had moved, and any bind another worker
// recorded moves it, so a binder racing a sendmmsg batch to foreign sockets restored a stat of every unrecorded path
// (up to unrecordedMax, each a path the run chose) per message, under the set's lock. Each path is stat'ed at most
// once per notification now, whatever the set does meanwhile, and a path added during the pass once, when first
// asked about.
func TestUnrecordedPathsAreStatedOncePerNotification(t *testing.T) {
	f := newFake()
	f.statCountPrefix = "/work/d/"
	var s runSockets
	const held = unrecordedMax - 1 // one short of the bound, so one more path is still named
	for i := range held {
		s.lost(fmt.Sprintf("/work/d/%d.sock", i))
	}
	p := newUnixPass()
	foreign := unixFile{dev: 1, ino: 7}
	const questions = 66 // as many as one sendmmsg notification asks before its batch is refused
	for i := range questions {
		if s.mayBeUnrecorded(f, foreign, p) {
			t.Fatal("a file no unrecorded path names was taken for an unrecorded bind's")
		}
		s.add(f, sockID{ino: uint64(i + 1), cookie: 1}, bindNow()) // a bind another worker records between two messages
	}
	if f.statCounted != held {
		t.Fatalf("%d stats of unrecorded paths for %d questions of one notification, want %d (each once)",
			f.statCounted, questions, held)
	}
	// A bind that goes unrecorded during the pass adds a path: it is stat'ed when first asked about, and only it.
	s.lost("/work/d/late.sock")
	f.statIDs["/work/d/late.sock"] = foreign.id()
	if !s.mayBeUnrecorded(f, foreign, p) {
		t.Fatal("the file an unrecorded bind's path names now was not taken for its socket")
	}
	if f.statCounted != unrecordedMax {
		t.Fatalf("%d stats after one more unrecorded path, want %d", f.statCounted, unrecordedMax)
	}
	// The next notification asks again: what a path names can change between notifications.
	if !s.mayBeUnrecorded(f, foreign, newUnixPass()) || f.statCounted != 2*unrecordedMax {
		t.Fatalf("a new notification made %d stats in all, want %d", f.statCounted, 2*unrecordedMax)
	}
}
