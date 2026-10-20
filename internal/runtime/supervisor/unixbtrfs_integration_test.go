// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The decision plane's btrfs fixture (internal/runtime/enforce/cgroup/testdata): an empty 16 MiB btrfs, gzipped, so
// mounting it needs only root, mount's loop option and the kernel's btrfs, which root-suites.sh's guests load.
const (
	btrfsFixture     = "../enforce/cgroup/testdata/btrfs-mixed-16m.img.gz"
	btrfsFixtureSize = 16 << 20
	// _IOW(BTRFS_IOCTL_MAGIC, n, struct btrfs_ioctl_vol_args), whose size is 4096 (linux/btrfs.h).
	btrfsForgetDev    = 0x50009405
	btrfsSubvolCreate = 0x5000940e
)

// btrfsArgs is struct btrfs_ioctl_vol_args.
type btrfsArgs struct {
	FD   int64
	Name [4088]byte
}

// mountBtrfsFixture mounts a private copy of the fixture at dir and creates the named subvolumes in it. It skips on
// a kernel with no btrfs and needs root.
func mountBtrfsFixture(t *testing.T, dir string, subvolumes ...string) {
	t.Helper()
	gz, err := os.ReadFile(btrfsFixture)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, btrfsFixtureSize+1))
	if err != nil || len(raw) != btrfsFixtureSize {
		t.Fatalf("btrfs fixture: %d bytes, %v", len(raw), err)
	}
	image := filepath.Join(t.TempDir(), "btrfs.img")
	if err := os.WriteFile(image, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Every mount of the fixture carries one fsid; forget the unmounted copies an earlier cell left registered.
	if fd, err := unix.Open("/dev/btrfs-control", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		var args btrfsArgs
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), btrfsForgetDev, uintptr(unsafe.Pointer(&args)))
		_ = unix.Close(fd)
		if errno != 0 {
			t.Fatalf("forget unmounted btrfs devices: %v", errno)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "mount", "-t", "btrfs", "-o", "loop,nosuid,nodev", image, dir).CombinedOutput(); err != nil {
		if fs, _ := os.ReadFile("/proc/filesystems"); !bytes.Contains(fs, []byte("\tbtrfs\n")) {
			t.Skipf("the kernel has no btrfs (root-suites.sh's guests load it, VM_MODULES): mount: %v\n%s", err, out)
		}
		t.Fatalf("mount the btrfs fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(dir, 0); err != nil {
			_ = unix.Unmount(dir, unix.MNT_DETACH)
		}
	})
	parent, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent) //nolint:errcheck // a directory this helper opened
	for _, name := range subvolumes {
		var args btrfsArgs
		copy(args.Name[:], name)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(parent), btrfsSubvolCreate, uintptr(unsafe.Pointer(&args))); errno != 0 {
			t.Fatalf("create subvolume %s: %v", name, errno)
		}
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
}

// TestUnixBoundOnBtrfs is R11a's kernel half on btrfs, as root in the KVM guest: UNIX_DIAG_VFS reports the
// superblock's device, while stat(2)'s st_dev is the subvolume's own — the
// top-level subvolume's included — so a comparison with st_dev never matched and every socket the run bound on btrfs
// was refused unix-foreign. owns reads the superblock from the file's mount (mountinfo), and the file btrfs makes
// for a bind reports a birth time within it, so the socket's own file in the top-level subvolume and in another is
// its own if no other socket shares the binding. Two fresh subvolumes repeat their first inode number (257), so one
// socket's binding is the other's file's too: the other file is born after the first socket was seen bound, which
// rules it out, and the namespace's dump lists both sockets under the one binding, which alone refuses unless both
// are the run's.
func TestUnixBoundOnBtrfs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts the btrfs fixture (root-suites.sh)")
	}
	k := sysKernel{}
	if !unixDiagAvailable() {
		t.Fatal("no sock_diag for AF_UNIX in the guest (root-suites.sh loads unix_diag)")
	}
	mnt := filepath.Join(shortTempDir(t), "b")
	mountBtrfsFixture(t, mnt, "s1", "s2")
	type bound struct {
		id sockID
		rs *runSock
		f  unixFile
	}
	at := map[string]bound{}
	for _, rel := range []string{"top.sock", "s1/a.sock", "s2/a.sock"} {
		// Each subvolume's files are made more than the coarse clock's lag after the last's sockets were seen bound,
		// so a birth time tells them apart (inode times lag the clock the loop reads by up to a tick).
		time.Sleep(4 * bindBornSlack)
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
			p := filepath.Join(mnt, rel)
			if typ == unix.SOCK_DGRAM {
				p += ".dg"
			}
			fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			id, err := k.SocketID(fd)
			if err != nil {
				t.Fatal(err)
			}
			rs := &runSock{binds: []int64{time.Now().UnixNano()}}
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: p}); err != nil {
				t.Fatal(err)
			}
			b, err := k.UnixBound(id)
			if err != nil {
				t.Fatal(err)
			}
			rs.b, rs.seen = b, time.Now().UnixNano()
			f, err := k.UnixFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if unix.Mkdev(b.major, b.minor) == f.dev {
				t.Fatalf("%s: st_dev %d:%d is the superblock's here, so this is not the btrfs case", p, b.major, b.minor)
			}
			if f.born == 0 {
				t.Fatalf("%s: btrfs reported no birth time (statx STATX_BTIME), which R11a needs here", p)
			}
			if o, err := owns(k, b, rs, f); o != ownsIfAlone || err != nil {
				t.Errorf("%s: UNIX_DIAG_VFS %+v, file %+v, binds %v: owns = %d, %v; want ownsIfAlone", p, b, f, rs.binds, o, err)
			}
			at[filepath.Base(filepath.Dir(p))+"/"+filepath.Base(p)] = bound{id, rs, f}
		}
	}
	// s1/a.sock and s2/a.sock are each their fresh subvolume's first file: one inode number, one superblock.
	s1, s2 := at["s1/a.sock"], at["s2/a.sock"]
	if s1.f.ino != s2.f.ino || s1.rs.b != s2.rs.b {
		t.Fatalf("the two subvolumes' sockets do not collide (%+v / %+v), so the cell proves nothing", s1, s2)
	}
	if o, err := owns(k, s1.rs.b, s1.rs, s2.f); o != ownsNot || err != nil {
		t.Errorf("s1's socket admits s2's file, which repeats its inode number and was born after s1 was seen bound: owns = %d, %v", o, err)
	}
	// The dump lists both sockets under the one binding (and any other this cell made that repeats the number, the
	// top-level subvolume's first file among them): alone holds only when every one of them is the run's.
	var set runSockets
	for name, s := range at {
		if name != "s2/a.sock" {
			set.add(k, s.id, s.rs.binds[0])
		}
	}
	// Each need's dump lists them: a stream connect's (one pass, the unconnected sockets), a datagram socket's
	// connect's (one pass, every socket) and a datagram's (every socket, however many datagrams).
	needs := []dumpNeed{needConnect(unix.SOCK_STREAM), needConnect(unix.SOCK_DGRAM), needDatagram}
	for _, need := range needs {
		if err := set.alone(k, s1.rs.b.key(), s1.f, newUnixPass(), need); !errors.Is(err, errBindingShared) {
			t.Errorf("alone (%+v) with s2's socket outside the set: %v, want errBindingShared", need, err)
		}
	}
	set.add(k, s2.id, s2.rs.binds[0])
	for _, need := range needs {
		if err := set.alone(k, s1.rs.b.key(), s1.f, newUnixPass(), need); err != nil {
			t.Errorf("alone (%+v) with every socket of the cell in the set: %v, want nil", need, err)
		}
	}
}

// TestIntegrationUnixRelayOnBtrfs is R11a end to end on btrfs, as root in the KVM guest: the target
// binds a socket in the top-level subvolume and one in a subvolume under its write directory and connects to each
// (admitted: the run bound them, and the files were born in their binds), and to the harness's socket in a third
// subvolume (refused unix-foreign, and the listener accepts nothing). The harness's socket is not its subvolume's
// first file here, so it repeats no inode number of the target's: the collisions are btrfsCollision's.
func TestIntegrationUnixRelayOnBtrfs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts the btrfs fixture (root-suites.sh)")
	}
	var foreign net.Listener
	h := startHarnessWith(t, harnessOpts{
		mode: modeUnixRelay,
		prepare: func(d string) {
			mountBtrfsFixture(t, filepath.Join(d, "b"), "s1", "s2")
			for i := range 16 { // past the inode numbers the target's two sockets take
				if err := os.WriteFile(filepath.Join(d, "b", "s2", "f"+strconv.Itoa(i)), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			ln, err := net.Listen("unix", filepath.Join(d, "b", "s2", "x.sock"))
			if err != nil {
				t.Fatal(err)
			}
			foreign = ln
			t.Cleanup(func() { _ = ln.Close() })
		},
		env: []string{helperOwnSocks + "=b/own.sock,b/s1/own.sock",
			helperUnixPaths + "=own_top=b/own.sock,own_sub=b/s1/own.sock,foreign=b/s2/x.sock"},
	})
	h.stop(t)
	for _, c := range []struct{ name, want string }{{"own_top", ""}, {"own_sub", ""}, {"foreign", "EACCES"}} {
		got := h.check(t, c.name).Err
		if (c.want == "" && got != "") || (c.want != "" && !isErrno(got, unix.EACCES)) {
			t.Errorf("%s: connect = %q, want %s", c.name, got, map[bool]string{true: "success", false: c.want}[c.want == ""])
		}
	}
	for dst, rule := range map[string]string{"unix:b/own.sock": "", "unix:b/s1/own.sock": "", "unix:b/s2/x.sock": ruleUnixForeign} {
		evs := h.netEvents(t, dst)
		switch {
		case len(evs) != 1:
			t.Errorf("%s: %d events, want one", dst, len(evs))
		case rule == "" && evs[0].Verdict != record.VerdictAllow:
			t.Errorf("%s: line %s/%s, want allow", dst, evs[0].Verdict, evs[0].Rule)
		case rule != "" && (evs[0].Verdict != record.VerdictRefused || evs[0].Rule != rule):
			t.Errorf("%s: line %s/%s, want refused/%s", dst, evs[0].Verdict, evs[0].Rule, rule)
		}
	}
	if ul, ok := foreign.(*net.UnixListener); ok {
		_ = ul.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if c, err := ul.Accept(); err == nil {
			_ = c.Close()
			t.Error("the foreign socket in another subvolume accepted a connection")
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("accept on the foreign socket: %v", err)
		}
	}
}

// btrfsCollision runs a modeUnixRelay target over the btrfs fixture under its directory, b/ with the subvolumes s1 and
// s2, where the harness's own stream socket b/s1/x.sock and the socket the target binds (own, under env) repeat one
// inode number in two subvolumes, so the superblock and inode number UNIX_DIAG_VFS reports are both files'. The
// harness's socket is made before the target starts, and more than bindBornSlack before, so its file is
// born before every bind of the target's; with live true it is listening while the target runs, with live false it
// is closed before (a stale socket file). The target connects to its own socket as ownAt and to the harness's as
// foreign; each answer and its one line are checked against the rule wanted ("" for an admit), and the harness's
// listener, when live, must accept nothing.
func btrfsCollision(t *testing.T, prepare func(b string), env []string, live bool, ownAt, ownRule, foreignRule string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts the btrfs fixture (root-suites.sh)")
	}
	var foreign net.Listener
	h := startHarnessWith(t, harnessOpts{
		mode: modeUnixRelay,
		prepare: func(d string) {
			b := filepath.Join(d, "b")
			mountBtrfsFixture(t, b, "s1", "s2")
			for _, dir := range []string{filepath.Join(b, "s1"), filepath.Join(b, "s2")} {
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			if prepare != nil {
				prepare(b)
			}
			ln, err := net.Listen("unix", filepath.Join(b, "s1", "x.sock"))
			if err != nil {
				t.Fatal(err)
			}
			if ul, ok := ln.(*net.UnixListener); ok && !live {
				ul.SetUnlinkOnClose(false) // a stale socket file: no socket is bound to it once closed
				_ = ln.Close()
			} else {
				foreign = ln
				t.Cleanup(func() { _ = ln.Close() })
			}
			time.Sleep(4 * bindBornSlack) // born well before the target's binds, on the kernel's coarse clock
		},
		env: append(env, helperUnixPaths+"=own="+ownAt+",foreign=b/s1/x.sock"),
	})
	h.stop(t)
	var own, theirs unix.Stat_t
	if err := unix.Stat(filepath.Join(h.dir, ownAt), &own); err != nil {
		t.Fatalf("the target's socket file: %v (checks %+v)", err, h.report.Checks)
	}
	if err := unix.Stat(filepath.Join(h.dir, "b", "s1", "x.sock"), &theirs); err != nil {
		t.Fatal(err)
	}
	if own.Ino != theirs.Ino || own.Dev == theirs.Dev {
		t.Fatalf("the two sockets do not repeat one inode number in two subvolumes (%d:%d, %d:%d), so the cell proves nothing",
			own.Dev, own.Ino, theirs.Dev, theirs.Ino)
	}
	for _, c := range []struct{ name, dst, rule string }{{"own", "unix:" + ownAt, ownRule}, {"foreign", "unix:b/s1/x.sock", foreignRule}} {
		got := h.check(t, c.name).Err
		if (c.rule == "" && got != "") || (c.rule != "" && !isErrno(got, unix.EACCES)) {
			t.Errorf("%s: connect = %q, want %s", c.name, got, map[bool]string{true: "success", false: "EACCES"}[c.rule == ""])
		}
		evs := h.netEvents(t, c.dst)
		switch {
		case len(evs) != 1:
			t.Errorf("%s: %d events, want one", c.dst, len(evs))
		case c.rule == "" && evs[0].Verdict != record.VerdictAllow:
			t.Errorf("%s: line %s/%s, want allow", c.dst, evs[0].Verdict, evs[0].Rule)
		case c.rule != "" && (evs[0].Verdict != record.VerdictRefused || evs[0].Rule != c.rule):
			t.Errorf("%s: line %s/%s, want refused/%s", c.dst, evs[0].Verdict, evs[0].Rule, c.rule)
		}
	}
	if ul, ok := foreign.(*net.UnixListener); ok && live {
		_ = ul.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if c, err := ul.Accept(); err == nil {
			_ = c.Close()
			t.Error("the foreign socket in another subvolume accepted a connection")
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("accept on the foreign socket: %v", err)
		}
	}
}

// TestIntegrationUnixRelayDotDotOnBtrfs end to end on btrfs, as root in the KVM guest:
// the target binds b/s1/lnk/../own.sock, and b/s1/lnk leads to b/s2/deep, so the kernel places the socket in s2 while
// R6's lexical spelling names s1. lnk and deep are their subvolumes' first files, so the harness's socket b/s1/x.sock
// and the target's b/s2/own.sock are each the second and repeat one inode number. R11a stat'ed the spelling's
// directory and recorded s1, so a connect to the harness's socket was admitted and reached it. No name is attributed
// now: the harness's file was born before the target's bind, so it is refused
// unix-foreign, and its listener accepts nothing; the target's own, which UNIX_DIAG_VFS cannot tell from the live
// harness socket's, is refused unix-origin-unread, fail closed.
func TestIntegrationUnixRelayDotDotOnBtrfs(t *testing.T) {
	btrfsCollision(t, func(b string) {
		deep := filepath.Join(b, "s2", "deep")
		if err := os.Mkdir(deep, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(deep, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../s2/deep", filepath.Join(b, "s1", "lnk")); err != nil {
			t.Fatal(err)
		}
	}, []string{helperOwnSocks + "=b/s1/lnk/../own.sock"}, true, "b/s2/own.sock", ruleUnixOriginUnread, ruleUnixForeign)
}

// TestIntegrationUnixRelayRebindOnBtrfs end to end on btrfs, as root in the KVM guest: the target's
// socket first binds the name of the harness's socket in s1, which fails (the name is taken), and then binds a name
// in s2, where it is that subvolume's first file and so repeats the inode number of the harness's socket. R11a kept
// the first bind's directory, so a connect to the harness's socket was admitted and reached it. Its file was born
// before either bind, so it is refused unix-foreign whichever bind took, and its listener accepts nothing; the
// target's own is refused unix-origin-unread while the harness's live socket shares its binding.
func TestIntegrationUnixRelayRebindOnBtrfs(t *testing.T) {
	btrfsCollision(t, nil, []string{helperOwnSocks + "=b/s1/x.sock>b/s2/own.sock"}, true, "b/s2/own.sock",
		ruleUnixOriginUnread, ruleUnixForeign)
}

// TestIntegrationUnixRelayMagicBindOnBtrfs end to end on btrfs, as root in the
// KVM guest: the target binds /proc/self/cwd/own.sock from b/s2, where the kernel resolves the magic link as the target
// and makes its socket, the first file there, while this process's cwd is b/s1, where the harness's socket repeats its
// inode number. R11a stat'ed the name's directory as this process, so it recorded s1: a connect to the harness's
// socket was admitted and reached it. A bind's name decides nothing now: the harness's file predates the bind
// (unix-foreign), and the target's own shares a live socket's binding (unix-origin-unread).
func TestIntegrationUnixRelayMagicBindOnBtrfs(t *testing.T) {
	btrfsCollision(t, func(b string) {
		t.Chdir(filepath.Join(b, "s1"))
	}, []string{helperOwnCwd + "=b/s2", helperOwnSocks + "=/proc/self/cwd/own.sock"}, true, "b/s2/own.sock",
		ruleUnixOriginUnread, ruleUnixForeign)
}

// TestIntegrationUnixRelayStaleCollisionOnBtrfs is the collision with no foreign socket listening, as root in the KVM
// guest: the harness's socket file in s1 is stale (its socket closed before the target ran) and repeats the inode
// number of the target's own in s2. The namespace's dump lists no other socket under the binding, so the target's
// own is admitted; the stale file was born before the target's bind, so a connect to it is refused unix-foreign and
// nothing is connected.
func TestIntegrationUnixRelayStaleCollisionOnBtrfs(t *testing.T) {
	btrfsCollision(t, nil, []string{helperOwnSocks + "=b/s2/own.sock"}, false, "b/s2/own.sock", "", ruleUnixForeign)
}
