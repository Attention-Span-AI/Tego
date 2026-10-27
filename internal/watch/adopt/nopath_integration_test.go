// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package adopt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tests here hold files the way an agent adopted with --boundary may hold them before it is adopted: from a
// chroot, through a mount it lazily unmounted, through a detached bind mount, on btrfs. Each such file is on a mounted
// or detached mount of a real filesystem, which the decision plane decides (bpf/decide.bpf.c tego_no_path passes only
// SB_NOUSER, S_PRIVATE and a pseudo dentry on an MNT_INTERNAL mount; tego_internal_mount says a detached mount is not
// skipped), so none is NoPath: each is counted in adoption-open-descriptors when it is across a rule.
// Reading "no path" from the holder's /proc/<pid>/mountinfo dropped every one of them.
// They mount, chroot and open_tree, so they need root: root-suites.sh runs them in a KVM guest.

// The decision plane's btrfs fixture (internal/runtime/enforce/cgroup/testdata): an empty 16 MiB btrfs, gzipped.
const (
	noPathBtrfsFixture     = "../../runtime/enforce/cgroup/testdata/btrfs-mixed-16m.img.gz"
	noPathBtrfsFixtureSize = 16 << 20
	// _IOW(BTRFS_IOCTL_MAGIC, n, struct btrfs_ioctl_vol_args), whose size is 4096 (linux/btrfs.h).
	noPathBtrfsForgetDev    = 0x50009405
	noPathBtrfsSubvolCreate = 0x5000940e
)

// noPathBtrfsArgs is struct btrfs_ioctl_vol_args.
type noPathBtrfsArgs struct {
	FD   int64
	Name [4088]byte
}

func noPathRequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts, chroots and clones mounts (root-suites.sh)")
	}
}

// heldFile opens path for writing and maps it shared and writable, the two ways an agent holds a file across a rule.
func heldFile(t *testing.T, dirfd int, name string) int {
	t.Helper()
	fd, err := unix.Openat(dirfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Ftruncate(fd, 4096); err != nil {
		t.Fatal(err)
	}
	m, err := syscall.Mmap(fd, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(m) })
	return fd
}

// wantPaths checks that pid's descriptors numbered in fds, and its mappings of the targets they name, are not NoPath.
func wantPaths(t *testing.T, pid int, fds ...int) {
	t.Helper()
	fs := NewFS("")
	got, err := fs.FDs(pid)
	if err != nil {
		t.Fatal(err)
	}
	byNum := map[int]FD{}
	for _, fd := range got {
		byNum[fd.Num] = fd
	}
	ms, err := fs.Maps(pid)
	if err != nil {
		t.Fatal(err)
	}
	maps := map[string]Mapping{}
	for _, m := range ms {
		maps[m.Path] = m
	}
	for _, n := range fds {
		fd, ok := byNum[n]
		if !ok || !fd.File() {
			t.Errorf("descriptor %d: %+v, want a file", n, fd)
			continue
		}
		if fd.NoPath {
			var st unix.Stat_t
			_ = unix.Stat(filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(n)), &st)
			t.Errorf("descriptor %d (%s, device %d:%d): NoPath, but the plane decides an open of it", n, fd.Target,
				unix.Major(st.Dev), unix.Minor(st.Dev))
		}
		target := strings.TrimSuffix(fd.Target, " (deleted)")
		if m, ok := maps[target]; !ok {
			t.Errorf("%s: not among pid %d's %d mapped files", target, pid, len(ms))
		} else if m.NoPath || !m.SharedWritable {
			t.Errorf("%s: mapping %+v, want a shared writable mapping on a path", target, m)
		}
	}
}

// TestNoPathChrootHelper is the chrooted holder of TestIntegrationNoPathChrootedHolder, run as a child of the test
// binary: it holds <dir>/data, mounts proc inside <dir> (so its mountinfo shows that mount and none of the
// filesystem the file is on), chroots into <dir>, says "ready" and waits for its stdin to close.
func TestNoPathChrootHelper(t *testing.T) {
	dir := os.Getenv("TEGO_TEST_NOPATH_CHROOT")
	if dir == "" {
		t.Skip("helper process for TestIntegrationNoPathChrootedHolder")
	}
	fd, err := unix.Open(filepath.Join(dir, "data"), unix.O_RDWR|unix.O_CREAT, 0o600)
	if err == nil {
		err = unix.Ftruncate(fd, 4096)
	}
	if err == nil {
		_, err = syscall.Mmap(fd, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	}
	if err == nil {
		err = unix.Mount("proc", filepath.Join(dir, "proc"), "proc", 0, "")
	}
	if err == nil {
		err = unix.Chroot(dir)
	}
	if err == nil {
		err = unix.Chdir("/")
	}
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("ready " + strconv.Itoa(fd) + "\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// TestIntegrationNoPathChrootedHolder: a process chrooted into a directory, holding a file it opened there. Its
// /proc/<pid>/mountinfo shows only the mounts under its root, none of the file's filesystem, but the file is on a
// mounted filesystem and the plane decides it.
func TestIntegrationNoPathChrootedHolder(t *testing.T) {
	noPathRequireRoot(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(filepath.Join(dir, "proc"), unix.MNT_DETACH) })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPathChrootHelper$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "TEGO_TEST_NOPATH_CHROOT="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready ") {
		t.Fatalf("the chrooted holder: %q %v", line, err)
	}
	fd, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "ready ")))
	if err != nil {
		t.Fatalf("the chrooted holder: %q", line)
	}
	if mi, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "mountinfo")); err == nil {
		t.Logf("the holder's mountinfo:\n%s", mi)
	}
	wantPaths(t, cmd.Process.Pid, fd)
}

// TestIntegrationNoPathLazilyUnmounted: a tmpfs whose file is held open and mapped, then lazily unmounted (umount -l).
// No namespace shows the mount any more; the plane still decides the file (a detached mount is not skipped).
func TestIntegrationNoPathLazilyUnmounted(t *testing.T) {
	noPathRequireRoot(t)
	mnt := filepath.Join(t.TempDir(), "m")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", mnt, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=1m"); err != nil {
		t.Fatal(err)
	}
	mounted := true
	t.Cleanup(func() {
		if mounted {
			_ = unix.Unmount(mnt, unix.MNT_DETACH)
		}
	})
	dirfd, err := unix.Open(mnt, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd := heldFile(t, dirfd, "secret.db")
	_ = unix.Close(dirfd)
	if err := unix.Unmount(mnt, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	mounted = false
	wantPaths(t, os.Getpid(), fd)
}

// TestIntegrationNoPathDetachedBind: files held through a detached clone of a mounted filesystem (open_tree with
// OPEN_TREE_CLONE and no move_mount): the clone is no mount of any namespace, its filesystem is. On tmpfs, and on
// btrfs, whose files' st_dev is their subvolume's anonymous device and never the superblock's that mountinfo shows.
func TestIntegrationNoPathDetachedBind(t *testing.T) {
	noPathRequireRoot(t)
	t.Run("tmpfs", func(t *testing.T) {
		mnt := filepath.Join(t.TempDir(), "m")
		if err := os.Mkdir(mnt, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount("tmpfs", mnt, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=1m"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
		tree := openTreeClone(t, mnt)
		wantPaths(t, os.Getpid(), heldFile(t, tree, "top.db"))
	})
	t.Run("btrfs", func(t *testing.T) {
		mnt := filepath.Join(t.TempDir(), "b")
		mountNoPathBtrfs(t, mnt, "sv")
		tree := openTreeClone(t, mnt)
		wantPaths(t, os.Getpid(), heldFile(t, tree, "top.db"), heldFile(t, tree, "sv/sub.db"))
	})
}

// openTreeClone is a detached clone of the mount at dir, closed at the test's end.
func openTreeClone(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.OpenTree(unix.AT_FDCWD, dir, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		t.Fatalf("open_tree %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// mountNoPathBtrfs mounts the btrfs fixture at dir with the named subvolumes, unmounted at the test's end.
func mountNoPathBtrfs(t *testing.T, dir string, subvolumes ...string) {
	t.Helper()
	gz, err := os.ReadFile(noPathBtrfsFixture)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, noPathBtrfsFixtureSize+1))
	if err != nil || len(raw) != noPathBtrfsFixtureSize {
		t.Fatalf("btrfs fixture: %d bytes, %v", len(raw), err)
	}
	image := filepath.Join(t.TempDir(), "btrfs.img")
	if err := os.WriteFile(image, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Every mount of the fixture carries one fsid; forget the unmounted copies an earlier test left registered.
	if fd, err := unix.Open("/dev/btrfs-control", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		var args noPathBtrfsArgs
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), noPathBtrfsForgetDev, uintptr(unsafe.Pointer(&args)))
		_ = unix.Close(fd)
		if errno != 0 {
			t.Fatalf("forget unmounted btrfs devices: %v", errno)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
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
		var args noPathBtrfsArgs
		copy(args.Name[:], name)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(parent), noPathBtrfsSubvolCreate, uintptr(unsafe.Pointer(&args))); errno != 0 {
			t.Fatalf("create subvolume %s: %v", name, errno)
		}
	}
}
