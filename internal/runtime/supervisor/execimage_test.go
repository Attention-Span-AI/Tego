// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// selfTask locks the test to one OS thread and returns its tid: the test process stands in for the
// trapping task where no other process is needed.
func selfTask(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	return unix.Gettid()
}

// spawnTask starts another process to stand in for the trapping task — a sleep with cwd dir and extra as
// its descriptors 3, 4, ... — and returns its pid. It has to be another process: resolved by this one,
// "self" names this process, so a walk that forgot to translate it would still pass a test whose task is
// the test itself.
func spawnTask(t *testing.T, dir string, extra ...*os.File) int {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	cmd := exec.Command(sleep, "60")
	cmd.Dir = dir
	cmd.ExtraFiles = extra
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// newMemfd makes a memfd holding a few bytes, closed at cleanup.
func newMemfd(t *testing.T, name string) int {
	t.Helper()
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if _, err := unix.Write(fd, []byte("\x7fELF")); err != nil {
		t.Fatal(err)
	}
	return fd
}

// statID is the identity stat(2) gives p, symlinks followed.
func statID(t *testing.T, p string) fileID {
	t.Helper()
	id, err := sysKernel{}.StatID(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestWalkExecReachesTheTasksDescriptor is the real-kernel half of the anonymous-image spelling problem: every way of
// naming the task's descriptor by pathname reaches the memfd the kernel would load for the task — not this
// process's descriptor of the same number, and not a string that merely looks like one. The loop used to
// recognise /proc/{self,thread-self,<tid>}/fd/N and nothing else, and continued the rest. The task is
// another process holding the memfd as its descriptor 3, which this process's descriptor 3 is not.
func TestWalkExecReachesTheTasksDescriptor(t *testing.T) {
	fd := newMemfd(t, "/../usr/bin/python3")
	if own, _ := os.Readlink("/proc/self/fd/3"); strings.HasPrefix(own, "/memfd:") {
		t.Skip("this process's own descriptor 3 is a memfd; the test could not tell the two apart")
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "run")
	if err := os.Symlink("/proc/self/fd/3", link); err != nil {
		t.Fatal(err)
	}
	devfd := filepath.Join(dir, "devfd")
	if err := os.Symlink("/dev/fd", devfd); err != nil {
		t.Fatal(err)
	}
	// The task's 4 is this process's /proc/self/fd, opened here: the kernel resolved "self" when it was
	// opened, so a name relative to it is this process's descriptor — n, the memfd's number here. Its 5 is
	// /proc itself, where "self" is still the caller's to resolve: the task's.
	ownFDDir, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer ownFDDir.Close() //nolint:errcheck // test descriptor
	procDir, err := os.Open("/proc")
	if err != nil {
		t.Fatal(err)
	}
	defer procDir.Close() //nolint:errcheck // test descriptor
	// The task gets the memfd through a duplicate this test owns and closes. Wrapping fd itself in an
	// os.File, which nothing closed, left its finalizer to close the number again after newMemfd's cleanup
	// had: at whatever later garbage collection, with the number by then another test's descriptor — a
	// harness's echo listener, which then refused connects, or a file a later test was reading.
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	memfd := os.NewFile(uintptr(dup), "memfd")
	defer memfd.Close() //nolint:errcheck // test descriptor
	pid := spawnTask(t, dir, memfd, ownFDDir, procDir)
	n := strconv.Itoa(fd)

	for _, q := range []struct {
		name string
		q    pathQuery
	}{
		{"/proc/self/fd", pathQuery{dirfd: atFDCWD, path: "/proc/self/fd/3"}},
		{"/dev/fd alias", pathQuery{dirfd: atFDCWD, path: "/dev/fd/3"}},
		{"a symlink to a descriptor", pathQuery{dirfd: atFDCWD, path: link}},
		{"a relative symlink from the task's cwd", pathQuery{dirfd: atFDCWD, path: "run"}},
		{"a symlink to /dev/fd", pathQuery{dirfd: atFDCWD, path: devfd + "/3"}},
		{"/proc/self/task/<tid>/fd", pathQuery{dirfd: atFDCWD, path: "/proc/self/task/" + strconv.Itoa(pid) + "/fd/3"}},
		{"/proc/thread-self/fd", pathQuery{dirfd: atFDCWD, path: "/proc/thread-self/fd/3"}},
		{"/proc/<tgid>/fd", pathQuery{dirfd: atFDCWD, path: "/proc/" + strconv.Itoa(pid) + "/fd/3"}},
		{"dotdot through /proc/self", pathQuery{dirfd: atFDCWD, path: "/proc/self/../self/fd/3"}},
		{"dirfd-relative", pathQuery{dirfd: 4, path: n}},
		{"relative to a /proc dirfd", pathQuery{dirfd: 5, path: "self/fd/3"}},
		{"AT_EMPTY_PATH", pathQuery{dirfd: 3, empty: true}},
	} {
		t.Run(q.name, func(t *testing.T) {
			q.q.tid = pid
			img, err := sysKernel{}.ExecImage(q.q)
			if err != nil {
				t.Fatalf("ExecImage: %v", err)
			}
			if !img.fileless() {
				t.Errorf("image %+v is not fileless: the walk did not reach the task's memfd", img)
			}
			if !strings.HasPrefix(img.link, "/memfd:/../usr/bin/python3") {
				t.Errorf("link = %q, want the kernel's raw spelling of the memfd", img.link)
			}
		})
	}
}

// TestWalkExecFollowsLikeTheKernel pins the walk to the kernel's own lookup on the cases the decision
// depends on: a symlink chain and a hard link reach the granted inode, ".." after a symlink is resolved
// physically (lexical cleaning would name another file), a symlink loop and a final symlink under
// AT_SYMLINK_NOFOLLOW are ELOOP, a missing name is ENOENT, and a relative path starts at the task's cwd.
func TestWalkExecFollowsLikeTheKernel(t *testing.T) {
	// Resolved, because the image's link is the kernel's spelling of where it lies (realDir).
	dir := realDir(t, t.TempDir())
	mk := func(p string) string {
		p = filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(p), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	target := mk("b/x")
	decoy := mk("a/x")
	for _, l := range []struct{ name, to string }{
		{"a/link", "../b/c"}, {"chain1", "chain2"}, {"chain2", target},
		{"loop1", "loop2"}, {"loop2", "loop1"}, {"dangling", "nowhere"},
	} {
		if err := os.Symlink(l.to, filepath.Join(dir, l.name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "b/c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(dir, "hard")); err != nil {
		t.Fatal(err)
	}
	tid := spawnTask(t, filepath.Join(dir, "b"))
	for _, tc := range []struct {
		name     string
		q        pathQuery
		want     string // the file whose identity the walk must reach
		wantErr  unix.Errno
		wantLink string
	}{
		{name: "symlink chain", q: pathQuery{path: filepath.Join(dir, "chain1")}, want: target, wantLink: target},
		{name: "hard link", q: pathQuery{path: filepath.Join(dir, "hard")}, want: target},
		{name: "dotdot after a symlink is physical", q: pathQuery{path: filepath.Join(dir, "a/link") + "/../x"}, want: target},
		{name: "symlink loop", q: pathQuery{path: filepath.Join(dir, "loop1")}, wantErr: unix.ELOOP},
		{name: "final symlink under AT_SYMLINK_NOFOLLOW", q: pathQuery{path: filepath.Join(dir, "chain1"), nofollow: true}, wantErr: unix.ELOOP},
		{name: "missing", q: pathQuery{path: filepath.Join(dir, "nope")}, wantErr: unix.ENOENT},
		{name: "dangling symlink", q: pathQuery{path: filepath.Join(dir, "dangling")}, wantErr: unix.ENOENT},
		{name: "through a file", q: pathQuery{path: target + "/x"}, wantErr: unix.ENOTDIR},
		{name: "relative from the task's cwd", q: pathQuery{path: "x"}, want: target},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.q.tid, tc.q.dirfd = tid, atFDCWD
			img, err := sysKernel{}.ExecImage(tc.q)
			if tc.wantErr != 0 {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExecImage: %v", err)
			}
			if img.id != statID(t, tc.want) {
				t.Errorf("reached %+v, want %s", img, tc.want)
			}
			if img.id == statID(t, decoy) {
				t.Error("reached the lexically cleaned path, not the one the kernel resolves")
			}
			if img.fileless() {
				t.Errorf("image %+v: want a linked file", img)
			}
			if tc.wantLink != "" && (img.link != tc.wantLink || !img.here) {
				t.Errorf("link/here = %q/%v, want %q/true", img.link, img.here, tc.wantLink)
			}
		})
	}
}

// TestWalkExecUnlinkedFileIsFileless: a file unlinked since it was opened has no path any rule can name,
// so the walk reports it fileless whatever spelling reached it.
func TestWalkExecUnlinkedFileIsFileless(t *testing.T) {
	tid := selfTask(t)
	p := filepath.Join(t.TempDir(), "dropped")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // test descriptor
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: "/proc/self/fd/" + strconv.Itoa(fd)})
	if err != nil {
		t.Fatal(err)
	}
	if !img.fileless() || img.linked {
		t.Errorf("image %+v: want an unlinked, fileless image", img)
	}
}

// TestFSTargetLandsWhereTheKernelWrites is FSTarget against the kernel (R15b): an fs path is resolved as
// the task resolves it, through its descriptors and symlinks, to the place in this process's view the
// syscall acts on — the file itself when the syscall follows it and it exists, else the resolved parent
// joined with the final component. The task is another process whose descriptor 3 is the write directory.
// Every case runs twice: with the query alone, which the walk answers, and with R6's joined spelling, which
// lets the one-lookup paths answer where they can (fsTargetIsSpelling, fsTargetInRoot); both land alike.
func TestFSTargetLandsWhereTheKernelWrites(t *testing.T) {
	dir := t.TempDir()
	w := filepath.Join(dir, "w")
	if err := os.Mkdir(w, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w, "out.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(w, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(w, "out.txt"), filepath.Join(dir, "file-link")); err != nil {
		t.Fatal(err)
	}
	// Dangling links an O_CREAT open follows to create their targets: one direct, one through the symlinked
	// directory, one relative.
	if err := os.Symlink(filepath.Join(w, "planted"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("alias/planted2", filepath.Join(dir, "dangling-via-alias")); err != nil {
		t.Fatal(err)
	}
	wdir, err := os.Open(w)
	if err != nil {
		t.Fatal(err)
	}
	defer wdir.Close() //nolint:errcheck // test descriptor
	pid := spawnTask(t, dir, wdir)
	for _, tc := range []struct {
		name string
		q    pathQuery
		want string
	}{
		{"a new file through the task's /proc/self/fd", pathQuery{path: "/proc/self/fd/3/new.txt"}, filepath.Join(w, "new.txt")},
		{"a new file through /dev/fd", pathQuery{path: "/dev/fd/3/new.txt"}, filepath.Join(w, "new.txt")},
		{"an existing file through a symlinked directory", pathQuery{path: "alias/out.txt"}, filepath.Join(w, "out.txt")},
		{"a followed symlink lands on its target", pathQuery{path: "file-link"}, filepath.Join(w, "out.txt")},
		{"an unfollowed symlink is the entry itself", pathQuery{path: "file-link", nofollow: true}, filepath.Join(dir, "file-link")},
		{"a dirfd-relative name", pathQuery{dirfd: 3, path: "sub"}, filepath.Join(w, "sub")},
		// An O_CREAT open follows a dangling final symlink and creates its target, so that is where it lands
		// (R15c): without it, a write the agent aimed through a link at a deny_write target not yet there was
		// decided at the link's own name.
		{"O_CREAT through a dangling link creates its target", pathQuery{path: "dangling", create: true}, filepath.Join(w, "planted")},
		{"O_CREAT through a dangling link via a symlinked directory", pathQuery{path: "dangling-via-alias", create: true}, filepath.Join(w, "planted2")},
		{"O_CREAT of a plain new name", pathQuery{path: "alias/fresh", create: true}, filepath.Join(w, "fresh")},
		{"without O_CREAT a dangling link is its own name", pathQuery{path: "dangling"}, filepath.Join(dir, "dangling")},
		{"a plain existing file", pathQuery{path: "w/out.txt"}, filepath.Join(w, "out.txt")},
		{"a plain new name", pathQuery{path: "w/new2.txt", create: true}, filepath.Join(w, "new2.txt")},
		{"a name through .. in a symlinked directory", pathQuery{path: "alias/../w/out.txt"}, filepath.Join(w, "out.txt")},
		// A trailing slash makes the kernel follow a final symlink even under O_NOFOLLOW: open("alias/",
		// O_NOFOLLOW) opens w, and an O_TMPFILE open there creates its file in w, so that is where it lands.
		{"O_NOFOLLOW with a trailing slash follows a symlinked directory", pathQuery{path: "alias/", nofollow: true}, w},
		{"O_NOFOLLOW with a trailing slash through a dirfd-relative link", pathQuery{dirfd: 3, path: "../alias/", nofollow: true}, w},
	} {
		for _, joined := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/joined=%v", tc.name, joined), func(t *testing.T) {
				q := tc.q
				q.tid = pid
				if q.dirfd == 0 {
					q.dirfd = atFDCWD
				}
				if joined {
					switch {
					case strings.HasPrefix(q.path, "/"):
						q.joined = q.path
					case q.dirfd == 3:
						q.joined = filepath.Join(w, q.path)
					default:
						q.joined = filepath.Clean(filepath.Join(dir, q.path))
					}
				}
				landing, err := sysKernel{}.FSTarget(q)
				if err != nil {
					t.Fatalf("FSTarget: %v", err)
				}
				want, _ := filepath.EvalSymlinks(filepath.Dir(tc.want))
				want = filepath.Join(want, filepath.Base(tc.want))
				if got := landing.at; got != want {
					t.Errorf("landed %q, want %q", got, want)
				}
			})
		}
	}
}

// TestExecImageHead: with head asked for, the walk reads an image's first bytes through its own descriptor (ADR 0048
// (3)): a script's #! line, an empty file as empty (not unreadable: the kernel answers it ENOEXEC), and nothing for an
// execute-only file this process may not read, whose form is then unknown. Root reads every file, so the last case
// is skipped as root.
func TestExecImageHead(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	head := func(p string) []byte {
		img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p, head: true})
		if err != nil {
			t.Fatalf("ExecImage(%s): %v", p, err)
		}
		return img.head
	}
	if got := head(write("s", "#!/usr/bin/rm -rf\n", 0o755)); string(got) != "#!/usr/bin/rm -rf\n" {
		t.Errorf("a script's head: %q", got)
	}
	if got := head(write("empty", "", 0o755)); got == nil || len(got) != 0 {
		t.Errorf("an empty file's head: %#v, want empty and not nil", got)
	}
	if os.Geteuid() == 0 {
		t.Log("root reads an execute-only file: that case is skipped")
		return
	}
	if got := head(write("xonly", "#!/usr/bin/rm -rf\n", 0o111)); got != nil {
		t.Errorf("an execute-only file's head: %q, want none", got)
	}
}

// TestExecImageHeadOpensOnlyRegular: a run with command rules asks every exec's image for its head, and the
// supervisor may run as root (tier 2), so the head read must never open what the agent names unless it is a regular
// file: an exec of /dev/watchdog would otherwise make root open a device whose open acts (a confused deputy). A FIFO
// and a character device keep head nil and are never reopened; a regular file is reopened once. The FIFO is watched
// with inotify too, which sees every open of it but an O_PATH one (the walk's).
func TestExecImageHeadOpensOnlyRegular(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "reg")
	if err := os.WriteFile(reg, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(in) //nolint:errcheck // the test's own inotify descriptor
	if _, err := unix.InotifyAddWatch(in, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	var opened []string
	prev := headOpen
	headOpen = func(p string) (int, error) {
		if l, err := os.Readlink(p); err == nil {
			opened = append(opened, l)
		} else {
			opened = append(opened, p)
		}
		return prev(p)
	}
	t.Cleanup(func() { headOpen = prev })
	image := func(p string) execImage {
		img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p, head: true})
		if err != nil {
			t.Fatalf("ExecImage(%s): %v", p, err)
		}
		return img
	}
	for _, p := range []string{fifo, "/dev/null"} {
		opened = nil
		if img := image(p); img.head != nil || img.regular {
			t.Errorf("%s: head %q, regular %v; want no head of a file that is not regular", p, img.head, img.regular)
		}
		if len(opened) != 0 {
			t.Errorf("%s: reopened O_RDONLY for its head: %v", p, opened)
		}
	}
	buf := make([]byte, 4096)
	if n, err := unix.Read(in, buf); n > 0 {
		t.Errorf("inotify saw the FIFO opened (%d bytes of events)", n)
	} else if !errors.Is(err, unix.EAGAIN) {
		t.Errorf("reading inotify: %v", err)
	}
	opened = nil
	if img := image(reg); string(img.head) != "#!/bin/sh\n" || !img.regular {
		t.Errorf("a regular file: head %q, regular %v", img.head, img.regular)
	}
	if len(opened) != 1 || opened[0] != reg {
		t.Errorf("a regular file is reopened once: %v", opened)
	}
}

// ownMagicDir knows the task's own thread group by every thread's directory: procfs looks a thread id up at its root as
// it does a tgid, so /proc/<tid> of a thread other than the leader, its fd and ns directories and its task/<tid> are the
// task's own as much as the leader's are, and the kernel follows their magic links for the task with no ptrace check.
// It compared with /proc/<tgid> alone and called those another process's, an unsure step (the task's side).
// Here the test process is the task; another process's directories, and an entry directory that holds
// no magic links the kernel follows freely (map_files, net), are not its own.
func TestOwnMagicDirKnowsEveryThread(t *testing.T) {
	pid, tid := strconv.Itoa(os.Getpid()), strconv.Itoa(otherThread(t))
	other := strconv.Itoa(spawnTask(t, t.TempDir()))
	w := &execWalk{q: pathQuery{tid: os.Getpid()}}
	for _, c := range []struct {
		dir string
		own bool
	}{
		{pid, true}, {pid + "/fd", true}, {pid + "/ns", true}, {pid + "/task/" + pid, true}, {pid + "/task/" + tid + "/fd", true},
		{tid, true}, {tid + "/fd", true}, {tid + "/ns", true}, {tid + "/task/" + pid + "/fd", true}, {tid + "/task/" + tid, true},
		{other, false}, {other + "/fd", false}, {other + "/task/" + other, false}, {pid + "/map_files", false}, {pid + "/net", false},
	} {
		fd, err := unix.Open("/proc/"+c.dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open /proc/%s: %v", c.dir, err)
		}
		if got := w.ownMagicDir(fd); got != c.own {
			t.Errorf("ownMagicDir(/proc/%s) = %v, want %v", c.dir, got, c.own)
		}
		_ = unix.Close(fd)
	}
}
