// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/deputy"
)

// The open deputy's walk follows a symlink only where the kernel's own lookup would follow it for the task: a trailing
// link that fs.protected_symlinks refuses (in a sticky world-writable directory, owned by neither the follower nor the
// directory's owner) is EACCES, and a non-trailing one is followed as the kernel follows it. The walk read every link
// and walked its target in userspace, so where the deputy's one-lookup pin (openat2, which the kernel refuses alike)
// failed and the walk took over, the held open pinned and delivered the target of a link the task's own open is
// refused.
// Here the follower is made another uid than the link's owner in the
// walk's facts, and the link lies in /tmp, a sticky world-writable directory root owns.
func TestDeputyWalkFollowsLinksAsTheKernelDoes(t *testing.T) {
	var tmp unix.Stat_t
	if err := unix.Stat("/tmp", &tmp); err != nil || tmp.Uid != 0 || tmp.Mode&(unix.S_ISVTX|0o002) != unix.S_ISVTX|0o002 {
		t.Skip("needs a root-owned, sticky, world-writable /tmp")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join("/tmp", "tego-deputy-walk-"+strconv.Itoa(os.Getpid())+"-"+filepath.Base(dir))
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if os.Geteuid() == 0 {
		// Root's link would be owned by /tmp's owner, which may_follow_link lets anyone follow: give it another owner.
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	var lst unix.Stat_t
	if err := unix.Lstat(link, &lst); err != nil {
		t.Fatal(err)
	}
	tid := selfTask(t)
	other := lst.Uid + 4242
	walk := func(path string, f *followFacts) error {
		p, err := walkAs(pathQuery{tid: tid, dirfd: atFDCWD, path: path}, os.Getpid(), false, f, 0)
		if err == nil {
			_ = unix.Close(p.FD)
		}
		return err
	}
	for _, tc := range []struct {
		name string
		path string
		f    *followFacts
		want error
	}{
		{"trailing link, another follower", link, &followFacts{fsuid: other, protected: true}, unix.EACCES},
		{"trailing link, its owner follows", link, &followFacts{fsuid: lst.Uid, protected: true}, nil},
		{"trailing link, protected_symlinks off", link, &followFacts{fsuid: other, protected: false}, nil},
		{"the link mid-path, another follower", link + "/target", &followFacts{fsuid: other, protected: true}, nil},
		{"the supervisor's own walk", link, nil, nil},
	} {
		if err := walk(tc.path, tc.f); !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
			t.Errorf("%s: walk = %v, want %v", tc.name, err, tc.want)
		}
	}
	// The deputy's pin, as this process: unprivileged it owns the link and follows it; root does not own it, and
	// may_follow_link checks no capability, so where the sysctl is on the kernel refuses root too, and so does the pin.
	p, err := DeputyPin(deputy.PinQuery{TID: tid, TGID: os.Getpid(), DirFD: atFDCWD, Path: link})
	if err == nil {
		_ = unix.Close(p.FD)
	}
	if os.Geteuid() == 0 && currentFollowFacts().protected {
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("DeputyPin as root of another's link in /tmp: %v, want EACCES", err)
		}
	} else if err != nil {
		t.Fatalf("DeputyPin of the link: %v", err)
	}
}

// A held open may never reach the open deputy's own thread group's /proc tree. The deputy runs the walk and the reopen
// itself, and a process always passes ptrace_may_access against itself, so without the guard it pins and delivers its
// own ptrace-gated entries (mem, environ, auxv, maps, fd/N, cwd, root, exe) that the agent's own open is refused, the
// deputy being undumpable (PR_SET_DUMPABLE 0, deputy confine). Here the test process stands in for the deputy
// (DeputyPin walks as os.Getpid()) and another process is the task; the deputy's own entries are refused EACCES, the
// agent's own answer, while the task's own are reached, so the guard is the deputy's and not a blanket refusal of
// procfs. Without deputyProcDepth the deputy's own entries pin as any O_PATH open does, and this
// fails.
func TestDeputyWalkRefusesItsOwnProc(t *testing.T) {
	task := spawnTask(t, t.TempDir())
	self := os.Getpid()
	pin := func(path string) error {
		p, err := DeputyPin(deputy.PinQuery{TID: task, TGID: task, DirFD: atFDCWD, Path: path})
		if err == nil {
			_ = unix.Close(p.FD)
		}
		return err
	}
	// The deputy's own ptrace-gated entries: the agent's own open of an undumpable process is refused EACCES, and so
	// is the held open. fd/N, cwd, root and exe are magic links the guard refuses at the fd/ or <pid>/ lookup, before
	// following; mem, environ, auxv and maps are plain files the guard refuses at the <pid>/ lookup.
	for _, name := range []string{"mem", "environ", "auxv", "maps", "fd/0", "cwd", "root", "exe", "task/" + strconv.Itoa(self) + "/mem"} {
		if err := pin("/proc/" + strconv.Itoa(self) + "/" + name); !errors.Is(err, unix.EACCES) {
			t.Errorf("held pin of the deputy's own /proc/%d/%s = %v, want EACCES", self, name, err)
		}
	}
	// A world-readable entry of the deputy (status, cmdline) is refused too: the deliberate over-refusal, never more
	// permissive than the agent's own, which the ADR 0041 D4 /proc row records.
	for _, name := range []string{"status", "cmdline", "stat"} {
		if err := pin("/proc/" + strconv.Itoa(self) + "/" + name); !errors.Is(err, unix.EACCES) {
			t.Errorf("held pin of the deputy's own /proc/%d/%s = %v, want EACCES (the over-refusal)", self, name, err)
		}
	}
	// The deputy's /proc directory itself: the lookup lands on it with no further component, as the agent's own open
	// of that listable directory does.
	if err := pin("/proc/" + strconv.Itoa(self)); err != nil {
		t.Errorf("held pin of the deputy's own /proc/%d = %v, want it reached", self, err)
	}
	// The same entries through the directory of one of the deputy's other threads, /proc/<tid> at the procfs root
	// beside /proc/<pid>, with an inode of its own: procfs looks any thread id up there, and its entries ask
	// ptrace_may_access about that thread, which the deputy always passes. The guard
	// knew the deputy only by its leader's directory, and these pinned. That directory itself is reached, as the
	// leader's is.
	tid := strconv.Itoa(otherThread(t))
	for _, name := range []string{"mem", "environ", "auxv", "maps", "fd/0", "cwd", "root", "exe", "status",
		"task/" + tid + "/maps", "task/" + strconv.Itoa(self) + "/environ"} {
		if err := pin("/proc/" + tid + "/" + name); !errors.Is(err, unix.EACCES) {
			t.Errorf("held pin of the deputy thread's /proc/%s/%s = %v, want EACCES", tid, name, err)
		}
	}
	if err := pin("/proc/" + tid); err != nil {
		t.Errorf("held pin of the deputy thread's /proc/%s = %v, want it reached", tid, err)
	}
	// The task's own /proc tree is reached (the pin is an O_PATH open, which a reopen's own ptrace check then governs):
	// the guard is the deputy's, not a blanket refusal of procfs.
	for _, name := range []string{"mem", "environ", "status", "fd/0"} {
		if err := pin("/proc/" + strconv.Itoa(task) + "/" + name); err != nil {
			t.Errorf("held pin of the task's own /proc/%d/%s = %v, want it reached", task, name, err)
		}
	}
	// A pin that names a final component in the deputy's directory without walking it, an O_CREAT|O_EXCL open's and an
	// O_CREAT open's of a name followed by "/", looks that name up there too, and is refused as every lookup there is.
	for _, own := range []string{"/proc/" + strconv.Itoa(self), "/proc/" + tid} {
		for _, q := range []deputy.PinQuery{{Path: own + "/environ", Excl: true, Nofollow: true}, {Path: own + "/environ/", Create: true}} {
			q.TID, q.TGID, q.DirFD = task, task, atFDCWD
			if p, err := DeputyPin(q); !errors.Is(err, unix.EACCES) {
				if err == nil {
					_ = unix.Close(p.FD)
				}
				t.Errorf("held pin %+v in the deputy's own directory = %v, want EACCES", q, err)
			}
		}
	}
}

// otherThread is a live thread of the test process other than its leader, standing in for one of the open deputy's
// threads (a Go deputy always has several): a goroutine locked to its OS thread until the test ends, when the thread
// exits with it.
func otherThread(t *testing.T) int {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	for range 16 {
		got := make(chan int)
		go func() {
			runtime.LockOSThread()
			tid := unix.Gettid()
			got <- tid
			<-stop
			if tid == os.Getpid() {
				// The leader, held until the test ends so the next goroutine gets another thread, and released then:
				// the leader never exits.
				runtime.UnlockOSThread()
			}
		}()
		if tid := <-got; tid != os.Getpid() {
			return tid
		}
	}
	t.Fatal("no thread of the test process other than its leader")
	return 0
}

// The deputy's own /proc tree reached through a descriptor rather than by name. A run process
// holds O_PATH descriptors of the deputy's entries (an O_PATH open is never held, and the kernel lets any process look
// these names up), and a held open of /proc/<pid>/fd/N lands on one by the magic link alone, its last step, with no
// further component looked up in the deputy's tree for the per-component guard to see. Entries strictly inside the
// tree are refused EACCES; the deputy's directory itself, and procfs and other objects outside the tree, are reached.
// Without the landing check (landsInDeputyProc) the inside entries pin, and this fails.
func TestDeputyWalkRefusesItsOwnProcByDescriptor(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	self := strconv.Itoa(os.Getpid())
	own := "/proc/" + self
	// thread is the directory of another of the deputy's threads, /proc/<tid> at the procfs root: its entries are the
	// deputy's as much as its leader's are.
	thread := "/proc/" + strconv.Itoa(otherThread(t))
	held := []struct {
		path    string
		refused bool
	}{
		{own + "/environ", true}, {own + "/mem", true}, {own + "/status", true}, {own + "/fd", true}, {own + "/task", true},
		{own + "/task/" + self, true}, {own + "/task/" + self + "/environ", true}, {own + "/net/dev", true},
		{thread + "/maps", true}, {thread + "/environ", true}, {thread + "/fd", true}, {thread + "/task", true},
		{thread + "/task/" + self + "/maps", true}, {thread, false},
		{own, false}, {"/proc/sys/kernel/ostype", false}, {"/proc/sys/kernel", false}, {dir, false}, {dir + "/f", false},
	}
	var files []*os.File
	for _, h := range held {
		fd, err := unix.Open(h.path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("O_PATH open of %s: %v", h.path, err)
		}
		f := os.NewFile(uintptr(fd), h.path)
		t.Cleanup(func() { _ = f.Close() })
		files = append(files, f)
	}
	holder := spawnTask(t, dir, files...)
	for i, h := range held {
		// By the magic link as the walk's last step, and by the descriptor itself (an AT_EMPTY_PATH pin, via "").
		for _, via := range []string{"/proc/" + strconv.Itoa(holder) + "/fd/", "/proc/self/fd/", ""} {
			q := deputy.PinQuery{TID: holder, TGID: holder, DirFD: atFDCWD, Path: via + strconv.Itoa(3+i)}
			if via == "" {
				q.DirFD, q.Path, q.Empty = int32(3+i), "", true
			}
			p, err := DeputyPin(q)
			if err == nil {
				_ = unix.Close(p.FD)
			}
			switch {
			case h.refused && !errors.Is(err, unix.EACCES):
				t.Errorf("held pin of %s%d, a descriptor of the deputy's own %s = %v, want EACCES", via, 3+i, h.path, err)
			case !h.refused && err != nil:
				t.Errorf("held pin of %s%d, a descriptor of %s = %v, want it reached", via, 3+i, h.path, err)
			}
		}
	}
}

// The deputy's own /proc tree reached through another mount of procfs: a second
// procfs instance, a bind mount of /proc, and a bind mount of the deputy's own /proc/<pid> directory alone. The guard
// compared each directory with the deputy's own /proc/<pid> on its mount, so all three reached the deputy's entries; it
// now asks each instance's root for "self", and a mount of part of a procfs, whose instance root it cannot reach, is
// refused as unsure. The task's own entries are reached on the first two. Root only (mounts); the mounts are detached at
// the test's end.
func TestDeputyWalkRefusesItsOwnProcOnEveryMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: mounts a procfs instance and two bind mounts")
	}
	dir := t.TempDir()
	task := strconv.Itoa(spawnTask(t, dir))
	self := strconv.Itoa(os.Getpid())
	for _, m := range []struct{ at, src, fstype string }{
		{"instance", "proc", "proc"}, {"bind", "/proc", ""}, {"part", "/proc/" + self, ""},
	} {
		at := filepath.Join(dir, m.at)
		if err := os.Mkdir(at, 0o755); err != nil {
			t.Fatal(err)
		}
		flags := uintptr(0)
		if m.fstype == "" {
			flags = unix.MS_BIND
		}
		if err := unix.Mount(m.src, at, m.fstype, flags, ""); err != nil {
			t.Fatalf("mount %s at %s: %v", m.src, at, err)
		}
		t.Cleanup(func() { _ = unix.Unmount(at, unix.MNT_DETACH) })
	}
	taskN, _ := strconv.Atoi(task)
	pin := func(p string) error {
		got, err := DeputyPin(deputy.PinQuery{TID: taskN, TGID: taskN, DirFD: atFDCWD, Path: p})
		if err == nil {
			_ = unix.Close(got.FD)
		}
		return err
	}
	thread := strconv.Itoa(otherThread(t))
	for _, p := range []string{"instance/" + self + "/environ", "instance/" + self + "/status", "bind/" + self + "/environ",
		"bind/" + self + "/task/" + self + "/maps", "part/environ", "part/task", "instance/" + thread + "/maps",
		"bind/" + thread + "/environ", "bind/" + thread + "/task/" + self + "/maps"} {
		if err := pin(filepath.Join(dir, p)); !errors.Is(err, unix.EACCES) {
			t.Errorf("held pin of %s, the deputy's own entry on another mount = %v, want EACCES", p, err)
		}
	}
	for _, p := range []string{"instance/" + task + "/status", "bind/" + task + "/environ", "instance/" + self, "bind/sys/kernel/ostype"} {
		if err := pin(filepath.Join(dir, p)); err != nil {
			t.Errorf("held pin of %s = %v, want it reached", p, err)
		}
	}
}

// stickyCreate is may_create_in_sticky's rule (fs.protected_regular, fs.protected_fifos) on the facts of an existing
// file an O_CREAT open finds, its directory and the opener. The deputy reopens such a file through /proc/self/fd, whose
// directory is no sticky one, so the held open succeeded where the task's own open is refused (round 1's residual of
// review finding F4, built here); as root, TestHeldOpenDifferentialAcrossMounts holds it to the kernel's answer.
func TestStickyCreate(t *testing.T) {
	world := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0o777, Uid: 0}
	group := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0o770, Uid: 0}
	plain := &unix.Stat_t{Mode: unix.S_IFDIR | 0o777, Uid: 0}
	other := &unix.Stat_t{Mode: unix.S_IFREG | 0o666, Uid: 2000}
	mine := &unix.Stat_t{Mode: unix.S_IFREG | 0o666, Uid: 1000}
	dirOwners := &unix.Stat_t{Mode: unix.S_IFREG | 0o666, Uid: 0}
	for _, tc := range []struct {
		name  string
		dir   *unix.Stat_t
		file  *unix.Stat_t
		level int
		want  error
	}{
		{"another's file in a sticky world-writable directory", world, other, 1, unix.EACCES},
		{"the same with the sysctl off", world, other, 0, nil},
		{"the opener's own file", world, mine, 1, nil},
		{"the directory owner's file", world, dirOwners, 1, nil},
		{"a directory not sticky", plain, other, 2, nil},
		{"a sticky group-writable directory, level 1", group, other, 1, nil},
		{"a sticky group-writable directory, level 2", group, other, 2, unix.EACCES},
	} {
		if err := stickyCreate(tc.dir, tc.file, 1000, tc.level); !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// mayFollow is may_follow_link's rule on the facts of the link and its directory, then the nosymfollow mount check.
func TestFollowFactsMayFollow(t *testing.T) {
	f := &followFacts{fsuid: 1000, protected: true}
	sticky := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0o777, Uid: 0}
	plain := &unix.Stat_t{Mode: unix.S_IFDIR | 0o777, Uid: 0}
	byOther := &unix.Stat_t{Mode: unix.S_IFLNK | 0o777, Uid: 2000}
	byDirOwner := &unix.Stat_t{Mode: unix.S_IFLNK | 0o777, Uid: 0}
	byFollower := &unix.Stat_t{Mode: unix.S_IFLNK | 0o777, Uid: 1000}
	fd, err := unix.Open(".", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a test descriptor
	for _, tc := range []struct {
		name     string
		dir      *unix.Stat_t
		dirOK    bool
		lst      *unix.Stat_t
		trailing bool
		want     error
	}{
		{"another's link in a sticky world-writable directory", sticky, true, byOther, true, unix.EACCES},
		// pick_link checks may_follow_link for a trailing link alone (WALK_TRAILING); the kernel follows this one, as
		// root's protected_symlink_mid case shows (refuted).
		{"the same, not trailing", sticky, true, byOther, false, nil},
		{"the directory owner's link", sticky, true, byDirOwner, true, nil},
		{"the follower's own link", sticky, true, byFollower, true, nil},
		{"a directory not sticky", plain, true, byOther, true, nil},
		{"a directory that cannot be read", sticky, false, byOther, true, unix.EACCES},
	} {
		if err := f.mayFollow(tc.dir, tc.dirOK, fd, tc.lst, tc.trailing); !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}
