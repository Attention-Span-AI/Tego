// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestParseProcStat covers the field arithmetic exec ids depend on, including a comm that contains the
// separators the naive parse would trip on.
func TestParseProcStat(t *testing.T) {
	fields := func(comm string, ppid int, start uint64) string {
		out := []string{"42", "(" + comm + ")", "S", strconv.Itoa(ppid)}
		for i := 5; i <= 21; i++ {
			out = append(out, "0")
		}
		return strings.Join(append(out, strconv.FormatUint(start, 10), "0", "0"), " ")
	}
	tests := []struct {
		name      string
		in        string
		wantPPID  int
		wantStart uint64
		wantErr   bool
	}{
		{name: "plain", in: fields("bash", 100, 1234), wantPPID: 100, wantStart: 1234},
		{name: "comm with a space", in: fields("Web Content", 7, 99), wantPPID: 7, wantStart: 99},
		{name: "comm with parentheses", in: fields("a) (b", 7, 99), wantPPID: 7, wantStart: 99},
		{name: "trailing newline", in: fields("sh", 1, 5) + "\n", wantPPID: 1, wantStart: 5},
		{name: "no comm", in: "42 bash S 1", wantErr: true},
		{name: "too few fields", in: "42 (bash) S 1 2 3", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "ppid not a number", in: "42 (bash) S x" + strings.Repeat(" 0", 20), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ppid, start, err := parseProcStat(tc.in)
			if tc.wantErr {
				if !errors.Is(err, errProcStat) {
					t.Fatalf("err = %v, want errProcStat", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if ppid != tc.wantPPID || start != tc.wantStart {
				t.Errorf("= %d, %d; want %d, %d", ppid, start, tc.wantPPID, tc.wantStart)
			}
		})
	}
}

// releasedStat is a /proc/<pid>/stat line of a task released while it was read: fs/proc/array.c's do_task_stat
// could not take its sighand lock, so process group and session are -1, ppid and num_threads 0. A reader on kernel
// 6.17 caught it for a live process whose old leader an execve from another thread released (de_thread), so it
// does not say the process is gone (internal/platform/proc's releasedStatLine gives the source lines).
const releasedStat = "842314 (exe) Z 0 -1 -1 0 -1 4228108 40251 0 0 0 4 27 0 0 20 0 0 0 82606841 0 0 0 0 0 0 0 " +
	"0 0 0 0 0 1 0 0 -1 6 0 0 0 0 0 0 0 0 0 0 0 0 0\n"

// TestAReleasedLineIsNotESRCH: a released line readStat's reads ran out on is errProcStat, never ESRCH. As ESRCH
// it took a live process mid-exec for a gone one: groupsOf left it out of the snapshot a group signal is decided
// on (R33), and groupMembers answered its group empty. The scan fails instead.
func TestAReleasedLineIsNotESRCH(t *testing.T) {
	if _, _, err := parseProcStat(releasedStat); !errors.Is(err, errProcStat) || errors.Is(err, unix.ESRCH) {
		t.Fatalf("parseProcStat(released) = %v, want errProcStat and not ESRCH", err)
	}
	_, err := parseProcPgrp([]byte(releasedStat))
	if !errors.Is(err, errProcStat) || errors.Is(err, unix.ESRCH) {
		t.Fatalf("parseProcPgrp(released) = %v, want errProcStat and not ESRCH", err)
	}
	if g, err := groupsOf([]int{842314}, func(int) (int, error) { return 0, err }); err == nil {
		t.Fatalf("groupsOf with a released line = %v, want the scan to fail", g)
	}
	if g, err := parseProcPgrp([]byte("9 (a) S 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5")); err != nil || g != 77 {
		t.Fatalf("parseProcPgrp(live) = %d, %v; want 77", g, err)
	}
}

// TestTheTTYClassDoesNotReadAReleasedLine: heldTTY refuses an open that would have made a session leader with no
// controlling terminal acquire one, by the session and tty_nr of the task's stat. A released line prints session -1
// and tty 0; read by hand it passed as a real session. Its task had already been released, so no open reached the
// thread that asked, but -1 is no session. sessionTTY now goes through readStat and ParseStat: a released line is
// read again, and one that stays released is errProcStat, which heldTTY refuses as unavailable.
func TestTheTTYClassDoesNotReadAReleasedLine(t *testing.T) {
	if s, tty, err := parseSessionTTY([]byte(releasedStat)); !errors.Is(err, errProcStat) {
		t.Fatalf("parseSessionTTY(released) = session %d, tty %d, %v; want errProcStat", s, tty, err)
	}
	if s, tty, err := parseSessionTTY([]byte("9 (a b) S 1 77 9 34817 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5")); err != nil || s != 9 || tty != 34817 {
		t.Fatalf("parseSessionTTY(live) = session %d, tty %d, %v; want 9, 34817", s, tty, err)
	}
}

// TestAReleasedLineLeavesAThreadUnknown: mutationMayRun drops a pending mutation once its thread's stat says it
// ended. Read by hand, a released line's state Z said "ended". That was true of the released task, but the line is
// one ParseStat refuses, so threadEnded now answers unknown: the mutation may run, and the walk cache stays
// invalidated. A gone thread (ENOENT, ESRCH) and a zombie's own line still end it.
func TestAReleasedLineLeavesAThreadUnknown(t *testing.T) {
	if ended, known := threadEnded([]byte(releasedStat), nil); known {
		t.Fatalf("threadEnded(released) = %v, known; want unknown", ended)
	}
	if ended, known := threadEnded(nil, fmt.Errorf("open: %w", os.ErrNotExist)); !ended || !known {
		t.Fatalf("threadEnded(ENOENT) = %v, %v; want ended", ended, known)
	}
	if ended, known := threadEnded(nil, unix.ESRCH); !ended || !known {
		t.Fatalf("threadEnded(ESRCH) = %v, %v; want ended", ended, known)
	}
	if ended, known := threadEnded(nil, unix.EACCES); known {
		t.Fatalf("threadEnded(EACCES) = %v, known; want unknown", ended)
	}
	if ended, known := threadEnded([]byte("9 (a) Z 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5"), nil); !ended || !known {
		t.Fatalf("threadEnded(zombie) = %v, %v; want ended", ended, known)
	}
	if ended, known := threadEnded([]byte("9 (a) S 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5"), nil); ended || !known {
		t.Fatalf("threadEnded(sleeping) = %v, %v; want running", ended, known)
	}
}

// statReads stands lines in for readStatFile at pid, one per read (the last repeats), and counts the reads; every
// other pid reads its file. A nil error and an empty line is the line; a non-nil error is that read's error.
func statReads(t *testing.T, pid int, lines []string, errs []error) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	f := func(p int) ([]byte, error) {
		if p != pid {
			return os.ReadFile("/proc/" + strconv.Itoa(p) + "/stat")
		}
		i := min(int(n.Add(1))-1, len(lines)-1)
		if errs[i] != nil {
			return nil, errs[i]
		}
		return []byte(lines[i]), nil
	}
	statFileSeam.Store(&f)
	t.Cleanup(func() { statFileSeam.Store(nil) })
	return &n
}

// TestTheStatReadersReadAReleasedLineAgain drives sessionTTY and mutationMayRun through readStatFile, so a reader
// that went back to one read of the file by hand fails here: no process holds the pid, so only the lines stood in
// answer. A released line is read again and the live line after it is used; one that stays released after three
// reads is errProcStat for sessionTTY and "may run" for mutationMayRun; a released line and then no file is gone.
func TestTheStatReadersReadAReleasedLineAgain(t *testing.T) {
	const pid = 1 << 30 // above any pid_max, so /proc/<pid> never exists
	live := "1073741824 (a b) S 1 77 9 34817 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5"
	zombie := "1073741824 (a) Z 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5"
	gone := fmt.Errorf("open /proc/%d/stat: %w", pid, os.ErrNotExist)

	n := statReads(t, pid, []string{releasedStat, releasedStat, live}, []error{nil, nil, nil})
	if s, tty, err := sessionTTY(pid); err != nil || s != 9 || tty != 34817 || n.Load() != 3 {
		t.Fatalf("sessionTTY(released, released, live) = %d, %d, %v after %d reads; want 9, 34817 after 3", s, tty, err, n.Load())
	}
	n = statReads(t, pid, []string{releasedStat}, []error{nil})
	if s, tty, err := sessionTTY(pid); !errors.Is(err, errProcStat) || n.Load() != 3 {
		t.Fatalf("sessionTTY(released x3) = %d, %d, %v after %d reads; want errProcStat after 3", s, tty, err, n.Load())
	}
	n = statReads(t, pid, []string{releasedStat}, []error{nil})
	if !mutationMayRun(pid, 0) || n.Load() != 3 {
		t.Fatalf("mutationMayRun(released x3) = false after %d reads; want may run after 3", n.Load())
	}
	n = statReads(t, pid, []string{releasedStat, zombie}, []error{nil, nil})
	if mutationMayRun(pid, 0) || n.Load() != 2 {
		t.Fatalf("mutationMayRun(released, zombie) = true after %d reads; want ended after 2", n.Load())
	}
	n = statReads(t, pid, []string{releasedStat, ""}, []error{nil, gone})
	if mutationMayRun(pid, 0) || n.Load() != 2 {
		t.Fatalf("mutationMayRun(released, gone) = true after %d reads; want ended after 2", n.Load())
	}
}

// TestInGroupOnThisProcess: InGroup is the lookup tgidOf revalidates a cached answer with. This thread is
// a thread of this process; pid 1 is not.
func TestInGroupOnThisProcess(t *testing.T) {
	k := sysKernel{}
	if !k.InGroup(os.Getpid(), os.Getpid()) {
		t.Error("InGroup(self, self) = false, want the leader in its own group")
	}
	if os.Getpid() != 1 && k.InGroup(os.Getpid(), 1) {
		t.Error("InGroup(self, 1) = true, want false")
	}
}

// TestParseTgid covers the one line of /proc/<pid>/status an exec id needs.
func TestParseTgid(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{name: "normal", in: "Name:\tbash\nUmask:\t0022\nState:\tS\nTgid:\t4200\nNgid:\t0\n", want: 4200},
		{name: "first line", in: "Tgid:\t7\n", want: 7},
		{name: "no tgid", in: "Name:\tbash\n", wantErr: true},
		{name: "not a number", in: "Tgid:\tx\n", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTgid(tc.in)
			if tc.wantErr {
				if !errors.Is(err, errProcStat) {
					t.Fatalf("err = %v, want errProcStat", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("= %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

// TestSysKernelProcReads reads this very process through the production kernel seam: the values are
// checked against what the runtime already knows rather than against a fixture.
func TestSysKernelProcReads(t *testing.T) {
	k := sysKernel{}
	pid := os.Getpid()
	tgid, err := k.Tgid(pid)
	if err != nil {
		t.Fatalf("Tgid: %v", err)
	}
	if tgid != pid {
		t.Errorf("Tgid = %d, want this process's own pid %d", tgid, pid)
	}
	ppid, start, err := k.ProcStat(pid)
	if err != nil {
		t.Fatalf("ProcStat: %v", err)
	}
	if ppid != os.Getppid() {
		t.Errorf("ppid = %d, want %d", ppid, os.Getppid())
	}
	if start == 0 {
		t.Error("starttime = 0")
	}
	if _, _, err := k.ProcStat(-1); err == nil {
		t.Error("ProcStat(-1) reported no error")
	}
	link, err := k.Readlink("/proc/self/cwd")
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if !strings.HasPrefix(link, "/") {
		t.Errorf("cwd = %q, want an absolute path", link)
	}
	if _, err := k.Readlink("/proc/self/nonexistent-magic-link"); err == nil {
		t.Error("Readlink of a missing link reported no error")
	}
}

// TestSysKernelPlaceLinkFollowsNoLinkBeforeItsName: the kernel's read of one name of a unix
// path being placed reads a symlink in a plain directory, and fails ELOOP where a directory before the name is a
// symlink, which Readlink, the /proc magic-link read, follows.
func TestSysKernelPlaceLinkFollowsNoLinkBeforeItsName(t *testing.T) {
	k := sysKernel{}
	base := t.TempDir()
	if err := os.Mkdir(base+"/real", 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"real/l": "x.sock", "dirlink": "real"} {
		if err := os.Symlink(target, base+"/"+link); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := k.PlaceLink(base + "/real/l"); got != "x.sock" || err != nil {
		t.Errorf("PlaceLink(real/l) = %q, %v; want x.sock", got, err)
	}
	if got, err := k.PlaceLink(base + "/dirlink/l"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("PlaceLink(dirlink/l) = %q, %v; want ELOOP, the directory link not followed", got, err)
	}
	if got, err := k.Readlink(base + "/dirlink/l"); got != "x.sock" || err != nil {
		t.Errorf("Readlink(dirlink/l) = %q, %v; want x.sock", got, err)
	}
}

// TestSysKernelUnlinkedTellsNameFromUnlink: readlink spells a live directory named "d (deleted)" exactly as it
// spells an unlinked "d", and the link count through the same /proc link tells them apart.
func TestSysKernelUnlinkedTellsNameFromUnlink(t *testing.T) {
	k := sysKernel{}
	base := t.TempDir()
	open := func(p string) string {
		t.Helper()
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(p, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return "/proc/self/fd/" + strconv.Itoa(fd)
	}
	live, gone := open(base+"/d (deleted)"), open(base+"/d")
	if err := os.Remove(base + "/d"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		link string
		want bool
	}{{live, false}, {gone, true}} {
		l, err := k.Readlink(tc.link)
		if err != nil || !strings.HasSuffix(l, deletedSuffix) {
			t.Fatalf("readlink %s = %q, %v; want a %q suffix", tc.link, l, err, deletedSuffix)
		}
		if got, err := k.Unlinked(tc.link); got != tc.want || err != nil {
			t.Errorf("Unlinked(%s -> %q) = %v, %v; want %v", tc.link, l, got, err, tc.want)
		}
	}
	if _, err := k.Unlinked("/proc/self/fd/-1"); err == nil {
		t.Error("Unlinked of a missing link reported no error")
	}
}

// TestSysKernelReadMem reads this process's own memory through process_vm_readv: the same call the loop
// makes against a target, with a buffer whose contents are known.
func TestSysKernelReadMem(t *testing.T) {
	k := sysKernel{}
	want := []byte("tego supervisor read-mem probe")
	src := make([]byte, len(want))
	copy(src, want)
	got := make([]byte, len(want))
	n, err := k.ReadMem(os.Getpid(), uint64(uintptrOf(src)), got)
	if err != nil {
		t.Fatalf("ReadMem: %v", err)
	}
	if n != len(want) || string(got) != string(want) {
		t.Errorf("read %d bytes %q, want %q", n, got, want)
	}
	if _, err := k.ReadMem(os.Getpid(), 0, got); err == nil {
		t.Error("a read of the null page reported no error")
	}
}

// TestSysKernelProcMemFallback exercises the /proc/<pid>/mem path directly: it only runs in production on
// a kernel without process_vm_readv, which this box is not, so nothing else would cover it.
func TestSysKernelProcMemFallback(t *testing.T) {
	k := sysKernel{}
	want := []byte("tego supervisor proc-mem probe")
	src := make([]byte, len(want))
	copy(src, want)
	got := make([]byte, len(want))
	n, err := k.readProcMem(os.Getpid(), uint64(uintptrOf(src)), got)
	if err != nil {
		t.Fatalf("readProcMem: %v", err)
	}
	if n != len(want) || string(got) != string(want) {
		t.Errorf("read %d bytes %q, want %q", n, got, want)
	}
	if _, err := k.readProcMem(os.Getpid(), 0, got); err == nil {
		t.Error("a read of the null page reported no error")
	}
	if _, err := k.readProcMem(-1, 0, got); err == nil {
		t.Error("a read of a nonexistent process reported no error")
	}
}

// uintptrOf is the address of a slice's first byte, for the read-mem probe above.
func uintptrOf(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }

// TestSameFilesAsksTheKernel pins sysKernel.SameFiles against the real kcmp(2): two threads of this process
// share one descriptor table, and a child process started without CLONE_FILES has its own.
func TestSameFilesAsksTheKernel(t *testing.T) {
	var k sysKernel
	tids := make(chan int)
	release := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- unix.Gettid()
		<-release
	}()
	other := <-tids
	defer close(release)
	same, err := k.SameFiles(os.Getpid(), other)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		t.Skipf("kcmp unavailable here: %v", err)
	}
	if err != nil || !same {
		t.Fatalf("SameFiles(leader, thread %d) = %v, %v; want true", other, same, err)
	}
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("no child to compare with: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if same, err := k.SameFiles(os.Getpid(), cmd.Process.Pid); err != nil || same {
		t.Fatalf("SameFiles(self, child) = %v, %v; want false", same, err)
	}
}

// TestGroupsOfSkipsOnlyExitedProcesses: a process that exited mid-scan is not in any group, but one the scan
// could not read might be, so it fails the scan with the pid named.
func TestGroupsOfSkipsOnlyExitedProcesses(t *testing.T) {
	read := func(errs map[int]error) func(int) (int, error) {
		return func(pid int) (int, error) {
			if err, ok := errs[pid]; ok {
				return 0, err
			}
			return pid / 10, nil
		}
	}
	got, err := groupsOf([]int{10, 11, 20}, read(map[int]error{11: unix.ESRCH}))
	if err != nil || len(got) != 2 || len(got[1]) != 1 || len(got[2]) != 1 {
		t.Fatalf("groupsOf with an exited pid = %v, %v; want {1:[10] 2:[20]}", got, err)
	}
	for _, e := range []error{unix.EMFILE, unix.ENFILE, unix.ENOMEM, unix.EACCES, errProcStat} {
		got, err := groupsOf([]int{10, 11, 20}, read(map[int]error{11: e}))
		if !errors.Is(err, e) || !strings.Contains(fmt.Sprint(err), "11") || got != nil {
			t.Errorf("groupsOf with pid 11 failing %v = %v, %v; want the error naming pid 11 and no groups", e, got, err)
		}
	}
}
