// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// compileDiagsWithin is compileWithin for a test that reads the diagnostics.
func compileDiagsWithin(t *testing.T, f *fixture, c *Contract, limit time.Duration) (*RuleTable, []Diagnostic) {
	t.Helper()
	type result struct {
		rt  *RuleTable
		ds  []Diagnostic
		err error
	}
	done := make(chan result, 1)
	go func() {
		rt, ds, err := Compile(c, f.machine, f.opts()...)
		done <- result{rt, ds, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("compile: %v\n%s", r.err, render(r.ds))
		}
		return r.rt, r.ds
	case <-time.After(limit):
		t.Fatalf("compile did not return within %s", limit)
		return nil, nil
	}
}

// leased writes a file and takes a write lease on it, as the owner of any file may (F_SETLEASE): the next
// open of it for reading breaks the lease, and one without O_NONBLOCK waits for the break, lease-break-time,
// 45 s by default, while the holder does not give it up. An agent can hold one on its own files while its run
// is live, which is when a second run's compile reads them. "" when this machine grants no lease (leases
// disabled, or a file system without them), and the caller skips that row alone.
func leased(t *testing.T, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "leased")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if !leaseOn(t, p) {
		return ""
	}
	return p
}

// leaseOn takes a write lease on the existing file at p through an O_RDONLY descriptor, which is all its
// owner needs, held until the test ends; false when this machine grants none, and the caller skips that row.
func leaseOn(t *testing.T, p string) bool {
	t.Helper()
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_WRLCK); err != nil {
		_ = unix.Close(fd)
		t.Logf("no write lease on %s here, that row is skipped: %v", p, err)
		return false
	}
	t.Cleanup(func() {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_UNLCK)
		_ = unix.Close(fd)
	})
	return true
}

// mqueueFile creates a POSIX message queue and returns its file under /dev/mqueue: a regular file, of size
// 80, on a file system that is neither a kernel interface list's nor one that stores data, which reads as a
// line of queue statistics. It is the plainest file an unprivileged user can make on such a file system.
// "" when no mqueue file system is mounted at /dev/mqueue, and the caller skips that row alone.
func mqueueFile(t *testing.T) string {
	t.Helper()
	if fi, err := os.Stat("/dev/mqueue"); err != nil || !fi.IsDir() {
		t.Log("no /dev/mqueue here, that row is skipped")
		return ""
	}
	name := "tego-test-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	fd, _, errno := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(p)), unix.O_CREAT|unix.O_EXCL|unix.O_RDONLY|unix.O_CLOEXEC, 0o600, 0, 0, 0)
	if errno != 0 {
		t.Logf("mq_open: %v, that row is skipped", errno)
		return ""
	}
	t.Cleanup(func() {
		_ = unix.Close(int(fd))
		_, _, _ = unix.Syscall(unix.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(p)), 0, 0)
		runtime.KeepAlive(p)
	})
	return "/dev/mqueue/" + name
}

// within runs f and fails the test when it has not returned after 10 s.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return within 10 s", what)
	}
}

// TestReadInterpAndShebangRefuse is I6 for R8's reads: ReadInterp and ReadShebang open the command, an mcp
// command and every exec.allow entry, which often lie in the worktree, and the Landlock tier's Prepare opens
// them again. Through os.Open a FIFO there blocked the operator's next compile (and the run's Prepare) in
// open(2) for ever, /dev/zero was a device's open, and a file under a write lease held it for the
// lease-break time. Each must now return at once with an error that is no verdict on the content, neither
// ErrNotELF nor ErrMalformedELF, so compile says it could not read the file rather than that it is a script
// or a broken binary; and so must a regular file on a file system that is not known to store data, which a
// list of file systems to skip would have let through.
func TestReadInterpAndShebangRefuse(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	zero := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	kmsg := filepath.Join(dir, "kmsg")
	if err := os.Symlink("/proc/kmsg", kmsg); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, path string }{
		{"a FIFO", fifo},
		{"a link to /dev/zero", zero},
		{"a link to /proc/kmsg", kmsg},
		{"a directory", dir},
		{"a file under a write lease", leased(t, elf64("/lib64/ld-linux-x86-64.so.2", 1))},
		{"a message queue", mqueueFile(t)},
	}
	for _, tc := range cases {
		if tc.path == "" {
			continue
		}
		within(t, "ReadInterp("+tc.name+")", func() {
			if got, err := ReadInterp(tc.path); err == nil || errors.Is(err, ErrNotELF) || errors.Is(err, ErrMalformedELF) {
				t.Errorf("ReadInterp(%s) = %q, %v; want an error that is no verdict on the content", tc.name, got, err)
			}
		})
		within(t, "ReadShebang("+tc.name+")", func() {
			if interp, _, ok, err := ReadShebang(tc.path); err == nil {
				t.Errorf("ReadShebang(%s) = %q, %v, nil; want an error", tc.name, interp, ok)
			}
		})
	}
	// The same reads of an ordinary binary and script are unchanged.
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, elf64("/lib64/ld-linux-x86-64.so.2", 3), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadInterp(bin); err != nil || got != "/lib64/ld-linux-x86-64.so.2" {
		t.Errorf("ReadInterp(an ELF) = %q, %v", got, err)
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env python3\n"+strings.Repeat("x", 1<<20)), 0o755); err != nil {
		t.Fatal(err)
	}
	if interp, arg, ok, err := ReadShebang(script); err != nil || !ok || interp != "/usr/bin/env" || arg != "python3" {
		t.Errorf("ReadShebang(a 1 MiB script) = %q, %q, %v, %v", interp, arg, ok, err)
	}
	if _, err := ReadInterp(script); !errors.Is(err, ErrNotELF) {
		t.Errorf("ReadInterp(a script) = %v, want ErrNotELF", err)
	}
}

// errReaderAt answers every read with err, as a descriptor under a lock or a lease answers EAGAIN.
type errReaderAt struct{ err error }

func (r errReaderAt) ReadAt([]byte, int64) (int, error) { return 0, r.err }

// shortThenErr serves data and answers err for any read past it.
type shortThenErr struct {
	data []byte
	err  error
}

func (r shortThenErr) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > int64(len(r.data)) {
		return 0, r.err
	}
	return copy(p, r.data[off:]), nil
}

// TestReadInterpReturnsReadErrors pins that readInterp tells a file it could not read from one whose content
// it judged: an error other than the end of the file is returned as it is, at the identification bytes and
// past them. It answered ErrNotELF for the first, so compile took a file it never read for a script, and the
// Landlock tier checked its #! instead of failing the run.
func TestReadInterpReturnsReadErrors(t *testing.T) {
	if _, err := readInterp(errReaderAt{syscall.EAGAIN}); !errors.Is(err, syscall.EAGAIN) {
		t.Errorf("an unreadable file: %v, want EAGAIN", err)
	}
	head := elf64("/lib64/ld-linux-x86-64.so.2", 3)[:70]
	if _, err := readInterp(shortThenErr{head, syscall.EIO}); !errors.Is(err, syscall.EIO) {
		t.Errorf("a read error past the header: %v, want EIO", err)
	}
	if _, err := readInterp(shortThenErr{head, io.EOF}); !errors.Is(err, ErrMalformedELF) {
		t.Errorf("a file that ends in the program headers: %v, want ErrMalformedELF", err)
	}
	// An e_phentsize past the fields read is the stride between headers, not more to read.
	wide := elf64("/lib64/ld.so", 1)
	wide[54], wide[55] = 0xff, 0xff
	r := &countingReaderAt{data: wide}
	_, _ = readInterp(r)
	if r.n > maxELFRead {
		t.Errorf("read %d bytes of a header claiming e_phentsize 65535, over maxELFRead %d", r.n, maxELFRead)
	}
}

// countingReaderAt is a bytes reader that counts what is asked of it.
type countingReaderAt struct {
	data []byte
	n    int
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.n += len(p)
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// interruptReads makes the first n reads through sysRead and sysPread answer with instead of reading, for the
// rest of the test, and returns the count of reads made.
func interruptReads(t *testing.T, n int, with error) *int {
	t.Helper()
	read, pread := sysRead, sysPread
	t.Cleanup(func() { sysRead, sysPread = read, pread })
	calls := 0
	sysRead = func(fd int, p []byte) (int, error) {
		if calls++; calls <= n {
			return 0, with
		}
		return read(fd, p)
	}
	sysPread = func(fd int, p []byte, off int64) (int, error) {
		if calls++; calls <= n {
			return 0, with
		}
		return pread(fd, p, off)
	}
	return &calls
}

// TestReadRetriesEINTR pins the read loops' answer to an interrupted read. A FUSE or network file system
// answers EINTR when a signal arrives while the read waits on its daemon or server, and os.File retried it;
// readBounded and preadFull refused it, so ReadInterp and ReadShebang failed a run on such a mount at
// Prepare (exit 125) now and then, and compile warned malformed-elf. EINTR is now retried up to maxEINTR
// times in one read loop and refused past that; EAGAIN, the answer of a lease or a lock the file's owner
// holds, is still refused at once.
func TestReadRetriesEINTR(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh -e\necho\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "python")
	if err := os.WriteFile(bin, elf64("/lib64/ld-fake.so.2", 3), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		n     int
		with  error
		ok    bool
		calls int // reads made before the refusal, 0 when it reads through
	}{
		{"EINTR up to the retries", maxEINTR, unix.EINTR, true, 0},
		{"EINTR past the retries", maxEINTR + 1, unix.EINTR, false, maxEINTR + 1},
		{"EAGAIN at once", maxEINTR, unix.EAGAIN, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(what string, err error, calls *int) {
				t.Helper()
				switch {
				case tc.ok && err != nil:
					t.Errorf("%s: %v; want the read retried through %d interruptions", what, err, tc.n)
				case !tc.ok && !errors.Is(err, tc.with):
					t.Errorf("%s: %v; want %v", what, err, tc.with)
				case !tc.ok && *calls != tc.calls:
					t.Errorf("%s: refused after %d reads; want %d", what, *calls, tc.calls)
				}
			}
			calls := interruptReads(t, tc.n, tc.with)
			data, err := readSmallErr(script, 64, true)
			check("readSmallErr", err, calls)
			if tc.ok && string(data) != "#!/bin/sh -e\necho\n" {
				t.Errorf("readSmallErr = %q", data)
			}

			calls = interruptReads(t, tc.n, tc.with)
			interp, arg, ok, err := ReadShebang(script)
			check("ReadShebang", err, calls)
			if tc.ok && (!ok || interp != "/bin/sh" || arg != "-e") {
				t.Errorf("ReadShebang = %q %q %v", interp, arg, ok)
			}

			calls = interruptReads(t, tc.n, tc.with)
			loader, err := ReadInterp(bin)
			check("ReadInterp", err, calls)
			if tc.ok && loader != "/lib64/ld-fake.so.2" {
				t.Errorf("ReadInterp = %q", loader)
			}
		})
	}
}

// TestExecPlantedFiles is the R8 half of I6: the command, an mcp command, an exec.allow entry and a script's
// #! interpreter are read to find a loader or an interpreter, and each can be a file the agent planted in a
// write entry before the next compile. As a FIFO, compile blocked in open(2) for ever; linked to /dev/zero, it
// ran a device's open. Each must compile promptly and warn naming the file and why it was not read.
func TestExecPlantedFiles(t *testing.T) {
	cases := []struct {
		name, yaml string
		plant      func(t *testing.T, f *fixture, work string)
		file, why  string
	}{
		{"the command is a FIFO", "command: [\"./work/run.sh\"]\n", func(t *testing.T, f *fixture, work string) {
			mkfifo(t, filepath.Join(work, "run.sh"))
		}, "run.sh", "a FIFO"},
		{"an exec.allow entry is a FIFO", "command: [\"python\"]\nexec:\n  allow: [\"./work/tool\"]\n", func(t *testing.T, f *fixture, work string) {
			mkfifo(t, filepath.Join(work, "tool"))
		}, "tool", "a FIFO"},
		{"an mcp command is a FIFO", "command: [\"python\"]\nmcp:\n  - name: srv\n    command: [\"./work/srv\"]\n", func(t *testing.T, f *fixture, work string) {
			mkfifo(t, filepath.Join(work, "srv"))
		}, "srv", "a FIFO"},
		{"a script's #! names a FIFO", "command: [\"./work/run.sh\"]\n", func(t *testing.T, f *fixture, work string) {
			mkfifo(t, filepath.Join(work, "interp"))
			f.file(filepath.Join(work, "run.sh"), "#!"+filepath.Join(work, "interp")+"\n", 0o755)
		}, "interp", "a FIFO"},
		{"the command links to /dev/zero", "command: [\"./work/run.sh\"]\n", func(t *testing.T, f *fixture, work string) {
			if err := os.Symlink("/dev/zero", filepath.Join(work, "run.sh")); err != nil {
				t.Fatal(err)
			}
		}, "run.sh", "a character device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			work := filepath.Join(f.project, "work")
			if err := os.Mkdir(work, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, f, work)
			_, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\n"+tc.yaml+"fs:\n  write: [\"work/\"]\n"), 10*time.Second)
			want := filepath.Join(work, tc.file) + ": not a regular file (" + tc.why + ")"
			if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodeMalformedELF && strings.Contains(d.Message, want) }) {
				t.Errorf("want a malformed-elf warning saying %q:\n%s", want, render(ds))
			}
		})
	}
}

func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestExecKernelFileLinks is R2-1's case on R8's reads: the command, an exec.allow entry and an mcp command
// linked to /proc/kmsg, a regular file of size 0. As root, os.Open of it succeeded and the read, parked by
// Go's poller on its EAGAIN, waited for the next kernel message, so the next compile hung, having consumed the
// unread kernel log. Such an entry is now refused before anything reads it, as an exec entry leading through
// /proc (R8a, exec-proc), and compile returns at once. It needs root to fail, and runs as root in the KVM guest
// (test/vm/kvm-run.sh), after the unread log is drained, as docs/p0/agent-contract.md section 10 says; as any
// other user it pins the prompt return. The bounded reader's refusal of a file system not known to store data,
// which this test held before R8a, is held by TestExecNonDataFileLinks.
func TestExecKernelFileLinks(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run", "tool", "srv"} {
		if err := os.Symlink("/proc/kmsg", filepath.Join(work, name)); err != nil {
			t.Fatal(err)
		}
	}
	c := f.load("version: 0\nname: t\ncommand: [\"./work/run\"]\nexec:\n  allow: [\"./work/tool\"]\nmcp:\n  - name: srv\n    command: [\"./work/srv\"]\nfs:\n  write: [\"work/\"]\n")
	done := make(chan []Diagnostic, 1)
	go func() {
		_, ds, _ := Compile(c, f.machine, f.opts()...)
		done <- ds
	}()
	var ds []Diagnostic
	select {
	case ds = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("compile did not return within 10s")
	}
	for _, name := range []string{"run", "tool", "srv"} {
		want := filepath.Join(work, name) + " leads through the /proc path /proc/kmsg"
		if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeExecProc && d.Severity == SeverityError && strings.Contains(d.Message, want)
		}) {
			t.Errorf("want an exec-proc error saying %q:\n%s", want, render(ds))
		}
	}
}

// TestExecNonDataFileLinks: an exec entry that is a link to a file on a file system not known to store data (sysfs
// here) is not read for its ELF header: the bounded reader refuses it, and compile says which file system it is on.
func TestExecNonDataFileLinks(t *testing.T) {
	const target = "/sys/kernel/uevent_seqnum"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("%s: %v", target, err)
	}
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run", "tool", "srv"} {
		if err := os.Symlink(target, filepath.Join(work, name)); err != nil {
			t.Fatal(err)
		}
	}
	_, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"./work/run\"]\nexec:\n  allow: [\"./work/tool\"]\nmcp:\n  - name: srv\n    command: [\"./work/srv\"]\nfs:\n  write: [\"work/\"]\n"), 10*time.Second)
	for _, name := range []string{"run", "tool", "srv"} {
		want := filepath.Join(work, name) + ": on a file system not known to store data (sysfs, magic 0x62656572)"
		// The fix names the file system as the mount table does, and says it is not on the list.
		fix := "is on sysfs (magic 0x62656572), which is not on the list of file systems Tego reads as data"
		if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeMalformedELF && strings.Contains(d.Message, want) && strings.Contains(d.Fix, fix)
		}) {
			t.Errorf("want a malformed-elf warning saying %q, with a fix saying %q:\n%s", want, fix, render(ds))
		}
	}
}

// loopWorktrees plants what makes each of R20's probes expensive to resolve in user space: a git directory
// work/g whose config and config.worktree each set 8 distinct core.hooksPath values, and n directories
// work/r<i>, each a worktree of it through a .git file and each holding the link l -> ., so a value
// "l/l/l/.../l" names a path that exists at every length the kernel accepts and loops at every length. value
// returns the i'th value.
func loopWorktrees(t *testing.T, f *fixture, work string, n int, value func(i int) string) {
	t.Helper()
	plantGitDir(t, f, filepath.Join(work, "g"), value)
	for i := 0; i < n; i++ {
		r := filepath.Join(work, "r"+strconv.Itoa(i))
		if err := os.Mkdir(r, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(".", filepath.Join(r, "l")); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(r, ".git"), "gitdir: ../g\n", 0o644)
	}
}

// plantGitDir makes a git directory at gd (HEAD, objects/, refs/, hooks/) whose config and config.worktree
// each set maxHooksValues core.hooksPath values, value(0) to value(2*maxHooksValues-1), all of which the
// search takes up, since each file contributes its last maxHooksValues distinct ones.
func plantGitDir(t *testing.T, f *fixture, gd string, value func(i int) string) {
	t.Helper()
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(gd, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(gd, "HEAD"), "ref: refs/heads/main\n", 0o644)
	for c, name := range []string{"config", "config.worktree"} {
		var b strings.Builder
		for i := 0; i < maxHooksValues; i++ {
			b.WriteString("[core]\n\thooksPath = " + value(c*maxHooksValues+i) + "\n")
		}
		f.file(filepath.Join(gd, name), b.String(), 0o644)
	}
}

// TestDenyWriteProbeCost is the cost of each probe R20's search makes, which its budget counts but did not
// bound: a probed path was resolved with filepath.EvalSymlinks, which follows up to 255 links and re-walks
// the path from the root at every component, before the only check that it existed. The agent chooses the
// core.hooksPath values of a git directory in its write entry, and every planted worktree of that git
// directory probes each value again. Three plants, each within the entry's budget, each took compile from
// under a second to tens of seconds or minutes: 16 values of about 4 KiB through a link loop from a thousand
// worktrees (about 20 s), 16 values naming real directories 1500 levels deep from four hundred worktrees
// (about 50 ms each, some five minutes), and two values of 250 KiB from a thousand worktrees (a minute or
// more). Each must now compile within 10 s.
func TestDenyWriteProbeCost(t *testing.T) {
	const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"
	loop := func(n int) string { return strings.TrimSuffix(strings.Repeat("l/", n), "/") }
	t.Run("4 KiB values through a link loop", func(t *testing.T) {
		f := newFixture(t)
		work := filepath.Join(f.project, "work")
		// config's values make a path past PATH_MAX from any worktree, config.worktree's one within it that
		// passes 40 links: the kernel refuses the first with ENAMETOOLONG and the second with ELOOP.
		loopWorktrees(t, f, work, 1000, func(i int) string {
			if i < maxHooksValues {
				return loop(2040 - i)
			}
			return loop(1700 - i)
		})
		start := time.Now()
		compileWithin(t, f, f.load(contract), 10*time.Second)
		t.Logf("compiled in %s", time.Since(start))
	})
	t.Run("values of 250 KiB", func(t *testing.T) {
		f := newFixture(t)
		work := filepath.Join(f.project, "work")
		loopWorktrees(t, f, work, 1000, func(i int) string {
			if i%maxHooksValues != maxHooksValues-1 {
				return "decoy" + strconv.Itoa(i)
			}
			return loop(125<<10 - i)
		})
		start := time.Now()
		compileWithin(t, f, f.load(contract), 10*time.Second)
		t.Logf("compiled in %s", time.Since(start))
	})
	t.Run("values deep in real directories", func(t *testing.T) {
		f := newFixture(t)
		work := filepath.Join(f.project, "work")
		if err := os.MkdirAll(work, 0o755); err != nil {
			t.Fatal(err)
		}
		// Each worktree's d links to work/deep/d, so "d/d/.../d" from any worktree is a real directory as
		// deep as the value is long.
		const levels = 1500
		deepChain(t, filepath.Join(work, "deep"), levels)
		deepValue := func(i int) string { return strings.TrimSuffix(strings.Repeat("d/", levels-i), "/") }
		loopWorktrees(t, f, work, 400, deepValue)
		for i := 0; i < 400; i++ {
			if err := os.Symlink("../deep/d", filepath.Join(work, "r"+strconv.Itoa(i), "d")); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := os.Lstat(filepath.Join(work, "r0", deepValue(0))); err != nil {
			t.Fatalf("the plant's deepest value must name a directory that exists: %v", err)
		}
		start := time.Now()
		rt := compileWithin(t, f, f.load(contract), 10*time.Second)
		t.Logf("compiled in %s", time.Since(start))
		want := filepath.Join(work, "r0", deepValue(0))
		if !slices.ContainsFunc(rt.DenyWrite, func(r FSRule) bool { return r.Path == want }) {
			t.Errorf("a hooks directory that exists, however deep, is still in the set")
		}
	})
}

// deepChain makes dir/d/d/.../d, levels deep, one level at a time from a descriptor, since the whole path is
// near PATH_MAX, and returns the deepest directory's path.
func deepChain(t *testing.T, dir string, levels int) string {
	t.Helper()
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < levels; i++ {
		if err := unix.Mkdirat(dfd, "d", 0o755); err != nil {
			t.Fatalf("level %d: %v", i, err)
		}
		next, err := unix.Openat(dfd, "d", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		_ = unix.Close(dfd)
		if err != nil {
			t.Fatal(err)
		}
		dfd = next
	}
	_ = unix.Close(dfd)
	return dir + strings.Repeat("/d", levels)
}

// TestEnvScanPlantedLinks is the cost of resolving what R6's .env scan finds: each .env file becomes a
// deny_read entry resolved like any other (E8), and the scan finds them where the agent writes, so the
// agent chooses both how many there are and where each link leads. Resolved with filepath.EvalSymlinks, a
// thousand .env.<n> links into a directory 1500 levels deep cost about 50 ms each, near a minute of the
// next compile. compiler.resolve is now the kernel's walk, and the compile must return within 10 s with
// every link still a deny_read entry governing where it leads.
func TestEnvScanPlantedLinks(t *testing.T) {
	f := newFixture(t)
	deep := deepChain(t, filepath.Join(f.root, "deep"), 1500)
	for i := 0; i < 1000; i++ {
		if err := os.Symlink(deep, filepath.Join(f.project, ".env."+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	rt, ds := compileWithinDiags(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\n"), 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	n := 0
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && strings.HasPrefix(filepath.Base(r.Path), ".env.") && r.Resolved == deep {
			n++
		}
	}
	// On a loaded machine the scan can reach envScanMaxTime first (398 of 1000 with the load average at 45,
	// 2026-09-24). That cut is the designed answer only when it is said: the [unenforced] warning naming the
	// scan's time limit. Silence with fewer than all of them is the failure.
	if n != 1000 && !(n > 0 && hasEnvScanCut(ds)) {
		t.Errorf("%d of the 1000 planted .env links are deny_read entries resolved to where they lead, and no warning says the scan was cut\n%s", n, render(ds))
	}
}

// TestDenyWriteCutSearchStillWarns is R20's one output kept when a limit cuts the search: the unenforced
// warning, per write entry, was written only when the entry had something in the set, so 4200 directories
// planted beside a real repository (plain mkdirs, past the 4096 directories one search examines) left the
// set empty and compile silent, the repository's hooks and config unnamed and no word of the cut. The entry
// must now be named with the cut, and a repository past the depth limit likewise; a tree that ends at the
// depth limit leaves nothing unsearched and warns nothing.
func TestDenyWriteCutSearchStillWarns(t *testing.T) {
	const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"
	warned := func(ds []Diagnostic, why string) bool {
		return slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeUnenforced && strings.Contains(d.Message, `fs.write "src/"`) && strings.Contains(d.Message, why) &&
				strings.Contains(d.Message, "may be writable by the agent without being named")
		})
	}

	f := newFixture(t)
	src := filepath.Join(f.project, "src")
	gitRepo(t, f, filepath.Join(src, "team", "real"))
	rt, _ := f.compile(f.load(contract))
	if !slices.Contains(denyWritePaths(rt), filepath.Join(src, "team", "real", ".git", "hooks")) {
		t.Fatalf("before the plant the repository is found: %v", denyWritePaths(rt))
	}
	for i := 0; i < 4200; i++ {
		if err := os.Mkdir(filepath.Join(src, "j"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rt, ds := f.compile(f.load(contract))
	if len(rt.DenyWrite) != 0 {
		t.Fatalf("the plant is past the budget, so the repository is not reached: %v", denyWritePaths(rt))
	}
	if !warned(ds, "ran out of its budget") {
		t.Errorf("an entry whose search the budget cut must say so with nothing in its set:\n%s", render(ds))
	}

	g := newFixture(t)
	src = filepath.Join(g.project, "src")
	gitRepo(t, g, filepath.Join(src, "a", "b", "c", "d", "real"))
	if _, ds := g.compile(g.load(contract)); !warned(ds, "stops at 4 levels") {
		t.Errorf("a repository past the depth limit must leave a warning naming the limit:\n%s", render(ds))
	}

	h := newFixture(t)
	src = filepath.Join(h.project, "src")
	if err := os.MkdirAll(filepath.Join(src, "a", "b", "c", "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.file(filepath.Join(src, "a", "b", "c", "d", "file"), "", 0o644)
	if _, ds := h.compile(h.load(contract)); strings.Contains(render(ds), "deny_write") {
		t.Errorf("a tree that ends at the depth limit leaves nothing unsearched:\n%s", render(ds))
	}
}

// TestEnvScanBounded is I6 for the built-in .env scan (R6's list, SEMANTICS §1): the project root is
// usually where the agent writes, and filepath.WalkDir read every entry of each directory, sorted, before
// its bound on entries was checked, so one directory of cheap hard links was listed in full, whatever its
// size. The scan now reads at most envScanMaxEntries entries in all, and says when it left entries unread,
// since a .env among them is then not in the list.
func TestEnvScanBounded(t *testing.T) {
	f := newFixture(t)
	wide := filepath.Join(f.project, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	// Hard links cost no inode each on a disk file system; a new file every 50000 names stays under ext4's
	// 65000 links to one inode. tmpfs charges each link to its inode limit, which a small one runs out of.
	const planted = 3 * envScanMaxEntries
	var one string
	for i := 0; i < planted; i++ {
		name := filepath.Join(wide, strconv.Itoa(i))
		if i%50000 == 0 {
			one = name
			f.file(one, "", 0o644)
			continue
		}
		if err := os.Link(one, name); errors.Is(err, syscall.ENOSPC) {
			t.Skipf("the file system under the test's temp dir holds no %d names: %v", planted, err)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	var envs []string
	var cut bool
	allocs := testing.AllocsPerRun(1, func() { envs, cut, _, _ = envFiles([]string{f.project}, time.Now().Add(time.Hour)) })
	t.Logf("%.0f allocations", allocs)
	if !cut {
		t.Error("a scan that left entries unread must say so")
	}
	// Each directory entry read costs allocations, about three for the bounded listing, so reading all 150000
	// costs several hundred thousand; the bounded scan reads at most envScanMaxEntries, a third of them.
	if allocs > 5*envScanMaxEntries {
		t.Errorf("the scan made %.0f allocations, as a scan that read all %d entries does", allocs, planted)
	}
	_ = envs
	_, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n"))
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && strings.Contains(d.Message, ".env files under "+f.project) && strings.Contains(d.Message, "left more unread")
	}) {
		t.Errorf("compile must say the .env scan was cut:\n%s", render(ds))
	}
	// Without the plant the scan reads everything and says nothing.
	g := newFixture(t)
	envs, cut, _, _ = envFiles([]string{g.project}, time.Now().Add(time.Hour))
	if cut || !slices.Equal(envs, []string{filepath.Join(g.project, ".env")}) {
		t.Errorf("envFiles = %v, cut %v; want the project's .env alone, uncut", envs, cut)
	}
}

// TestDenyWriteWholeCompileBudget pins the budget the write entries share: each entry's search has a budget
// of its own, and a contract of many write entries (E24) each over a tree the agent filled cost compile that
// many budgets. Four entries of 4100 planted directories spend four entries' worth of directories examined;
// the fifth entry's search then finds no budget left, says so, and does not reach the repository beneath it.
func TestDenyWriteWholeCompileBudget(t *testing.T) {
	f := newFixture(t)
	var yaml strings.Builder
	yaml.WriteString("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [")
	for e := 1; e <= maxSearchWhole; e++ {
		dir := filepath.Join(f.project, "e"+strconv.Itoa(e))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxSearchDirs+4; i++ {
			if err := os.Mkdir(filepath.Join(dir, "j"+strconv.Itoa(i)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		yaml.WriteString("\"e" + strconv.Itoa(e) + "/\", ")
	}
	last := "e" + strconv.Itoa(maxSearchWhole+1)
	gitRepo(t, f, filepath.Join(f.project, last, "sub", "real"))
	yaml.WriteString("\"" + last + "/\"]\n")
	rt, ds := compileDiagsWithin(t, f, f.load(yaml.String()), 10*time.Second)
	if slices.Contains(denyWritePaths(rt), filepath.Join(f.project, last, "sub", "real", ".git", "hooks")) {
		t.Errorf("the last entry's search ran within a budget the compile had spent: %v", denyWritePaths(rt))
	}
	// It says which budget: its own is untouched, so the warning must not say it ran out.
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && strings.Contains(d.Message, `fs.write "`+last+`/"`) &&
			strings.Contains(d.Message, "ran out of the budget all write entries share") && !strings.Contains(d.Message, "ran out of its budget")
	}) {
		t.Errorf("the last entry must say the shared budget ran out, and only that:\n%s", render(ds))
	}
}

// chainPlant makes the costliest walk the kernel takes: dir/deep/d/.../d, as deep as PATH_MAX allows, whose
// deepest directory (bottom) holds 39 links L1..L39, each Li naming bottom/L(i+1) by its absolute path and
// L39 naming dir/deep, so bottom/L1/x walks the chain of directories 40 times, 40 being the most links one
// walk follows. It returns bottom and logs what one walk of bottom/L1/x costs here.
func chainPlant(t *testing.T, dir string) string {
	t.Helper()
	deep := filepath.Join(dir, "deep")
	bottom := deepChain(t, deep, (pathMax-64-len(deep))/2)
	for i := 1; i <= 39; i++ {
		target := filepath.Join(bottom, "L"+strconv.Itoa(i+1))
		if i == 39 {
			target = deep
		}
		if err := os.Symlink(target, filepath.Join(bottom, "L"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	var st unix.Stat_t
	start := time.Now()
	if err := unix.Lstat(filepath.Join(bottom, "L1", "x"), &st); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("the chain must walk to its end and find nothing there: %v", err)
	}
	t.Logf("one walk through the chain: %s", time.Since(start))
	return bottom
}

// cutBy reports whether ds hold an unenforced warning about the write entry declared as entry that says
// why, the text limitNote or undone gives.
func cutBy(ds []Diagnostic, entry, why string) bool {
	return slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && strings.Contains(d.Message, `fs.write "`+entry+`"`) && strings.Contains(d.Message, why) &&
			strings.Contains(d.Message, "may be writable by the agent without being named")
	})
}

// TestDenyWriteSearchTime is the bound on what R20's search costs as a whole, not per operation: its budget
// counts probes, and the kernel's walk of one path follows up to 40 links of up to 4095 bytes each, so each
// core.hooksPath value naming a path through a chain of 39 links 1980 directories deep made one probe about
// 10 ms. 16 such values probed from each of a thousand planted worktrees took compile two minutes, within the
// budget, whether the values were absolute (one path, probed again from each worktree, since it does not
// exist) or relative, a different path from each worktree through its own link into the chain. The search's
// time limit now cuts it: compile returns within 10 s, and the entry's warning says the time ran out.
func TestDenyWriteSearchTime(t *testing.T) {
	const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, f *fixture, work, bottom string)
	}{
		{"absolute values from a thousand worktrees", func(t *testing.T, f *fixture, work, bottom string) {
			loopWorktrees(t, f, work, 1000, func(i int) string { return filepath.Join(bottom, "L1", "f"+strconv.Itoa(i)) })
		}},
		{"relative values, a different path from each worktree", func(t *testing.T, f *fixture, work, bottom string) {
			loopWorktrees(t, f, work, 1000, func(i int) string { return "d/L1/f" + strconv.Itoa(i) })
			for i := 0; i < 1000; i++ {
				if err := os.Symlink(bottom, filepath.Join(work, "r"+strconv.Itoa(i), "d")); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			work := filepath.Join(f.project, "work")
			if err := os.Mkdir(work, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, f, work, chainPlant(t, work))
			start := time.Now()
			rt, ds := compileDiagsWithin(t, f, f.load(contract), 10*time.Second)
			t.Logf("compiled in %s", time.Since(start))
			if !cutBy(ds, "work/", "ran out of its time limit, "+maxSearchTime.String()) {
				t.Errorf("the entry's warning must say its search ran out of time:\n%s", render(ds))
			}
			// What the search reached before the limit is still named.
			if !slices.Contains(denyWritePaths(rt), filepath.Join(work, "g", "config")) {
				t.Errorf("the planted git directory's config, probed first, is in the set: %v", denyWritePaths(rt))
			}
		})
	}
}

// TestDenyWriteSearchTimeWhole pins the time all write entries share: two entries over the plant spend it,
// each its own limit and then what is left of the whole, and a third entry, a real repository, finds none
// left for its submodules and says so. Its own .git's hooks and config are still named: every entry's fixed
// targets are probed before any entry's walk, so the first two entries' plants cannot spend the time they
// need (it got nothing when each entry's search ran whole, one after the other).
func TestDenyWriteSearchTimeWhole(t *testing.T) {
	f := newFixture(t)
	for _, e := range []string{"e1", "e2"} {
		work := filepath.Join(f.project, e)
		if err := os.Mkdir(work, 0o755); err != nil {
			t.Fatal(err)
		}
		bottom := chainPlant(t, work)
		loopWorktrees(t, f, work, 400, func(i int) string { return filepath.Join(bottom, "L1", "f"+strconv.Itoa(i)) })
	}
	e3 := filepath.Join(f.project, "e3")
	gitRepo(t, f, e3)
	start := time.Now()
	rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"e1/\", \"e2/\", \"e3/\"]\n"), 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	if !cutBy(ds, "e1/", "ran out of its time limit") {
		t.Errorf("the first entry spends its own time:\n%s", render(ds))
	}
	shared := "ran out of the time limit all write entries share, " + maxSearchTimeWhole.String()
	if !cutBy(ds, "e3/", shared) || cutBy(ds, "e3/", "ran out of its time limit") {
		t.Errorf("the third entry must say the shared time ran out, and only that:\n%s", render(ds))
	}
	for _, want := range []string{filepath.Join(e3, ".git", "hooks"), filepath.Join(e3, ".git", "config")} {
		if !slices.Contains(denyWritePaths(rt), want) {
			t.Errorf("the third entry's own %s must be named before the other entries' walks spend the time: %v", want, denyWritePaths(rt))
		}
	}
}

// TestDenyWriteFixedTargetsFirst is R20's order within the time limit, which made a small plant enough to
// cut the search where the budget needed a thousand: the targets whose number is fixed whatever the agent
// plants came after walks it can make as long as it likes. A repository's own core.hooksPath directory was
// probed only after the walk of its .git/modules/, and the global config's for it after that, so a hundred
// planted git directories there, each setting 16 values through the 39-link chain, spent the time and
// dropped src/.husky and src/.githooks; and the enclosing
// repository's core.hooksPath was taken up only after the walk beneath an entry that is not a repository, so
// .git files planted beneath frontend/, each naming a gitdir through the chain, dropped frontend/.husky,
// the target Husky's monorepo layout puts there, and left the set empty. Each must now be named, with the
// cut still said.
func TestDenyWriteFixedTargetsFirst(t *testing.T) {
	t.Run("a repository's core.hooksPath before its submodules", func(t *testing.T) {
		f := newFixture(t)
		src := filepath.Join(f.project, "src")
		gitRepo(t, f, src)
		f.file(filepath.Join(src, ".git", "config"), "[core]\n\thooksPath = .husky\n", 0o644)
		f.file(filepath.Join(f.home, ".gitconfig"), "[core]\n\thooksPath = .githooks\n", 0o644)
		for _, d := range []string{".husky", ".githooks"} {
			if err := os.Mkdir(filepath.Join(src, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		bottom := chainPlant(t, src)
		for m := 0; m < 100; m++ {
			mod := "m" + strconv.Itoa(m)
			plantGitDir(t, f, filepath.Join(src, ".git", "modules", mod), func(i int) string {
				return filepath.Join(bottom, "L1", mod+"f"+strconv.Itoa(i))
			})
		}
		start := time.Now()
		rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"), 10*time.Second)
		t.Logf("compiled in %s", time.Since(start))
		if !cutBy(ds, "src/", "the search for repositories and submodules beneath it ran out of its time limit") {
			t.Fatalf("the plant must spend the search's time for this test to say anything:\n%s", render(ds))
		}
		for _, want := range []string{filepath.Join(src, ".husky"), filepath.Join(src, ".githooks"), filepath.Join(src, ".git", "hooks"), filepath.Join(src, ".git", "config")} {
			if !slices.Contains(denyWritePaths(rt), want) {
				t.Errorf("the repository's own %s must be named before its submodules are walked: %v", want, denyWritePaths(rt))
			}
		}
	})
	t.Run("the enclosing repository's core.hooksPath before the walk beneath the entry", func(t *testing.T) {
		f := newFixture(t)
		mono := filepath.Join(f.project, "mono")
		gitRepo(t, f, mono)
		f.file(filepath.Join(mono, ".git", "config"), "[core]\n\thooksPath = frontend/.husky/_\n", 0o644)
		front := filepath.Join(mono, "frontend")
		if err := os.MkdirAll(filepath.Join(front, ".husky", "_"), 0o755); err != nil {
			t.Fatal(err)
		}
		bottom := chainPlant(t, front)
		for i := 0; i < 800; i++ {
			p := filepath.Join(front, "p"+strconv.Itoa(i))
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(p, ".git"), "gitdir: "+filepath.Join(bottom, "L1", "g"+strconv.Itoa(i))+"\n", 0o644)
		}
		start := time.Now()
		rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"mono/frontend/\"]\n"), 10*time.Second)
		t.Logf("compiled in %s", time.Since(start))
		if !cutBy(ds, "mono/frontend/", "the search for repositories and submodules beneath it ran out of its time limit") {
			t.Fatalf("the plant must spend the search's time for this test to say anything:\n%s", render(ds))
		}
		if !slices.Contains(denyWritePaths(rt), filepath.Join(front, ".husky")) {
			t.Errorf("the enclosing repository's hooks directory must be named before the walk beneath the entry: %v", denyWritePaths(rt))
		}
	})
}

// TestDenyWriteFixedPassCut pins the fixed pass's own limit and its note. The fixed targets are probed for
// every write entry before any walk, and are still charged to the time all entries share, since a contract
// can hold thousands of entries (E24) and each root name the agent links into the 39-link chain makes a probe
// cost a walk of it. When earlier entries' fixed passes spend that time, a later entry's own repository is
// not probed, and its warning must say which part of its search was cut: its root and its repository's
// hooks and config, not only the repositories beneath it. The first entry links nothing into the chain, so its
// fixed pass runs in time however slow the machine is: with its root names linked too, its 15 probes cost 15
// walks of the chain, which a loaded machine slows past the entry's own 2 s (a walk of 120 ms in a KVM guest
// with four busy loops a CPU, 2026-10-17), and the check that its fixed pass is not said to be cut then failed
// for the machine's sake.
func TestDenyWriteFixedPassCut(t *testing.T) {
	f := newFixture(t)
	bottom := chainPlant(t, f.project)
	var yaml strings.Builder
	yaml.WriteString("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [")
	for e := 0; e < 150; e++ {
		entry := filepath.Join(f.project, "w"+strconv.Itoa(e))
		if e == 0 {
			if err := os.Mkdir(entry, 0o755); err != nil {
				t.Fatal(err)
			}
			yaml.WriteString("\"w0/\", ")
			continue
		}
		for _, n := range denyWriteAtRoot {
			p := filepath.Join(entry, n.name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(bottom, "L1", "x"), p); err != nil {
				t.Fatal(err)
			}
		}
		yaml.WriteString("\"w" + strconv.Itoa(e) + "/\", ")
	}
	real := filepath.Join(f.project, "zreal")
	gitRepo(t, f, real)
	yaml.WriteString("\"zreal/\"]\n")
	start := time.Now()
	_, ds := compileDiagsWithin(t, f, f.load(yaml.String()), 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	if !cutBy(ds, "zreal/", "the search of the names at its root and of the hooks directories and configs of the repository it is or lies in "+
		"ran out of the time limit all write entries share") {
		t.Errorf("the last entry's warning must say its fixed targets were cut:\n%s", render(ds))
	}
	if !cutBy(ds, "w0/", "the search for repositories and submodules beneath it ran out of the time limit all write entries share") ||
		cutBy(ds, "w0/", "the search of the names at its root") {
		// w0's fixed pass ran in time; only its walk, which came after every fixed pass, found none left.
		t.Errorf("the first entry's fixed pass ran in time and must not be said to be cut:\n%s", render(ds))
	}
}

// TestDenyWriteWalkCutByAnotherEntry pins that one write entry's limits do not become another's. A .git file
// the agent plants beneath e1 names e2's git directory, and the planted gitdirs after it spend e1's time,
// so e1's walk takes up e2's submodules with no time left. That walk was kept as done, its cut inherited, and
// e2, whose own time was untouched, never walked its submodules, dropping their hooks. A walk another
// entry's limits cut is now taken up again within the limits of the entry that reaches it.
func TestDenyWriteWalkCutByAnotherEntry(t *testing.T) {
	f := newFixture(t)
	e2 := filepath.Join(f.project, "e2")
	gitRepo(t, f, e2)
	sub := filepath.Join(e2, ".git", "modules", "sub")
	plantGitDir(t, f, sub, func(i int) string { return "decoy" + strconv.Itoa(i) })
	e1 := filepath.Join(f.project, "e1")
	if err := os.MkdirAll(filepath.Join(e1, "a0"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(e1, "a0", ".git"), "gitdir: "+filepath.Join(e2, ".git")+"\n", 0o644)
	bottom := chainPlant(t, e1)
	for i := 0; i < 800; i++ {
		p := filepath.Join(e1, "p"+strconv.Itoa(i))
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(p, ".git"), "gitdir: "+filepath.Join(bottom, "L1", "g"+strconv.Itoa(i))+"\n", 0o644)
	}
	start := time.Now()
	rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"e1/\", \"e2/\"]\n"), 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	if !cutBy(ds, "e1/", "ran out of its time limit") {
		t.Fatalf("the plant must spend e1's time for this test to say anything:\n%s", render(ds))
	}
	if !slices.Contains(denyWritePaths(rt), filepath.Join(sub, "hooks")) {
		t.Errorf("e2's submodule must be walked in e2's own time: %v", denyWritePaths(rt))
	}
	if cutBy(ds, "e2/", "ran out of") {
		t.Errorf("e2's search was not cut, and must not say so:\n%s", render(ds))
	}
}

// TestDenyWriteReadCutReadAgain pins the same for a git directory's configs: a read a limit cut left its
// core.hooksPath values unknown, and they stayed unknown for every write entry that reached the git directory
// later, which then named none of them and said nothing, since the cut was the first entry's. The next entry
// to reach it now reads them again.
func TestDenyWriteReadCutReadAgain(t *testing.T) {
	f := newFixture(t)
	gd := filepath.Join(f.project, "g")
	plantGitDir(t, f, gd, func(i int) string { return "/hooks" + strconv.Itoa(i) })
	s := &denySearch{probe: func(string, string) {}, known: map[fileID]*gitDirInfo{}, proc: true}
	first, second := &entrySearch{}, &entrySearch{}
	s.resume(first)
	s.entry.bytes = maxSearchBytes - 16 // less than either config holds
	in := s.info(gd)
	if in == nil || !in.readCut || len(in.hooks) != 0 {
		t.Fatalf("a read the budget cut must be marked so: %+v", in)
	}
	s.pause(first, false)
	s.resume(second)
	again := s.info(gd)
	if again != in || again.readCut || len(again.hooks) != 2*maxHooksValues {
		t.Errorf("the next entry to reach the git directory must read its configs again: %+v", again)
	}
}

// TestEnvScanTime is the bound on resolving what R6's .env scan finds: each .env file becomes a deny_read
// entry resolved by the kernel's walk (E8), and the agent chooses how many there are (up to 50000 found
// names) and where each links. Ten thousand .env.<n> links into the 39-link chain cost the next compile
// minutes. The scan and the resolution now stop at the scan's time limit and say so; the project's own .env
// files, which are not links, are resolved before any link, so the plant does not push them out of the list.
func TestEnvScanTime(t *testing.T) {
	f := newFixture(t)
	bottom := chainPlant(t, f.root)
	for i := 0; i < 10000; i++ {
		if err := os.Symlink(filepath.Join(bottom, "L1", "x"+strconv.Itoa(i)), filepath.Join(f.project, ".env."+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	app := filepath.Join(f.project, "zz-app")
	if err := os.Mkdir(app, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(app, ".env"), "SECRET=2", 0o600)
	start := time.Now()
	rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\n"), 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && strings.Contains(d.Message, ".env files under "+f.project) &&
			strings.Contains(d.Message, "ran out of its time limit, "+envScanMaxTime.String()) && strings.Contains(d.Message, "not yet resolved")
	}) {
		t.Errorf("compile must say the .env scan ran out of time:\n%s", render(ds))
	}
	for _, want := range []string{filepath.Join(f.project, ".env"), filepath.Join(app, ".env")} {
		if !slices.ContainsFunc(rt.FS, func(r FSRule) bool { return r.Kind == FSDenyRead && r.Path == want }) {
			t.Errorf("the project's own %s is not a deny_read entry: the planted links pushed it out", want)
		}
	}
}

// TestDenyWriteUnreadableFiles is R20's other silent cut: a git config, config.worktree, .git file or
// commondir the search found but could not read was taken as saying nothing, so a core.hooksPath in it, or
// the git directory it names, left the set with no word said. An agent makes one unreadable while the next
// compile runs (a write lease it holds through an O_RDONLY open, which the supervisor allows, as root too) or
// before it (chmod 000, which no tier's supervisor is notified of), and restores it after. The warning must
// now name the file and why; with nothing else in the set, the entry gets a warning of its own. A directory
// its owner made unsearchable hides the repositories beneath it the same way, and is named the same way; and
// without /proc, through which every probe and read goes, every entry says the search resolved nothing.
func TestDenyWriteUnreadableFiles(t *testing.T) {
	unreadable := []struct {
		name, why string
		make      func(t *testing.T, p string) bool
	}{
		{"chmod 000", "permission denied", func(t *testing.T, p string) bool {
			if os.Geteuid() == 0 {
				t.Log("root reads a file of mode 000, that row is skipped")
				return false
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
			return true
		}},
		{"a write lease held", "a lease or a lock is held on it", func(t *testing.T, p string) bool {
			return leaseOn(t, p)
		}},
	}
	for _, u := range unreadable {
		t.Run("config, "+u.name, func(t *testing.T) {
			f := newFixture(t)
			src := filepath.Join(f.project, "src")
			gitRepo(t, f, src)
			config := filepath.Join(src, ".git", "config")
			f.file(config, "[core]\n\thooksPath = .husky\n", 0o644)
			if err := os.Mkdir(filepath.Join(src, ".husky"), 0o755); err != nil {
				t.Fatal(err)
			}
			const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"
			if rt, _ := f.compile(f.load(contract)); !slices.Contains(denyWritePaths(rt), filepath.Join(src, ".husky")) {
				t.Fatalf("before the plant the hooks path is named: %v", denyWritePaths(rt))
			}
			if !u.make(t, config) {
				t.SkipNow()
			}
			rt, ds := compileDiagsWithin(t, f, f.load(contract), 10*time.Second)
			if slices.Contains(denyWritePaths(rt), filepath.Join(src, ".husky")) {
				t.Fatalf("the config was read after all: %v", denyWritePaths(rt))
			}
			if !cutBy(ds, "src/", "it could not read "+config+" ("+u.why+")") {
				t.Errorf("the entry's warning must name the config it could not read, and why:\n%s", render(ds))
			}
		})
		t.Run(".git file, "+u.name+", nothing else in the set", func(t *testing.T) {
			f := newFixture(t)
			gd := filepath.Join(f.project, "gd")
			for _, d := range []string{"objects", "refs"} {
				if err := os.MkdirAll(filepath.Join(gd, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f.file(filepath.Join(gd, "HEAD"), "ref: refs/heads/main\n", 0o644)
			f.file(filepath.Join(gd, "config"), "[core]\n\thooksPath = .husky\n", 0o644)
			wt := filepath.Join(f.project, "wt")
			if err := os.MkdirAll(filepath.Join(wt, ".husky"), 0o755); err != nil {
				t.Fatal(err)
			}
			dotgit := filepath.Join(wt, ".git")
			f.file(dotgit, "gitdir: ../gd\n", 0o644)
			const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"wt/\"]\n"
			if rt, _ := f.compile(f.load(contract)); !slices.Equal(denyWritePaths(rt), []string{filepath.Join(wt, ".husky")}) {
				t.Fatalf("before the plant the linked worktree's hooks path is the set: %v", denyWritePaths(rt))
			}
			if !u.make(t, dotgit) {
				t.SkipNow()
			}
			rt, ds := compileDiagsWithin(t, f, f.load(contract), 10*time.Second)
			if len(rt.DenyWrite) != 0 {
				t.Fatalf("the .git file was read after all: %v", denyWritePaths(rt))
			}
			if !cutBy(ds, "wt/", "named nothing beneath it, but it could not read "+dotgit+" ("+u.why+")") {
				t.Errorf("an entry with nothing in the set must still name the .git file it could not read:\n%s", render(ds))
			}
		})
	}
	t.Run("a directory above a repository, chmod 000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lists a directory of mode 000")
		}
		f := newFixture(t)
		src := filepath.Join(f.project, "src")
		team := filepath.Join(src, "team")
		gitRepo(t, f, filepath.Join(team, "real"))
		const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"
		if rt, _ := f.compile(f.load(contract)); !slices.Contains(denyWritePaths(rt), filepath.Join(team, "real", ".git", "hooks")) {
			t.Fatalf("before the plant the repository is found: %v", denyWritePaths(rt))
		}
		if err := os.Chmod(team, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(team, 0o755) })
		rt, ds := compileDiagsWithin(t, f, f.load(contract), 10*time.Second)
		if len(rt.DenyWrite) != 0 {
			t.Fatalf("the directory was searched after all: %v", denyWritePaths(rt))
		}
		if !cutBy(ds, "src/", "it could not read "+team+" (a directory it could not open: permission denied)") {
			t.Errorf("the entry must name the directory it could not open:\n%s", render(ds))
		}
	})
	t.Run("no /proc", func(t *testing.T) {
		f := newFixture(t)
		src := filepath.Join(f.project, "src")
		gitRepo(t, f, src)
		saved := procSelfFD
		procSelfFD = filepath.Join(f.root, "no-proc", "self", "fd") + "/"
		t.Cleanup(func() { procSelfFD = saved })
		rt, ds := compileDiagsWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"), 10*time.Second)
		if len(rt.DenyWrite) != 0 {
			t.Fatalf("without /proc nothing is resolved, so nothing is in the set: %v", denyWritePaths(rt))
		}
		if !cutBy(ds, "src/", "/proc is not mounted") {
			t.Errorf("the entry must say the search resolved nothing without /proc:\n%s", render(ds))
		}
	})
}

// TestDataFSList pins the file systems R8's and R20's reads take as data, which decides whether a run starts
// at all: a binary on a file system missing from the list fails the run at Prepare (exit 125). The HPC,
// container and embedded file systems below were missing, so a command on a Lustre or GPFS home, or in an
// aufs or shiftfs container root, could not run. The kernel's own interfaces stay off the list.
func TestDataFSList(t *testing.T) {
	for name, magic := range map[string]uint32{
		"Lustre": 0x0bd00bd0, "GPFS": 0x47504653, "BeeGFS": 0x19830326, "aufs": 0x61756673, "shiftfs": 0x6a656a62,
		"UBIFS": 0x24051905, "JFFS2": 0x72b6, "HFS": 0x4244, "UFS": 0x00011954, "VxFS": 0xa501fcf5, "romfs": 0x7275,
		"hostfs": 0x00c0ffee, "PanFS": 0xaad7aaea, "OrangeFS": 0x20030528, "ext4": 0xef53, "NFS": 0x6969, "FUSE": 0x65735546,
	} {
		if !dataFS[magic] {
			t.Errorf("%s (0x%x) is not read as data", name, magic)
		}
	}
	for name, magic := range map[string]uint32{
		"procfs": 0x9fa0, "sysfs": 0x62656572, "debugfs": 0x64626720, "tracefs": 0x74726163, "securityfs": 0x73636673,
		"configfs": 0x62656570, "cgroup2": 0x63677270, "bpffs": 0xcafe4a11, "efivarfs": 0xde5e81e4, "pstore": 0x6165676c,
		"mqueue": 0x19800202, "rpc_pipefs": 0x67596969, "functionfs": 0xa647361, "xenfs": 0xabba1974, "devpts": 0x1cd1,
	} {
		if dataFS[magic] {
			t.Errorf("%s (0x%x), a kernel interface, is read as data", name, magic)
		}
	}
}

// hasEnvScanCut is whether ds carries the [unenforced] warning the .env scan writes when it runs out of time.
func hasEnvScanCut(ds []Diagnostic) bool {
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, "ran out of its time limit") {
			return true
		}
	}
	return false
}
