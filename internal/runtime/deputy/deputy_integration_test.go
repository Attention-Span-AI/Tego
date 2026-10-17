// SPDX-License-Identifier: Apache-2.0

//go:build integration

package deputy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The integration tests re-execute the test binary as the deputy: Main with a plain pin (an O_PATH open of the path
// as given, no walk), which is all these tests need of the walk; the supervisor's tests run the real one.
const (
	deputyEnv     = "TEGO_DEPUTY_TEST"
	deputyArgsEnv = "TEGO_DEPUTY_ARGS"
	// forbiddenEnv makes the re-executed binary install the filter and then make one syscall it forbids.
	forbiddenEnv = "TEGO_DEPUTY_FORBIDDEN"
	// migrateEnv makes the re-executed deputy's goroutine free to leave the thread that set no_new_privs before it
	// installs its filter (migrateBetweenSteps).
	migrateEnv = "TEGO_DEPUTY_MIGRATE"
	// readlinkEnv makes the re-executed binary readlink the path it names and print the errno ("ok" for none).
	readlinkEnv = "TEGO_DEPUTY_READLINK"
)

func TestMain(m *testing.M) {
	if os.Getenv(deputyEnv) != "" {
		if os.Getenv(migrateEnv) != "" {
			confineStep = migrateBetweenSteps
		}
		os.Exit(Main(strings.Fields(os.Getenv(deputyArgsEnv)), plainPin))
	}
	if what := os.Getenv(forbiddenEnv); what != "" {
		os.Exit(forbiddenMain(what))
	}
	if p := os.Getenv(readlinkEnv); p != "" {
		_, err := os.Readlink(p)
		var errno syscall.Errno
		switch {
		case err == nil:
			os.Stdout.WriteString("ok")
		case errors.As(err, &errno):
			os.Stdout.WriteString(unix.ErrnoName(errno))
		default:
			os.Stdout.WriteString(err.Error())
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// plainPin opens q.Path O_PATH, relative to the caller's cwd, following a final symlink unless Nofollow says not to.
func plainPin(q PinQuery) (Pinned, error) {
	if q.Create {
		dir, leaf := filepath.Split(q.Path)
		if _, err := os.Lstat(q.Path); errors.Is(err, os.ErrNotExist) {
			fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			return Pinned{FD: fd, Leaf: leaf}, err
		}
	}
	flags := unix.O_PATH | unix.O_CLOEXEC
	if q.Nofollow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(q.Path, flags, 0)
	// A pathname under /proc/self/fd names a descriptor's object, which the reply says (Pinned.ByDescriptor).
	return Pinned{FD: fd, ByDescriptor: strings.HasPrefix(q.Path, "/proc/self/fd/")}, err
}

// migrateBetweenSteps is confineStep for a deputy started under migrateEnv. Once no_new_privs is set it parks a
// goroutine locked to the current thread for good, which leaves that thread to it: a goroutine free to move resumes on
// another thread, as the Go scheduler may move it at any point, and one locked to this thread comes back to it.
// no_new_privs is a thread's, so a deputy started without it (from a privileged stage, which sets it only after the
// deputy's exec) whose filter is then installed from another thread is refused EACCES.
func migrateBetweenSteps(step string) {
	if step != "nnp" {
		return
	}
	locked := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		close(locked)
		select {}
	}()
	<-locked
}

// startDeputy starts the test binary as a deputy, as the child stage does but without CLONE_PARENT (the test is the
// parent), and returns its client once the hello and the readiness message have come.
func startDeputy(t *testing.T, env ...string) (*Client, *exec.Cmd) { return startDeputyB(t, env...) }

// startDeputyB is startDeputy for a test or a benchmark; env is added to the deputy's environment.
func startDeputyB(t testing.TB, env ...string) (*Client, *exec.Cmd) {
	t.Helper()
	return startDeputyAs(t, nil, env...)
}

// startDeputyAs is startDeputyB with the deputy exec'd under cred (nil: this process's), as a privileged stage execs
// it with the agent's credentials.
func startDeputyAs(t testing.TB, cred *syscall.Credential, env ...string) (*Client, *exec.Cmd) {
	t.Helper()
	launcher, stage, err := Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	stageF := os.NewFile(uintptr(stage), "stage")
	readyW := os.NewFile(uintptr(ready[1]), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), deputyEnv+"=1", deputyArgsEnv+"=--parent "+strconv.Itoa(os.Getpid()),
		"GODEBUG=decoratemappings=0"), env...)
	cmd.ExtraFiles = []*os.File{stageF, readyW}
	cmd.Stderr = os.Stderr
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stageF.Close()
	_ = readyW.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := awaitReadyTest(ready[0]); err != nil {
		t.Fatalf("deputy not ready: %v", err)
	}
	_ = unix.Close(ready[0])
	c, err := Hello(launcher, 5*time.Second)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if c.PID() != cmd.Process.Pid {
		t.Fatalf("hello names pid %d, the deputy is %d", c.PID(), cmd.Process.Pid)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cmd
}

func awaitReadyTest(fd int) error {
	tv := unix.NsecToTimeval((10 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	b := make([]byte, 512)
	n, err := unix.Read(fd, b)
	if err != nil {
		return err
	}
	if n == 1 && b[0] == 1 {
		return nil
	}
	if n > 1 && b[0] == 0 {
		return errors.New("the deputy failed: " + string(b[1:n]))
	}
	return errors.New("end of stream before the readiness message")
}

// TestDeputyPinsAndOpens is the deputy's two requests end to end on a real process under its real filter: a pinned
// file reopened read-only reads its bytes, a create beneath a pinned directory takes the umask sent with it, an
// errno comes back as the errno, and many concurrent callers each get their own answer while the deputy's runtime
// collects garbage (the filter allows what the runtime does at steady state).
func TestDeputyPinsAndOpens(t *testing.T) {
	c, cmd := startDeputy(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: file}, nil)
	pin, leaf := p.FD, p.Leaf
	if err != nil || leaf != "" || p.ByDescriptor {
		t.Fatalf("pin = %+v %v", p, err)
	}
	fd, err := c.Open(pin, "", unix.O_RDONLY, 0, -1, nil)
	_ = unix.Close(pin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 16)
	n, _ := unix.Read(fd, buf)
	_ = unix.Close(fd)
	if string(buf[:n]) != "held" {
		t.Fatalf("read %q through the deputy's descriptor", buf[:n])
	}

	created := filepath.Join(dir, "new")
	p, err = c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: created, Create: true}, nil)
	pin, leaf = p.FD, p.Leaf
	if err != nil || leaf != "new" {
		t.Fatalf("pin create = %q %v", leaf, err)
	}
	fd, err = c.Open(pin, leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o666, 0o077, nil)
	_ = unix.Close(pin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = unix.Close(fd)
	st, err := os.Stat(created)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("created %v, mode %v: want 0600 from umask 077", err, st.Mode())
	}

	if _, err := c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: filepath.Join(dir, "missing")}, nil); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("pin of a missing name = %v, want ENOENT", err)
	}

	// The reply carries how the pin was reached: a descriptor's object is ByDescriptor. plainPin
	// opens in the deputy, whose standard input is /dev/null.
	p, err = c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: "/proc/self/fd/0"}, nil)
	if err != nil || !p.ByDescriptor {
		t.Fatalf("pin of a descriptor's object = %+v %v, want ByDescriptor", p, err)
	}
	_ = unix.Close(p.FD)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				p, err := c.Pin(PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: file}, nil)
				if err != nil {
					errs <- err
					return
				}
				pin := p.FD
				fd, err := c.Open(pin, "", unix.O_RDONLY, 0, -1, nil)
				_ = unix.Close(pin)
				if err != nil {
					errs <- err
					return
				}
				_ = unix.Close(fd)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent request: %v", err)
	}
	if c.Outstanding() != 0 {
		t.Fatalf("%d requests outstanding after every reply", c.Outstanding())
	}
	// Closing the control socket ends the deputy.
	_ = c.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("deputy exit after the control socket closed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deputy still running 10 s after its control socket closed")
	}
}

// TestDeputyIsNotDumpable: the agent shares the deputy's uid, and a dumpable deputy would let it ptrace the deputy or
// take its descriptors through /proc/<pid>/fd.
//
// As root the deputy is exec'd as nobody, as a privileged stage execs it with the agent's credentials, and nobody tries
// the readlink: root's CAP_SYS_PTRACE reads a non-dumpable process's descriptors, which says nothing of the flag.
func TestDeputyIsNotDumpable(t *testing.T) {
	var cred *syscall.Credential
	if os.Geteuid() == 0 {
		cred = &syscall.Credential{Uid: 65534, Gid: 65534}
	}
	c, _ := startDeputyAs(t, cred)
	b, err := os.ReadFile("/proc/" + strconv.Itoa(c.PID()) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp:"); ok && strings.TrimSpace(v) != "2" {
			t.Fatalf("deputy Seccomp: %s, want 2 (filter mode)", strings.TrimSpace(v))
		}
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok && strings.TrimSpace(v) != "1" {
			t.Fatalf("deputy NoNewPrivs: %s, want 1", strings.TrimSpace(v))
		}
	}
	fd3 := "/proc/" + strconv.Itoa(c.PID()) + "/fd/3"
	if cred != nil {
		// A readlink as the deputy's own uid, which a dumpable process would let in: this binary re-executed so.
		rl := exec.Command(os.Args[0], "-test.run=^$")
		rl.Env = append(os.Environ(), readlinkEnv+"="+fd3)
		rl.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		if out, err := rl.Output(); err != nil || string(out) != "EACCES" {
			t.Fatalf("readlink of the deputy's control descriptor as its own uid = %q %v, want EACCES (not dumpable)", out, err)
		}
		return
	}
	if _, err := os.Readlink(fd3); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("readlink of the deputy's control descriptor = %v, want EACCES (not dumpable)", err)
	}
}

// TestDeputyConfinesOnOneThread: no_new_privs is a thread's, and a privileged stage starts the deputy before it sets
// no_new_privs on itself (the agent's credentials drop after the deputy's exec), so the deputy's threads have none. Its
// confinement runs on the one thread that sets no_new_privs and installs the filter, which TSYNC then puts on every
// thread with no_new_privs. It ran on whichever thread the Go scheduler gave it, so a filter installed from another
// thread than the one that set no_new_privs was refused EACCES and the deputy died before it was ready: a held run at
// a root tier then degraded, at random (a KVM run's "no child processes"). Here the deputy's
// goroutine is made free to move between the two steps (migrateBetweenSteps); its start must not depend on where it
// runs. This test process has no no_new_privs of its own, as a privileged stage has none when it starts the deputy.
func TestDeputyConfinesOnOneThread(t *testing.T) {
	if b, err := os.ReadFile("/proc/self/status"); err == nil && strings.Contains(string(b), "NoNewPrivs:\t1") {
		t.Skip("this test process runs under no_new_privs, which the deputy would inherit")
	}
	c, _ := startDeputy(t, migrateEnv+"=1")
	tasks, err := os.ReadDir("/proc/" + strconv.Itoa(c.PID()) + "/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(c.PID()) + "/task/" + task.Name() + "/status")
		if err != nil {
			continue // a thread that ended
		}
		if !strings.Contains(string(b), "NoNewPrivs:\t1") || !strings.Contains(string(b), "Seccomp:\t2") {
			t.Fatalf("deputy thread %s: want no_new_privs and the filter on every thread:\n%s", task.Name(), b)
		}
	}
}

// forbiddenMain installs the deputy's filter on every thread and makes one syscall it does not allow; the kernel
// must kill the process with SIGSYS before the call returns.
func forbiddenMain(what string) int {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 3
	}
	prog, err := Filter(FilterSpec{TGID: os.Getpid(), EventFD: -1})
	if err != nil {
		return 4
	}
	if err := installTSync(prog); err != nil {
		return 5
	}
	switch what {
	case "socket":
		_, _ = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	case "execve":
		_ = syscall.Exec("/bin/true", []string{"true"}, nil)
	case "fork":
		_, _, _ = unix.RawSyscall(unix.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	case "ptrace":
		_, _, _ = unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0)
	case "ioctl":
		_, _, _ = unix.RawSyscall(unix.SYS_IOCTL, 0, unix.TIOCSTI, 0)
	case "kill-other":
		_ = unix.Kill(1, 0)
	case "write-file":
		_, _ = unix.Write(1, []byte("x"))
	case "fcntl-lock":
		_, _ = unix.FcntlInt(0, unix.F_SETLK, 0)
	case "allowed":
		return 0
	}
	return 6 // the call returned: the filter let it through
}

// TestDeputyFilterKillsForbiddenSyscalls: execve, a new process, a socket, ptrace, ioctl, a signal to another process,
// a write to a file and an fcntl lock each kill the process (SIGSYS), and the filter alone, with nothing forbidden
// made, lets it exit normally.
func TestDeputyFilterKillsForbiddenSyscalls(t *testing.T) {
	for _, what := range []string{"socket", "execve", "fork", "ptrace", "ioctl", "kill-other", "write-file", "fcntl-lock", "allowed"} {
		t.Run(what, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = append(os.Environ(), forbiddenEnv+"="+what)
			err := cmd.Run()
			if what == "allowed" {
				if err != nil {
					t.Fatalf("the filter alone: %v", err)
				}
				return
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("%s: %v, want death by SIGSYS", what, err)
			}
			ws := ee.Sys().(syscall.WaitStatus)
			if !ws.Signaled() || ws.Signal() != syscall.SIGSYS {
				t.Fatalf("%s: %v (exit %d), want death by SIGSYS", what, err, ws.ExitStatus())
			}
		})
	}
}

// BenchmarkDeputyPinOpen is one pin and one open of an existing file through a real deputy: the deputy's share of a
// held open (supervisor's BenchmarkHeldOpen measures the whole).
func BenchmarkDeputyPinOpen(b *testing.B) {
	c, _ := startDeputyB(b)
	file := filepath.Join(b.TempDir(), "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		b.Fatal(err)
	}
	q := PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: file}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := c.Pin(q, nil)
		if err != nil {
			b.Fatal(err)
		}
		fd, err := c.Open(p.FD, "", unix.O_RDONLY, 0, -1, nil)
		_ = unix.Close(p.FD)
		if err != nil {
			b.Fatal(err)
		}
		_ = unix.Close(fd)
	}
}
