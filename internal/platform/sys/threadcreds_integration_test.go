// SPDX-License-Identifier: Apache-2.0

//go:build integration

package sys

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

const (
	// helperTgkill makes the test binary a uid-1000 process that sends signal 0 to one thread of its
	// parent (tgkill) and prints the errno.
	helperTgkill = "TEGO_SYS_TGKILL"
)

func TestMain(m *testing.M) {
	if v := os.Getenv(helperTgkill); v != "" {
		pid, tid, _ := strings.Cut(v, ",")
		p, _ := strconv.Atoi(pid)
		t, _ := strconv.Atoi(tid)
		err := unix.Tgkill(p, t, 0)
		if err == nil {
			os.Stdout.WriteString("ok")
		} else {
			os.Stdout.WriteString(err.Error())
		}
		os.Exit(0)
	}
	// The same leak gate as the unit build's TestMain (leakcheck_test.go).
	os.Exit(testutil.LeakCheckMain(m))
}

// TestIntegrationRunAsTakesTheTaskCredentials is the tier-2 shape, as root: a thread takes a uid-1000
// task's credentials for one unix connect and nothing else in the process does. The kernel then judges
// the connect as it judges the task's own — a 0600 root socket in a 0700 root directory is refused, and a
// socket the task may open is connected with the task's ids in SO_PEERCRED — while the task cannot signal
// the thread that holds its uid, and the thread is gone once RunAs returns.
func TestIntegrationRunAsTakesTheTaskCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: taking another user's ids needs CAP_SETUID and CAP_SETGID (make vm-root-test, kvm-run.sh)")
	}
	const uid, gid = 1000, 1000
	want := TaskCreds{EUID: uid, EGID: gid, FSUID: uid, FSGID: gid, Groups: []uint32{gid}}
	before, err := ReadTaskCreds(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	// A root-only socket, and one anyone may open.
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := listenUnix(t, filepath.Join(private, "secret.sock"), 0o600)
	public, err := os.MkdirTemp("", "tego-runas-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(public) })
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	open := listenUnix(t, filepath.Join(public, "open.sock"), 0o777)

	var inside TaskCreds
	var resuid [3]int
	var privErr, openErr error
	var tid int
	self := testutil.ExecutableForAnyUID(t) // run as uid 1000 below
	held := make(chan int)
	released := make(chan struct{})
	go func() {
		// While the thread holds uid 1000, a uid-1000 process may not signal it: its real and saved uids
		// are still 0 (kill_ok_by_cred), so the task it acts for cannot kill this process through it. The
		// helper is started from this goroutine, whose thread is root's: a fork inherits the forking
		// thread's credentials, and the held thread's could not switch the child to uid 1000.
		defer close(released)
		cmd := exec.Command(self, "-test.run=^$")
		cmd.Env = append(os.Environ(), helperTgkill+"="+strconv.Itoa(os.Getpid())+","+strconv.Itoa(<-held))
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("tgkill helper: %v", err)
		} else if string(out) != unix.EPERM.Error() {
			t.Errorf("a uid-%d process signalled the thread holding its uid: %q, want %q", uid, out, unix.EPERM.Error())
		}
	}()
	err = RunAs(want, func() {
		tid = unix.Gettid()
		inside, _ = ThreadCreds()
		resuid[0], resuid[1], resuid[2] = unix.Getresuid()
		privErr = connectPath(filepath.Join(private, "secret.sock"))
		openErr = connectPath(filepath.Join(public, "open.sock"))
		held <- tid
		<-released
	})
	if err != nil {
		t.Fatalf("RunAs: %v", err)
	}
	if inside.EUID != uid || inside.EGID != gid || inside.FSUID != uid || inside.FSGID != gid ||
		len(inside.Groups) != 1 || inside.Groups[0] != gid || inside.CapEff != 0 {
		t.Errorf("thread credentials inside RunAs = %+v, want %+v with no effective capability", inside, want)
	}
	if resuid != [3]int{0, uid, 0} {
		t.Errorf("getresuid inside RunAs = %v, want [0 %d 0]: the real and saved ids are kept", resuid, uid)
	}
	if !errors.Is(privErr, unix.EACCES) {
		t.Errorf("connect to a 0600 root socket in a 0700 root directory = %v, want EACCES", privErr)
	}
	if secret.count() != 0 {
		t.Error("the root-only listener accepted a connection")
	}
	if openErr != nil {
		t.Errorf("connect to a socket uid %d may open = %v", uid, openErr)
	}
	if cred := open.peer(t); cred == nil || cred.Uid != uid || cred.Gid != gid {
		t.Errorf("SO_PEERCRED = %+v, want uid %d gid %d", cred, uid, gid)
	}

	after, err := ReadTaskCreds(os.Getpid())
	if err != nil || !after.Equal(before) {
		t.Errorf("process credentials after RunAs = %+v (%v), want %+v", after, err, before)
	}
	// The thread exits with its goroutine; give the runtime a moment to reap it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat("/proc/self/task/" + strconv.Itoa(tid)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			c, _ := ReadTaskCreds(tid)
			t.Errorf("thread %d still exists after RunAs returned, holding %+v", tid, c)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Whichever thread the goroutine lands on, the main thread included, the process keeps its own
	// credentials: the leader's are what /proc/<pid>/status reports for the whole process, and a main
	// thread whose goroutine exits locked is parked by the runtime rather than destroyed.
	for i := 0; i < 32; i++ {
		if err := RunAs(want, func() {}); err != nil {
			t.Fatalf("RunAs #%d: %v", i, err)
		}
		if c, err := ReadTaskCreds(os.Getpid()); err != nil || !c.Equal(before) {
			t.Fatalf("after RunAs #%d the thread group leader holds %+v (%v), want %+v", i, c, err, before)
		}
	}
	// A fresh thread, as any goroutine gets, holds the process's credentials, not the task's.
	fresh := make(chan TaskCreds, 1)
	go func() {
		c, _ := ThreadCreds()
		fresh <- c
	}()
	if c := <-fresh; !c.Equal(before) {
		t.Errorf("a goroutine after RunAs holds %+v, want the process's %+v", c, before)
	}
}

// connectPath connects a fresh stream socket to path and closes it.
func connectPath(path string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck // test cleanup
	return unix.Connect(fd, &unix.SockaddrUnix{Name: path})
}

// peerListener is a unix listener that records the SO_PEERCRED of each connection it accepts.
type peerListener struct {
	creds chan *unix.Ucred
}

func listenUnix(t *testing.T, path string, mode os.FileMode) *peerListener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	p := &peerListener{creds: make(chan *unix.Ucred, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			raw, err := c.(*net.UnixConn).SyscallConn()
			var cred *unix.Ucred
			if err == nil {
				_ = raw.Control(func(fd uintptr) {
					cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				})
			}
			p.creds <- cred
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *peerListener) count() int {
	select {
	case <-p.creds:
		return 1
	case <-time.After(100 * time.Millisecond):
		return 0
	}
}

func (p *peerListener) peer(t *testing.T) *unix.Ucred {
	t.Helper()
	select {
	case c := <-p.creds:
		return c
	case <-time.After(5 * time.Second):
		return nil
	}
}
