// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// Set in a re-exec of this test binary, which then stands in for the shim: it has the launcher's image (the test
// binary's) and a shim's argv, so procAdmit and procStillShim judge it as they judge the real one.
const (
	envFakeShim = "TEGO_RELAY_TEST_SHIM" // "real": dial, hello, start; "inherited": a relay of its own, the hello not its
	envFakeDial = "TEGO_RELAY_TEST_DIAL" // the address it dials
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(envFakeShim); mode != "" {
		os.Exit(fakeShimMain(mode))
	}
	os.Exit(m.Run())
}

// fakeShimMain dials one connection, says hello on it only as a real shim would, starts a child as a shim starts its
// server, prints the child's pid, and holds until stdin ends.
func fakeShimMain(mode string) int {
	if mode == "stage-child" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	}
	var preexisting *exec.Cmd
	if mode == "preexisting" {
		preexisting = exec.Command("sleep", "30")
		if err := preexisting.Start(); err != nil {
			return 1
		}
		defer func() { _ = preexisting.Process.Kill(); _ = preexisting.Wait() }()
	}
	var c net.Conn
	if mode != "undialled" {
		var err error
		c, err = net.Dial("tcp", os.Getenv(envFakeDial))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = c.Close() }()
	}
	if mode == "real" || mode == "preexisting" {
		if err := NewFrameWriter(c).Write(Frame{V: ProtocolVersion, Server: "files", Argv: filesCmd, PID: os.Getpid()}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if f, err := NewFrameReader(c, 0).Read(); err != nil || !f.OK {
			fmt.Fprintln(os.Stderr, "not admitted:", err, f.Error)
			return 1
		}
	}
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	if mode == "real" || mode == "preexisting" {
		if err := NewFrameWriter(c).Write(Frame{Child: child.Process.Pid}); err != nil {
			return 1
		}
		if f, err := NewFrameReader(c, 0).Read(); err != nil || !f.OK {
			fmt.Fprintln(os.Stderr, "child not admitted:", err, f.Error)
			return 1
		}
	}
	if preexisting != nil {
		fmt.Println(preexisting.Process.Pid)
	} else {
		fmt.Println(child.Process.Pid)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

// fakeShim starts the stand-in with stdin, extra descriptors and the address it dials, and returns its pid and its
// child's.
func fakeShim(t *testing.T, mode, dial string, stdin *os.File, extra ...*os.File) (shimPID, childPID int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Args = []string{"x", "mcp", "relay", "--server", "files", "--", "python3"}
	cmd.Env = append(os.Environ(), envFakeShim+"="+mode, envFakeDial+"="+dial)
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = extra
	var hold io.Closer
	if stdin != nil {
		cmd.Stdin = stdin
	} else {
		w, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		hold = w
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hold != nil {
			_ = hold.Close()
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("the stand-in shim: %v", err)
	}
	if childPID, err = strconv.Atoi(strings.TrimSpace(line)); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid, childPID
}

// realGate is a started service with the real admission and the real gate, placing peers in this test's own cgroup.
func realGate(t *testing.T) *Service {
	t.Helper()
	cg, err := procCgroupPath(os.Getpid())
	if err != nil {
		t.Skip("no unified cgroup:", err)
	}
	mount, err := cgroup2Mount()
	if err != nil {
		t.Skip(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(mount+cg, &st); err != nil {
		t.Skip(err)
	}
	s, err := New(Options{Servers: []Server{filesServer()}, Exe: "/usr/bin/tego", Poll: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background(), source.RunRef{ID: "r-test", Agent: "a", Dir: t.TempDir(), CgroupID: st.Ino}, &sink{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

// pendingOf is pid's pending start; a real shim's hello is answered before it prints, so it is there.
func pendingOf(t *testing.T, s *Service, pid int) pendingStart {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[pid]
	if !ok {
		t.Fatalf("no pending start for %d", pid)
	}
	return p
}

// TestGatePassesARealShim: a shim that dialled the relay itself and said its own hello starts its server, also when
// the client handed it socket stdio, as Node does: only TCP sockets are counted.
func TestGatePassesARealShim(t *testing.T) {
	t.Run("pipe stdio", func(t *testing.T) {
		s := realGate(t)
		_, child := fakeShim(t, "real", s.ctl.Addr().String(), nil)
		if !s.Relayed("files", child) {
			t.Fatal("a real shim's start was refused")
		}
	})
	t.Run("socket stdio", func(t *testing.T) {
		s := realGate(t)
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		mine, theirs := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "theirs")
		defer func() { _, _ = mine.Close(), theirs.Close() }()
		_, child := fakeShim(t, "real", s.ctl.Addr().String(), theirs)
		if !s.Relayed("files", child) {
			t.Fatal("a real shim on socket stdio was refused")
		}
	})
}

// The real admission admits the shim's image and connection, but an earlier child
// still cannot use the start registered for the shim's new child (SEC06/C51).
func TestGateRefusesARealShimsPreexistingChild(t *testing.T) {
	s := realGate(t)
	pid, attacker := fakeShim(t, "preexisting", s.ctl.Addr().String(), nil)
	p := pendingOf(t, s, pid)
	if s.Relayed("files", attacker) {
		t.Fatal("a child created before the shim's hello consumed the pending start")
	}
	if !s.Relayed("files", p.pid) {
		t.Fatal("the preexisting child stole the shim's registered start")
	}
}

// Before the shim has dialled it holds only the inherited TCP socket. A forged
// hello and registration on it must still fail: the shim did not create it.
func TestGateRefusesInheritedControlBeforeShimDials(t *testing.T) {
	s := realGate(t)
	c, err := net.Dial("tcp", s.ctl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	inherited, err := c.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inherited.Close() }()
	pid, child := fakeShim(t, "undialled", "", nil, inherited)
	fw, fr := NewFrameWriter(c), NewFrameReader(c, 0)
	if err := fw.Write(Frame{V: ProtocolVersion, Server: "files", Argv: filesCmd, PID: pid}); err != nil {
		t.Fatal(err)
	}
	if f, err := fr.Read(); err != nil || !f.OK {
		t.Fatalf("admitting the inherited socket: %v %+v", err, f)
	}
	if err := fw.Write(Frame{Child: child}); err != nil {
		t.Fatal(err)
	}
	if f, err := fr.Read(); err != nil || f.OK || f.Error == "" {
		t.Fatalf("an inherited socket authorized a forged child registration: %v %+v", err, f)
	}
}

// TestGateRefusesAShimUnderARelayOfTheAgents: procAdmit proves a process holds the socket, not that it wrote the hello.
// The agent dials, starts a real shim with that descriptor inherited and the relay variable naming its own listener, and
// writes the hello. The shim is admitted, dials the agent's listener, and would write whatever that says to the server,
// undecided. The gate sees the second TCP socket.
func TestGateRefusesAShimUnderARelayOfTheAgents(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(listen, func(t *testing.T) {
			s := realGate(t)
			fake, err := net.Listen("tcp", listen)
			if err != nil {
				t.Skip(err)
			}
			defer func() { _ = fake.Close() }()
			c, err := net.Dial("tcp", s.ctl.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			inherited, err := c.(*net.TCPConn).File()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inherited.Close() }()
			pid, child := fakeShim(t, "inherited", fake.Addr().String(), nil, inherited)
			if err := NewFrameWriter(c).Write(Frame{V: ProtocolVersion, Server: "files", Argv: filesCmd, PID: pid}); err != nil {
				t.Fatal(err)
			}
			if f, err := NewFrameReader(c, 0).Read(); err != nil || !f.OK {
				t.Fatalf("the inherited socket's hello should pass admission, which cannot tell: %v %q", err, f.Error)
			}
			if err := NewFrameWriter(c).Write(Frame{Child: child}); err != nil {
				t.Fatal(err)
			}
			if f, err := NewFrameReader(c, 0).Read(); err != nil || f.OK || f.Error == "" {
				t.Fatalf("a shim under the agent's relay registered a child: %v %+v", err, f)
			}
			if s.Relayed("files", child) {
				t.Fatal("a shim holding a second TCP socket started a declared server")
			}
		})
	}
}

// TestGateRefusesAnotherProcessOrSocket: an agent keeping the control connection open keeps a pending start after the
// shim dies, so what admission proved is checked again: the same process by its start, still holding the admitted socket.
func TestGateRefusesAnotherProcessOrSocket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*admission)
	}{
		{"the pid was reissued", func(a *admission) { a.start++ }},
		{"the admitted socket is not held", func(a *admission) { a.inode++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := realGate(t)
			pid, child := fakeShim(t, "real", s.ctl.Addr().String(), nil)
			p := pendingOf(t, s, pid)
			t.Cleanup(func() { _ = p.child.Close() })
			tc.alter(&p.shim)
			s.mu.Lock()
			s.pending[pid] = p
			s.mu.Unlock()
			if s.Relayed("files", child) {
				t.Fatal("the gate passed what admission did not prove")
			}
		})
	}
}
