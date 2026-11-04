// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

func stageSocket(t *testing.T) (*os.File, uint64) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "release"), os.NewFile(uintptr(pair[1]), "stage")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(b.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return b, st.Ino
}

func stageProcess(t *testing.T, socket *os.File, argv []string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = argv
	cmd.Env = append(os.Environ(), envFakeShim+"=stage-child")
	cmd.ExtraFiles = []*os.File{socket}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// TestStageGrantIsExactChild: a preexisting sibling cannot take the allowance, even with the exact stage vector.
// The fresh socket must be at fd 3, the resolved image must be ours, and the child must retain its one pinned
// identity through registration. The stage allowance by itself never authorizes a server exec (ADR 0126/SEC06).
func TestStageGrantIsExactChild(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, hello := dial(t, s, "files", filesCmd)
	if !hello.OK {
		t.Fatal(hello.Error)
	}
	sibling := exec.Command("sleep", "30")
	if err := sibling.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Process.Kill(); _ = sibling.Wait() })
	socket, ino := stageSocket(t)
	argv := append([]string{"/proc/self/exe", ServerCommand, "/usr/bin/python3"}, filesCmd...)
	stage := StageRequest{Socket: ino, Argv: argv}
	bad := stage
	bad.Socket = ^uint64(0)
	if s.prepareStage(pendingOf(t, s, os.Getpid()).shim, bad) {
		t.Fatal("prepared a socket the shim does not hold")
	}
	bad = stage
	bad.Argv = slices.Clone(argv)
	bad.Argv[1] = "run"
	if s.prepareStage(pendingOf(t, s, os.Getpid()).shim, bad) {
		t.Fatal("prepared another tego command")
	}
	if err := sh.fw.Write(Frame{Stage: &stage}); err != nil {
		t.Fatal(err)
	}
	if ans := sh.read(); !ans.OK {
		t.Fatal(ans.Error)
	}
	child := stageProcess(t, socket, argv)
	var own unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &own); err != nil {
		t.Fatal(err)
	}
	if s.Stage(sibling.Process.Pid, own.Dev, own.Ino, argv) != "" {
		t.Fatal("a preexisting sibling consumed the stage allowance")
	}
	if s.Stage(child.Process.Pid, own.Dev, own.Ino+1, argv) != "" {
		t.Fatal("another executable consumed the stage allowance")
	}
	other := slices.Clone(argv)
	other[len(other)-1] = "/other-server.py"
	if s.Stage(child.Process.Pid, own.Dev, own.Ino, other) != "" {
		t.Fatal("another server vector consumed the stage allowance")
	}
	if got := s.Stage(child.Process.Pid, own.Dev, own.Ino, argv); got != s.StageRule() {
		t.Fatalf("stage grant %q, want %q", got, s.StageRule())
	}
	p := pendingOf(t, s, os.Getpid())
	if p.pid != child.Process.Pid || p.child == nil || p.bound {
		t.Fatalf("stage identity not pinned awaiting registration: %+v", p)
	}
	if s.Relayed("files", child.Process.Pid) || s.bindChild(p.shim, sibling.Process.Pid) {
		t.Fatal("an unconfirmed child or sibling consumed the server start")
	}
	if s.Stage(child.Process.Pid, own.Dev, own.Ino, argv) != "" {
		t.Fatal("one child used the stage allowance twice")
	}
	if err := sh.fw.Write(Frame{Child: child.Process.Pid}); err != nil {
		t.Fatal(err)
	}
	if ans := sh.read(); !ans.OK {
		t.Fatal(ans.Error)
	}
	if s.Relayed("files", sibling.Process.Pid) || !s.Relayed("files", child.Process.Pid) || s.Relayed("files", child.Process.Pid) {
		t.Fatal("the confirmed child's one server start was not exclusive")
	}
	if _, err := sys.PollPidfdFD(p.child, 0); !errors.Is(err, sys.ErrClosed) {
		t.Fatalf("consumed stage identity not closed: %v", err)
	}
}

func TestStageIdentityClosedOnDisconnect(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, ans := dial(t, s, "files", filesCmd)
	if !ans.OK {
		t.Fatal(ans.Error)
	}
	socket, ino := stageSocket(t)
	argv := append([]string{"/proc/self/exe", ServerCommand, "/usr/bin/python3"}, filesCmd...)
	p := pendingOf(t, s, os.Getpid())
	if !s.prepareStage(p.shim, StageRequest{Socket: ino, Argv: argv}) {
		t.Fatal("stage not prepared")
	}
	child := stageProcess(t, socket, argv)
	var own unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &own); err != nil {
		t.Fatal(err)
	}
	if s.Stage(child.Process.Pid, own.Dev, own.Ino, argv) == "" {
		t.Fatal("stage not admitted")
	}
	p = pendingOf(t, s, os.Getpid())
	_ = sh.c.Close()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.PollPidfdFD(p.child, 0); !errors.Is(err, sys.ErrClosed) {
		t.Fatalf("disconnected stage's pidfd not closed: %v", err)
	}
	if s.bindChild(p.shim, child.Process.Pid) || s.Relayed("files", child.Process.Pid) {
		t.Fatal("disconnected stage retained start authority")
	}
}
