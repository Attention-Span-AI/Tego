// SPDX-License-Identifier: Apache-2.0

//go:build integration

package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"golang.org/x/sys/unix"
)

// The tests here run the watcher against the real proc connector, which needs CAP_NET_ADMIN: root. They run in
// root-suites (a KVM guest, or sudo on a CI runner) and skip anywhere else.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the proc connector is a multicast netlink group that needs CAP_NET_ADMIN")
	}
}

// openListener opens the real listener, or skips on a kernel that was built without a proc connector.
func openListener(t *testing.T) *procconn.Listener {
	t.Helper()
	l, err := procconn.Open()
	if errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.ENOENT) {
		t.Skipf("this kernel has no proc connector (CONFIG_PROC_EVENTS): %v", err)
	}
	if err != nil {
		t.Fatalf("procconn.Open as root: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// gated is a Source over the real listener that tells the test when the watcher first waits for events (its
// start-up scan is done) and, when armed, holds the watcher away from the socket until released: a way to
// fill the kernel's buffer while the watcher is busy.
type gated struct {
	*procconn.Listener
	ready chan struct{}
	once  sync.Once
	mu    sync.Mutex
	gate  chan struct{} // nil: open
}

func newGated(l *procconn.Listener) *gated { return &gated{Listener: l, ready: make(chan struct{})} }

func (g *gated) Recv() ([]procconn.Event, error) {
	g.once.Do(func() { close(g.ready) })
	g.mu.Lock()
	gate := g.gate
	g.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return g.Listener.Recv()
}

func (g *gated) hold() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = make(chan struct{})
	return g.gate
}

func (g *gated) release(gate chan struct{}) {
	g.mu.Lock()
	g.gate = nil
	g.mu.Unlock()
	close(gate)
}

// seen collects a watcher's sightings and lets a test wait for one.
type seen struct {
	mu sync.Mutex
	s  []Sighting
}

func (c *seen) emit(s Sighting) error { c.mu.Lock(); c.s = append(c.s, s); c.mu.Unlock(); return nil }

func (c *seen) all() []Sighting {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Sighting(nil), c.s...)
}

func (c *seen) wait(t *testing.T, what string, pred func(Sighting) bool) Sighting {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range c.all() {
			if pred(s) {
				return s
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no sighting: %s; saw:\n%s", what, dump(c.all()))
	return Sighting{}
}

func (c *seen) count(pred func(Sighting) bool) int {
	n := 0
	for _, s := range c.all() {
		if pred(s) {
			n++
		}
	}
	return n
}

func dump(ss []Sighting) string {
	var b strings.Builder
	for _, s := range ss {
		b.WriteString("  " + s.TextLine() + "\n")
	}
	return b.String()
}

// fakeAgents are scripts named like the agents they stand for. The agent waits for a byte on a fifo, runs one tool
// (a second script, which waits on its own fifo) and exits 7; the tool exits 3. Holding each on a fifo is what
// keeps a process alive until the watcher has read /proc: a watcher reads a process after its exec event, so a
// script that finished at once would be a race the test cannot win.
type fakeAgents struct {
	dir, agent, tool, agentGo, toolGo string
}

func newFakeAgents(t *testing.T, name string) *fakeAgents {
	t.Helper()
	d := t.TempDir()
	f := &fakeAgents{dir: d, agent: filepath.Join(d, name), tool: filepath.Join(d, "fake-tool"),
		agentGo: filepath.Join(d, "agent.go"), toolGo: filepath.Join(d, "tool.go")}
	for _, p := range []string{f.agentGo, f.toolGo} {
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(f.agent, "#!/bin/sh\nread _ < \"$AGENT_GO\"\n[ -z \"$AGENT_TOOL\" ] || \"$AGENT_TOOL\"\nexit 7\n")
	write(f.tool, "#!/bin/sh\nread _ < \"$TOOL_GO\"\nexit 3\n")
	return f
}

// start runs the agent, with the tool when withTool, and extra environment.
func (f *fakeAgents) start(t *testing.T, withTool bool, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(f.agent)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "AGENT_GO=" + f.agentGo, "TOOL_GO=" + f.toolGo}, env...)
	if withTool {
		cmd.Env = append(cmd.Env, "AGENT_TOOL="+f.tool)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// let opens a fifo for writing, which lets the process reading it go on. It cannot block for long: the reader is
// already waiting, or comes (the open waits for it).
func let(t *testing.T, fifo string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err == nil {
			_, err = f.Write([]byte("go\n"))
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("nothing is reading %s", fifo)
	}
}

// waitComm waits until the process has exec'd into the script, whose comm is the script's name.
func waitComm(t *testing.T, pid int, comm string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil && strings.TrimSpace(string(b)) == comm {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid %d never became %s", pid, comm)
}

func startWatcher(t *testing.T, src Source, c *seen, children bool) (w *Watcher, stop func() error) {
	t.Helper()
	w = New(NewFS(""), Options{Rules: sig.Default(), Emit: c.emit, Children: children})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, src) }()
	t.Cleanup(cancel)
	return w, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			return errors.New("Run did not return when its context ended")
		}
	}
}

// A fake agent started while the watcher listens is recognised by its exec; its tool, which it starts, is followed;
// the tool's and the agent's exits end the session; a program that is not an agent is never reported; and the
// kernel's event buffer does not overflow on the way (the path with no ENOBUFS).
func TestIntegrationWatcherSeesAFakeAgentItsChildAndTheirExit(t *testing.T) {
	requireRoot(t)
	// An agent that is already running when the watcher starts is found by the scan.
	early := newFakeAgents(t, "claude")
	earlyCmd := early.start(t, false)
	waitComm(t, earlyCmd.Process.Pid, "claude")

	src := newGated(openListener(t))
	c := &seen{}
	w, stop := startWatcher(t, src, c, true)
	<-src.ready

	found := c.wait(t, "the agent that was running already", func(s Sighting) bool {
		return s.Event == EventAgentStarted && s.PID == int32(earlyCmd.Process.Pid)
	})
	if found.Seen != SeenScan || found.Rule != "claude" || found.PPID != int32(os.Getpid()) || found.Comm != "claude" {
		t.Fatalf("scan found %+v", found)
	}

	// A new agent, in the middle of other traffic: a program that is no agent starts and ends.
	live := newFakeAgents(t, "claude")
	agent := live.start(t, true, "TEGO_RUN_ID=r-0a1b2c3d-0123456789abc-xyz123")
	other := exec.Command("/bin/sh", "-c", "exit 0")
	if err := other.Run(); err != nil {
		t.Fatal(err)
	}
	pid := int32(agent.Process.Pid)
	start := c.wait(t, "agent_started by exec", func(s Sighting) bool { return s.Event == EventAgentStarted && s.PID == pid })
	if start.Seen != SeenExec || start.Rule != "claude" || start.PPID != int32(os.Getpid()) || start.Comm != "claude" ||
		start.Session == 0 || len(start.Argv) < 2 || !strings.HasSuffix(start.Argv[len(start.Argv)-1], "/claude") {
		t.Fatalf("agent_started = %+v", start)
	}
	// Started from this test, in no tego run's cgroup, with a run id in its environment that nothing backs.
	if start.OutsideGovernedRun == nil || !*start.OutsideGovernedRun || start.RunID != "r-0a1b2c3d-0123456789abc-xyz123" ||
		start.RunCgroupID != "" || !strings.Contains(start.Note, "no run's cgroup") || start.Cgroup == "" {
		t.Fatalf("governance: %+v", start)
	}

	// The agent runs its tool.
	let(t, live.agentGo)
	forked := c.wait(t, "child_forked", func(s Sighting) bool { return s.Event == EventChildForked && s.PPID == pid })
	if forked.Session != start.Session {
		t.Fatalf("the child joined session %d, not the agent's %d", forked.Session, start.Session)
	}
	execd := c.wait(t, "child_exec", func(s Sighting) bool { return s.Event == EventChildExec && s.PID == forked.PID })
	if execd.Comm != "fake-tool" || execd.Session != start.Session || !strings.HasSuffix(execd.Argv[len(execd.Argv)-1], "/fake-tool") {
		t.Fatalf("child_exec = %+v", execd)
	}
	let(t, live.toolGo)
	cexit := c.wait(t, "child_exited", func(s Sighting) bool { return s.Event == EventChildExited && s.PID == forked.PID })
	if cexit.ExitCode == nil || *cexit.ExitCode != 3 {
		t.Fatalf("child_exited = %+v", cexit)
	}
	aexit := c.wait(t, "agent_exited", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid })
	if aexit.ExitCode == nil || *aexit.ExitCode != 7 || aexit.Signal != 0 || aexit.Descendants != 1 || aexit.StillRunning != 0 || aexit.Rule != "claude" {
		t.Fatalf("agent_exited = %+v", aexit)
	}

	// The early agent ends too.
	let(t, early.agentGo)
	c.wait(t, "the early agent's exit", func(s Sighting) bool {
		return s.Event == EventAgentExited && s.PID == int32(earlyCmd.Process.Pid) && s.ExitCode != nil && *s.ExitCode == 7
	})

	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, s := range c.all() {
		if s.PID == int32(other.Process.Pid) {
			t.Errorf("a program that is no agent was reported: %s", s.TextLine())
		}
	}
	if st := w.Stats(); st.Overruns != 0 || st.Rescans != 1 || w.Sessions() != 0 || w.Processes() != 0 {
		t.Fatalf("stats %+v, %d session(s), %d process(es) followed; want one scan, no overrun and nothing left", st, w.Sessions(), w.Processes())
	}
}

// The kernel's buffer overflows for real: the watcher is held away from the socket (and the socket made tiny)
// while a burst of programs runs and the agents change under it. When the watcher goes on it sees ENOBUFS, reads
// what survived, scans /proc, and ends with the true picture: each agent reported once, the exits it missed
// found, and nothing followed that is gone.
func TestIntegrationOverrunResynchronisesWithTheRealKernel(t *testing.T) {
	requireRoot(t)
	l := openListener(t)
	if err := l.SetRecvBuffer(4096); err != nil {
		t.Fatalf("SetRecvBuffer: %v", err)
	}
	src := newGated(l)
	c := &seen{}
	w, stop := startWatcher(t, src, c, true)
	<-src.ready

	// A is running, with its tool, and followed before the burst. Then the watcher is held away from the socket and
	// the burst fills the kernel's buffer: everything after it, B's start and the exits of A and its tool, is
	// dropped by the kernel, so only the scan can tell the watcher what happened.
	a := newFakeAgents(t, "claude")
	aCmd := a.start(t, true)
	pidA := int32(aCmd.Process.Pid)
	c.wait(t, "agent A", func(s Sighting) bool { return s.Event == EventAgentStarted && s.PID == pidA })
	let(t, a.agentGo)
	tool := c.wait(t, "A's tool", func(s Sighting) bool { return s.Event == EventChildExec && s.PPID == pidA })

	gate := src.hold()
	// The watcher may be blocked in the socket's poll: one harmless event wakes it, and it then waits at the gate.
	if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 1500; i++ { // a fork, an exec and an exit each: far over a 4 KiB buffer
		if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err != nil {
			t.Fatal(err)
		}
	}
	// The buffer is full. What happens now never reaches the watcher as an event.
	b := newFakeAgents(t, "claude")
	bCmd := b.start(t, false)
	pidB := int32(bCmd.Process.Pid)
	waitComm(t, bCmd.Process.Pid, "claude")
	let(t, a.toolGo) // A's tool ends, then A
	aCmd.Wait()
	src.release(gate)

	// B was never announced by an event, so the scan finds it; A and its tool were found gone by the scan, their
	// statuses unknown. Each is reported once, whatever the kernel dropped.
	bStart := c.wait(t, "B's start", func(s Sighting) bool { return s.Event == EventAgentStarted && s.PID == pidB })
	if bStart.Seen != SeenScan || bStart.Rule != "claude" {
		t.Fatalf("B = %+v: its exec event should have been dropped and the scan should have found it", bStart)
	}
	aExit := c.wait(t, "A's exit", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pidA })
	if aExit.ExitCode != nil || !strings.Contains(aExit.Note, "scan") || aExit.Descendants != 1 {
		t.Fatalf("A's exit = %+v: its exit event should have been dropped and the scan should have found it gone", aExit)
	}
	c.wait(t, "A's tool exit", func(s Sighting) bool { return s.Event == EventChildExited && s.PID == tool.PID })
	// B goes on, and ends by its own event now that the watcher is current.
	let(t, b.agentGo)
	bCmd.Wait()
	c.wait(t, "B's exit", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pidB })
	time.Sleep(500 * time.Millisecond) // let the watcher finish whatever the burst left queued
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, tc := range []struct {
		what  string
		event string
		pid   int32
	}{{"A started", EventAgentStarted, pidA}, {"A exited", EventAgentExited, pidA}, {"B started", EventAgentStarted, pidB}, {"B exited", EventAgentExited, pidB}} {
		if n := c.count(func(s Sighting) bool { return s.Event == tc.event && s.PID == tc.pid }); n != 1 {
			t.Errorf("%s reported %d times, want once\n%s", tc.what, n, dump(c.all()))
		}
	}
	st := w.Stats()
	if st.Overruns == 0 {
		t.Fatalf("the kernel's buffer never overflowed (stats %+v): the test did not reach what it is for", st)
	}
	if c.count(func(s Sighting) bool { return s.Event == EventResync }) != st.Overruns || st.Rescans != st.Overruns+1 {
		t.Errorf("stats %+v do not match the resync lines", st)
	}
	if w.Sessions() != 0 || w.Processes() != 0 {
		t.Fatalf("%d session(s) and %d process(es) still followed after everything exited\n%s", w.Sessions(), w.Processes(), dump(c.all()))
	}
}

// leaderExitAgent is a process whose main thread exits (a raw exit(2), SYS_exit given as argv[1]) while a thread of
// it runs on; the thread prints its id and waits.
const leaderExitAgent = `
import ctypes, sys, threading, time
libc = ctypes.CDLL(None)
def worker():
    sys.stdout.write("%d\n" % threading.get_native_id())
    sys.stdout.flush()
    while True:
        time.sleep(0.2)
threading.Thread(target=worker).start()
time.sleep(0.3)
libc.syscall(int(sys.argv[1]), 0)
`

// TestIntegrationFactsReadAnAgentWhoseLeaderExited: on the running kernel, a process whose main thread has exited
// reads as a zombie with no exe and no cmdline at /proc/<pid>, and the scan read it as gone, so the guard never saw
// an agent that did this before it looked. facts reads its program,
// arguments and cgroup through its live thread. It needs no privilege.
func TestIntegrationFactsReadAnAgentWhoseLeaderExited(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	sysExit := "60" // amd64
	switch runtime.GOARCH {
	case "arm64":
		sysExit = "93"
	case "amd64":
	default:
		t.Skipf("no SYS_exit number for %s here", runtime.GOARCH)
	}
	cmd := exec.Command(python, "-c", leaderExitAgent, sysExit, "tego-leader-exit-marker")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var tid int
	if _, err := fmt.Fscan(out, &tid); err != nil {
		t.Fatalf("the agent printed no thread id: %v", err)
	}
	pid := cmd.Process.Pid
	fs := NewFS("")
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		st, err := fs.Stat(pid)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == 'Z' && st.NumThreads > 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent's leader did not exit: state %c, %d threads", st.State, st.NumThreads)
		}
	}
	if exe, _ := fs.Exe(pid); exe != "" {
		t.Logf("/proc/%d/exe of the exited leader still reads %q", pid, exe)
	}
	w := New(fs, Options{Rules: sig.Default()})
	f, err := w.facts(pid)
	if err != nil {
		t.Fatalf("facts of a process whose leader exited: %v", err)
	}
	if !strings.Contains(filepath.Base(f.Exe), "python") || len(f.Argv) == 0 || f.Argv[len(f.Argv)-1] != "tego-leader-exit-marker" ||
		f.start == 0 || f.tid != tid {
		t.Errorf("facts = %+v, want python and its arguments, read through thread %d", f, tid)
	}
	want, _ := fs.Cgroup(tid)
	if cg, err := f.via.Cgroup(f.tid); err != nil || cg != want {
		t.Errorf("cgroup through the thread = %q, %v; want %q", cg, err, want)
	}
}
