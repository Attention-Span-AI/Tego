// SPDX-License-Identifier: Apache-2.0

//go:build integration

package watcher

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"golang.org/x/sys/unix"
)

// leaderFirstAgent writes a python agent named claude whose main thread exits by a raw exit(2) (code 0) once fifo
// first is opened, while a thread of it waits on fifo second; mode "fork" makes the thread fork a sleeping child (its pid
// on stdout) first and then wait on fifo third. The thread then ends the process with exit_group(3).
func leaderFirstAgent(t *testing.T) (script string, fifos []string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	dir := t.TempDir()
	for _, n := range []string{"first", "second", "third"} {
		p := filepath.Join(dir, n)
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		fifos = append(fifos, p)
	}
	script = filepath.Join(dir, "claude")
	body := "#!" + python + `
import ctypes, os, sys, threading, time
libc = ctypes.CDLL(None)
def worker():
    open(sys.argv[2]).read()
    if sys.argv[4] == "fork":
        pid = os.fork()
        if pid == 0:
            time.sleep(60)
            os._exit(5)
        sys.stdout.write("%d\n" % pid)
        sys.stdout.flush()
        open(sys.argv[3]).read()
    os._exit(3)
threading.Thread(target=worker).start()
open(sys.argv[1]).read()
libc.syscall(60, 0)
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, fifos
}

// waitLeaderExited waits until /proc says pid's leader exited while a thread of it runs.
func waitLeaderExited(t *testing.T, pid int) {
	t.Helper()
	fs := NewFS("")
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if st, err := fs.Stat(pid); err == nil && st.LeaderExited() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d: its main thread did not exit", pid)
		}
	}
}

// TestIntegrationWatcherFollowsAnAgentWhoseMainThreadExits: an agent the watcher saw start has its main thread exit
// while a thread of it runs, forks a child and later ends the process with exit_group(3) (reproduced with this
// agent: agent_exited exit=0 for the live process, and its thread's child was not followed). Now no agent_exited
// comes while it runs, the child is followed, and the end is reported once the last
// thread exits, with no status: 0 then 3 could be either, and the line says so.
func TestIntegrationWatcherFollowsAnAgentWhoseMainThreadExits(t *testing.T) {
	requireRoot(t)
	script, fifos := leaderFirstAgent(t)
	src := newGated(openListener(t))
	c := &seen{}
	_, stop := startWatcher(t, src, c, true)
	<-src.ready
	cmd := exec.Command(script, fifos[0], fifos[1], fifos[2], "fork")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := int32(cmd.Process.Pid)
	c.wait(t, "agent_started", func(s Sighting) bool { return s.Event == EventAgentStarted && s.PID == pid })
	let(t, fifos[0])
	waitLeaderExited(t, int(pid))
	let(t, fifos[1])
	var child int
	if _, err := fmt.Fscan(bufio.NewReader(out), &child); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	c.wait(t, "child_forked of the thread's child", func(s Sighting) bool { return s.Event == EventChildForked && s.PID == int32(child) })
	if n := c.count(func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid }); n != 0 {
		t.Fatalf("agent_exited while its thread runs: %s", dump(c.all()))
	}
	let(t, fifos[2])
	var ee *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("the agent's wait status = %v, want exit status 3", err)
	}
	x := c.wait(t, "agent_exited", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid })
	if x.ExitCode != nil || x.Note == "" || x.StillRunning != 1 {
		t.Errorf("agent_exited = %s; want no status, a note, and the child still running", x.TextLine())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationWatcherEndsAnAgentFoundWithItsMainThreadGone: the watcher starts after the agent's main thread has
// exited; its scan reports the agent through its thread, and the agent's end, the thread's exit_group(3),
// is the only exit event left. It was never reported and the session stayed (reproduced with this agent); now it is,
// and no session is left.
func TestIntegrationWatcherEndsAnAgentFoundWithItsMainThreadGone(t *testing.T) {
	requireRoot(t)
	script, fifos := leaderFirstAgent(t)
	cmd := exec.Command(script, fifos[0], fifos[1], fifos[2], "plain")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := int32(cmd.Process.Pid)
	let(t, fifos[0])
	waitLeaderExited(t, int(pid))
	src := newGated(openListener(t))
	c := &seen{}
	w, stop := startWatcher(t, src, c, false)
	<-src.ready
	c.wait(t, "agent_started by the scan", func(s Sighting) bool {
		return s.Event == EventAgentStarted && s.PID == pid && s.Seen == SeenScan
	})
	let(t, fifos[1])
	x := c.wait(t, "agent_exited", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid })
	if x.ExitCode != nil || x.Note == "" {
		t.Errorf("agent_exited = %s; want no status (the main thread's exit was not read) and a note", x.TextLine())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if w.Sessions() != 0 || w.Processes() != 0 {
		t.Errorf("after the agent ended: %d session(s), %d process(es) followed; want none", w.Sessions(), w.Processes())
	}
}

// TestIntegrationAGroupReadsGoneAtItsLastTasksExitEvent cross-checks the end procconn.Group tells from the events
// alone against /proc: once the proc connector's exit event of a process's last task has been read, /proc shows the
// process gone (the kernel sends a task's event after it has released the task), and the leader's own event, while a
// thread of it runs, does not. Group no longer reads /proc at an event (read late, an earlier event found it gone
// too); this says its end is never later than /proc's. Two shapes, many
// times each: the main thread exits first and the thread ends the process later; and a main thread's exit_group(2) that
// ends a thread with it.
func TestIntegrationAGroupReadsGoneAtItsLastTasksExitEvent(t *testing.T) {
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	script := filepath.Join(t.TempDir(), "group")
	body := "#!" + python + `
import ctypes, os, sys, threading, time
libc = ctypes.CDLL(None)
def worker():
    if sys.argv[1] == "first":
        time.sleep(0.2)
        os._exit(3)
    time.sleep(60)
threading.Thread(target=worker).start()
time.sleep(0.01)
if sys.argv[1] == "first":
    libc.syscall(60, 0)
os._exit(2)
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	l := openListener(t)
	type read struct {
		ev   procconn.Event
		gone bool
	}
	w := New(NewFS(""), Options{})
	reads := make(chan read, 4096)
	want := make(chan int32, 1)
	go func() {
		var pid int32
		for {
			evs, err := l.Recv()
			for _, ev := range evs {
				select {
				case pid = <-want:
				default:
				}
				if ev.Kind == procconn.Exit && pid != 0 && ev.TGID == pid {
					reads <- read{ev, goneNow(w, ev.TGID)}
				}
			}
			if err != nil && !procconn.IsOverrun(err) {
				return
			}
		}
	}()
	const runs = 40
	for _, mode := range []string{"first", "group"} {
		endAtLeader, lag := 0, 0
		for range runs {
			cmd := exec.Command(script, mode)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := int32(cmd.Process.Pid)
			want <- pid
			var got []read
			for quiet := time.After(3 * time.Second); len(got) < 2; {
				select {
				case r := <-reads:
					if r.ev.TGID == pid {
						got = append(got, r)
					}
				case <-quiet:
					t.Fatalf("%s: pid %d: %d exit event(s) read, want 2 (%+v)", mode, pid, len(got), got)
				}
			}
			_ = cmd.Wait() // reaped only once its events are read: /proc shows its zombie until then
			if !got[1].gone {
				lag++
			}
			if got[0].gone {
				endAtLeader++
				if mode == "first" {
					t.Errorf("first: pid %d: gone at the first exit event %+v, while its thread ran", pid, got[0].ev)
				}
			}
		}
		t.Logf("MEASURE %s: %d runs, the last task's event read gone in %d, the first event already gone in %d",
			mode, runs, runs-lag, endAtLeader)
		if lag != 0 {
			t.Errorf("%s: /proc lagged the last task's exit event in %d of %d runs", mode, lag, runs)
		}
	}
}

// goneNow is whether /proc shows process tgid with no task that runs: it cannot be read, it is dead or a zombie whose
// group has ended, or its leader exited and every task left is a zombie.
func goneNow(w *Watcher, tgid int32) bool {
	st, err := w.p.Stat(int(tgid))
	if err != nil || st.Gone() {
		return true
	}
	return st.LeaderExited() && len(w.listTasks(tgid).Live) == 0
}
