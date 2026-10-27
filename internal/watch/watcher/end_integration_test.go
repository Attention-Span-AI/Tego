// SPDX-License-Identifier: Apache-2.0

//go:build integration

package watcher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"golang.org/x/sys/unix"
)

// badELF writes an x86-64 ET_EXEC whose only PT_LOAD lies above every user address: an exec of it passes the point of
// no return (begin_new_exec, de_thread) and then fails to map it, so the task dies of SIGSEGV with no exec event.
func badELF(t *testing.T, path string) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("the hand-made ELF is x86-64")
	}
	b := make([]byte, 64+56)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	const va = 0x7f00000000000000
	le.PutUint16(b[16:], 2)  // ET_EXEC
	le.PutUint16(b[18:], 62) // EM_X86_64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], va+120) // entry
	le.PutUint64(b[32:], 64)     // phoff
	le.PutUint16(b[52:], 64)     // ehsize
	le.PutUint16(b[54:], 56)     // phentsize
	le.PutUint16(b[56:], 1)      // phnum
	ph := b[64:]
	le.PutUint32(ph[0:], 1) // PT_LOAD
	le.PutUint32(ph[4:], 5) // R+X
	le.PutUint64(ph[16:], va)
	le.PutUint64(ph[24:], va)
	le.PutUint64(ph[32:], 120)
	le.PutUint64(ph[40:], 120)
	le.PutUint64(ph[48:], 0x1000)
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// shapesAgent writes a python agent named claude that waits on the fifo in argv[1] and then ends by the shape in
// argv[2], with the thread that ends it started only once the fifo is opened:
//
//   - zap: a worker thread runs sh -c 'exit 3' (de_thread zaps the live main thread with code 0);
//   - zapsig: a worker thread runs sh -c 'kill -SEGV $$';
//   - badexec: a worker thread execs argv[3], which fails after de_thread (SIGSEGV, no exec event);
//   - thread: a worker thread's exit_group(3) while the main thread sleeps (the thread's exit event may come first);
//   - first: the main thread's own exit(2), code 0, then the worker's exit_group(3) (wait(2) says 3, the events 0 and 3).
func shapesAgent(t *testing.T) (script, bad string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	dir := t.TempDir()
	bad = filepath.Join(dir, "bad")
	badELF(t, bad)
	script = filepath.Join(dir, "claude")
	body := "#!" + python + `
import ctypes, os, sys, threading, time
libc = ctypes.CDLL(None)
mode = sys.argv[2]
open(sys.argv[1]).read()
def worker():
    if mode == "zap":
        os.execv("/bin/sh", ["sh", "-c", "exit 3"])
    if mode == "zapsig":
        os.execv("/bin/sh", ["sh", "-c", "kill -SEGV $$"])
    if mode == "badexec":
        os.execv(sys.argv[3], [sys.argv[3]])
    time.sleep(0.05)
    os._exit(3)
threading.Thread(target=worker).start()
if mode == "first":
    libc.syscall(60, 0)
threading.Event().wait()
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, bad
}

// rawStatus is a wait status in the raw form exit events carry.
func rawStatus(ws syscall.WaitStatus) uint32 {
	if ws.Signaled() {
		return uint32(ws.Signal())
	}
	return uint32(ws.ExitStatus()) << 8
}

// collector keeps the events of the processes it was told to keep, from the moment it was told.
type collector struct {
	mu   sync.Mutex
	want map[int32][]procconn.Event
	more chan struct{}
}

func collect(t *testing.T) *collector {
	l := openListener(t)
	c := &collector{want: map[int32][]procconn.Event{}, more: make(chan struct{}, 1)}
	go func() {
		for {
			evs, err := l.Recv()
			c.mu.Lock()
			for _, ev := range evs {
				if got, ok := c.want[ev.TGID]; ok {
					c.want[ev.TGID] = append(got, ev)
				}
			}
			c.mu.Unlock()
			select {
			case c.more <- struct{}{}:
			default:
			}
			if procconn.IsOverrun(err) {
				t.Errorf("the kernel dropped events: the run says nothing")
			}
			if err != nil && !procconn.IsOverrun(err) {
				return
			}
		}
	}()
	return c
}

func (c *collector) keep(pid int32) { c.mu.Lock(); c.want[pid] = nil; c.mu.Unlock() }

// fold folds pid's events read so far into g, from the n-th on, and says how many it has folded.
func (c *collector) fold(pid int32, g *procconn.Group, n int) int {
	c.mu.Lock()
	evs := c.want[pid][n:]
	c.mu.Unlock()
	for _, ev := range evs {
		switch {
		case ev.Kind == procconn.Fork && ev.PID != ev.TGID:
			g.Fork(ev)
		case ev.Kind == procconn.Exec:
			g.Exec(ev)
		case ev.Kind == procconn.Exit:
			g.Exit(ev)
		}
	}
	return n + len(evs)
}

// TestIntegrationAProcessEndsAtItsEventsWithAStatusWaitAgrees: procconn.Group over the real kernel's events, for each
// shape of end the reviews found, many times: the
// process is listed after the listener was subscribed, its events are folded from there, and the end is reached;
// a status Group knows is the one wait(2) reports, and the shapes whose compared codes always agree give one. A failed
// exec's (badexec) is known only when the zapped main thread's exit names the leader's pid: one filled after de_thread
// swapped the tids names the exec'ing thread's old tid and carries 0, which the SIGSEGV of the death then disagrees
// with (a code read before the leader's is compared too).
func TestIntegrationAProcessEndsAtItsEventsWithAStatusWaitAgrees(t *testing.T) {
	requireRoot(t)
	script, bad := shapesAgent(t)
	c := collect(t)
	w := New(NewFS(""), Options{})
	const runs = 30
	for _, sh := range []struct {
		mode  string
		known bool // the codes agree, so the status is known
	}{{"zap", true}, {"zapsig", true}, {"badexec", false}, {"thread", true}, {"first", false}} {
		knownN := 0
		for i := range runs {
			fifo := filepath.Join(t.TempDir(), "go")
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(script, fifo, sh.mode, bad)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := int32(cmd.Process.Pid)
			c.keep(pid)
			waitComm(t, int(pid), "claude")
			g := procconn.NewGroup(pid, w.listTasks(pid), func() procconn.Listing { return w.listTasks(pid) })
			let(t, fifo)
			err := cmd.Wait()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				t.Fatal(err)
			}
			want := rawStatus(cmd.ProcessState.Sys().(syscall.WaitStatus))
			n := 0
			for deadline := time.Now().Add(5 * time.Second); !g.Ended(); {
				select {
				case <-c.more:
				case <-time.After(10 * time.Millisecond):
				}
				if n = c.fold(pid, g, n); !g.Ended() && time.Now().After(deadline) {
					t.Fatalf("%s run %d: pid %d did not end at its events (wait %#x)", sh.mode, i, pid, want)
				}
			}
			raw, known := g.Status()
			if known && raw&^0x80 != want { // a dumped core's bit, which wait's signal leaves out
				t.Fatalf("%s run %d: pid %d: status %#x, wait(2) says %#x", sh.mode, i, pid, raw, want)
			}
			if known {
				knownN++
			} else if sh.known {
				t.Errorf("%s run %d: pid %d: status unknown (%s), wait(2) says %#x", sh.mode, i, pid, g.Why(), want)
			}
		}
		t.Logf("MEASURE %s: %d runs, the status known in %d, never another than wait(2)'s", sh.mode, runs, knownN)
	}
}

// TestThreadKilledAloneHelper is the child of TestIntegrationAThreadKilledAloneGivesNoSignal: a thread installs a
// seccomp filter that kills it alone (SECCOMP_RET_KILL_THREAD) on getppid and calls it, and the process then exits 0.
func TestThreadKilledAloneHelper(t *testing.T) {
	if os.Getenv("TEGO_KILL_THREAD_HELPER") != "1" {
		t.Skip("the child of TestIntegrationAThreadKilledAloneGivesNoSignal")
	}
	fifo := os.Getenv("TEGO_KILL_THREAD_GO")
	if b, err := os.ReadFile(fifo); err != nil || len(b) == 0 {
		os.Exit(6)
	}
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: unix.SYS_GETPPID},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_THREAD},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
		if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
			os.Exit(7)
		}
		close(done)
		_, _, _ = unix.Syscall(unix.SYS_GETPPID, 0, 0, 0)
	}()
	<-done
	time.Sleep(200 * time.Millisecond)
	unix.Exit(0)
}

// TestIntegrationAThreadKilledAloneGivesNoSignal: a task killed alone by SIGSYS (SECCOMP_RET_KILL_THREAD), then the
// process's exit_group(0), which wait(2) reports as exited 0. Group gave signal 31 when the killed task was the main
// thread; a status it knows is now wait(2)'s, many times.
func TestIntegrationAThreadKilledAloneGivesNoSignal(t *testing.T) {
	requireRoot(t)
	c := collect(t)
	w := New(NewFS(""), Options{})
	killed, knownN := 0, 0
	const runs = 20
	for i := range runs {
		fifo := filepath.Join(t.TempDir(), "go")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestThreadKilledAloneHelper$")
		cmd.Env = append(os.Environ(), "TEGO_KILL_THREAD_HELPER=1", "TEGO_KILL_THREAD_GO="+fifo)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := int32(cmd.Process.Pid)
		c.keep(pid)
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			if st, err := w.p.Stat(int(pid)); err == nil && st.State == 'S' && st.NumThreads > 1 {
				break // blocked on the fifo, its runtime's threads started
			}
			if time.Now().After(deadline) {
				t.Fatal("the helper did not start")
			}
		}
		g := procconn.NewGroup(pid, w.listTasks(pid), func() procconn.Listing { return w.listTasks(pid) })
		let(t, fifo)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("run %d: the helper: %v", i, err)
		}
		n := 0
		for deadline := time.Now().Add(5 * time.Second); !g.Ended(); {
			select {
			case <-c.more:
			case <-time.After(10 * time.Millisecond):
			}
			if n = c.fold(pid, g, n); !g.Ended() && time.Now().After(deadline) {
				t.Fatalf("run %d: pid %d did not end at its events", i, pid)
			}
		}
		c.mu.Lock()
		for _, ev := range c.want[pid] {
			if ev.Kind == procconn.Exit && ev.ExitCode == uint32(unix.SIGSYS) {
				killed++
			}
		}
		c.mu.Unlock()
		raw, known := g.Status()
		if known && raw != 0 {
			t.Fatalf("run %d: pid %d: status %#x for a process wait(2) says exited 0", i, pid, raw)
		}
		if known {
			knownN++
		}
	}
	if killed == 0 {
		t.Fatal("no task was killed by SIGSYS: the shape did not happen")
	}
	t.Logf("MEASURE %d runs, %d SIGSYS exits read, the status known (0) in %d", runs, killed, knownN)
}

// TestIntegrationWatcherReportsTheStatusOfAProgramAThreadRan: the real watcher, for an agent whose worker thread runs
// sh -c 'exit 3' (de_thread zaps its live main thread): it printed agent_exited exit=0 in some runs, the zap's exit
// read late having ended the process. Every run now reports 3. An agent
// whose thread's exec fails after the zap is reported ended, by SIGSEGV, its session closed (s5-2).
func TestIntegrationWatcherReportsTheStatusOfAProgramAThreadRan(t *testing.T) {
	requireRoot(t)
	script, bad := shapesAgent(t)
	src := newGated(openListener(t))
	c := &seen{}
	w, stop := startWatcher(t, src, c, false)
	<-src.ready
	run := func(mode string) (int32, syscall.WaitStatus) {
		fifo := filepath.Join(t.TempDir(), "go")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(script, fifo, mode, bad)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := int32(cmd.Process.Pid)
		c.wait(t, "agent_started", func(s Sighting) bool { return s.Event == EventAgentStarted && s.PID == pid })
		let(t, fifo)
		_ = cmd.Wait()
		return pid, cmd.ProcessState.Sys().(syscall.WaitStatus)
	}
	const runs = 30
	for i := range runs {
		pid, ws := run("zap")
		x := c.wait(t, "agent_exited", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid })
		if ws.ExitStatus() != 3 || x.ExitCode == nil || *x.ExitCode != 3 || x.Signal != 0 {
			t.Fatalf("run %d: wait %v, %s; want exit 3 both", i, ws, x.TextLine())
		}
	}
	pid, ws := run("badexec")
	x := c.wait(t, "agent_exited", func(s Sighting) bool { return s.Event == EventAgentExited && s.PID == pid })
	if ws.Signal() != syscall.SIGSEGV || x.Signal != int(syscall.SIGSEGV) || x.ExitCode == nil {
		t.Fatalf("the failed exec: wait %v, %s; want SIGSEGV both", ws, x.TextLine())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if w.Sessions() != 0 {
		t.Fatalf("%d session(s) left open: %s", w.Sessions(), fmt.Sprint(dump(c.all())))
	}
}
