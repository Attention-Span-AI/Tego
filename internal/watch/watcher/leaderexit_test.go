// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/sig"
)

// threadExit is the exit event of thread tid of process tgid.
func threadExit(tid, tgid int32, status uint32) procconn.Event {
	return procconn.Event{Kind: procconn.Exit, PID: tid, TGID: tgid, ExitCode: status}
}

// threadFork is the fork event of thread tid of process tgid.
func threadFork(tid, tgid int32) procconn.Event {
	return procconn.Event{Kind: procconn.Fork, PID: tid, TGID: tgid, ParentTGID: 400}
}

// twoThreadAgent puts in fp an agent at pid 500 with a second thread, 5001. A watcher that follows it from its exec
// reads the thread's fork event next (startTwoThreads).
func twoThreadAgent(fp *fakeProc) {
	agent := claudeProc(400, termCG, "")
	agent.threads, agent.start = 2, 50
	fp.add(500, agent)
	thread := claudeProc(400, termCG, "")
	thread.tgid, thread.threads, thread.start = 500, 2, 51
	fp.add(5001, thread)
}

// TestAnAgentFoundWithItsLeaderGoneEndsWithItsLastThread: a scan reports an agent whose main thread had exited. The
// only exit event left for it is its last thread's, which the watcher used to
// skip as a thread's, so the session was never ended and its stale root hid a later agent given the pid. The
// thread's exit ends the process, with no status (the main thread's
// code was never read), and an agent the terminal later starts at the reused pid is an agent of its own.
func TestAnAgentFoundWithItsLeaderGoneEndsWithItsLastThread(t *testing.T) {
	fp, o := newFake(), &out{}
	twoThreadAgent(fp)
	fp.procs[500].state, fp.procs[500].exe, fp.procs[500].argv = 'Z', "", nil
	w := newWatcher(fp, o, false)
	must(t, w.rescan(false))
	if o.find(EventAgentStarted, 500) == nil {
		t.Fatalf("the scan did not report the agent: %v", o.kinds())
	}
	handle(t, w, threadExit(5001, 500, 3<<8))
	x := o.find(EventAgentExited, 500)
	if x == nil || w.Sessions() != 0 || w.Processes() != 0 {
		t.Fatalf("after the last thread's exit: sightings %v, %d session(s), %d process(es); want agent_exited and none",
			o.kinds(), w.Sessions(), w.Processes())
	}
	if x.ExitCode != nil || x.Signal != 0 || x.Note == "" {
		t.Errorf("agent_exited = %+v; want no status, and a note saying why", x)
	}
	again := claudeProc(401, termCG, "")
	again.start = 99
	fp.add(500, again)
	handle(t, w, evExec(500))
	if got := strings.Join(o.kinds(), ","); got != "agent_started,agent_exited,agent_started" {
		t.Fatalf("a new agent at the reused pid: sightings %s", got)
	}
}

// startTwoThreads is the agent of twoThreadAgent followed from its exec, then its thread's fork.
func startTwoThreads(t *testing.T, w *Watcher) {
	t.Helper()
	handle(t, w, evExec(500), threadFork(5001, 500))
}

// TestTheEndIsTheEventsNotWhatProcShowsWhenTheyAreRead: the end of a process is told by its tasks' exit events alone.
// It used to be the first exit event after which /proc showed no task of it running, as /proc read when the event was
// handled, so an event read late ended it early. Each row
// is the kernel's own sequence, read once /proc shows the process gone, or its pid reused.
func TestTheEndIsTheEventsNotWhatProcShowsWhenTheyAreRead(t *testing.T) {
	zapped := evExit(500, 0) // a thread's exec zaps the live main thread (de_thread) with code 0
	for _, tc := range []struct {
		name      string
		evs       []procconn.Event
		code, sig int
		known     bool
	}{
		{"a thread's exec zaps the main thread, then the program exits 3 (s5-1)",
			[]procconn.Event{zapped, evExec(500), evExit(500, 3<<8)}, 3, 0, true},
		{"the same, the program killed by SIGSEGV (s5-1)", []procconn.Event{zapped, evExec(500), evExit(500, 11)}, 0, 11,
			true},
		{"an exec that fails after the zap kills its task, now the leader, with no exec event (s5-2)",
			[]procconn.Event{zapped, evExit(500, 11)}, 0, 11, true},
		{"exit_group(3) from the thread: its event first, the main thread's next (c5-2)",
			[]procconn.Event{threadExit(5001, 500, 3<<8), evExit(500, 3<<8)}, 3, 0, true},
		{"the main thread killed alone by SIGSYS, then the thread's exit_group(0) (c5-1)",
			[]procconn.Event{evExit(500, 31), threadExit(5001, 500, 0)}, 0, 0, false},
	} {
		for _, reused := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, pid reused %v", tc.name, reused), func(t *testing.T) {
				fp, o := newFake(), &out{}
				twoThreadAgent(fp)
				w := newWatcher(fp, o, false)
				startTwoThreads(t, w)
				fp.del(5001)
				fp.del(500)
				if reused {
					fp.add(500, fproc{ppid: 1, comm: "bash", exe: "/usr/bin/bash", argv: []string{"bash"}, start: 77})
				}
				for i, ev := range tc.evs {
					if ev.TimestampNS == 0 {
						ev.TimestampNS = procconn.Monotonic() // filled in the order read, after the session began
					}
					must(t, w.Handle(ev))
					if x := o.find(EventAgentExited, 500); x != nil && i < len(tc.evs)-1 {
						t.Fatalf("ended at event %d of %d: %+v", i, len(tc.evs), x)
					}
				}
				x := o.find(EventAgentExited, 500)
				if x == nil || w.Sessions() != 0 || len(w.groups) != 0 {
					t.Fatalf("sightings %v, %d session(s), groups %v; want agent_exited and nothing left", o.kinds(),
						w.Sessions(), w.groups)
				}
				switch {
				case !tc.known:
					if x.ExitCode != nil || x.Note == "" {
						t.Fatalf("agent_exited = %+v; want no status and a note", x)
					}
				case x.ExitCode == nil || *x.ExitCode != tc.code || x.Signal != tc.sig:
					t.Fatalf("agent_exited = %+v; want code %d signal %d", x, tc.code, tc.sig)
				}
			})
		}
	}
}

// TestAnAgentWhoseMainThreadExitsRunsOnInItsSession: the main thread of a followed agent exits while a thread of it
// runs (pthread_exit in main). The watcher used to report agent_exited with the main thread's code at once, for a
// process that ran on, and stopped following what its thread then forked.
// The session lives on; the thread's child is followed; the process ends with its last thread, and the status is
// unknown when the codes disagree: wait(2) reports 3 after exit_group(3) and the main thread's 0 after the thread's own
// exit(3), and the events cannot tell which.
func TestAnAgentWhoseMainThreadExitsRunsOnInItsSession(t *testing.T) {
	fp, o := newFake(), &out{}
	twoThreadAgent(fp)
	w := newWatcher(fp, o, true)
	startTwoThreads(t, w)
	handle(t, w, evExit(500, 0))
	if o.find(EventAgentExited, 500) != nil || w.Sessions() != 1 {
		t.Fatalf("the main thread's exit was taken for the process's: sightings %v, %d session(s)", o.kinds(), w.Sessions())
	}
	fp.add(502, fproc{ppid: 500, comm: "sleep", exe: "/usr/bin/sleep", argv: []string{"sleep", "60"}})
	handle(t, w, evFork(500, 502))
	if o.find(EventChildForked, 502) == nil {
		t.Fatalf("a child the agent's thread forked was not followed: %v", o.kinds())
	}
	handle(t, w, threadExit(5001, 500, 3<<8))
	x := o.find(EventAgentExited, 500)
	if x == nil || x.ExitCode != nil || x.Note == "" || x.StillRunning != 1 {
		t.Fatalf("agent_exited = %+v; want one with no status, a note, and the child still running", x)
	}
	if w.Sessions() != 1 {
		t.Fatal("the session ended while the child runs")
	}
}

// TestAThreadThatRunsAProgramAfterItsLeaderWentFirstEndsWithIt: the agent's main thread exits, then its thread
// execs, which makes that thread the leader under the agent's pid (de_thread). Its exit ends the process with its own
// code; it is not a later process's second leader exit. A non-leader exec of a live process (Go's syscall.Exec from
// another thread) goes the same way: the old leader's exit event comes first, while the exec'ing thread runs.
func TestAThreadThatRunsAProgramAfterItsLeaderWentFirstEndsWithIt(t *testing.T) {
	fp, o := newFake(), &out{}
	twoThreadAgent(fp)
	w := newWatcher(fp, o, false)
	startTwoThreads(t, w)
	handle(t, w, evExit(500, 0))
	fp.del(5001)
	fp.procs[500].state, fp.procs[500].threads = 'S', 1 // the thread took the leader's pid
	handle(t, w, evExec(500), evExit(500, 4<<8))
	x := o.find(EventAgentExited, 500)
	if x == nil || x.ExitCode == nil || *x.ExitCode != 4 || w.Sessions() != 0 {
		t.Fatalf("agent_exited = %+v, %d session(s); want code 4 and none", x, w.Sessions())
	}
}

// TestAProcessWhoseTasksAreAllZombiesHasEnded: a traced process's exited threads stay zombies until its tracer reaps
// them, so its stat goes on counting them; its last task's exit event ends it all the same.
func TestAProcessWhoseTasksAreAllZombiesHasEnded(t *testing.T) {
	fp, o := newFake(), &out{}
	twoThreadAgent(fp)
	w := newWatcher(fp, o, false)
	startTwoThreads(t, w)
	handle(t, w, evExit(500, 0))
	fp.procs[5001].state = 'Z' // exited, not reaped
	must(t, w.Handle(threadExit(5001, 500, 0)))
	if x := o.find(EventAgentExited, 500); x == nil || w.Sessions() != 0 {
		t.Fatalf("sightings %v, %d session(s); want the agent ended", o.kinds(), w.Sessions())
	}
}

// TestWhatAnEndNeedsIsForgottenWithItsProcess: the exits kept of a process whose leader went first are dropped when a
// scan finds the process gone (its end's event was lost), so nothing is kept of a process no session follows.
func TestWhatAnEndNeedsIsForgottenWithItsProcess(t *testing.T) {
	fp, o := newFake(), &out{}
	twoThreadAgent(fp)
	w := newWatcher(fp, o, false)
	startTwoThreads(t, w)
	handle(t, w, evExit(500, 0))
	if len(w.groups) != 1 {
		t.Fatalf("groups = %v, want the leader's exit of 500 kept", w.groups)
	}
	fp.del(5001)
	fp.del(500)
	must(t, w.Overrun())
	if len(w.groups) != 0 || o.find(EventAgentExited, 500) == nil {
		t.Fatalf("after a scan found 500 gone: groups %v, sightings %v", w.groups, o.kinds())
	}
}

// tapped records what a Tap is told.
type tapped struct {
	evs  []procconn.Event
	lost int
}

func (t *tapped) Event(ev procconn.Event) { t.evs = append(t.evs, ev) }
func (t *tapped) Lost()                   { t.lost++ }

// TestTheTapIsToldEveryEventAndEveryLoss: the guard reads its adoptions' ends from the watcher's Tap, so the Tap is told
// every event the watcher handles, of any process, and every loss.
func TestTheTapIsToldEveryEventAndEveryLoss(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	tap := &tapped{}
	w := New(fp, Options{Rules: sig.Default(), Emit: o.emit, Tap: tap})
	evs := []procconn.Event{evExec(500), evFork(1, 900), threadExit(901, 900, 0), evExit(900, 0)}
	for i := range evs {
		evs[i].TimestampNS = procconn.Monotonic()
	}
	handle(t, w, evs...)
	must(t, w.Overrun())
	if len(tap.evs) != len(evs) || tap.lost != 1 {
		t.Fatalf("the tap was told %d event(s) and %d loss(es), want %d and 1", len(tap.evs), tap.lost, len(evs))
	}
	for i := range evs {
		if tap.evs[i] != evs[i] {
			t.Errorf("event %d: %+v, want %+v", i, tap.evs[i], evs[i])
		}
	}
}

// TestALeaderThatWentFirstGivesOnlyAStatusTheCodesAgreeOn: the main thread's exit(0), then the last thread's exit(0),
// is status 0 (no group exit, or one with code 0). A signal that ends the rest is no proof of a group exit (a task
// can be killed alone), so with the main thread's 0 it leaves the status unknown.
func TestALeaderThatWentFirstGivesOnlyAStatusTheCodesAgreeOn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		last  uint32
		known bool
	}{
		{"exit(0) of the last thread", 0, true},
		{"SIGTERM", 15, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, o := newFake(), &out{}
			twoThreadAgent(fp)
			w := newWatcher(fp, o, false)
			startTwoThreads(t, w)
			handle(t, w, evExit(500, 0), threadExit(5001, 500, tc.last))
			x := o.find(EventAgentExited, 500)
			if x == nil || (x.ExitCode != nil) != tc.known || tc.known && (*x.ExitCode != 0 || x.Signal != 0) ||
				!tc.known && x.Note == "" {
				t.Fatalf("agent_exited = %+v, want the status known %v (code 0)", x, tc.known)
			}
		})
	}
}

// TestTheScanListsTheThreadsTheEventsDidNotSay: the end is told by the events from the tasks a process had when it was
// followed, so a scan lists them: of an agent it finds running, and, after the kernel dropped events, of each process
// it follows (a thread whose fork was dropped would otherwise leave the main thread's exit taken for the end). While
// the main thread runs at the scan, what was dropped says nothing of the status.
func TestTheScanListsTheThreadsTheEventsDidNotSay(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprintf("after lost events %v", lost), func(t *testing.T) {
			fp, o := newFake(), &out{}
			twoThreadAgent(fp)
			w := newWatcher(fp, o, false)
			if lost {
				handle(t, w, evExec(500)) // the thread's fork is among the dropped events
				must(t, w.Overrun())
			} else {
				must(t, w.rescan(false))
			}
			handle(t, w, evExit(500, 0))
			if o.find(EventAgentExited, 500) != nil {
				t.Fatalf("the main thread's exit ended an agent whose thread runs: %v", o.kinds())
			}
			handle(t, w, threadExit(5001, 500, 0))
			x := o.find(EventAgentExited, 500)
			if x == nil || x.ExitCode == nil || *x.ExitCode != 0 || w.Sessions() != 0 || len(w.groups) != 0 {
				t.Fatalf("agent_exited = %+v, %d session(s), groups %v; want code 0 and nothing left", x, w.Sessions(),
					w.groups)
			}
		})
	}
}

// TestAProcessThatEndsDuringAScanIsEndedByItsExit: a scan lists the tasks of what it follows after reading /proc once,
// so a process can end between the two reads. One the scan found then has no task listed and is reported ended there,
// with no status (its listing is its lower bound, and none of its exits is filled after it); one
// followed from its events before the scan is not listed again, so its exit gives its status. Either way no session is
// left.
func TestAProcessThatEndsDuringAScanIsEndedByItsExit(t *testing.T) {
	for _, followed := range []bool{false, true} {
		t.Run(fmt.Sprintf("followed before the scan %v", followed), func(t *testing.T) {
			fp, o := newFake(), &out{}
			fp.add(500, claudeProc(400, termCG, ""))
			w := newWatcher(fp, o, false)
			if followed {
				handle(t, w, evExec(500))
			}
			fp.onTasks = func(pid int) {
				if pid == 500 {
					fp.del(500) // it exits after the scan's read of /proc, before its tasks are listed
				}
			}
			must(t, w.rescan(false))
			fp.onTasks = nil
			if want := map[bool]int{false: 0, true: 1}[followed]; w.Sessions() != want {
				t.Fatalf("%d session(s) after the scan, want %d: %v", w.Sessions(), want, o.kinds())
			}
			handle(t, w, evExit(500, 3<<8))
			x := o.find(EventAgentExited, 500)
			if x == nil || w.Sessions() != 0 || len(w.groups) != 0 {
				t.Fatalf("agent_exited = %+v, %d session(s), groups %v; want it ended and nothing left", x, w.Sessions(),
					w.groups)
			}
			switch {
			case followed && (x.ExitCode == nil || *x.ExitCode != 3):
				t.Fatalf("agent_exited = %+v, want code 3 (its events were followed from its exec)", x)
			case !followed && (x.ExitCode != nil || x.Signal != 0 || !strings.Contains(x.Note, "listed")):
				t.Fatalf("agent_exited = %+v, want no status and a note that its tasks were listed after it ended", x)
			}
		})
	}
}
