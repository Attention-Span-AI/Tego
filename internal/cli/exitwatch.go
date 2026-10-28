// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
)

// exitWatch is an adopted root process's exit status as the kernel's process events (the proc connector) report it:
// tego is not the agent's parent and cannot wait for it. The end and the status are procconn.Group's, the one rule
// the agent watcher applies too: the root's tasks are listed once the listener is subscribed, after a CLOCK_MONOTONIC
// reading that is the group's lower bound (an exit filled before it says nothing), the
// events follow its threads from there, the end is the exit of the last of them, and the status is known only where
// every compared code agrees with the main thread's, whichever was read first (c6-1, s6-2).
//
// It stops at a fork that names the pid again (a later process: the kernel reports a fork before the child runs), and
// at lost events once the root has ended or is gone (its end may have been among them); lost events while the root runs
// make it list the root's tasks again (procconn.Group.Resync). A root gone before the listener was subscribed, a
// connector that cannot be opened, or an end that may have been lost leaves the status unknown, which run_end then says.
type exitWatch struct {
	p     adopt.Proc
	id    adopt.Identity
	close func()

	mu   sync.Mutex
	g    *procconn.Group
	over bool // nothing more of the root's is folded in
}

// newExitWatch is a watch of id's exit, to be fed the events read from the moment it is made, under a listener
// subscribed before: it lists id's tasks that run now.
func newExitWatch(p adopt.Proc, id adopt.Identity) *exitWatch {
	w := &exitWatch{p: p, id: id, close: func() {}}
	w.g = procconn.NewGroup(int32(id.PID), adopt.ListTasks(p, id), func() procconn.Listing { return adopt.ListTasks(p, id) })
	w.over = w.g.Ended() // it ended before the listener was subscribed: its exit was not seen
	return w
}

// watchExit starts listening for id's exit on a listener of its own (tego adopt). Only events read once the listener
// is subscribed and id's tasks are then listed are the root's.
func watchExit(p adopt.Proc, id adopt.Identity) *exitWatch {
	src, err := agentsOpen()
	if err != nil {
		return &exitWatch{p: p, id: id, close: func() {}, g: procconn.NewGroup(int32(id.PID), procconn.Listing{}, nil),
			over: true}
	}
	w := newExitWatch(p, id)
	w.close = func() { _ = src.Close() }
	if w.over {
		return w
	}
	go func() {
		for {
			evs, err := src.Recv()
			w.feed(evs)
			switch {
			case err == nil:
			case procconn.IsOverrun(err):
				w.Lost()
			default:
				return
			}
		}
	}()
	return w
}

// feed folds in one batch the connector's Recv returned, as one step: the status is never asked between two events
// of it.
func (w *exitWatch) feed(evs []procconn.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ev := range evs {
		w.event(ev)
	}
}

// Event folds in one event (the guard's watcher hands them over one by one).
func (w *exitWatch) Event(ev procconn.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.event(ev)
}

func (w *exitWatch) event(ev procconn.Event) {
	if w.over {
		return
	}
	if ev.Kind == procconn.Fork && int(ev.ParentTGID) == w.id.PID && ev.PID == ev.TGID {
		w.g.Fork(ev) // a child of the root: the root ran when it forked
	}
	if int(ev.TGID) != w.id.PID {
		return
	}
	switch {
	case ev.Kind == procconn.Fork && ev.PID == ev.TGID:
		w.over = true // a new process has the pid
	case ev.Kind == procconn.Fork:
		w.g.Fork(ev)
	case ev.Kind == procconn.Exec:
		w.g.Exec(ev)
	case ev.Kind == procconn.Exit:
		w.g.Exit(ev)
	}
}

// Lost is the kernel's report that it dropped events.
func (w *exitWatch) Lost() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.over {
		return
	}
	l := adopt.ListTasks(w.p, w.id)
	if w.g.Ended() || len(l.Live) == 0 {
		w.over = true
		return
	}
	w.g.Resync(l)
}

// status is the exit status, ok false when it is not known: the root's end was not read within exitStatusWait (the
// kernel sends a task's exit event a little after the cgroup's emptying that ended the run), or its tasks' codes do not
// say.
func (w *exitWatch) status() (code, signal int, ok bool) {
	for deadline := time.Now().Add(exitStatusWait); ; time.Sleep(10 * time.Millisecond) {
		w.mu.Lock()
		raw, known := w.g.Status()
		settled := w.g.Ended() || w.over
		w.mu.Unlock()
		if settled || time.Now().After(deadline) {
			if !known {
				return 0, 0, false
			}
			code, signal = procconn.SplitStatus(raw)
			return code, signal, true
		}
	}
}

// stop stops listening.
func (w *exitWatch) stop() { w.close() }
