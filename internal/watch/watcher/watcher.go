// SPDX-License-Identifier: Apache-2.0

// Package watcher recognises agent processes as they start and reports them (docs/poc/agent-watcher.md, M2,
// detection only). It reads the proc connector's fork, exec and exit events (internal/watch/procconn), asks
// /proc what each new program is, applies a list of signatures (internal/watch/sig), follows a recognised agent's
// descendants (internal/watch/tree), and writes one sighting per fact: an agent started, whether it started
// inside a tego run, an agent exited.
//
// It only OBSERVES. It never signals, moves, blocks, traces or alters a process, writes nothing to /proc or to a
// cgroup, and opens nothing of the agent's but files under /proc/<pid>/ for reading. Governing an agent it found
// is a later package; this one tells the operator that one is running.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"github.com/attention-span-ai/tego/internal/watch/tree"
)

// Source is where events come from: a *procconn.Listener, or a stand-in in a test.
type Source interface {
	Recv() ([]procconn.Event, error)
	Close() error
}

// drainer is a Source that can hand over, without blocking, the events it still holds (*procconn.Listener does).
type drainer interface {
	Drain() ([]procconn.Event, error)
}

// Options configure a Watcher.
type Options struct {
	Rules sig.List
	Emit  Emit
	// Children also reports each followed descendant's fork, exec and exit. Off, a session is one agent_started
	// line and one agent_exited line, with the descendants counted.
	Children bool
	Limits   tree.Limits
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Tap, when set, is told each event before the watcher applies it, and each loss of events the kernel reports
	// before the scan that follows it, on the watcher's goroutine (the guard reads its adopted agents' ends from it).
	Tap Tap
}

// Tap sees what the watcher reads from its Source. Its methods run on the watcher's goroutine and must not block.
type Tap interface {
	Event(procconn.Event)
	Lost()
}

// Stats counts what the watcher did, for the tests and for a summary at the end of a run.
type Stats struct {
	Events    int // proc-connector events handled
	Matched   int // agents recognised
	Skipped   int // exec events whose process was gone or changed before /proc could be read
	Overruns  int // times the kernel reported lost events
	Rescans   int // /proc scans (one at the start, one per overrun)
	Dropped   int // sessions given up under the caps
	Untracked int // children not followed because a session filled the process cap
}

// Watcher is the state of one watch. It is not safe for concurrent use: Run drives it from one goroutine.
type Watcher struct {
	p      Proc
	opt    Options
	tr     *tree.Tree
	st     Stats
	needID bool // some rule needs the executable's file identity
	// groups are what the events said so far of each followed process (procconn.Group), from the fork or the exec it
	// was first followed at, or from the listing a scan made of it, which give each its lower bound.
	groups map[int32]*procconn.Group
}

// agent is what the tree's Meta holds for a session.
type agent struct {
	rule string
	exe  string
	argv []string
	comm string
}

// New is a watcher over p.
func New(p Proc, opt Options) *Watcher {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Emit == nil {
		opt.Emit = func(Sighting) error { return nil }
	}
	w := &Watcher{p: p, opt: opt, tr: tree.New(opt.Limits), groups: map[int32]*procconn.Group{}}
	for _, r := range opt.Rules {
		if r.File != (sig.FileID{}) {
			w.needID = true
		}
	}
	return w
}

// Stats is the counters so far.
func (w *Watcher) Stats() Stats { return w.st }

// Run reads src until ctx ends or src fails, and closes src on the way out. It first scans /proc for agents that
// are already running (the listener is open by then, so nothing started during the scan is missed: an event that
// repeats what the scan found changes nothing). A source that reports lost events (procconn.IsOverrun) makes it
// scan again. It returns nil when ctx ends, and the first error otherwise.
func (w *Watcher) Run(ctx context.Context, src Source) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = src.Close()
		case <-stop:
		}
	}()
	defer func() { _ = src.Close() }()
	if err := w.rescan(false); err != nil {
		return err
	}
	for {
		evs, err := src.Recv()
		switch {
		case err == nil:
			for _, ev := range evs {
				if err := w.Handle(ev); err != nil {
					return err
				}
			}
		case ctx.Err() != nil || errors.Is(err, procconn.ErrClosed):
			return nil
		case procconn.IsOverrun(err):
			// Read what survived first, then look at /proc: the scan is then newer than every event still to come.
			if d, ok := src.(drainer); ok {
				evs, derr := d.Drain()
				for _, ev := range evs {
					if err := w.Handle(ev); err != nil {
						return err
					}
				}
				if errors.Is(derr, procconn.ErrClosed) {
					return nil
				}
				if derr != nil {
					return derr
				}
			}
			if err := w.Overrun(); err != nil {
				return err
			}
		default:
			return err
		}
	}
}

// Overrun is what a source's lost events call for: count it, say so, scan /proc again.
func (w *Watcher) Overrun() error {
	if w.opt.Tap != nil {
		w.opt.Tap.Lost()
	}
	w.st.Overruns++
	return w.rescan(true)
}

// Scan reads /proc for agents that are already running, and reconciles what the watcher follows with it.
func (w *Watcher) Scan() error { return w.rescan(false) }

func (w *Watcher) say(s Sighting) error {
	s.Time = w.opt.Now().UTC().Format(time.RFC3339Nano)
	return w.opt.Emit(s)
}

// Handle applies one proc-connector event.
func (w *Watcher) Handle(ev procconn.Event) error {
	if w.opt.Tap != nil {
		w.opt.Tap.Event(ev)
	}
	w.st.Events++
	switch ev.Kind {
	case procconn.Fork:
		return w.onFork(ev)
	case procconn.Exec:
		return w.onExec(ev)
	case procconn.Exit:
		return w.onExit(ev)
	}
	return nil
}

func (w *Watcher) onFork(ev procconn.Event) error {
	if ev.PID != ev.TGID {
		// A new thread, not a new process: of a followed one, it runs until its own exit event (procconn.Group).
		if g := w.groups[ev.TGID]; g != nil {
			g.Fork(ev)
		}
		return nil
	}
	if g := w.groups[ev.ParentTGID]; g != nil {
		g.Fork(ev) // the parent ran when it forked: what its tasks' exits filled before say (procconn.Group)
	}
	// A parent the tree does not follow is none of our business, and costs no read.
	if w.tr.Owner(ev.ParentTGID) == nil {
		return nil
	}
	e := tree.Entry{TGID: ev.TGID, PPID: ev.ParentTGID, Start: w.startOf(ev.TGID)}
	s, res, dropped := w.tr.Fork(ev.ParentTGID, e)
	if err := w.sayDrops(dropped); err != nil {
		return err
	}
	switch res {
	case tree.NotFollowed, tree.Duplicate:
		return nil
	case tree.Full:
		w.st.Untracked++
		return w.say(Sighting{Event: EventUntracked, Session: s.ID, PID: ev.TGID, PPID: ev.ParentTGID, Untracked: s.Untracked,
			Note: "this session fills the process cap; its children are no longer followed"})
	case tree.Added:
	}
	w.groups[ev.TGID] = procconn.NewGroupAt(ev.TGID, ev)
	if w.opt.Children {
		return w.say(Sighting{Event: EventChildForked, Session: s.ID, PID: ev.TGID, PPID: ev.ParentTGID})
	}
	return nil
}

func (w *Watcher) onExec(ev procconn.Event) error {
	if s := w.tr.Owner(ev.TGID); s != nil {
		// A followed process ran a program: already in its session. The task that ran it is its leader now and its only
		// task, so the exits read of it before say nothing of its end (procconn.Group.Exec). Say what it ran, when asked.
		if g := w.groups[ev.TGID]; g != nil {
			g.Exec(ev)
		}
		if !w.opt.Children || ev.TGID == s.Root.TGID {
			return nil
		}
		f, err := w.facts(int(ev.TGID))
		if err != nil {
			w.st.Skipped++
			return nil
		}
		argv, trunc := capArgv(f.Argv)
		return w.say(Sighting{Event: EventChildExec, Session: s.ID, PID: ev.TGID, PPID: f.ppid, Exe: f.Exe, Argv: argv, ArgvTruncated: trunc, Comm: f.Comm})
	}
	f, err := w.facts(int(ev.TGID))
	if err != nil {
		w.st.Skipped++
		return nil
	}
	if err := w.consider(f, SeenExec); err != nil {
		return err
	}
	if _, kept := w.groups[ev.TGID]; !kept && w.tr.Owner(ev.TGID) != nil {
		// Followed from this exec: it is the lower bound, so a zapped main thread's exit filled before it and read
		// after it says nothing.
		w.groups[ev.TGID] = procconn.NewGroupAt(ev.TGID, ev)
	}
	return nil
}

// facts are what /proc says about a process, before it is matched. via and tid are where the rest of its files are
// read: the process itself, or, for one whose leader exited, a live thread of it under /proc/<pid>/task.
type facts struct {
	sig.Facts
	pid   int
	ppid  int32
	start uint64
	via   Proc
	tid   int
}

// facts reads the process the way a signature needs it, and refuses a read that a changing process could have
// torn: the start time is read before and after the other files, and a process that is gone, a zombie whose group
// has ended, a kernel thread (no exe), or one whose start time moved (the pid was reused mid-read) is an error the
// caller skips. A process whose leader exited while other threads of it run reads as a zombie whose program,
// arguments and environment are gone from /proc/<pid>; it is alive and runs its program, so it is read through one of
// those threads (liveThread), which must still be the same task once the reads are done (the guard never saw an
// agent whose main thread had exited before it looked).
func (w *Watcher) facts(pid int) (facts, error) {
	st1, err := w.p.Stat(pid)
	if err != nil {
		return facts{}, err
	}
	if st1.Gone() {
		return facts{}, proc.ErrGone
	}
	via, tid, viaStart := w.p, pid, st1.StartTicks
	if st1.State == 'Z' {
		if via, tid, viaStart, err = liveThread(w.p, pid); err != nil {
			return facts{}, err
		}
	}
	exe, err := via.Exe(tid)
	if err != nil {
		return facts{}, err
	}
	if exe == "" {
		return facts{}, fmt.Errorf("pid %d: no executable (a kernel thread)", pid)
	}
	argv, err := via.Argv(tid)
	if err != nil {
		return facts{}, err
	}
	f := facts{Facts: sig.Facts{Exe: exe, Argv: argv, Comm: st1.Comm}, pid: pid, ppid: int32(st1.PPID), start: st1.StartTicks,
		via: via, tid: tid}
	if w.needID {
		if f.File, err = via.ExeFile(tid); err != nil {
			f.File = sig.FileID{}
		}
	}
	st2, err := w.p.Stat(pid)
	if err != nil {
		return facts{}, err
	}
	if st2.StartTicks != st1.StartTicks {
		return facts{}, proc.ErrGone
	}
	if tid != pid {
		if ts, err := via.Stat(tid); err != nil || ts.StartTicks != viaStart {
			return facts{}, proc.ErrGone // the thread exited, and its id may name a new thread of the process
		}
	}
	return f, nil
}

// liveThread is a thread of process pid, other than its exited leader, that is neither dead nor a zombie: the Proc
// that reads it (pid's task directory, so it is of pid's thread group), its id and its start time. A process none of
// whose threads can be read so is gone.
func liveThread(p Proc, pid int) (Proc, int, uint64, error) {
	tasks, tids, err := p.Tasks(pid)
	if err != nil {
		return nil, 0, 0, err
	}
	for _, tid := range tids {
		if tid == pid {
			continue
		}
		if ts, err := tasks.Stat(tid); err == nil && ts.State != 'Z' && ts.State != 'X' {
			return tasks, tid, ts.StartTicks, nil
		}
	}
	return nil, 0, 0, fmt.Errorf("pid %d: %w (its leader exited and no thread of it could be read)", pid, proc.ErrGone)
}

// startOf is a process's start time, 0 when /proc cannot say (it already exited).
func (w *Watcher) startOf(tgid int32) uint64 {
	st, err := w.p.Stat(int(tgid))
	if err != nil {
		return 0
	}
	return st.StartTicks
}

// consider matches a process against the rules and, when one names it, starts a session and reports it.
func (w *Watcher) consider(f facts, seen string) error {
	rule, ok := w.opt.Rules.Match(f.Facts)
	if !ok {
		return nil
	}
	root := tree.Entry{TGID: int32(f.pid), PPID: f.ppid, Start: f.start}
	s, created, dropped := w.tr.Start(root, &agent{rule: rule.Name, exe: f.Exe, argv: f.Argv, comm: f.Comm})
	if err := w.sayDrops(dropped); err != nil {
		return err
	}
	if !created {
		return nil
	}
	w.st.Matched++
	envRun, _ := f.via.RunID(f.tid)
	cg, _ := f.via.Cgroup(f.tid)
	outside, cgRun, note := governance(envRun, cg)
	argv, trunc := capArgv(f.Argv)
	return w.say(Sighting{
		Event: EventAgentStarted, Session: s.ID, PID: root.TGID, PPID: root.PPID,
		Exe: f.Exe, Argv: argv, ArgvTruncated: trunc, Comm: f.Comm, Rule: rule.Name, Seen: seen,
		OutsideGovernedRun: &outside, RunID: envRun, RunCgroupID: cgRun, Cgroup: cg, Note: note, Start: f.start,
	})
}

// onExit applies the exit of a task of a followed process. The process ends with the exit of the last of its tasks
// the events say run (procconn.Group): its leader's in the usual case, its last thread's when the leader exited
// first. The events alone tell it, never /proc read when an event
// is handled: a zapped main thread's exit read late used to end an agent with code 0 whose exec'd program exited 3, an
// exec that failed after de_thread left its session open, and a thread's exit read once the process had gone ended it
// before its main thread's event, next in the socket, gave the status. A thread's exit of a process no session
// follows costs no read.
func (w *Watcher) onExit(ev procconn.Event) error {
	if w.tr.Owner(ev.TGID) == nil {
		return nil
	}
	if !w.group(ev.TGID).Exit(ev) {
		return nil
	}
	return w.ended(ev.TGID)
}

// ended reports the end of followed process tgid, whose group has ended, with the status its events say.
func (w *Watcher) ended(tgid int32) error {
	g := w.groups[tgid]
	delete(w.groups, tgid)
	res := w.tr.Exit(tgid)
	var code *int
	sigNo, note := 0, ""
	if raw, known := g.Status(); known {
		c, s := procconn.SplitStatus(raw)
		code, sigNo = &c, s
	} else {
		note = "the status is unknown: " + g.Why()
	}
	switch {
	case res.Root:
		return w.sayAgentExit(res.Session, code, sigNo, note)
	case w.opt.Children:
		return w.say(Sighting{Event: EventChildExited, Session: res.Session.ID, PID: tgid, ExitCode: code, Signal: sigNo, Note: note})
	}
	return nil
}

// group is what the events said of followed process tgid. Every way of following a process makes its group; one
// missing all the same is begun with no lower bound, which states no status.
func (w *Watcher) group(tgid int32) *procconn.Group {
	g := w.groups[tgid]
	if g == nil {
		g = procconn.NewGroup(tgid, procconn.Listing{Live: []int32{tgid}}, nil)
		w.groups[tgid] = g
	}
	return g
}

// relist lists, after a scan, the tasks of each process the scan newly follows (not in before, the processes followed
// when it began, in pid order), where its procconn.Group starts, and of every followed process after lost events
// (Group.Resync). A process whose listing finds nothing that runs has ended, and is reported so, its status unknown:
// it ended after the scan read /proc, so its exits were filled before the listing, which is its lower bound now, and
// none of them can end it later. Without lost events, a process followed before the scan is left as its events have
// it: it may have ended since the scan read /proc, and a listing would then lose what its events say of its status.
func (w *Watcher) relist(lost bool, before []int32) error {
	for _, tgid := range w.tr.Followed() {
		if _, old := slices.BinarySearch(before, tgid); old && !lost {
			continue
		}
		g, kept := w.groups[tgid]
		l := w.listTasks(tgid)
		if kept {
			g.Resync(l)
		} else {
			g = procconn.NewGroup(tgid, l, func() procconn.Listing { return w.listTasks(tgid) })
			w.groups[tgid] = g
		}
		if g.Ended() {
			if err := w.ended(tgid); err != nil {
				return err
			}
		}
	}
	return nil
}

// listTasks lists the tasks of process tgid for its group (procconn.List): none when its task list cannot be read (it
// has gone).
func (w *Watcher) listTasks(tgid int32) procconn.Listing {
	var tasks Proc
	enum := func() ([]int32, error) {
		p, tids, err := w.p.Tasks(int(tgid))
		tasks = p
		out := make([]int32, 0, len(tids))
		for _, tid := range tids {
			out = append(out, int32(tid))
		}
		return out, err
	}
	state := func(tid int32) procconn.TaskState {
		ts, err := tasks.Stat(int(tid))
		switch {
		case err != nil || ts.State == 'X':
			return procconn.TaskDying
		case ts.State == 'Z':
			return procconn.TaskZombie
		case ts.Exiting():
			return procconn.TaskExiting
		}
		return procconn.TaskRunning
	}
	return procconn.List(enum, state)
}

// forgetGroups drops what onExit kept of processes the tree no longer follows (a scan found them gone, or their session
// was dropped).
func (w *Watcher) forgetGroups() {
	for tgid := range w.groups {
		if w.tr.Owner(tgid) == nil {
			delete(w.groups, tgid)
		}
	}
}

func (w *Watcher) sayAgentExit(s *tree.Session, code *int, sigNo int, note string) error {
	a, _ := s.Meta.(*agent)
	out := Sighting{Event: EventAgentExited, Session: s.ID, PID: s.Root.TGID, ExitCode: code, Signal: sigNo,
		Descendants: s.Seen - 1, StillRunning: s.Members(), Untracked: s.Untracked, Note: note}
	if a != nil {
		out.Rule, out.Exe, out.Comm = a.rule, a.exe, a.comm
	}
	return w.say(out)
}

func (w *Watcher) sayDrops(ds []tree.Drop) error {
	if len(ds) > 0 {
		w.forgetGroups()
	}
	for _, d := range ds {
		w.st.Dropped++
		a, _ := d.Session.Meta.(*agent)
		s := Sighting{Event: EventSessionDrop, Session: d.Session.ID, PID: d.Session.Root.TGID, Dropped: d.Members, Reason: d.Reason,
			Note: "the watcher's bounds were reached; this agent's processes are no longer followed, and its exit will not be reported"}
		if a != nil {
			s.Rule, s.Exe = a.rule, a.exe
		}
		if err := w.say(s); err != nil {
			return err
		}
	}
	return nil
}

// snapshot is every live process as the tree wants it, from /proc. A process whose leader exited while other threads
// of it run reads as a zombie, but counts them in num_threads: it is alive, and its threads' children name it their
// parent, so it is kept; a zombie whose group has ended (one task, the leader) is not.
func (w *Watcher) snapshot() ([]tree.Entry, error) {
	pids, err := w.p.PIDs()
	if err != nil {
		return nil, err
	}
	out := make([]tree.Entry, 0, len(pids))
	for _, pid := range pids {
		st, err := w.p.Stat(pid)
		if err != nil || st.Gone() {
			continue
		}
		out = append(out, tree.Entry{TGID: int32(pid), PPID: int32(st.PPID), Start: st.StartTicks})
	}
	return out, nil
}

// rescan reads /proc once and reconciles: followed processes that are gone are ended, descendants that were
// missed are followed, and any running process a rule names that the watcher does not follow is reported as seen
// by scan. lost says the scan follows an overrun, so a line says events were lost.
func (w *Watcher) rescan(lost bool) (err error) {
	w.st.Rescans++
	before := w.tr.Followed()
	snap, err := w.snapshot()
	if err != nil {
		return fmt.Errorf("watcher: reading /proc: %w", err)
	}
	if lost {
		if err := w.say(Sighting{Event: EventResync, Note: "the kernel dropped process events (the proc connector's socket overflowed); /proc was read again to catch up"}); err != nil {
			return err
		}
	}
	if err := w.reconcile(snap); err != nil {
		return err
	}
	defer func() {
		if err == nil {
			err = w.relist(lost, before)
		}
	}()
	// Candidates: a process no session holds, read once. Oldest first, so a wrapper is met before what it ran
	// (a descendant of a matched agent then joins the session as a child, not as a second agent).
	sort.Slice(snap, func(i, j int) bool {
		if snap[i].Start != snap[j].Start {
			return snap[i].Start < snap[j].Start
		}
		return snap[i].TGID < snap[j].TGID
	})
	for _, e := range snap {
		if w.tr.Owner(e.TGID) != nil {
			continue
		}
		f, err := w.facts(int(e.TGID))
		if err != nil {
			if !errors.Is(err, proc.ErrGone) && !errors.Is(err, fs.ErrNotExist) {
				w.st.Skipped++
			}
			continue
		}
		if err := w.consider(f, SeenScan); err != nil {
			return err
		}
		// A scan that finds an agent finds its descendants too: they were alive, so they are in snap.
		if w.tr.Owner(e.TGID) != nil {
			if err := w.reconcile(snap); err != nil {
				return err
			}
		}
	}
	return nil
}

// reconcile is the tree's Resync against snap, and a line for each thing it changed.
func (w *Watcher) reconcile(snap []tree.Entry) error {
	r := w.tr.Resync(snap)
	if len(r.Exited) > 0 {
		w.forgetGroups()
	}
	if err := w.sayDrops(r.Dropped); err != nil {
		return err
	}
	for _, g := range r.Exited {
		switch {
		case g.Root:
			if err := w.sayAgentExit(g.Session, nil, 0, "found gone by a scan of /proc: the exit event was lost, so the status is unknown"); err != nil {
				return err
			}
		case w.opt.Children:
			if err := w.say(Sighting{Event: EventChildExited, Session: g.Session.ID, PID: g.TGID, Note: "found gone by a scan of /proc"}); err != nil {
				return err
			}
		}
	}
	if w.opt.Children {
		for _, f := range r.Added {
			if err := w.say(Sighting{Event: EventChildForked, Session: f.Session.ID, PID: f.Entry.TGID, PPID: f.Entry.PPID, Seen: SeenScan}); err != nil {
				return err
			}
		}
	}
	return nil
}
