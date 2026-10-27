// SPDX-License-Identifier: Apache-2.0

package procconn

// Group is what the events of one process have said of its end and its exit status. A process is a thread group, and
// the proc connector reports the fork of each of its threads and children, its execs, and the exit of each of its
// tasks, each exit with that task's own exit_code. Group is the one rule every reader of the events applies (the agent
// watcher, and the exit status an adoption's run_end carries). ADR 0055 (e) gives the kernel facts it rests on and the
// exhaustive model (model_test.go) that checks it against them.
//
// Every group has a lower bound, since: the timestamp of the fork or the exec it was first followed from, or a
// CLOCK_MONOTONIC reading taken before /proc listed the tasks of a process found running (Listing). An event filled
// before since never ends the group, never gives it a code and never adds a task to it. The kernel fills a task's exit
// event after exit_notify, so a task /proc listed running has its exit filled after the listing; an older exit is of a
// task that had already exited, such as a main thread an exec zapped, whose event names the leader's pid only when it
// was filled before de_thread swapped the tids, that is before the Exec event.
//
// The end is told by the events: Group keeps the set of the process's tasks that run, from what it was followed with,
// adds each thread a Fork event names, and takes out each task an Exit event names. The process ends at the exit that
// empties the set. An exec ends every other task and leaves the exec'ing one as the leader under the leader's pid
// (de_thread): an Exec event makes the leader alone the set and its timestamp the new since. An exec that fails after
// de_thread kills its task, now the leader, with no Exec event: a second exit of the leader's pid with no Fork of the pid
// read in between is that task's death, and of the two the later filled is the end. A process listed with its leader
// already exited may be in an exec whose de_thread has not swapped the tids yet, and one whose tasks kept changing
// under its listing may have been listed without a task that runs, so the exit that empties the set of either is
// checked with a fresh listing (the relist function its reader gives): a process that still runs is followed on from
// that listing.
//
// The status a waiter reads (wait_task_zombie) is signal->group_exit_code once SIGNAL_GROUP_EXIT is set, else the
// leader's own exit_code. The flag is set by the first group exit (exit_group(2), whose caller carries its code; a
// fatal signal or a core dump, whose tasks die with its code) and, from Linux 5.19, by the last task to enter do_exit
// when nothing set it before (synchronize_group_exit), with that task's code. exit_code is fixed when do_exit starts and
// the event is filled after exit_notify, so the order in which exits are read is not the order in which the tasks
// began to exit (a slow main thread's exit(0) read after a worker's exit_group(3), which wait(2) reports). So the
// status is known only when the leader's exit was read and every other
// task's exit read at or after since carries the same code (a dumped core's bit aside), whichever was read first. A
// task's code is left out only when a later fork of the process was filled after its exit: the forking task was then
// running, so that task neither entered do_exit last nor set a group exit the forking task did not die of. The leader's
// code is never left out: before 5.19 it is the status whenever no group exit happened.
//
// Everything else is unknown, with its reason (Why): a process whose leader's exit was not read, one whose listing found
// every task already exiting (its deciding exit may have been filled before since), one whose events the kernel dropped
// once its leader exited, and one with no lower bound. One case the events cannot tell: a fatal signal or another
// thread's exit_group arriving while a task is between its exit(2) syscall and do_exit's first lock, in which case the
// task's event carries its own code and wait(2) the signal's (the "racing exit" residual of ADR 0055 (e)).
type Group struct {
	tgid       int32
	since      uint64             // the lower bound; 0 none (Status unknown, nothing filtered)
	live       map[int32]struct{} // the tasks that run
	leader     uint32
	leaderSeen bool
	leaderAt   uint64  // the leader's exit's timestamp
	others     []coded // the exits of the other tasks of the set, read at or after since
	lifeAt     uint64  // the latest timestamp of a fork by the process at or after since
	core       uint32  // 0x80 once a code compared says a core was dumped
	lost       bool    // events may have been dropped once the leader exited (Resync)
	exiting    bool    // the listing found no task that ran outside do_exit
	leaderGone bool    // the listing found the leader exited: an emptied set is checked with a fresh listing
	unsure     bool    // the listing was unstable: an emptied set is checked with a fresh listing
	unlisted   bool    // the listing found no task that ran: it ended there
	relist     func() Listing
	ended      bool
}

// coded is one exit's code and timestamp.
type coded struct {
	code uint32
	at   uint64
}

// Listing is the tasks of a process /proc listed after the listener was subscribed (List).
type Listing struct {
	// Since is CLOCK_MONOTONIC in the kernel's own time (Monotonic), read before the tasks were listed; 0 when it could
	// not be read.
	Since uint64
	// Live is the tasks read running: neither dead nor zombies.
	Live []int32
	// Exiting reports that no task was read running outside do_exit (PF_EXITING), none running included.
	Exiting bool
	// Unstable reports a listing a task kept changing under (List's tries ran out): it may miss a task that runs.
	Unstable bool
}

// NewGroup is process tgid found running, as l lists it. relist lists it afresh; nil leaves an emptied set the end.
func NewGroup(tgid int32, l Listing, relist func() Listing) *Group {
	g := &Group{tgid: tgid, relist: relist}
	g.reset(l)
	g.confirmUnlisted(l)
	return g
}

// confirmUnlisted checks, with a fresh listing, an unstable listing that read no task running: an exec's de_thread can
// move the exec'ing thread to the leader's tid between List's reads of the two, so it was read at neither (the exhaustive
// model's three-task scenarios with a thread made during the run and a listing reader). A fresh listing with a task that
// runs follows the process on from it; otherwise it ended there, as a stable empty listing does.
func (g *Group) confirmUnlisted(l Listing) {
	if g.unlisted && l.Unstable {
		g.ended = false
		g.confirm()
	}
}

// NewGroupAt is process tgid followed from its fork or exec event ev: its leader alone, since ev's timestamp.
func NewGroupAt(tgid int32, ev Event) *Group {
	g := &Group{tgid: tgid}
	g.reset(Listing{Since: ev.TimestampNS, Live: []int32{tgid}})
	return g
}

// reset starts over from listing l: nothing read before it says anything.
func (g *Group) reset(l Listing) {
	g.since = l.Since
	g.live = make(map[int32]struct{}, len(l.Live))
	for _, tid := range l.Live {
		g.live[tid] = struct{}{}
	}
	_, leader := g.live[g.tgid]
	g.leaderGone = !leader && len(l.Live) > 0
	g.unsure = l.Unstable
	g.exiting = l.Exiting || l.Unstable
	g.leader, g.leaderSeen, g.leaderAt, g.others, g.lifeAt, g.core, g.lost = 0, false, 0, nil, 0, 0, false
	g.unlisted = len(l.Live) == 0
	if g.unlisted {
		g.ended = true // nothing of it ran when it was listed
	}
}

// Fork folds in a Fork event that names the process: a new thread of it (PID its own, TGID the process's), or a child
// it forked (ParentTGID the process's).
func (g *Group) Fork(ev Event) {
	if g.ended || before(ev, g.since) {
		return
	}
	g.lifeAt = max(g.lifeAt, ev.TimestampNS)
	if ev.TGID == g.tgid && ev.PID != ev.TGID {
		g.live[ev.PID] = struct{}{}
	}
}

// Exec folds in Exec event ev of the process: the task that ran the program is its leader now, and its only task.
func (g *Group) Exec(ev Event) {
	if g.ended || before(ev, g.since) {
		return // an exec the listing already saw the result of
	}
	g.reset(Listing{Since: ev.TimestampNS, Live: []int32{g.tgid}})
}

// Exit folds in one exit event of the process (ev.TGID is its). It reports whether this event ended it: its last task
// that ran exited.
func (g *Group) Exit(ev Event) bool {
	if g.ended || before(ev, g.since) {
		return false
	}
	_, member := g.live[ev.PID]
	if !member && ev.PID == g.tgid && g.leaderGone {
		// The leader was listed exited: this is its own exit filled after the listing, or the death, under the leader's
		// pid, of a listed thread whose exec swapped the tids and then failed (no Exec event). A fresh listing tells.
		return g.confirm()
	}
	if !member && ev.PID == g.tgid && g.leaderSeen {
		// The leader's pid exits again: an exec made a thread the leader (de_thread) and then failed, with no Exec event.
		// The two exits are the zapped leader's and that task's death, and the later filled is the death.
		if before(ev, g.leaderAt) {
			// The zapped leader's, read after the death: the process ended there, with the death's code.
			code, at, lost := g.leader, g.leaderAt, g.lost
			g.reset(Listing{Since: g.since, Live: nil})
			g.leader, g.leaderSeen, g.leaderAt, g.lost, g.core, g.unlisted = code, true, at, lost, code&0x80, false
			return true
		}
		lost := g.lost
		g.reset(Listing{Since: g.since, Live: []int32{g.tgid}})
		g.lost = lost
		member = true
	}
	if !member {
		return false
	}
	delete(g.live, ev.PID)
	if ev.PID == g.tgid {
		g.leader, g.leaderSeen, g.leaderAt = ev.ExitCode, true, ev.TimestampNS
	} else {
		g.others = append(g.others, coded{ev.ExitCode, ev.TimestampNS})
	}
	if len(g.live) > 0 {
		return false
	}
	if g.leaderGone || g.unsure {
		return g.confirm()
	}
	g.ended = true
	return true
}

// confirm decides, for a process listed with its leader exited, whether an exit that would end it by its events did:
// a fresh listing with a task that runs says an exec swapped the tids meanwhile, and the process is followed on from
// that listing. Without a relist function the exit ends it.
func (g *Group) confirm() bool {
	if g.relist != nil {
		if l := g.relist(); len(l.Live) > 0 {
			g.reset(l)
			return false
		}
	}
	g.ended = true
	return true
}

// Resync is, after the kernel dropped events, the tasks of the process as /proc lists them now (read after the events
// that survived). While the leader runs, nothing dropped says anything of the status; once it has exited, a code
// dropped may have been another one, and the status is unknown.
func (g *Group) Resync(l Listing) {
	if g.ended {
		return
	}
	g.reset(l)
	g.confirmUnlisted(l)
	if _, leaderRuns := g.live[g.tgid]; !leaderRuns {
		g.lost = true
	}
}

// before reports whether ev was filled before timestamp at, both known (an event's timestamp is CLOCK_MONOTONIC's,
// read as the kernel fills it, before it reads the task's pid).
func before(ev Event, at uint64) bool { return ev.TimestampNS != 0 && ev.TimestampNS < at }

// sameStatus reports whether two raw codes say the same status, the dumped-core bit of a signal's aside.
func sameStatus(a, b uint32) bool { return a&^0x80 == b&^0x80 }

// Ended reports whether an event folded in ended the process.
func (g *Group) Ended() bool { return g.ended }

// compared is whether the code of an exit at timestamp at is held to the leader's: no later fork of the process says
// its task exited while another of it ran on.
func (g *Group) compared(at uint64) bool { return g.lifeAt == 0 || at == 0 || at >= g.lifeAt }

// Status is the process's exit status as a raw wait status (Event.ExitCode's form), known false when it has not
// ended or the events folded in do not say it (see Group).
func (g *Group) Status() (raw uint32, known bool) {
	if g.Why() != "" {
		return 0, false
	}
	raw, core := g.leader, g.leader&0x80
	for _, o := range g.others {
		if g.compared(o.at) {
			core |= o.code & 0x80
		}
	}
	if raw&0x7f != 0 {
		raw |= core
	}
	return raw, true
}

// Why is, for a status Status does not know, the reason in a sentence; "" when it is known.
func (g *Group) Why() string {
	switch {
	case !g.ended:
		return "the process has not been seen to end"
	case g.since == 0:
		return "no lower bound could be read for its events (CLOCK_MONOTONIC or the time namespace's offset), so the " +
			"exits read of it may be older than its listing"
	case g.lost:
		return "the kernel dropped process events after its main thread exited, and a code among them may differ"
	case g.unlisted:
		return "no task of it ran when its tasks were listed, after it was found, so no exit of it was read"
	case g.exiting:
		return "every task of it was already exiting when its tasks were listed, after it was found, and the exit " +
			"that decided its status may have been filled before"
	case !g.leaderSeen:
		return "its main thread had exited before the process was followed, and that thread's exit carries the status " +
			"wait(2) reports unless a group exit or, from Linux 5.19, another task's later exit decided it"
	}
	for _, o := range g.others {
		if g.compared(o.at) && !sameStatus(o.code, g.leader) {
			return "its tasks' exits carry different codes: wait(2) reports a group exit's code (exit_group(2), a " +
				"fatal signal), or else the leader's own before Linux 5.19 and the last task to begin exiting's from it, " +
				"and the order in which the kernel's events are read does not say which task began to exit last"
		}
	}
	return ""
}

// SplitStatus splits a raw wait status (a task's exit_code, Event.ExitCode): the signal that ended it in the low 7 bits,
// else the exit code in the next 8.
func SplitStatus(raw uint32) (code, signal int) {
	if s := int(raw & 0x7f); s != 0 {
		return 0, s
	}
	return int(raw>>8) & 0xff, 0
}
