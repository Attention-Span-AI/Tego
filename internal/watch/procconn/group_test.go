// SPDX-License-Identifier: Apache-2.0

package procconn

import (
	"strings"
	"testing"
)

// TestGroupEndsWithItsLastTaskAndSaysOnlyAStatusTheEventsAgreeOn: the end of a process is the exit of the last of its
// tasks the events say run, told by events filled at or after its lower bound, and its status is the one every
// compared code agrees on, whichever was read first. The rows are the kernel's own
// sequences for each shape; a row's events are stamped in the order read unless it says otherwise (at).
func TestGroupEndsWithItsLastTaskAndSaysOnlyAStatusTheEventsAgreeOn(t *testing.T) {
	const tgid = 500
	leader := func(code uint32) Event { return Event{Kind: Exit, PID: tgid, TGID: tgid, ExitCode: code} }
	thread := func(tid int32, code uint32) Event { return Event{Kind: Exit, PID: tid, TGID: tgid, ExitCode: code} }
	clone := func(tid int32) Event { return Event{Kind: Fork, PID: tid, TGID: tgid, ParentTGID: 1} }
	child := Event{Kind: Fork, PID: 900, TGID: 900, ParentTGID: tgid}
	execd := Event{Kind: Exec, PID: tgid, TGID: tgid}
	at := func(ev Event, ns uint64) Event { ev.TimestampNS = ns; return ev }
	fork := (*Listing)(nil)
	listed := func(since uint64, live ...int32) *Listing { return &Listing{Since: since, Live: live} }
	for _, tc := range []struct {
		name   string
		from   *Listing // nil: followed from its fork at timestamp 1
		relist *Listing // a fresh listing's answer, where the group asks for one
		evs    []Event
		endAt  int // index of the event that ends it, -1 none, -2 ended by its listing
		raw    uint32
		known  bool
	}{
		{"a single-threaded exit(3)", fork, nil, []Event{leader(3 << 8)}, 0, 3 << 8, true},
		{"killed by SIGKILL", fork, nil, []Event{clone(501), thread(501, 9), leader(9)}, 2, 9, true},
		{"exit_group(3) from the leader, a thread's event read after it", fork, nil, []Event{clone(501), clone(502),
			thread(501, 3<<8), leader(3 << 8), thread(502, 3<<8)}, 4, 3 << 8, true},
		{"workers that left on their own before the leader's exit_group(2): a slow exit(2) of the leader and a worker's " +
			"later exit(7) give the same events, and wait(2) the 7 from 5.19 (c6-1)", fork, nil, []Event{clone(501),
			clone(502), thread(501, 0), thread(502, 7<<8), leader(2 << 8)}, 4, 0, false},
		{"the same with a fork after the workers' exits: they left while the process ran on", fork, nil, []Event{
			clone(501), clone(502), thread(501, 0), thread(502, 7<<8), child, leader(2 << 8)}, 5, 2 << 8, true},
		{"a fork filled before a worker's exit is no proof", fork, nil, []Event{clone(501), child, thread(501, 3<<8),
			leader(0)}, 3, 0, false},
		{"a worker's exit_group(3) read before the slow leader's own exit(0) (c6-1, s6-2)", fork, nil, []Event{
			clone(501), thread(501, 3<<8), leader(0)}, 2, 0, false},
		{"the leader killed alone by SIGSYS and slow, the rest's exit_group(0) read first (c6-1's c5-1 order)", fork, nil,
			[]Event{clone(501), thread(501, 0), leader(31)}, 2, 0, false},
		{"exit_group(3) from a thread, its event first and the leader's next (c5-2)", fork, nil, []Event{clone(501),
			thread(501, 3<<8), leader(3 << 8)}, 2, 3 << 8, true},
		{"the leader's exit while a thread runs is not the end", fork, nil, []Event{clone(501), leader(0)}, -1, 0, false},
		{"the leader went first, the last thread's exit(0)", fork, nil, []Event{clone(501), leader(0), thread(501, 0)}, 2,
			0, true},
		{"the leader went first, the group then ended with exit_group(3) or a thread's exit(3): unknown", fork, nil,
			[]Event{clone(501), leader(0), thread(501, 3<<8)}, 2, 0, false},
		{"the leader killed alone by SIGSYS, the rest then exit_group(0) (c5-1)", listed(1, tgid, 501, 502), nil,
			[]Event{leader(31), thread(501, 0), thread(502, 0)}, 2, 0, false},
		{"a thread killed alone by SIGSYS before the leader's exit_group(0)", fork, nil, []Event{clone(501), clone(502),
			thread(501, 31), leader(0), thread(502, 0)}, 4, 0, false},
		{"a core dump by a thread: its code says so", fork, nil, []Event{clone(501), leader(11), thread(501, 0x80|11)},
			2, 0x80 | 11, true},
		{"found with its leader gone: the last thread's exit ends it, unknown", listed(1, 501), nil, []Event{
			thread(501, 3<<8)}, 0, 0, false},
		{"found with its leader gone, the emptied set while an exec swapped the tids: followed on from a fresh listing",
			listed(50, 501), listed(70, tgid), []Event{at(thread(501, 0), 60), at(execd, 65), at(leader(3<<8), 80)}, 2,
			3 << 8, true},
		{"a task that left before it was followed says nothing", listed(1, tgid), nil, []Event{thread(509, 7<<8),
			leader(0)}, 1, 0, true},
		{"two tasks after the leader with different codes", fork, nil, []Event{clone(501), clone(502), leader(0),
			thread(501, 0), thread(502, 4<<8)}, 4, 0, false},
		{"the leader went first, then its thread ran a program and so became the leader", fork, nil, []Event{clone(501),
			leader(0), execd, leader(4 << 8)}, 3, 4 << 8, true},
		{"a thread's exec zaps the live leader, then the program exits 3 (s5-1)", fork, nil, []Event{clone(501),
			leader(0), execd, leader(3 << 8)}, 3, 3 << 8, true},
		{"the same, the program killed by SIGSEGV (s5-1)", fork, nil, []Event{clone(501), leader(0), execd, leader(11)},
			3, 11, true},
		{"the zapped leader's event sent after the exec, under the exec'ing thread's old tid", fork, nil, []Event{
			clone(501), execd, thread(501, 0), leader(3 << 8)}, 3, 3 << 8, true},
		{"the zap's event under the old tid before the exec event", fork, nil, []Event{clone(501), thread(501, 0), execd,
			leader(3 << 8)}, 3, 3 << 8, true},
		{"an exec that fails after the zap: its task dies by SIGSEGV with no exec event (s5-2)", fork, nil, []Event{
			clone(501), leader(0), leader(11)}, 2, 11, true},
		{"the program's threads are followed after the exec", fork, nil, []Event{clone(501), leader(0), execd,
			clone(503), leader(0), thread(503, 0)}, 5, 0, true},
		{"the zapped leader's event filled before the exec, with the leader's pid, and sent after it", fork, nil,
			[]Event{at(clone(501), 10), at(execd, 30), at(leader(0), 20), at(leader(3<<8), 40)}, 3, 3 << 8, true},
		{"the same with the zapped thread's event too, both read after the exec", fork, nil, []Event{at(clone(501), 10),
			at(clone(502), 11), at(execd, 30), at(thread(502, 0), 21), at(leader(0), 20), at(leader(11), 40)}, 5, 11,
			true},
		{"an exec that fails after the zap, its death read before the zapped leader's event (s5-2)", fork, nil, []Event{
			at(clone(501), 10), at(leader(11), 30), at(leader(0), 20)}, 2, 11, true},
		{"the same in the order sent", fork, nil, []Event{at(clone(501), 10), at(leader(0), 20), at(leader(11), 30)}, 2,
			11, true},
		{"a session begun at an exec, the zapped leader's exit filled before it and read after (c6-2)",
			&Listing{Since: 100, Live: []int32{tgid}}, nil, []Event{at(leader(0), 90), at(leader(3<<8), 110)}, 1,
			3 << 8, true},
		{"a scan just after a worker's exec, the zapped leader's exit filled before its listing (s6-1)",
			listed(50, tgid), nil, []Event{at(leader(0), 40), at(leader(3<<8), 60)}, 1, 3 << 8, true},
		{"a thread's fork filled before the listing adds no task", listed(50, tgid), nil, []Event{at(clone(501), 40),
			at(leader(0), 60)}, 1, 0, true},
		{"listed with every task already exiting: unknown", &Listing{Since: 50, Live: []int32{tgid}, Exiting: true},
			nil, []Event{at(leader(3<<8), 60)}, 0, 0, false},
		{"no lower bound could be read: unknown", listed(0, tgid), nil, []Event{leader(3 << 8)}, 0, 0, false},
		{"listed with no task that ran: ended there, unknown", listed(50), nil, []Event{at(leader(3<<8), 60)}, -2, 0,
			false},
		{"an unstable listing that missed a thread: the emptied set is checked with a fresh listing",
			&Listing{Since: 50, Live: []int32{tgid}, Unstable: true}, listed(70, 502), []Event{at(leader(0), 60),
				at(thread(502, 0), 80)}, 1, 0, false},
		{"an unstable listing that read no task running (an exec's de_thread moved the thread to the leader's tid " +
			"between its reads) is checked with a fresh listing, and followed on from it",
			&Listing{Since: 50, Exiting: true, Unstable: true}, listed(70, tgid), []Event{at(leader(3<<8), 80)}, 0,
			3 << 8, true},
		{"an unstable listing that read no task running, with no fresh listing to ask: ended there, unknown",
			&Listing{Since: 50, Exiting: true, Unstable: true}, nil, []Event{at(leader(3<<8), 80)}, -2, 0, false},
		{"no event after the end is the process's", fork, nil, []Event{leader(3 << 8), thread(501, 0), leader(9)}, 0,
			3 << 8, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var g *Group
			if tc.from == nil {
				g = NewGroupAt(tgid, Event{Kind: Fork, PID: tgid, TGID: tgid, TimestampNS: 1})
			} else {
				var relist func() Listing
				if tc.relist != nil {
					asked := 0
					relist = func() Listing { // the row's answer, then nothing that runs: the process has gone
						if asked++; asked > 1 {
							return Listing{Since: 1000, Exiting: true}
						}
						return *tc.relist
					}
				}
				g = NewGroup(tgid, *tc.from, relist)
			}
			end := -1
			if g.Ended() {
				end = -2
			}
			stamp := uint64(1)
			for i, ev := range tc.evs {
				if ev.TimestampNS == 0 {
					stamp++
					ev.TimestampNS = stamp
				}
				switch ev.Kind {
				case Exec:
					g.Exec(ev)
				case Fork:
					g.Fork(ev)
				case Exit:
					if g.Exit(ev) {
						if end != -1 {
							t.Fatalf("it ended twice: at %d and %d", end, i)
						}
						end = i
					}
				}
			}
			if end != tc.endAt || g.Ended() != (tc.endAt != -1) {
				t.Fatalf("ended at event %d (Ended %v), want %d", end, g.Ended(), tc.endAt)
			}
			raw, known := g.Status()
			if raw != tc.raw || known != tc.known {
				t.Fatalf("status %#x known %v (%s), want %#x known %v", raw, known, g.Why(), tc.raw, tc.known)
			}
			if why := g.Why(); known == (why != "") {
				t.Fatalf("Why = %q with the status known %v", why, known)
			}
		})
	}
}

// TestGroupAfterDroppedEvents: a listing read after the kernel dropped events is what runs; while the leader runs,
// nothing dropped says anything of the status, and once it has exited the status is unknown.
func TestGroupAfterDroppedEvents(t *testing.T) {
	const tgid = 500
	g := NewGroupAt(tgid, Event{Kind: Fork, PID: tgid, TGID: tgid, TimestampNS: 1})
	g.Fork(Event{Kind: Fork, PID: 501, TGID: tgid, TimestampNS: 2})
	g.Exit(Event{Kind: Exit, PID: tgid, TGID: tgid, ExitCode: 0, TimestampNS: 3})
	g.Resync(Listing{Since: 10, Live: []int32{tgid, 502}}) // the exec the dropped events held, then a thread of it
	g.Exit(Event{Kind: Exit, PID: 502, TGID: tgid, ExitCode: 5 << 8, TimestampNS: 11})
	if !g.Exit(Event{Kind: Exit, PID: tgid, TGID: tgid, ExitCode: 5 << 8, TimestampNS: 12}) {
		t.Fatal("the leader's exit did not end it")
	}
	if raw, known := g.Status(); raw != 5<<8 || !known {
		t.Fatalf("leader running at the resync: status %#x known %v (%s), want 5<<8", raw, known, g.Why())
	}
	g = NewGroupAt(tgid, Event{Kind: Fork, PID: tgid, TGID: tgid, TimestampNS: 1})
	g.Fork(Event{Kind: Fork, PID: 501, TGID: tgid, TimestampNS: 2})
	g.Exit(Event{Kind: Exit, PID: tgid, TGID: tgid, ExitCode: 0, TimestampNS: 3})
	g.Resync(Listing{Since: 10, Live: []int32{501}})
	if !g.Exit(Event{Kind: Exit, PID: 501, TGID: tgid, ExitCode: 0, TimestampNS: 11}) {
		t.Fatal("the last thread's exit did not end it")
	}
	if _, known := g.Status(); known || !strings.Contains(g.Why(), "dropped") {
		t.Fatalf("leader gone at the resync: known %v, why %q; want unknown, for the dropped events", known, g.Why())
	}
}

// TestParseTimensOffsets: the monotonic offset of a time namespace, by name or by clock id; none is no offset known.
func TestParseTimensOffsets(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"monotonic 0 0\nboottime 0 0\n", 0, true},
		{"boottime 5 0\nmonotonic 12 500\n", 12_000_000_500, true},
		{"1 -3 0\n7 0 0\n", -3_000_000_000, true},
		{"boottime 5 0\n", 0, false},
		{"monotonic x 0\n", 0, false},
	} {
		if got, ok := parseTimensOffsets([]byte(tc.in)); got != tc.want || ok != tc.ok {
			t.Errorf("%q: %d %v, want %d %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestListRetriesAListingATaskChangedUnder: a task gone since it was enumerated, or one the second enumeration finds,
// makes List list again; a stable listing tells running, exiting and zombie tasks apart.
func TestListRetriesAListingATaskChangedUnder(t *testing.T) {
	calls := 0
	tasks := func() ([]int32, error) {
		calls++
		if calls == 2 {
			return []int32{500, 501, 502}, nil // a thread made while the first listing was read
		}
		return []int32{500, 501}, nil
	}
	reads := 0
	state := func(tid int32) TaskState {
		reads++
		switch {
		case tid == 501 && reads > 4:
			return TaskExiting
		case tid == 501:
			return TaskDying // gone since enumerated, the first time
		}
		return TaskRunning
	}
	l := List(tasks, state)
	if l.Exiting || len(l.Live) != 2 || l.Live[0] != 500 || l.Live[1] != 501 {
		t.Fatalf("listing %+v, want 500 running and 501 exiting", l)
	}
	if calls < 4 {
		t.Fatalf("listed %d times, want a retry", calls)
	}
	zombie := List(func() ([]int32, error) { return []int32{500}, nil }, func(int32) TaskState { return TaskZombie })
	if !zombie.Exiting || len(zombie.Live) != 0 {
		t.Fatalf("a zombie alone: %+v, want nothing running", zombie)
	}
	churn := 0
	never := List(func() ([]int32, error) { churn++; return []int32{500, int32(churn)}, nil },
		func(int32) TaskState { return TaskRunning })
	if !never.Unstable {
		t.Fatalf("a listing a new task appears in every time: %+v, want Unstable", never)
	}
}
