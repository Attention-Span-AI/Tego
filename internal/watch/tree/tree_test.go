// SPDX-License-Identifier: Apache-2.0

package tree

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func e(tgid, ppid int32, start uint64) Entry { return Entry{TGID: tgid, PPID: ppid, Start: start} }

func pidsOf(s *Session) []int32 {
	var out []int32
	for p := range s.members {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestLifecycle(t *testing.T) {
	tr := New(Limits{})
	s, created, dropped := tr.Start(e(100, 1, 5), "claude")
	if !created || dropped != nil || s.Meta != "claude" || s.Members() != 1 || !s.Has(100) {
		t.Fatalf("Start = %+v created=%v dropped=%v", s, created, dropped)
	}
	// A fork of a followed process joins; a fork of a stranger does not.
	if got, res, _ := tr.Fork(100, e(101, 100, 6)); got != s || res != Added {
		t.Fatalf("Fork of the root: %v, %v", got, res)
	}
	if got, res, _ := tr.Fork(101, e(102, 101, 7)); got != s || res != Added {
		t.Fatalf("Fork of a child (a grandchild): %v, %v", got, res)
	}
	if got, res, _ := tr.Fork(999, e(103, 999, 8)); got != nil || res != NotFollowed {
		t.Fatalf("Fork of a stranger joined: %v, %v", got, res)
	}
	if tr.Owner(103) != nil || tr.PIDs() != 3 || s.Seen != 3 {
		t.Fatalf("pids %d, seen %d, owner(103) %v", tr.PIDs(), s.Seen, tr.Owner(103))
	}
	// A child exits: the session goes on.
	if r := tr.Exit(102); r.Session != s || r.Root || r.Ended {
		t.Fatalf("Exit(102) = %+v", r)
	}
	// The root exits with a child alive: the root's exit is reported once, the session lives on.
	if r := tr.Exit(100); r.Session != s || !r.Root || r.Ended || !s.RootExited {
		t.Fatalf("Exit(100) = %+v", r)
	}
	if len(tr.Sessions()) != 1 || tr.Owner(101) != s {
		t.Fatal("a session ended with a descendant alive")
	}
	// The last process exits: the session ends and the tree is empty.
	if r := tr.Exit(101); r.Session != s || r.Root || !r.Ended {
		t.Fatalf("Exit(101) = %+v", r)
	}
	if len(tr.Sessions()) != 0 || tr.PIDs() != 0 {
		t.Fatalf("tree not empty: %d sessions, %d pids", len(tr.Sessions()), tr.PIDs())
	}
	// An exit nobody followed is none of the tree's business.
	if r := tr.Exit(100); r != (ExitResult{}) {
		t.Fatalf("Exit of an unknown pid = %+v", r)
	}
}

func TestRootAloneEndsAtItsExit(t *testing.T) {
	tr := New(Limits{})
	s, _, _ := tr.Start(e(7, 1, 1), nil)
	if r := tr.Exit(7); !r.Root || !r.Ended || r.Session != s || len(tr.Sessions()) != 0 {
		t.Fatalf("Exit(7) = %+v", r)
	}
}

// The same process reported twice, or a descendant that is itself an agent, starts no second session.
func TestStartIsIdempotentAndDescendantsBelongToTheirSession(t *testing.T) {
	tr := New(Limits{})
	s, _, _ := tr.Start(e(10, 1, 1), nil)
	tr.Fork(10, e(11, 10, 2))
	if got, created, _ := tr.Start(e(10, 1, 1), nil); got != s || created {
		t.Fatalf("a second Start of the root: %v, created=%v", got, created)
	}
	if got, created, _ := tr.Start(e(11, 10, 2), nil); got != s || created {
		t.Fatalf("Start of a descendant: %v, created=%v", got, created)
	}
	if len(tr.Sessions()) != 1 {
		t.Fatalf("%d sessions, want 1", len(tr.Sessions()))
	}
}

// A fork event for a process a scan already found, or one reported twice, changes nothing.
func TestForkOfAFollowedProcessIsADuplicate(t *testing.T) {
	tr := New(Limits{})
	s, _, _ := tr.Start(e(10, 1, 5), nil)
	tr.Fork(10, e(11, 10, 6))
	if got, res, _ := tr.Fork(10, e(11, 10, 6)); got != s || res != Duplicate || s.Seen != 2 || tr.PIDs() != 2 {
		t.Fatalf("Fork = %v, %v; seen %d, pids %d", got, res, s.Seen, tr.PIDs())
	}
	// With the start time unknown, the tree cannot tell, and takes it as a new process.
	if _, res, _ := tr.Fork(10, e(11, 10, 0)); res != Added || s.Seen != 3 {
		t.Fatalf("Fork with no start = %v, seen %d", res, s.Seen)
	}
	// The same pid with another start time is another process.
	if _, res, _ := tr.Fork(10, e(11, 10, 99)); res != Added || s.Members() != 2 {
		t.Fatalf("Fork with another start = %v, members %d", res, s.Members())
	}
}

// A pid whose exit was never seen and that forks again is a new process, not the old member.
func TestForkOverAStalePid(t *testing.T) {
	tr := New(Limits{})
	a, _, _ := tr.Start(e(10, 1, 1), nil)
	b, _, _ := tr.Start(e(20, 1, 1), nil)
	tr.Fork(10, e(11, 10, 2))
	if tr.Owner(11) != a {
		t.Fatal("setup")
	}
	// Pid 11 is reused, by a child of the other session.
	if got, res, _ := tr.Fork(20, e(11, 20, 9)); got != b || res != Added {
		t.Fatalf("Fork = %v, %v", got, res)
	}
	if tr.Owner(11) != b || a.Has(11) || !b.Has(11) || tr.PIDs() != 3 {
		t.Fatalf("owner(11)=%v a=%v b=%v pids=%d", tr.Owner(11), pidsOf(a), pidsOf(b), tr.PIDs())
	}
}

func TestSessionCapDropsTheOldestAndSaysSo(t *testing.T) {
	tr := New(Limits{MaxSessions: 3})
	var first *Session
	for i := int32(1); i <= 3; i++ {
		s, _, _ := tr.Start(e(i*10, 1, 1), nil)
		if i == 1 {
			first = s
			tr.Fork(10, e(11, 10, 1))
		}
	}
	s4, created, dropped := tr.Start(e(40, 1, 1), nil)
	if !created || len(dropped) != 1 {
		t.Fatalf("created=%v dropped=%v", created, dropped)
	}
	d := dropped[0]
	if d.Session != first || d.Reason != DropMaxSessions || d.Members != 2 {
		t.Fatalf("drop = %+v, want the first session, max-sessions, 2 members", d)
	}
	if tr.Owner(10) != nil || tr.Owner(11) != nil || tr.Owner(40) != s4 || len(tr.Sessions()) != 3 || tr.PIDs() != 3 {
		t.Fatalf("after the drop: owner(10)=%v owner(11)=%v sessions=%d pids=%d", tr.Owner(10), tr.Owner(11), len(tr.Sessions()), tr.PIDs())
	}
	// Followed no longer: its exit is not reported.
	if r := tr.Exit(10); r != (ExitResult{}) {
		t.Fatalf("Exit of a dropped session's root = %+v", r)
	}
}

func TestPIDCapDropsTheOldestOtherSession(t *testing.T) {
	tr := New(Limits{MaxPIDs: 4})
	old, _, _ := tr.Start(e(10, 1, 1), nil)
	tr.Fork(10, e(11, 10, 1))
	cur, _, _ := tr.Start(e(20, 1, 1), nil)
	tr.Fork(20, e(21, 20, 1))
	// Full. Another child of the newer session needs room: the older session goes.
	got, res, dropped := tr.Fork(20, e(22, 20, 1))
	if got != cur || res != Added || len(dropped) != 1 || dropped[0].Session != old || dropped[0].Reason != DropMaxPIDs || dropped[0].Members != 2 {
		t.Fatalf("Fork = %v, %v, %+v", got, res, dropped)
	}
	if tr.PIDs() != 3 || cur.Untracked != 0 {
		t.Fatalf("pids=%d untracked=%d", tr.PIDs(), cur.Untracked)
	}
}

// One session that fills the cap alone is not cut in half: its newest children go untracked, and are counted.
func TestPIDCapOnOneSessionStopsItGrowing(t *testing.T) {
	tr := New(Limits{MaxPIDs: 3})
	s, _, _ := tr.Start(e(10, 1, 1), nil)
	tr.Fork(10, e(11, 10, 1))
	tr.Fork(10, e(12, 10, 1))
	got, res, dropped := tr.Fork(10, e(13, 10, 1))
	if got != s || res != Full || len(dropped) != 0 || s.Untracked != 1 || tr.Owner(13) != nil || tr.PIDs() != 3 {
		t.Fatalf("Fork = %v, %v, %v; untracked=%d pids=%d", got, res, dropped, s.Untracked, tr.PIDs())
	}
	// Room again once one exits.
	tr.Exit(12)
	if _, res, _ := tr.Fork(10, e(14, 10, 1)); res != Added {
		t.Fatal("a freed slot was not reusable")
	}
}

func TestStartMakesRoomUnderThePIDCap(t *testing.T) {
	tr := New(Limits{MaxPIDs: 2})
	old, _, _ := tr.Start(e(10, 1, 1), nil)
	tr.Fork(10, e(11, 10, 1))
	_, created, dropped := tr.Start(e(20, 1, 1), nil)
	if !created || len(dropped) != 1 || dropped[0].Session != old || dropped[0].Reason != DropMaxPIDs {
		t.Fatalf("created=%v dropped=%+v", created, dropped)
	}
	if tr.PIDs() != 1 {
		t.Fatalf("pids = %d", tr.PIDs())
	}
}

// Memory stays inside the caps however many processes come and go.
func TestBoundedUnderChurn(t *testing.T) {
	tr := New(Limits{MaxSessions: 5, MaxPIDs: 50})
	for i := int32(0); i < 2000; i++ {
		tr.Start(e(1000+i*100, 1, uint64(i)), nil)
		for k := int32(1); k <= 20; k++ {
			tr.Fork(1000+i*100, e(1000+i*100+k, 1000+i*100, uint64(i)))
		}
		if len(tr.Sessions()) > 5 || tr.PIDs() > 50 || len(tr.owner) != tr.PIDs() {
			t.Fatalf("round %d: %d sessions, %d pids", i, len(tr.Sessions()), tr.PIDs())
		}
		total := 0
		for _, s := range tr.Sessions() {
			total += s.Members()
		}
		if total != tr.PIDs() {
			t.Fatalf("round %d: sessions hold %d, owner map %d", i, total, tr.PIDs())
		}
	}
}

func TestResync(t *testing.T) {
	type want struct {
		exited []int32
		root   bool
		added  []int32
		ended  int
		pids   []int32 // followed afterwards, sorted
	}
	for _, tc := range []struct {
		name  string
		setup func(*Tree)
		snap  []Entry
		want  want
	}{
		{
			name:  "nothing changed",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(1, 0, 1), e(10, 1, 5), e(11, 10, 6), e(50, 1, 9)},
			want:  want{pids: []int32{10, 11}},
		},
		{
			name:  "a child's exit was lost",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(10, 1, 5)},
			want:  want{exited: []int32{11}, pids: []int32{10}},
		},
		{
			name:  "the root's exit was lost, a child lives",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(11, 1, 6)},
			want:  want{exited: []int32{10}, root: true, pids: []int32{11}},
		},
		{
			name:  "everything exited: the session ends",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(1, 0, 1)},
			want:  want{exited: []int32{10, 11}, root: true, ended: 1},
		},
		{
			name:  "a pid was reused: the new process is not the old member",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(10, 1, 5), e(11, 777, 4000)},
			want:  want{exited: []int32{11}, pids: []int32{10}},
		},
		{
			name:  "a pid reused by a child of someone else is not adopted as a descendant",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil) },
			snap:  []Entry{e(10, 1, 5), e(11, 777, 4000)},
			want:  want{pids: []int32{10}},
		},
		{
			name:  "a missed fork joins",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil) },
			snap:  []Entry{e(10, 1, 5), e(11, 10, 6), e(60, 1, 9)},
			want:  want{added: []int32{11}, pids: []int32{10, 11}},
		},
		{
			name:  "a chain of missed forks joins whole, parents first",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil) },
			snap:  []Entry{e(12, 11, 7), e(11, 10, 6), e(10, 1, 5), e(13, 12, 8), e(14, 11, 8)},
			want:  want{added: []int32{11, 12, 14, 13}, pids: []int32{10, 11, 12, 13, 14}},
		},
		{
			name:  "a forked child's unknown start time is filled in",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 0)) },
			snap:  []Entry{e(10, 1, 5), e(11, 10, 6)},
			want:  want{pids: []int32{10, 11}},
		},
		{
			name:  "a missed fork under a member that was itself missed",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil); tr.Fork(10, e(11, 10, 6)) },
			snap:  []Entry{e(10, 1, 5), e(11, 10, 6), e(12, 11, 7)},
			want:  want{added: []int32{12}, pids: []int32{10, 11, 12}},
		},
		{
			name:  "an empty snapshot",
			setup: func(tr *Tree) { tr.Start(e(10, 1, 5), nil) },
			snap:  nil,
			want:  want{exited: []int32{10}, root: true, ended: 1},
		},
		{
			name:  "no sessions",
			setup: func(tr *Tree) {},
			snap:  []Entry{e(10, 1, 5)},
			want:  want{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := New(Limits{})
			tc.setup(tr)
			got := tr.Resync(tc.snap)
			var exited, added []int32
			rootSeen := false
			for _, g := range got.Exited {
				exited = append(exited, g.TGID)
				rootSeen = rootSeen || g.Root
			}
			for _, f := range got.Added {
				added = append(added, f.Entry.TGID)
			}
			var followed []int32
			for p := range tr.owner {
				followed = append(followed, p)
			}
			sort.Slice(followed, func(i, j int) bool { return followed[i] < followed[j] })
			if !reflect.DeepEqual(exited, tc.want.exited) || rootSeen != tc.want.root || !reflect.DeepEqual(added, tc.want.added) ||
				len(got.Ended) != tc.want.ended || !reflect.DeepEqual(followed, tc.want.pids) {
				t.Fatalf("exited=%v root=%v added=%v ended=%d followed=%v\nwant %+v", exited, rootSeen, added, len(got.Ended), followed, tc.want)
			}
			if tc.name == "a forked child's unknown start time is filled in" {
				if s := tr.Owner(11); s == nil || s.members[11] != 6 {
					t.Fatalf("start of 11 = %v", s.members[11])
				}
			}
			// A second resync with the same snapshot changes nothing.
			if again := tr.Resync(tc.snap); len(again.Exited)+len(again.Added)+len(again.Ended)+len(again.Dropped) != 0 {
				t.Fatalf("a second Resync changed things: %+v", again)
			}
		})
	}
}

// A root that exited and whose session lives on is not reported as exited a second time.
func TestResyncReportsTheRootOnce(t *testing.T) {
	tr := New(Limits{})
	s, _, _ := tr.Start(e(10, 1, 5), nil)
	tr.Fork(10, e(11, 10, 6))
	tr.Exit(10)
	got := tr.Resync([]Entry{e(11, 1, 6)})
	if len(got.Exited) != 0 || !s.RootExited {
		t.Fatalf("Resync = %+v", got)
	}
}

// Resync under the caps: the descendants it finds are bounded like any fork's, and a drop is reported.
func TestResyncRespectsTheCaps(t *testing.T) {
	tr := New(Limits{MaxPIDs: 3})
	s, _, _ := tr.Start(e(10, 1, 5), nil)
	var snap []Entry
	snap = append(snap, e(10, 1, 5))
	for i := int32(11); i <= 16; i++ {
		snap = append(snap, e(i, 10, 6))
	}
	got := tr.Resync(snap)
	if len(got.Added) != 2 || tr.PIDs() != 3 || s.Untracked != 4 {
		t.Fatalf("added %d, pids %d, untracked %d", len(got.Added), tr.PIDs(), s.Untracked)
	}
}

func ExampleTree() {
	tr := New(Limits{})
	s, _, _ := tr.Start(Entry{TGID: 10, PPID: 1}, "claude")
	tr.Fork(10, Entry{TGID: 11, PPID: 10})
	fmt.Println(s.Meta, s.Members())
	// Output: claude 2
}
