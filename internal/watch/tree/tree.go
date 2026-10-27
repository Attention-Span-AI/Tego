// SPDX-License-Identifier: Apache-2.0

// Package tree follows the processes of a recognised agent (docs/poc/agent-watcher.md, M2). A session starts
// when the caller recognises an agent process, grows as that process and its descendants fork, and ends when its
// processes have exited. It is pure: it reads nothing, and it never touches a process. The caller feeds it what
// the proc connector reported and, to repair a gap, a snapshot of /proc.
//
// Memory is bounded by two caps, MaxSessions and MaxPIDs. Past one, the OLDEST session is dropped whole, with
// every pid it held, and the drop is returned to the caller so it can say so: a watcher must never grow without
// bound on a busy host, and must never lose a process without saying. A single session that alone fills MaxPIDs
// stops growing instead (its newest children go untracked, counted in Session.Untracked), since dropping part of
// a session would leave a half-followed tree that looks whole.
package tree

import (
	"slices"
	"sort"
)

// Entry is one process as the tree knows it. Start is /proc/<pid>/stat's starttime, in clock ticks since boot, 0
// when the caller does not know it: a fork event carries no start time and a process may be gone before anyone
// reads it. A start time, once known, is what tells a pid that was reused from the process it replaced.
type Entry struct {
	TGID  int32
	PPID  int32
	Start uint64
}

// Limits are the caps. A zero field takes its default.
type Limits struct {
	MaxSessions int // sessions followed at once; default 64
	MaxPIDs     int // processes followed, all sessions together; default 8192
}

const (
	defaultMaxSessions = 64
	defaultMaxPIDs     = 8192
)

func (l Limits) norm() Limits {
	if l.MaxSessions <= 0 {
		l.MaxSessions = defaultMaxSessions
	}
	if l.MaxPIDs <= 0 {
		l.MaxPIDs = defaultMaxPIDs
	}
	return l
}

// Session is one recognised agent and the processes it started. Callers read its fields and never write them.
type Session struct {
	ID   uint64
	Root Entry
	// Meta is whatever the caller attached at Start, for example what the signature that matched said.
	Meta any
	// RootExited is true from the moment the root process exited. The session lives on while any descendant does:
	// a daemonised child outlives its parent, and the tree keeps following it.
	RootExited bool
	// Untracked counts children the tree refused because MaxPIDs was full and this session alone filled it.
	Untracked int
	// Seen counts every process the session ever held, the root included.
	Seen int

	members map[int32]uint64 // live members: tgid -> start (0 unknown)
}

// Members is how many processes of the session are alive, the root included until it exits.
func (s *Session) Members() int { return len(s.members) }

// Drop is a session the tree gave up to stay inside its caps.
type Drop struct {
	Session *Session
	Reason  string // DropMaxSessions or DropMaxPIDs
	Members int    // processes it held, which are no longer followed
}

// The reasons a session is dropped.
const (
	DropMaxSessions = "max-sessions"
	DropMaxPIDs     = "max-pids"
)

// Tree is the set of live sessions. It is not safe for concurrent use: one goroutine owns it.
type Tree struct {
	lim      Limits
	next     uint64
	sessions []*Session         // oldest first
	owner    map[int32]*Session // tgid -> its session
}

// New is an empty tree under lim.
func New(lim Limits) *Tree {
	return &Tree{lim: lim.norm(), owner: map[int32]*Session{}}
}

// PIDs is how many processes are followed, all sessions together.
func (t *Tree) PIDs() int { return len(t.owner) }

// Sessions is the live sessions, oldest first. The slice is a copy.
func (t *Tree) Sessions() []*Session { return append([]*Session(nil), t.sessions...) }

// Followed is every followed process, all sessions together, in pid order.
func (t *Tree) Followed() []int32 {
	out := make([]int32, 0, len(t.owner))
	for tgid := range t.owner {
		out = append(out, tgid)
	}
	slices.Sort(out)
	return out
}

// Owner is the session tgid belongs to, nil when it is not followed.
func (t *Tree) Owner(tgid int32) *Session { return t.owner[tgid] }

// Start begins a session at root. When root is already followed (a descendant of a session, or a second report of
// the same process) nothing starts: the owning session comes back with created false. Otherwise it returns the
// new session, after dropping the oldest ones the caps required.
func (t *Tree) Start(root Entry, meta any) (s *Session, created bool, dropped []Drop) {
	if o := t.owner[root.TGID]; o != nil {
		return o, false, nil
	}
	for len(t.sessions) >= t.lim.MaxSessions {
		dropped = append(dropped, t.dropOldest(DropMaxSessions))
	}
	for len(t.owner)+1 > t.lim.MaxPIDs && len(t.sessions) > 0 {
		dropped = append(dropped, t.dropOldest(DropMaxPIDs))
	}
	t.next++
	s = &Session{ID: t.next, Root: root, Meta: meta, Seen: 1, members: map[int32]uint64{root.TGID: root.Start}}
	t.sessions = append(t.sessions, s)
	t.owner[root.TGID] = s
	return s, true, dropped
}

// ForkResult says what a Fork did.
type ForkResult int

// The outcomes of a Fork.
const (
	NotFollowed ForkResult = iota // the parent is not followed: nothing was recorded
	Added                         // the child joined its parent's session
	Duplicate                     // the child was already followed, the same process: a report the tree had seen, or a scan had found
	Full                          // MaxPIDs is full and this session alone fills it: the child is not followed (Untracked counts it)
)

// Fork records child as a member of its parent's session. A parent the tree does not follow is none of its
// business. A child the tree already follows is a Duplicate when its start time is known and the same as the
// one held (a scan met it before its fork event came), and otherwise a pid that was reused after a missed exit:
// the stale entry is replaced. When MaxPIDs is full the oldest other session is dropped to make room; if the
// parent's own session is the only one, the child is not followed and Untracked counts it.
func (t *Tree) Fork(parent int32, child Entry) (s *Session, res ForkResult, dropped []Drop) {
	s = t.owner[parent]
	if s == nil {
		return nil, NotFollowed, nil
	}
	if old := t.owner[child.TGID]; old != nil {
		if old == s && child.Start != 0 && old.members[child.TGID] == child.Start {
			return s, Duplicate, nil
		}
		t.remove(old, child.TGID)
		t.endIfEmpty(old)
	}
	for len(t.owner)+1 > t.lim.MaxPIDs {
		d, ok := t.dropOldestOther(s)
		if !ok {
			s.Untracked++
			return s, Full, dropped
		}
		dropped = append(dropped, d)
	}
	s.members[child.TGID] = child.Start
	s.Seen++
	t.owner[child.TGID] = s
	return s, Added, dropped
}

// ExitResult is what an exit changed.
type ExitResult struct {
	Session *Session // nil when the process was not followed
	Root    bool     // it was the session's root, which has now exited
	Ended   bool     // that was the session's last process: the session is gone from the tree
}

// Exit removes tgid. The session ends when its last process does.
func (t *Tree) Exit(tgid int32) ExitResult {
	s := t.owner[tgid]
	if s == nil {
		return ExitResult{}
	}
	res := ExitResult{Session: s}
	if tgid == s.Root.TGID && !s.RootExited {
		s.RootExited, res.Root = true, true
	}
	t.remove(s, tgid)
	res.Ended = t.endIfEmpty(s)
	return res
}

func (t *Tree) remove(s *Session, tgid int32) {
	delete(s.members, tgid)
	delete(t.owner, tgid)
}

func (t *Tree) endIfEmpty(s *Session) bool {
	if len(s.members) > 0 {
		return false
	}
	for i, x := range t.sessions {
		if x == s {
			t.sessions = append(t.sessions[:i], t.sessions[i+1:]...)
			break
		}
	}
	return true
}

// dropOldest drops the oldest session and everything it holds.
func (t *Tree) dropOldest(reason string) Drop { return t.dropSession(t.sessions[0], reason) }

// dropOldestOther is dropOldest for the oldest session but keep, false when keep is the only one.
func (t *Tree) dropOldestOther(keep *Session) (Drop, bool) {
	for _, s := range t.sessions {
		if s != keep {
			return t.dropSession(s, DropMaxPIDs), true
		}
	}
	return Drop{}, false
}

func (t *Tree) dropSession(s *Session, reason string) Drop {
	d := Drop{Session: s, Reason: reason, Members: len(s.members)}
	for tgid := range s.members {
		delete(t.owner, tgid)
	}
	s.members = map[int32]uint64{}
	t.endIfEmpty(s)
	return d
}

// Resynced is what a Resync changed.
type Resynced struct {
	Exited  []Gone  // followed processes found gone, in session then pid order
	Added   []Found // descendants found, in the order they joined
	Ended   []*Session
	Dropped []Drop
}

// Gone is a followed process Resync found exited.
type Gone struct {
	Session *Session
	TGID    int32
	Root    bool
}

// Found is a descendant Resync found and now follows.
type Found struct {
	Session *Session
	Entry   Entry
}

// Resync repairs the tree after the caller lost events (the proc connector reports ENOBUFS when its socket
// overflows; a missed exit leaves a pid the tree still follows, a missed fork a descendant it never met). snap is
// every process now alive, as the caller just read it from /proc. It reports what changed:
//
//   - a followed process that is not in snap, or that is there with another start time (its pid was reused), has
//     exited: it is removed, and a root among them is marked exited;
//   - a process in snap whose parent is followed is a descendant that was missed: it joins that session, parents
//     before children, so a missed chain is followed whole. A fork's start time is filled in when snap has it.
func (t *Tree) Resync(snap []Entry) Resynced {
	var out Resynced
	now := make(map[int32]Entry, len(snap))
	children := map[int32][]Entry{}
	for _, e := range snap {
		now[e.TGID] = e
		children[e.PPID] = append(children[e.PPID], e)
	}
	for _, s := range t.Sessions() {
		pids := make([]int32, 0, len(s.members))
		for tgid := range s.members {
			pids = append(pids, tgid)
		}
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
		for _, tgid := range pids {
			e, alive := now[tgid]
			if known := s.members[tgid]; alive && known != 0 && e.Start != 0 && known != e.Start {
				alive = false
			}
			if alive {
				if s.members[tgid] == 0 {
					s.members[tgid] = e.Start
				}
				continue
			}
			g := Gone{Session: s, TGID: tgid}
			if tgid == s.Root.TGID && !s.RootExited {
				s.RootExited, g.Root = true, true
			}
			t.remove(s, tgid)
			out.Exited = append(out.Exited, g)
		}
	}
	// A followed process that survived may have children the tree missed; walk down from every one, so a chain
	// of missed forks joins whole. Process ids ascend, so the walk is the same on every run.
	var queue []int32
	for tgid := range t.owner {
		queue = append(queue, tgid)
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		s := t.owner[p]
		if s == nil {
			continue
		}
		kids := children[p]
		sort.Slice(kids, func(i, j int) bool { return kids[i].TGID < kids[j].TGID })
		for _, c := range kids {
			if t.owner[c.TGID] != nil {
				continue
			}
			_, res, dropped := t.Fork(p, c)
			out.Dropped = append(out.Dropped, dropped...)
			if res == Added {
				out.Added = append(out.Added, Found{Session: s, Entry: c})
				queue = append(queue, c.TGID)
			}
		}
	}
	for _, s := range t.Sessions() {
		if t.endIfEmpty(s) {
			out.Ended = append(out.Ended, s)
		}
	}
	return out
}
