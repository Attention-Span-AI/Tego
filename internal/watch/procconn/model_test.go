// SPDX-License-Identifier: Apache-2.0

package procconn

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"os"
	"slices"
	"testing"
)

// The exhaustive model of the exit protocol Group reads (ADR 0055 (e)): every
// interleaving of a small process's tasks, of the kernel's steps for each, and of a reader that lists and reads the
// events, checked against what wait(2) would report. The kernel facts it encodes are those of v6.17's kernel/exit.c,
// kernel/signal.c, fs/exec.c, kernel/fork.c and drivers/connector/cn_proc.c:
//
//   - M1 a task's exit_code is fixed when do_exit starts (E), where PF_EXITING is set, and from 5.19 the last task to
//     start do_exit with no group exit sets SIGNAL_GROUP_EXIT with its own code (synchronize_group_exit);
//   - M2 exit_group(2) sets SIGNAL_GROUP_EXIT with its code unless already set (then it takes group_exit_code) or an
//     exec is zapping (code 0), and zaps the other tasks, which die with group_exit_code; a fatal signal does the same
//     with its number, for every task not yet in do_exit; a task already in its own exit(2) or seccomp's
//     SECCOMP_RET_KILL_THREAD keeps its own code (the racing exit residual);
//   - M3 the exit event is filled after exit_notify (X): its timestamp first, then the task's pid, then it is sent; a
//     task can be preempted between any two, so events are read in any order their sends had;
//   - M4 an exec zaps the other tasks (code 0), waits until each has passed exit_notify, then de_thread swaps the
//     exec'ing thread's tid with the old leader's and releases it; the Exec event is filled after the swap; an exec that
//     fails after it dies of SIGSEGV with no Exec event;
//   - M5 a fork event is filled and sent before the new task runs, after it is listed in /proc, and a fork fails once a
//     fatal signal is pending for its caller;
//   - M6 wait_task_zombie reports group_exit_code once SIGNAL_GROUP_EXIT is set, else the leader's exit_code.
//
// Properties: Group never ends while a task of the process has not passed exit_notify; it has ended once every event is
// read; a status it calls known is the one wait(2) reports, on a kernel before 5.19 and on one from it, except where a
// task's own exit raced a group exit (M2's residual, which no event tells).

const (
	mTGID  = 100
	mChild = 200
)

// A task's fate: what it does once it runs.
const (
	fExit0  = "exit0"  // exit(0) or pthread_exit
	fExit5  = "exit5"  // syscall(SYS_exit, 5)
	fGroup3 = "group3" // exit_group(3)
	fKill   = "kill31" // seccomp SECCOMP_RET_KILL_THREAD (SIGSYS)
	fExec   = "exec"   // execve that succeeds; its program then exit_group(7)
	fBadEx  = "badexec"
	fWait   = "wait" // nothing of its own: it dies when a group exit or an exec zaps it
)

type mScenario struct {
	fates  []string // per task, task 0 the leader
	clone  bool     // task 1 makes the last task (it starts not yet made)
	child  bool     // task 1 forks a child process first
	killer bool     // a SIGKILL from outside
	reader string   // "fork" (followed from its fork), "list" (found running), "exec" (followed from an Exec event)
}

func (s mScenario) String() string {
	return fmt.Sprintf("fates=%v clone=%v child=%v killer=%v reader=%s", s.fates, s.clone, s.child, s.killer, s.reader)
}

type mTask struct {
	tid    int32
	fate   string
	st     byte // 'N' not made, 'P' made not runnable, 'R' runs, 'E' in do_exit, 'Z' zombie, 'G' gone
	pre    int  // pre-actions done: 0 none, 1 fork filled (child), 2 fork sent
	exec   int  // exec's progress: 1 zapped others, 2 swapped, 3 Exec filled, 4 Exec sent
	ev     int  // exit event's progress: 0 none, 1 timestamp, 2 pid, 3 sent
	code   uint32
	ts     uint64
	pid    int32
	zap    bool
	racer  bool
	forkTS uint64
}

type mState struct {
	sc     *mScenario
	tasks  []mTask
	flag   bool
	gec    uint32
	execBy int // task zapping for an exec, -1 none
	quick  int
	clock  uint64
	queue  []Event
	killed bool
	lastIn uint32 // the code of the last task to begin do_exit with no group exit set
	synced bool
	// the reader
	rd      int // events read
	phase   int // listing: 0 not begun, 1 listed (enum1 held), 2 reads done; 3 grouped
	since   uint64
	enum1   []int32
	readIdx int
	live    []int32
	exiting bool
	stable  bool
	tries   int
	g       *Group
	racer   bool
	bad     string
}

func (s *mState) clone() *mState {
	c := *s
	c.tasks = slices.Clone(s.tasks)
	c.queue = slices.Clone(s.queue)
	c.enum1 = slices.Clone(s.enum1)
	c.live = slices.Clone(s.live)
	if s.g != nil {
		g := *s.g
		g.live = make(map[int32]struct{}, len(s.g.live))
		for k := range s.g.live {
			g.live[k] = struct{}{}
		}
		g.others = slices.Clone(s.g.others)
		c.g = &g
	}
	return &c
}

func (s *mState) key() [2]uint64 {
	b := make([]byte, 0, 256)
	u := func(v uint64) { b = binary.AppendUvarint(b, v) }
	for _, t := range s.tasks {
		u(uint64(t.tid))
		b = append(b, t.st, byte(t.pre), byte(t.exec), byte(t.ev), boolByte(t.zap), boolByte(t.racer))
		u(uint64(t.code))
		u(t.ts)
		u(uint64(t.pid))
		u(t.forkTS)
	}
	b = append(b, boolByte(s.flag), byte(s.execBy+1), byte(s.quick), boolByte(s.killed), boolByte(s.synced))
	u(uint64(s.gec))
	u(uint64(s.lastIn))
	u(s.clock)
	for _, ev := range s.queue {
		b = append(b, byte(ev.Kind))
		u(uint64(ev.PID))
		u(uint64(ev.TGID))
		u(uint64(ev.ExitCode))
		u(ev.TimestampNS)
	}
	b = append(b, 0xff, byte(s.rd), byte(s.phase), byte(s.readIdx), boolByte(s.exiting), boolByte(s.stable),
		byte(s.tries), boolByte(s.racer))
	u(s.since)
	for _, x := range s.enum1 {
		u(uint64(x))
	}
	b = append(b, 0xfe)
	for _, x := range s.live {
		u(uint64(x))
	}
	if g := s.g; g != nil {
		b = append(b, 0xfd)
		live := make([]int32, 0, len(g.live))
		for k := range g.live {
			live = append(live, k)
		}
		slices.Sort(live)
		for _, x := range live {
			u(uint64(x))
		}
		b = append(b, 0xfc, boolByte(g.leaderSeen), boolByte(g.lost), boolByte(g.exiting), boolByte(g.leaderGone),
			boolByte(g.ended), boolByte(g.unlisted), boolByte(g.unsure))
		u(g.since)
		u(uint64(g.leader))
		u(g.leaderAt)
		u(g.lifeAt)
		u(uint64(g.core))
		for _, o := range g.others {
			u(uint64(o.code))
			u(o.at)
		}
	}
	return [2]uint64{maphash.Bytes(seed1, b), maphash.Bytes(seed2, b)}
}

// seed1 and seed2 hash a state twice: 128 bits make a collision between two of the model's states negligible.
var seed1, seed2 = maphash.MakeSeed(), maphash.MakeSeed()

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

func (s *mState) tick() uint64 { s.clock++; return s.clock }

// byTID is the index of the task that holds tid now, -1 none.
func (s *mState) byTID(tid int32) int {
	for i, t := range s.tasks {
		if t.tid == tid && t.st != 'N' && t.st != 'G' {
			return i
		}
	}
	return -1
}

// zapOthers marks every task but i that has not begun to exit as zapped.
func (s *mState) zapOthers(i int) {
	for j := range s.tasks {
		if j != i && (s.tasks[j].st == 'R' || s.tasks[j].st == 'P') {
			s.tasks[j].zap = true
		}
	}
}

// enter is do_exit's start for task i with code (M1).
func (s *mState) enter(i int, code uint32) {
	t := &s.tasks[i]
	t.code, t.st = code, 'E'
	s.quick--
	if s.quick == 0 && !s.flag {
		s.lastIn, s.synced = code, true // from 5.19, synchronize_group_exit sets the flag with this code
	}
}

// zapCode is the code a zapped task dies with (M2, M4).
func (s *mState) zapCode() uint32 {
	if s.flag {
		return s.gec
	}
	return 0 // an exec's zap
}

// groupExit is do_group_exit(code) by task i: the flag and the zap, then do_exit.
func (s *mState) groupExit(i int, code uint32) {
	switch {
	case s.flag:
		code = s.gec
	case s.execBy >= 0:
		code = 0
	default:
		s.flag, s.gec = true, code
		s.zapOthers(i)
	}
	s.enter(i, code)
}

func (s *mState) send(ev Event) { s.queue = append(s.queue, ev) }

// moves are the states one step on from s.
func (s *mState) moves() []*mState {
	var out []*mState
	for i := range s.tasks {
		out = append(out, s.taskMoves(i)...)
	}
	if s.sc.killer && !s.killed {
		n := s.clone()
		n.killed = true
		wants := false
		for _, t := range n.tasks {
			wants = wants || t.st == 'R'
		}
		if wants && !n.flag {
			n.flag, n.gec = true, 9
			n.zapOthers(-1)
		}
		out = append(out, n)
	}
	out = append(out, s.readerMoves()...)
	return out
}

func (s *mState) taskMoves(i int) []*mState {
	t := s.tasks[i]
	one := func(f func(n *mState)) []*mState { n := s.clone(); f(n); return []*mState{n} }
	switch t.st {
	case 'N', 'Z', 'G':
		if t.st != 'N' && t.ev < 3 && t.code != ^uint32(0) {
			return s.eventMoves(i)
		}
		return nil
	case 'E':
		return one(func(n *mState) {
			// exit_notify: a non-leader is released; the leader stays a zombie for its parent.
			if n.tasks[i].tid == mTGID {
				n.tasks[i].st = 'Z'
			} else {
				n.tasks[i].st = 'G'
			}
		})
	case 'P':
		return nil
	}
	// It runs. A fork filled is sent, and an exec past de_thread sends its event, before a signal is acted on.
	if t.zap && !(i == 1 && t.pre == 1) && (t.exec < 2 || t.exec == 4) {
		var out []*mState
		out = append(out, one(func(n *mState) { n.enter(i, n.zapCode()) })...)
		if (t.fate == fExit0 || t.fate == fExit5 || t.fate == fKill) && t.exec == 0 {
			// Already in its own exit when the zap came (M2's residual if a group exit zapped it).
			out = append(out, one(func(n *mState) {
				n.racer = n.racer || n.flag
				n.enter(i, ownCode(t.fate))
			})...)
		}
		return out
	}
	if i == 1 && (s.sc.clone || s.sc.child) && t.pre < 2 {
		return one(func(n *mState) {
			if n.tasks[1].pre == 0 {
				n.tasks[1].pre, n.tasks[1].forkTS = 1, n.tick()
				if n.sc.clone {
					last := len(n.tasks) - 1
					n.tasks[last].st = 'P'
					n.quick++
				}
				return
			}
			n.tasks[1].pre = 2
			if n.sc.clone {
				last := len(n.tasks) - 1
				n.send(Event{Kind: Fork, PID: n.tasks[last].tid, TGID: mTGID, ParentTGID: 1, TimestampNS: n.tasks[1].forkTS})
				if n.tasks[last].st == 'P' {
					n.tasks[last].st = 'R'
				}
			} else {
				n.send(Event{Kind: Fork, PID: mChild, TGID: mChild, ParentTGID: mTGID, TimestampNS: n.tasks[1].forkTS})
			}
		})
	}
	switch t.fate {
	case fExit0, fExit5, fKill:
		return one(func(n *mState) {
			if t.fate == fKill && n.running() == 1 && !n.flag {
				n.flag, n.gec = true, 31 // the last task: force_sig_seccomp, a group exit
			}
			n.enter(i, ownCode(t.fate))
		})
	case fGroup3:
		return one(func(n *mState) { n.groupExit(i, 3<<8) })
	case fWait:
		return nil
	case fExec, fBadEx:
		switch t.exec {
		case 0:
			if s.execBy >= 0 {
				return nil
			}
			return one(func(n *mState) {
				n.execBy = i
				n.zapOthers(i)
				n.tasks[i].exec = 1
			})
		case 1:
			for j, o := range s.tasks {
				if j != i && o.st != 'N' && o.st != 'Z' && o.st != 'G' {
					return nil // de_thread waits for every other task's exit_notify
				}
			}
			return one(func(n *mState) {
				if old := n.byTID(mTGID); old >= 0 && old != i {
					n.tasks[old].tid, n.tasks[old].st = n.tasks[i].tid, 'G'
				} else if old < 0 {
					for j := range n.tasks {
						if n.tasks[j].tid == mTGID && j != i {
							n.tasks[j].tid = n.tasks[i].tid
						}
					}
				}
				n.tasks[i].tid = mTGID
				n.execBy = -1
				n.tasks[i].exec = 2
			})
		case 2:
			if t.fate == fBadEx {
				return one(func(n *mState) {
					if !n.flag {
						n.flag, n.gec = true, 11
					}
					n.enter(i, n.gec)
				})
			}
			return one(func(n *mState) { n.tasks[i].forkTS, n.tasks[i].exec = n.tick(), 3 })
		case 3:
			return one(func(n *mState) {
				n.send(Event{Kind: Exec, PID: mTGID, TGID: mTGID, TimestampNS: n.tasks[i].forkTS})
				n.tasks[i].exec = 4
			})
		default:
			return one(func(n *mState) { n.groupExit(i, 7<<8) })
		}
	}
	return nil
}

// eventMoves fill and send task i's exit event (M3): the timestamp, then the pid, then the send.
func (s *mState) eventMoves(i int) []*mState {
	n := s.clone()
	t := &n.tasks[i]
	switch t.ev {
	case 0:
		t.ts, t.ev = n.tick(), 1
	case 1:
		t.pid, t.ev = t.tid, 2
	default:
		n.send(Event{Kind: Exit, PID: t.pid, TGID: mTGID, ExitCode: t.code, TimestampNS: t.ts})
		t.ev = 3
	}
	return []*mState{n}
}

func ownCode(fate string) uint32 {
	switch fate {
	case fExit5:
		return 5 << 8
	case fKill:
		return 31
	}
	return 0
}

// running counts the tasks not yet in do_exit.
func (s *mState) running() int {
	n := 0
	for _, t := range s.tasks {
		if t.st == 'R' || t.st == 'P' {
			n++
		}
	}
	return n
}

// listNow is the reader's relist: the tasks as /proc shows them at this step.
func (s *mState) listNow() Listing {
	l := Listing{Since: s.tick(), Exiting: true}
	for _, t := range s.tasks {
		switch t.st {
		case 'R', 'P':
			l.Live, l.Exiting = append(l.Live, t.tid), false
		case 'E':
			l.Live = append(l.Live, t.tid)
		}
	}
	slices.Sort(l.Live)
	return l
}

func (s *mState) readerMoves() []*mState {
	if s.sc.reader == "list" && s.phase < 3 {
		n := s.clone()
		switch n.phase {
		case 0:
			n.since, n.enum1, n.readIdx, n.live, n.exiting, n.stable = n.tick(), nil, 0, nil, true, true
			for _, t := range n.tasks {
				if t.st != 'N' && t.st != 'G' {
					n.enum1 = append(n.enum1, t.tid)
				}
			}
			slices.Sort(n.enum1)
			n.phase = 1
		case 1:
			if n.readIdx < len(n.enum1) {
				tid := n.enum1[n.readIdx]
				n.readIdx++
				j := n.byTID(tid)
				switch {
				case j < 0:
					n.stable = false
				case n.tasks[j].st == 'R' || n.tasks[j].st == 'P':
					n.live, n.exiting = append(n.live, tid), false
				case n.tasks[j].st == 'E':
					n.live = append(n.live, tid)
				}
				break
			}
			var fresh []int32
			for _, t := range n.tasks {
				if t.st != 'N' && t.st != 'G' && !slices.Contains(n.enum1, t.tid) {
					fresh, n.stable = append(fresh, t.tid), false
				}
			}
			if !n.stable && n.tries < 2 {
				n.tries++
				n.phase = 0
				break
			}
			if !n.stable {
				n.live = append(n.live, fresh...) // List's last try: what only the second enumeration showed runs
			}
			l := Listing{Since: n.since, Live: n.live, Exiting: n.exiting, Unstable: !n.stable}
			n.g = NewGroup(mTGID, l, n.listNow)
			n.phase = 3
			n.checkEnd()
		}
		return []*mState{n}
	}
	if s.rd >= len(s.queue) || s.phase != 3 && s.sc.reader == "list" {
		return nil
	}
	n := s.clone()
	ev := n.queue[n.rd]
	n.rd++
	if n.g == nil {
		if n.sc.reader == "exec" && ev.Kind == Exec {
			n.g = NewGroupAt(mTGID, ev)
		}
		return []*mState{n}
	}
	if n.g.relist != nil {
		n.g.relist = n.listNow
	}
	switch {
	case ev.Kind == Fork && (ev.TGID == mTGID || ev.ParentTGID == mTGID):
		n.g.Fork(ev)
	case ev.Kind == Exec && ev.TGID == mTGID:
		n.g.Exec(ev)
	case ev.Kind == Exit && ev.TGID == mTGID:
		if n.g.Exit(ev) {
			n.checkEnd()
		}
	}
	return []*mState{n}
}

// checkEnd is the first property, where the group has just ended: no task of the process has yet to pass exit_notify.
func (s *mState) checkEnd() {
	if s.g == nil || !s.g.Ended() || s.bad != "" {
		return
	}
	for _, t := range s.tasks {
		if t.st == 'R' || t.st == 'P' || t.st == 'E' {
			s.bad = fmt.Sprintf("ended while task tid %d is %c; listing since %d live %v stable %v; events %v", t.tid,
				t.st, s.since, s.live, s.stable, s.queue)
			return
		}
	}
}

// waitStatus is wait(2)'s status at the end (M6), on a kernel from 5.19 (synchronize_group_exit) or before it.
func (s *mState) waitStatus(newKern bool) uint32 {
	switch {
	case s.flag:
		return s.gec
	case newKern && s.synced:
		return s.lastIn
	}
	for _, t := range s.tasks {
		if t.tid == mTGID {
			return t.code
		}
	}
	return 0
}

type mResult struct {
	traces, known, unknown, residual int
	fail                             string
}

func explore(sc mScenario) mResult {
	n := len(sc.fates)
	s := &mState{sc: &sc, execBy: -1}
	for i := 0; i < n; i++ {
		t := mTask{tid: mTGID + int32(i), fate: sc.fates[i], st: 'R', code: ^uint32(0)}
		if sc.clone && i == n-1 {
			t.st = 'N'
		} else {
			s.quick++
		}
		s.tasks = append(s.tasks, t)
	}
	s.clock = 1
	if sc.reader == "fork" {
		// Followed from its fork: the threads it had when the model starts were made after it, their forks queued.
		s.g = NewGroupAt(mTGID, Event{Kind: Fork, PID: mTGID, TGID: mTGID, TimestampNS: 1})
		for _, t := range s.tasks[1:] {
			if t.st == 'R' {
				s.send(Event{Kind: Fork, PID: t.tid, TGID: mTGID, ParentTGID: 1, TimestampNS: s.tick()})
			}
		}
	}
	var r mResult
	seen := map[[2]uint64]bool{}
	var walk func(*mState)
	walk = func(st *mState) {
		if r.fail != "" {
			return
		}
		k := st.key()
		if seen[k] {
			return
		}
		seen[k] = true
		if st.bad != "" {
			r.fail = st.bad
			return
		}
		next := st.moves()
		if len(next) > 0 {
			for _, m := range next {
				walk(m)
			}
			return
		}
		r.traces++
		for _, t := range st.tasks {
			if t.st != 'Z' && t.st != 'G' && !(t.st == 'N' && sc.clone) {
				r.fail = fmt.Sprintf("the model stuck: task %+v", t)
				return
			}
		}
		if st.g == nil {
			return // followed from an Exec that never came (the exec failed)
		}
		if !st.g.Ended() {
			r.fail = fmt.Sprintf("every event read and the group has not ended; events %v", st.queue)
			return
		}
		raw, known := st.g.Status()
		oldK, newK := st.waitStatus(false), st.waitStatus(true)
		switch {
		case !known:
			r.unknown++
		case sameStatus(raw, oldK) && sameStatus(raw, newK):
			r.known++
		case st.racer:
			r.residual++
		default:
			r.fail = fmt.Sprintf("status %#x known, wait(2) reports %#x before 5.19 and %#x from it; events %v", raw,
				oldK, newK, st.queue)
		}
	}
	walk(s)
	return r
}

// scenarios are the model's inputs: up to three tasks, at most one each of exec, exit_group, a thread-directed kill and
// the leader's own exit, the other tasks' own exits or none, a thread made during the run or a child forked, a SIGKILL
// from outside, and each reader.
func scenarios(three bool) []mScenario {
	var out []mScenario
	leaderFates := []string{fExit0, fGroup3, fKill, fExec, fWait}
	threadFates := []string{fExit0, fExit5, fGroup3, fKill, fExec, fBadEx, fWait}
	ok := func(fates []string, killer bool) bool {
		count := map[string]int{}
		for _, f := range fates {
			count[f]++
		}
		if count[fExec]+count[fBadEx] > 1 || count[fGroup3] > 1 || count[fKill] > 1 {
			return false
		}
		if count[fWait] > 0 && count[fExec]+count[fBadEx]+count[fGroup3] == 0 && !killer {
			return false // nothing would end it
		}
		return true
	}
	add := func(fates []string) {
		for _, killer := range []bool{false, true} {
			if !ok(fates, killer) {
				continue
			}
			for _, extra := range []string{"", "clone", "child"} {
				if extra == "clone" && len(fates) < 3 {
					continue
				}
				for _, reader := range []string{"fork", "list", "exec"} {
					if reader == "exec" && !slices.Contains(fates, fExec) {
						continue
					}
					out = append(out, mScenario{fates: slices.Clone(fates), clone: extra == "clone",
						child: extra == "child", killer: killer, reader: reader})
				}
			}
		}
	}
	for _, l := range leaderFates {
		for _, a := range threadFates {
			add([]string{l, a})
			if !three {
				continue
			}
			for _, b := range threadFates {
				add([]string{l, a, b})
			}
		}
	}
	return out
}

// TestGroupAgainstTheExitModel runs the model over every scenario: no early end, an end once all is read, and no known
// status other than wait(2)'s outside the racing-exit residual. It runs the two-task scenarios (about 100k traces, a
// few seconds); the three-task ones take longer than go test's default 10-minute timeout on a loaded box, so they run
// only with TEGO_TEST_EXIT_MODEL=full (and a -timeout to match), never under -short.
func TestGroupAgainstTheExitModel(t *testing.T) {
	var total mResult
	for _, sc := range scenarios(!testing.Short() && os.Getenv("TEGO_TEST_EXIT_MODEL") == "full") {
		r := explore(sc)
		if r.fail != "" {
			t.Errorf("%v: %s", sc, r.fail)
			continue
		}
		total.traces += r.traces
		total.known += r.known
		total.unknown += r.unknown
		total.residual += r.residual
	}
	t.Logf("MODEL traces=%d known=%d unknown=%d racing-exit residual=%d", total.traces, total.known, total.unknown,
		total.residual)
}
