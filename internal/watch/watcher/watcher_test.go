// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"github.com/attention-span-ai/tego/internal/watch/tree"
	"golang.org/x/sys/unix"
)

// A real run id's shape (internal/ledger), and the cgroup a run gets (identity.UserCgroupPath).
const (
	runA     = "r-0a1b2c3d-0123456789abc-xyz123"
	runB     = "r-0a1b2c3d-0123456789abd-xyz124"
	runACG   = "/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-watch.slice/run-" + runA + ".scope"
	termCG   = "/user.slice/user-1000.slice/user@1000.service/app.slice/gnome-terminal.scope"
	claudeEx = "/home/u/.local/share/claude/versions/2.1.290"
)

// fakeProc is /proc as a map. A process missing from it is one that has exited. Reads are counted.
type fakeProc struct {
	mu    sync.Mutex
	procs map[int]*fproc
	stats int
	// onStat, when set, runs at each Stat call (to change the process between the two reads of one match).
	onStat func(pid, n int)
	// onTasks, when set, runs at each Tasks call, before it answers (to end a process between a scan's two reads).
	onTasks func(pid int)
}

type fproc struct {
	ppid   int
	comm   string
	state  byte
	start  uint64
	exe    string
	argv   []string
	cgroup string
	envRun string
	file   sig.FileID
	// threads is num_threads; 0 reads as 1.
	threads int
	// tgid, when set, makes the entry a thread of process tgid other than its leader: /proc/<tid> and
	// /proc/<tgid>/task/<tid> answer for it, no listing of /proc names it.
	tgid int
}

func newFake() *fakeProc { return &fakeProc{procs: map[int]*fproc{}} }

func (f *fakeProc) add(pid int, p fproc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.state == 0 {
		p.state = 'S'
	}
	if p.start == 0 {
		p.start = uint64(1000 + pid)
	}
	f.procs[pid] = &p
}

func (f *fakeProc) del(pid int) { f.mu.Lock(); delete(f.procs, pid); f.mu.Unlock() }

func (f *fakeProc) get(pid int) (*fproc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.procs[pid]
	if p == nil {
		return nil, fmt.Errorf("proc: pid %d: %w", pid, proc.ErrGone)
	}
	return p, nil
}

func (f *fakeProc) PIDs() ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int
	for pid, p := range f.procs {
		if p.tgid == 0 {
			out = append(out, pid)
		}
	}
	return out, nil
}

// Tasks is process pid's task directory: pid and the thread entries of it.
func (f *fakeProc) Tasks(pid int) (Proc, []int, error) {
	if f.onTasks != nil {
		f.onTasks(pid)
	}
	if _, err := f.get(pid); err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tids := []int{pid}
	for tid, p := range f.procs {
		if p.tgid == pid {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return taskDir{f: f, pid: pid}, tids, nil
}

// taskDir is the fake's /proc/<pid>/task: a thread id of another process is not there.
type taskDir struct {
	f   *fakeProc
	pid int
}

func (d taskDir) in(tid int) error {
	p, err := d.f.get(tid)
	if err != nil {
		return err
	}
	if tid != d.pid && p.tgid != d.pid {
		return fmt.Errorf("proc: pid %d: task %d: %w", d.pid, tid, proc.ErrGone)
	}
	return nil
}

func (d taskDir) PIDs() ([]int, error) { _, tids, err := d.f.Tasks(d.pid); return tids, err }
func (d taskDir) Stat(tid int) (proc.Stat, error) {
	if err := d.in(tid); err != nil {
		return proc.Stat{}, err
	}
	return d.f.Stat(tid)
}
func (d taskDir) Exe(tid int) (string, error) {
	if err := d.in(tid); err != nil {
		return "", err
	}
	return d.f.Exe(tid)
}
func (d taskDir) Argv(tid int) ([]string, error) {
	if err := d.in(tid); err != nil {
		return nil, err
	}
	return d.f.Argv(tid)
}
func (d taskDir) Cgroup(tid int) (string, error) {
	if err := d.in(tid); err != nil {
		return "", err
	}
	return d.f.Cgroup(tid)
}
func (d taskDir) ExeFile(tid int) (sig.FileID, error) {
	if err := d.in(tid); err != nil {
		return sig.FileID{}, err
	}
	return d.f.ExeFile(tid)
}
func (d taskDir) RunID(tid int) (string, error) {
	if err := d.in(tid); err != nil {
		return "", err
	}
	return d.f.RunID(tid)
}
func (d taskDir) Tasks(int) (Proc, []int, error) {
	return nil, nil, errors.New("no task directory under a task's")
}

func (f *fakeProc) Stat(pid int) (proc.Stat, error) {
	f.mu.Lock()
	f.stats++
	n, hook := f.stats, f.onStat
	f.mu.Unlock()
	if hook != nil {
		hook(pid, n)
	}
	p, err := f.get(pid)
	if err != nil {
		return proc.Stat{}, err
	}
	threads := max(p.threads, 1)
	return proc.Stat{PID: pid, Comm: p.comm, State: p.state, PPID: p.ppid, StartTicks: p.start, NumThreads: threads}, nil
}

func (f *fakeProc) Exe(pid int) (string, error) {
	p, err := f.get(pid)
	if err != nil {
		return "", err
	}
	return p.exe, nil
}

func (f *fakeProc) Argv(pid int) ([]string, error) {
	p, err := f.get(pid)
	if err != nil {
		return nil, err
	}
	return p.argv, nil
}

func (f *fakeProc) Cgroup(pid int) (string, error) {
	p, err := f.get(pid)
	if err != nil {
		return "", err
	}
	return p.cgroup, nil
}

func (f *fakeProc) ExeFile(pid int) (sig.FileID, error) {
	p, err := f.get(pid)
	if err != nil {
		return sig.FileID{}, err
	}
	return p.file, nil
}

func (f *fakeProc) RunID(pid int) (string, error) {
	p, err := f.get(pid)
	if err != nil {
		return "", err
	}
	return p.envRun, nil
}

// out collects sightings.
type out struct {
	mu sync.Mutex
	s  []Sighting
}

func (o *out) emit(s Sighting) error { o.mu.Lock(); o.s = append(o.s, s); o.mu.Unlock(); return nil }

func (o *out) kinds() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var k []string
	for _, s := range o.s {
		k = append(k, s.Event)
	}
	return k
}

func (o *out) find(event string, pid int32) *Sighting {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.s {
		if o.s[i].Event == event && o.s[i].PID == pid {
			return &o.s[i]
		}
	}
	return nil
}

func newWatcher(p Proc, o *out, children bool) *Watcher {
	return New(p, Options{Rules: sig.Default(), Emit: o.emit, Children: children,
		Now: func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }})
}

func evExec(pid int32) procconn.Event {
	return procconn.Event{Kind: procconn.Exec, PID: pid, TGID: pid}
}
func evFork(parent, child int32) procconn.Event {
	return procconn.Event{Kind: procconn.Fork, PID: child, TGID: child, ParentTGID: parent}
}
func evExit(pid int32, status uint32) procconn.Event {
	return procconn.Event{Kind: procconn.Exit, PID: pid, TGID: pid, ExitCode: status}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// handle hands evs to w. Over the fake, an exit event first does to /proc what the kernel has done by the time it
// sends one: the task is released, and a leader whose group has other threads stays a zombie that counts them.
func handle(t *testing.T, w *Watcher, evs ...procconn.Event) {
	t.Helper()
	for _, ev := range evs {
		if ev.TimestampNS == 0 {
			ev.TimestampNS = procconn.Monotonic() // filled as handled, after any listing made before: the kernel's clock
		}
		if fp, ok := w.p.(*fakeProc); ok && ev.Kind == procconn.Exit {
			fp.exited(ev)
		}
		must(t, w.Handle(ev))
	}
}

// exited is the fake's /proc once the task ev names has exited.
func (f *fakeProc) exited(ev procconn.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	group := f.procs[int(ev.TGID)]
	if ev.PID != ev.TGID {
		if th := f.procs[int(ev.PID)]; th != nil && th.tgid == int(ev.TGID) {
			delete(f.procs, int(ev.PID))
			if group != nil && group.threads > 1 {
				group.threads--
			}
		}
		return
	}
	if group == nil {
		return
	}
	if group.threads > 1 {
		group.state = 'Z' // the leader exited while other threads of it run
		return
	}
	delete(f.procs, int(ev.TGID))
}

func claudeProc(ppid int, cg, env string) fproc {
	return fproc{ppid: ppid, comm: "claude", exe: claudeEx, argv: []string{"claude", "--resume"}, cgroup: cg, envRun: env}
}

func TestAgentStartedOutsideAnyRun(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500))
	s := o.find(EventAgentStarted, 500)
	if s == nil || len(o.s) != 1 {
		t.Fatalf("sightings: %+v", o.s)
	}
	if s.Rule != "claude" || s.PPID != 400 || s.Exe != claudeEx || s.Seen != SeenExec || s.Session == 0 ||
		s.OutsideGovernedRun == nil || !*s.OutsideGovernedRun || s.RunID != "" || s.Cgroup != termCG || s.Comm != "claude" ||
		len(s.Argv) != 2 || s.Time != "2026-10-06T12:00:00Z" {
		t.Fatalf("agent_started = %+v", s)
	}
}

func TestGovernedAndNot(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cgroup, env  string
		outside      bool
		runID, cgRun string
		note         string
	}{
		{"in a run's cgroup with its id", runACG, runA, false, runA, runA, ""},
		{"in a run's cgroup, the environment stripped", runACG, "", false, "", runA, ""},
		{"in a run's cgroup, another run's id in the environment", runACG, runB, false, runB, runA, ""},
		{"the id inherited but the process left the run", termCG, runA, true, runA, "", "moved out"},
		{"the id forged in a terminal", termCG, runB, true, runB, "", "no run's cgroup"},
		{"no id, no run", termCG, "", true, "", "", ""},
		{"no cgroup readable", "", "", true, "", "", ""},
		{"a docker run's container parent", "/tego/claude/" + runA + "/abc123", "", false, "", runA, ""},
		{"a scope that is not a run id", "/app.slice/run-notarun.scope", "", true, "", "", ""},
		{"an adoption's scope", "/tego.slice/tego-adopt-claude.slice/adopt-" + runA + ".scope", "", false, "", runA, ""},
		// A user's own cgroup with a run's name, where tego makes none: no run holds the agent.
		{"a run's name in a user's own cgroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/run-" + runA + ".scope",
			"", true, "", "", ""},
		{"an adoption's name in a user's own cgroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/adopt-" + runA +
			".scope", "", true, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, o := newFake(), &out{}
			fp.add(500, claudeProc(400, tc.cgroup, tc.env))
			handle(t, newWatcher(fp, o, false), evExec(500))
			s := o.find(EventAgentStarted, 500)
			if s == nil || *s.OutsideGovernedRun != tc.outside || s.RunID != tc.runID || s.RunCgroupID != tc.cgRun || !strings.Contains(s.Note, tc.note) ||
				s.Start == 0 {
				t.Fatalf("agent_started = %+v, want outside=%v run_id=%q cgroup run=%q note~%q", s, tc.outside, tc.runID, tc.cgRun, tc.note)
			}
		})
	}
}

func TestNotAnAgentIsNotReported(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, fproc{ppid: 1, comm: "bash", exe: "/usr/bin/bash", argv: []string{"-bash"}})
	fp.add(501, fproc{ppid: 500, comm: "node", exe: "/usr/bin/node", argv: []string{"node", "/srv/app.js"}})
	w := newWatcher(fp, o, true)
	handle(t, w, evExec(500), evFork(500, 501), evExec(501), evExit(501, 0), evExit(500, 0))
	if len(o.s) != 0 || w.Sessions() != 0 {
		t.Fatalf("sightings for a non-agent: %+v", o.s)
	}
}

func TestSessionFollowsDescendantsAndEndsAtTheRootsExit(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500))
	// The agent runs git (fork, exec, exit); git forks a helper that is still alive when the agent exits.
	fp.add(501, fproc{ppid: 500, comm: "git", exe: "/usr/bin/git", argv: []string{"git", "status"}})
	fp.add(502, fproc{ppid: 501, comm: "git-helper", exe: "/usr/lib/git-core/helper", argv: []string{"helper"}})
	handle(t, w, evFork(500, 501), evExec(501), evFork(501, 502), evExec(502), evExit(501, 0<<8))
	// An unrelated process forks and exits meanwhile.
	handle(t, w, evFork(1, 900), evExec(900), evExit(900, 0))
	handle(t, w, evExit(500, 3<<8))
	if got := o.kinds(); strings.Join(got, ",") != "agent_started,agent_exited" {
		t.Fatalf("events = %v", got)
	}
	x := o.find(EventAgentExited, 500)
	if x == nil || x.ExitCode == nil || *x.ExitCode != 3 || x.Signal != 0 || x.Descendants != 2 || x.StillRunning != 1 || x.Rule != "claude" || x.Exe != claudeEx {
		t.Fatalf("agent_exited = %+v", x)
	}
	if w.Sessions() != 1 {
		t.Fatal("the session ended while a descendant ran")
	}
	handle(t, w, evExit(502, 0))
	if w.Sessions() != 0 {
		t.Fatal("the session did not end with its last process")
	}
	if len(o.s) != 2 {
		t.Fatalf("a quiet descendant's exit was reported without Children: %v", o.kinds())
	}
}

func TestChildrenAreReportedWhenAsked(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, true)
	handle(t, w, evExec(500))
	fp.add(501, fproc{ppid: 500, comm: "git", exe: "/usr/bin/git", argv: []string{"git", "status"}})
	handle(t, w, evFork(500, 501), evExec(501), evExit(501, 128<<8), evExit(500, 0))
	want := "agent_started,child_forked,child_exec,child_exited,agent_exited"
	if got := strings.Join(o.kinds(), ","); got != want {
		t.Fatalf("events = %s, want %s", got, want)
	}
	c := o.find(EventChildExec, 501)
	if c.Exe != "/usr/bin/git" || len(c.Argv) != 2 || c.Session != o.find(EventAgentStarted, 500).Session {
		t.Fatalf("child_exec = %+v", c)
	}
	if e := o.find(EventChildExited, 501); *e.ExitCode != 128 {
		t.Fatalf("child_exited = %+v", e)
	}
	// The agent's own exec of another program is not a child.
	o2 := &out{}
	fp.add(600, claudeProc(400, termCG, ""))
	w2 := newWatcher(fp, o2, true)
	handle(t, w2, evExec(600), evExec(600))
	if len(o2.s) != 1 {
		t.Fatalf("the root's re-exec was reported: %v", o2.kinds())
	}
}

func TestSignalExit(t *testing.T) {
	for _, tc := range []struct {
		raw        uint32
		code, sigN int
	}{{0, 0, 0}, {1 << 8, 1, 0}, {255 << 8, 255, 0}, {9, 0, 9}, {11 | 0x80, 0, 11}, {2, 0, 2}} {
		if c, s := procconn.SplitStatus(tc.raw); c != tc.code || s != tc.sigN {
			t.Errorf("SplitStatus(%#x) = %d, %d; want %d, %d", tc.raw, c, s, tc.code, tc.sigN)
		}
	}
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500), evExit(500, 9))
	if x := o.find(EventAgentExited, 500); x == nil || x.Signal != 9 || *x.ExitCode != 0 {
		t.Fatalf("agent_exited = %+v", x)
	}
}

// A process that exits before /proc is read is no agent the watcher can name: nothing is reported, and the
// watcher goes on.
func TestExecOfAProcessThatAlreadyExited(t *testing.T) {
	fp, o := newFake(), &out{}
	w := newWatcher(fp, o, true)
	handle(t, w, evExec(500), evExit(500, 0))
	if len(o.s) != 0 || w.Stats().Skipped != 1 || w.Sessions() != 0 {
		t.Fatalf("sightings %v, stats %+v", o.kinds(), w.Stats())
	}
	// And one that is a zombie, or a kernel thread with no exe.
	fp.add(501, fproc{ppid: 1, comm: "claude", exe: claudeEx, argv: []string{"claude"}, state: 'Z'})
	fp.add(502, fproc{ppid: 2, comm: "claude", exe: "", argv: nil})
	handle(t, w, evExec(501), evExec(502))
	if len(o.s) != 0 || w.Stats().Skipped != 3 {
		t.Fatalf("sightings %v, stats %+v", o.kinds(), w.Stats())
	}
}

// The pid is reused between the two reads of its start time: what was read belongs to no one process.
func TestAReadTornByPidReuseIsDropped(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	fp.onStat = func(pid, n int) {
		if n == 2 { // between the first Stat and the second
			fp.mu.Lock()
			fp.procs[500].start = 99999
			fp.mu.Unlock()
		}
	}
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500))
	if len(o.s) != 0 || w.Stats().Skipped != 1 {
		t.Fatalf("sightings %v, stats %+v", o.kinds(), w.Stats())
	}
}

func TestThreadsAreNotProcesses(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, true)
	handle(t, w, evExec(500))
	// clone(CLONE_THREAD): a child pid in the parent's own thread group. It costs no read of /proc.
	reads := fp.stats
	handle(t, w, procconn.Event{Kind: procconn.Fork, PID: 510, TGID: 500, ParentTGID: 500})
	if fp.stats != reads {
		t.Fatalf("a new thread cost %d read(s) of /proc", fp.stats-reads)
	}
	// A worker thread exits: the process is still there.
	handle(t, w, procconn.Event{Kind: procconn.Exit, PID: 510, TGID: 500, ExitCode: 0})
	if w.Sessions() != 1 || len(o.s) != 1 {
		t.Fatalf("a thread was taken for a process: %v", o.kinds())
	}
	// A thread of the agent that execs (the kernel makes it the leader): it is the same process.
	handle(t, w, procconn.Event{Kind: procconn.Exec, PID: 510, TGID: 500})
	if len(o.s) != 1 {
		t.Fatalf("a re-exec made a second agent: %v", o.kinds())
	}
}

func TestOneSessionForAWrapperAndItsChild(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, fproc{ppid: 400, comm: "node", exe: "/usr/bin/node", argv: []string{"node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"}, cgroup: termCG})
	fp.add(501, fproc{ppid: 500, comm: "codex", exe: "/opt/codex/vendor/codex", argv: []string{"codex"}, cgroup: termCG})
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500), evFork(500, 501), evExec(501))
	if got := o.kinds(); len(got) != 1 || got[0] != EventAgentStarted || w.Sessions() != 1 || w.Stats().Matched != 1 {
		t.Fatalf("events %v, sessions %d", got, w.Sessions())
	}
}

func TestAPidReusedAfterTheAgentIsANewSession(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	handle(t, w, evExec(500), evExit(500, 0))
	fp.add(500, claudeProc(401, termCG, "")) // the pid comes round again
	handle(t, w, evExec(500))
	if strings.Join(o.kinds(), ",") != "agent_started,agent_exited,agent_started" || o.s[0].Session == o.s[2].Session {
		t.Fatalf("events = %v", o.kinds())
	}
}

func TestSessionCapIsReported(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	fp.add(600, claudeProc(400, termCG, ""))
	w := New(fp, Options{Rules: sig.Default(), Emit: o.emit, Limits: tree.Limits{MaxSessions: 1}})
	handle(t, w, evExec(500), evExec(600))
	d := o.find(EventSessionDrop, 500)
	if d == nil || d.Reason != tree.DropMaxSessions || d.Rule != "claude" || !strings.Contains(d.Note, "no longer followed") || w.Stats().Dropped != 1 || w.Sessions() != 1 {
		t.Fatalf("events %v, drop %+v", o.kinds(), d)
	}
	// The dropped agent's exit is not reported: it is no longer followed, and the line above said so.
	handle(t, w, evExit(500, 0))
	if o.find(EventAgentExited, 500) != nil {
		t.Fatal("a dropped session reported an exit")
	}
}

func TestProcessCapIsReported(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := New(fp, Options{Rules: sig.Default(), Emit: o.emit, Limits: tree.Limits{MaxPIDs: 2}})
	handle(t, w, evExec(500), evFork(500, 501), evFork(500, 502))
	u := o.find(EventUntracked, 502)
	if u == nil || u.Untracked != 1 || w.Stats().Untracked != 1 {
		t.Fatalf("events %v", o.kinds())
	}
	handle(t, w, evExit(500, 0))
	if x := o.find(EventAgentExited, 500); x == nil || x.Untracked != 1 {
		t.Fatalf("agent_exited = %+v", x)
	}
}

// What a scan at the start finds: an agent that predates the watcher, and the processes under it.
func TestScanFindsAgentsAlreadyRunning(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(1, fproc{ppid: 0, comm: "systemd", exe: "/usr/lib/systemd/systemd", argv: []string{"/sbin/init"}, start: 1})
	fp.add(300, fproc{ppid: 1, comm: "bash", exe: "/usr/bin/bash", argv: []string{"-bash"}, start: 50})
	fp.add(500, fproc{ppid: 300, comm: "node", exe: "/usr/bin/node", argv: []string{"node", "/lib/node_modules/@openai/codex/bin/codex.js"}, cgroup: runACG, envRun: runA, start: 60})
	fp.add(501, fproc{ppid: 500, comm: "codex", exe: "/opt/codex", argv: []string{"codex"}, cgroup: runACG, start: 61})
	fp.add(502, fproc{ppid: 501, comm: "sh", exe: "/bin/sh", argv: []string{"sh", "-c", "make"}, cgroup: runACG, start: 62})
	w := newWatcher(fp, o, false)
	must(t, w.Scan())
	if got := strings.Join(o.kinds(), ","); got != "agent_started" || w.Sessions() != 1 {
		t.Fatalf("events %s", got)
	}
	s := o.s[0]
	if s.PID != 500 || s.Seen != SeenScan || *s.OutsideGovernedRun || s.RunCgroupID != runA || s.Rule != "codex" {
		t.Fatalf("agent_started = %+v", s)
	}
	// Its descendants are followed: when the agent exits, two of its processes are counted, and one is still running.
	handle(t, w, evExit(502, 0), evExit(500, 0))
	x := o.find(EventAgentExited, 500)
	if x == nil || x.Descendants != 2 || x.StillRunning != 1 {
		t.Fatalf("agent_exited = %+v", x)
	}
}

// scripted is a Source: each step is a batch of events or an error; when they are gone it blocks until Close.
type scripted struct {
	mu     sync.Mutex
	steps  []step
	closed chan struct{}
	once   sync.Once
}

type step struct {
	before func() // runs before the step is delivered: the world moves on
	evs    []procconn.Event
	err    error
}

func newScripted(steps ...step) *scripted {
	return &scripted{steps: steps, closed: make(chan struct{})}
}

func (s *scripted) Recv() ([]procconn.Event, error) {
	s.mu.Lock()
	if len(s.steps) == 0 {
		s.mu.Unlock()
		<-s.closed
		return nil, procconn.ErrClosed
	}
	st := s.steps[0]
	s.steps = s.steps[1:]
	s.mu.Unlock()
	if st.before != nil {
		st.before()
	}
	return st.evs, st.err
}

func (s *scripted) remaining() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.steps) }

func (s *scripted) Close() error { s.once.Do(func() { close(s.closed) }); return nil }

func runUntilDrained(t *testing.T, w *Watcher, src interface {
	Source
	remaining() int
}) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, src) }()
	deadline := time.After(10 * time.Second)
	for src.remaining() != 0 {
		select {
		case <-deadline:
			t.Fatal("the watcher did not consume the script")
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(20 * time.Millisecond) // the last step is being handled
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return when its context ended")
		return nil
	}
}

// The proc connector drops events (ENOBUFS): the watcher reads /proc once more and catches up on what it missed.
func TestOverrunResynchronises(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	fp.add(501, fproc{ppid: 500, comm: "git", exe: "/usr/bin/git", argv: []string{"git"}})
	fp.add(502, fproc{ppid: 500, comm: "make", exe: "/usr/bin/make", argv: []string{"make"}})
	w := newWatcher(fp, o, true)
	src := newScripted(
		step{evs: []procconn.Event{evExec(500), evFork(500, 501), evFork(500, 502)}},
		// While the socket overflowed: 501 exited, 502 exec'd and forked a compiler (both events lost), a second
		// agent started in another terminal, and the first agent's own start of a codex went by.
		step{before: func() {
			fp.del(501)
			fp.add(503, fproc{ppid: 502, comm: "cc1", exe: "/usr/lib/gcc/cc1", argv: []string{"cc1"}})
			fp.add(700, fproc{ppid: 400, comm: "codex", exe: "/opt/codex", argv: []string{"codex"}, cgroup: termCG})
		}, err: overrun()},
		// After it, events flow again: the lost child's compiler exits, and so does the agent (gone from /proc by the
		// time their events are read).
		step{before: func() { fp.del(503); fp.del(502); fp.del(500) },
			evs: []procconn.Event{evExit(503, 0), evExit(502, 0), evExit(500, 0)}},
	)
	must(t, runUntilDrained(t, w, src))
	want := "agent_started,child_forked,child_forked,resync,child_exited,child_forked,agent_started,child_exited,child_exited,agent_exited"
	if got := strings.Join(o.kinds(), ","); got != want {
		t.Fatalf("events = %s\n   want   %s", got, want)
	}
	st := w.Stats()
	if st.Overruns != 1 || st.Rescans != 2 {
		t.Fatalf("stats = %+v", st)
	}
	late := o.find(EventAgentStarted, 700)
	if late == nil || late.Seen != SeenScan || late.Rule != "codex" || !*late.OutsideGovernedRun {
		t.Fatalf("the agent started during the overrun: %+v", late)
	}
	if x := o.find(EventAgentExited, 500); x == nil || x.Descendants != 3 || x.StillRunning != 0 {
		t.Fatalf("agent_exited = %+v", x)
	}
	if w.Sessions() != 1 { // the late codex is still running
		t.Fatalf("sessions = %d", w.Sessions())
	}
}

// A root whose exit event was lost is found gone by the scan, with its status unknown.
func TestOverrunFindsALostRootExit(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	src := newScripted(
		step{evs: []procconn.Event{evExec(500)}},
		step{before: func() { fp.del(500) }, err: overrun()},
	)
	must(t, runUntilDrained(t, w, src))
	x := o.find(EventAgentExited, 500)
	if x == nil || x.ExitCode != nil || !strings.Contains(x.Note, "status is unknown") || w.Sessions() != 0 {
		t.Fatalf("events %v, exited %+v", o.kinds(), x)
	}
	if r := o.find(EventResync, 0); r == nil || !strings.Contains(r.Note, "dropped") {
		t.Fatalf("no resync line: %v", o.kinds())
	}
}

func TestOverrunWithAReusedPid(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	fp.add(501, fproc{ppid: 500, comm: "git", exe: "/usr/bin/git", argv: []string{"git"}, start: 2000})
	w := newWatcher(fp, o, true)
	src := newScripted(
		step{evs: []procconn.Event{evExec(500), evFork(500, 501)}},
		// 501 exited and its pid came back as a child of an unrelated shell.
		step{before: func() {
			fp.add(501, fproc{ppid: 300, comm: "ls", exe: "/bin/ls", argv: []string{"ls"}, start: 9000})
		}, err: overrun()},
	)
	must(t, runUntilDrained(t, w, src))
	if e := o.find(EventChildExited, 501); e == nil {
		t.Fatalf("the reused pid was kept as a descendant: %v", o.kinds())
	}
	// The unrelated process that has the pid now is nobody's business: its exit is not reported.
	before := len(o.s)
	handle(t, w, evExit(501, 0))
	if len(o.s) != before {
		t.Fatalf("the reused pid's exit was reported: %v", o.kinds())
	}
}

func overrun() error { return fmt.Errorf("procconn: recvfrom: %w", unix.ENOBUFS) }

func TestRunStopsWhenTheOutputIsGone(t *testing.T) {
	fp := newFake()
	fp.add(500, claudeProc(400, termCG, ""))
	boom := errors.New("write: broken pipe")
	w := New(fp, Options{Rules: sig.Default(), Emit: func(Sighting) error { return boom }})
	src := newScripted(step{evs: []procconn.Event{evExec(500)}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Run(ctx, src); !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the output's error", err)
	}
}

func TestRunReturnsASourceError(t *testing.T) {
	w := newWatcher(newFake(), &out{}, false)
	bad := errors.New("procconn: recvfrom: bad file descriptor")
	if err := w.Run(context.Background(), newScripted(step{err: bad})); !errors.Is(err, bad) {
		t.Fatalf("Run = %v", err)
	}
}

func TestJSONLinesAndText(t *testing.T) {
	var jb, tb bytes.Buffer
	outside := true
	code := 0
	s := Sighting{Event: EventAgentStarted, Time: "2026-10-06T12:00:00Z", Session: 1, PID: 5, PPID: 4, Rule: "claude", Seen: SeenExec,
		Exe: "/x/\x1b[31mclaude", Argv: []string{"claude", "a b", "\x1b]0;pwned\x07"}, OutsideGovernedRun: &outside, ExitCode: &code}
	must(t, JSONLines(&jb)(s))
	must(t, Text(&tb)(s))
	var back Sighting
	if err := json.Unmarshal(bytes.TrimSpace(jb.Bytes()), &back); err != nil || back.PID != 5 || !*back.OutsideGovernedRun || back.Argv[2] != "\x1b]0;pwned\x07" {
		t.Fatalf("json line %q: %v %+v", jb.String(), err, back)
	}
	if strings.Count(jb.String(), "\n") != 1 {
		t.Fatalf("a JSON line is one line: %q", jb.String())
	}
	line := tb.String()
	if strings.ContainsAny(strings.TrimSuffix(line, "\n"), "\x1b\x07") || strings.Count(line, "\n") != 1 ||
		!strings.Contains(line, "OUTSIDE-GOVERNED-RUN") || !strings.Contains(line, "rule=claude") {
		t.Fatalf("text line %q", line)
	}
	governed := false
	g := Sighting{Event: EventAgentStarted, Time: "t", PID: 5, OutsideGovernedRun: &governed, RunCgroupID: runA}
	if l := g.TextLine(); !strings.Contains(l, "governed-by="+runA) || strings.Contains(l, "OUTSIDE") {
		t.Fatalf("governed text line %q", l)
	}
}

func TestCapArgv(t *testing.T) {
	big := strings.Repeat("x", 3000)
	got, trunc := capArgv([]string{"a", big, big, "z"})
	if len(got) != 2 || !trunc {
		t.Fatalf("capArgv kept %d args, truncated=%v", len(got), trunc)
	}
	if got, trunc := capArgv([]string{"a", "b"}); len(got) != 2 || trunc {
		t.Fatalf("a short argv was cut: %v %v", got, trunc)
	}
	if got, trunc := capArgv([]string{strings.Repeat("y", 10000)}); len(got) != 1 || len(got[0]) != maxArgvBytes || !trunc {
		t.Fatalf("one huge argument: %d %v", len(got[0]), trunc)
	}
}

func TestRunIDFromEnviron(t *testing.T) {
	for env, want := range map[string]string{
		"": "", "A=1\x00B=2\x00": "", "A=1\x00TEGO_RUN_ID=" + runA + "\x00B=2\x00": runA,
		"TEGO_RUN_ID=" + runA: runA, "XTEGO_RUN_ID=" + runB + "\x00": "", "TEGO_RUN_ID_X=" + runB: "",
	} {
		if got := runIDFromEnviron([]byte(env)); got != want {
			t.Errorf("runIDFromEnviron(%q) = %q, want %q", env, got, want)
		}
	}
}

// drainSource is a scripted Source that also holds events a Drain hands over.
type drainSource struct {
	*scripted
	queued []procconn.Event
	drains int
}

func (d *drainSource) Drain() ([]procconn.Event, error) {
	d.drains++
	q := d.queued
	d.queued = nil
	return q, nil
}

// After an overrun the events that survived are read BEFORE /proc, so that the scan is newer than all of them. A
// fork that was queued before the overflow, whose child has since exited with its exit event dropped, is applied
// and then undone by the scan; applied after the scan it would stay followed for ever.
func TestOverrunReadsTheSurvivorsBeforeTheScan(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, true)
	src := &drainSource{
		scripted: newScripted(
			step{evs: []procconn.Event{evExec(500)}},
			step{err: overrun()},
		),
		queued: []procconn.Event{evFork(500, 503)}, // 503 is not in /proc: it exited, and its exit was dropped
	}
	must(t, runUntilDrained(t, w, src))
	if src.drains != 1 || w.Processes() != 1 || w.Sessions() != 1 {
		t.Fatalf("drains %d, followed %d process(es) in %d session(s); events %v", src.drains, w.Processes(), w.Sessions(), o.kinds())
	}
	if got := strings.Join(o.kinds(), ","); got != "agent_started,child_forked,resync,child_exited" {
		t.Fatalf("events = %s", got)
	}
}

// A process reported twice is one agent: the second report starts no session and says nothing.
func TestConsideringTheSameProcessTwiceReportsOnce(t *testing.T) {
	fp, o := newFake(), &out{}
	fp.add(500, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	f, err := w.facts(500)
	must(t, err)
	must(t, w.consider(f, SeenExec))
	must(t, w.consider(f, SeenScan))
	if len(o.s) != 1 || w.Stats().Matched != 1 || w.Sessions() != 1 {
		t.Fatalf("events %v, stats %+v", o.kinds(), w.Stats())
	}
}

// TestSnapshotKeepsAProcessWhoseLeaderExited: a process whose main thread has exited while other threads of it run
// reads as a zombie in /proc/<pid>/stat, with its live threads in num_threads; it is alive, and the children its
// threads fork name it their parent, so the tree keeps it. A zombie whose group has ended is left out (the same test
// in the adoption's walk).
func TestSnapshotKeepsAProcessWhoseLeaderExited(t *testing.T) {
	fp := newFake()
	fp.add(500, fproc{ppid: 1, comm: "python3", exe: "/usr/bin/python3", state: 'Z', threads: 2, start: 10})
	fp.add(501, fproc{ppid: 500, comm: "sleep", exe: "/usr/bin/sleep", state: 'S', start: 11})
	fp.add(502, fproc{ppid: 1, comm: "dead", exe: "/usr/bin/dead", state: 'Z', threads: 1, start: 12})
	w := New(fp, Options{Rules: sig.Default(), Emit: func(Sighting) error { return nil }})
	snap, err := w.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := map[int32]bool{}
	for _, e := range snap {
		got[e.TGID] = true
	}
	if !got[500] || !got[501] || got[502] {
		t.Errorf("snapshot = %+v, want 500 (its leader exited, a thread runs) and its child 501, not the zombie 502", snap)
	}
}

// TestScanFindsAnAgentWhoseLeaderExited: an agent whose main thread exited before the guard looked reads as a zombie
// whose program, arguments and environment are gone from /proc/<pid>, while its thread runs the agent. The scan used
// to skip it as gone, uncounted, so `tego agents --follow --adopt` never adopted it. It is matched through the
// thread, with the thread's cgroup and run id, as one process.
func TestScanFindsAnAgentWhoseLeaderExited(t *testing.T) {
	fp, o := newFake(), &out{}
	leader := claudeProc(400, "/where-the-leader-died", "")
	leader.state, leader.threads, leader.exe, leader.argv = 'Z', 2, "", nil
	fp.add(500, leader)
	thread := claudeProc(400, runACG, runA)
	thread.tgid, thread.threads = 500, 2
	fp.add(5001, thread)
	fp.add(600, claudeProc(400, termCG, ""))
	w := newWatcher(fp, o, false)
	must(t, w.rescan(false))
	s := o.find(EventAgentStarted, 500)
	if s == nil || s.Exe != claudeEx || len(s.Argv) != 2 || s.Cgroup != runACG || s.RunID != runA || s.Seen != SeenScan {
		t.Fatalf("agent_started for 500 = %+v, want the agent read through thread 5001 (sightings %+v)", s, o.s)
	}
	if o.find(EventAgentStarted, 5001) != nil || o.find(EventAgentStarted, 600) == nil {
		t.Errorf("sightings %v: want 500 and 600, never the thread 5001 as a process of its own", o.kinds())
	}
	// The thread exits while it is read and its id names a new task: what was read may be another's, and it is gone.
	reads := 0
	fp.onStat = func(pid, _ int) {
		if pid != 5001 {
			return
		}
		if reads++; reads == 2 {
			fp.mu.Lock()
			fp.procs[5001].start++
			fp.mu.Unlock()
		}
	}
	if f, err := w.facts(500); !errors.Is(err, proc.ErrGone) {
		t.Errorf("facts(500) through a thread reused mid-read = %+v, %v; want ErrGone", f, err)
	}
}
