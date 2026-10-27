// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// fakeProc is one process of the fake machine.
type fakeProc struct {
	ppid    int
	start   uint64
	state   byte
	comm    string
	exe     string
	argv    []string
	cgroup  string
	uid     [3]int
	gid     [3]int
	cwd     string
	fds     []FD
	tgid    int
	exeFile FileID
	cgns    uint64
	pidns   uint64
	// thread says the entry is a task of process tgid other than its leader: /proc/<tid> answers for it, but no
	// listing of /proc names it (PIDs), as the kernel does.
	thread bool
}

// machine is a fake /proc and cgroup filesystem in one: moving a pid into a cgroup directory changes what its
// /proc/<pid>/cgroup says, as the kernel does. A process whose leader exited while a thread of it runs (exitLeader)
// behaves as a guest of 6.17 showed: its stat says Z with the group's thread count, its leader stays in the cgroup it
// was in (its /proc/<pid>/cgroup and cgroup.procs say so) while a write of its pid moves its live threads only, which
// only cgroup.threads lists where they are.
type machine struct {
	mu    sync.Mutex
	mount string
	procs map[int]*fakeProc
	// cgroups are the existing cgroup directories, relative to the mount.
	cgroups map[string]bool
	frozen  map[string]bool
	// refuse makes Add into the named directory (absolute) fail with the errno.
	refuse map[string]syscall.Errno
	// onAdd runs after each successful Add, with the lock released: a test forks or exits a process there.
	onAdd func(m *machine, dir string, pid int)
	// statHook runs before each Stat: a test replaces a process under its pid there.
	statHook func(m *machine, pid int)
	// exited are the pids whose Watch reports exited.
	exited map[int]bool
	adds   []string
	// readCount counts Stat calls per pid.
	statCalls map[int]int
}

func newMachine() *machine {
	return &machine{mount: "/sys/fs/cgroup", procs: map[int]*fakeProc{}, cgroups: map[string]bool{"/": true},
		frozen: map[string]bool{}, refuse: map[string]syscall.Errno{}, exited: map[int]bool{}, statCalls: map[int]int{}}
}

// add puts a process on the machine, in cgroup cg (relative), creating the cgroup.
func (m *machine) add(pid, ppid int, cg, exe string, uid int) *fakeProc {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := &fakeProc{ppid: ppid, start: uint64(1000 + pid), state: 'S', comm: filepath.Base(exe), exe: exe,
		argv: []string{exe}, cgroup: cg, uid: [3]int{uid, uid, uid}, gid: [3]int{uid, uid, uid}, cwd: "/home/u", tgid: pid, exeFile: FileID{Dev: 1, Ino: uint64(pid)},
		cgns: 7, pidns: 8}
	m.procs[pid] = p
	m.cgroups[cg] = true
	return p
}

// exitLeader ends process pid's leader while a thread of it, tid, runs on, as pthread_exit in main does: the leader
// is a zombie with no program, the thread runs pid's program in its cgroup.
func (m *machine) exitLeader(pid, tid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.procs[pid]
	th := *p
	th.thread, th.start, th.ppid = true, p.start+1, p.ppid
	m.procs[tid] = &th
	p.state, p.exe, p.argv, p.fds = 'Z', "", nil, nil
}

// liveThreads is how many tasks of process pid are alive, the leader included unless it is a zombie; the lock is held.
func (m *machine) liveThreads(pid int) int {
	n := 0
	for _, q := range m.procs {
		if (q.tgid == pid || q == m.procs[pid]) && q.state != 'Z' && q.state != 'X' {
			n++
		}
	}
	return n
}

func (m *machine) env() Env { return Env{Proc: m, FS: m, Live: m, Mount: m.mount} }

func (m *machine) cgroupOf(pid int) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[pid]; ok {
		return p.cgroup
	}
	return ""
}

func (m *machine) get(pid int) (*fakeProc, error) {
	p, ok := m.procs[pid]
	if !ok {
		return nil, fmt.Errorf("pid %d: %w", pid, proc.ErrGone)
	}
	return p, nil
}

func (m *machine) PIDs() ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []int
	for pid, p := range m.procs {
		if !p.thread {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out, nil
}

func (m *machine) Tasks(pid int) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.get(pid); err != nil {
		return nil, err
	}
	out := []int{pid}
	for tid, q := range m.procs {
		if q.thread && q.tgid == pid {
			out = append(out, tid)
		}
	}
	sort.Ints(out)
	return out, nil
}

func (m *machine) Stat(pid int) (proc.Stat, error) {
	if m.statHook != nil {
		m.statHook(m, pid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statCalls[pid]++
	p, err := m.get(pid)
	if err != nil {
		return proc.Stat{}, err
	}
	// num_threads counts the group's tasks not yet released: its live ones, and a zombie leader until it is reaped.
	threads := 1
	if l, ok := m.procs[p.tgid]; ok {
		threads = m.liveThreads(p.tgid)
		if l.state == 'Z' {
			threads++
		}
	}
	return proc.Stat{PID: pid, Comm: p.comm, State: p.state, PPID: p.ppid, StartTicks: p.start, NumThreads: threads}, nil
}

func (m *machine) Exe(pid int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return "", err
	}
	return p.exe, nil
}

func (m *machine) Argv(pid int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return nil, err
	}
	return p.argv, nil
}

func (m *machine) Cgroup(pid int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return "", err
	}
	return p.cgroup, nil
}

func (m *machine) Status(pid int) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return Status{}, err
	}
	return Status{Tgid: p.tgid, UID: p.uid, GID: p.gid}, nil
}

func (m *machine) Cwd(pid int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return "", err
	}
	return p.cwd, nil
}

func (m *machine) FDs(pid int) ([]FD, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return nil, err
	}
	return append([]FD(nil), p.fds...), nil
}

func (m *machine) ExeFile(pid int) (FileID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return FileID{}, err
	}
	return p.exeFile, nil
}

func (m *machine) Namespace(pid int, kind string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.get(pid)
	if err != nil {
		return 0, err
	}
	if kind == "cgroup" {
		return p.cgns, nil
	}
	return p.pidns, nil
}

func (m *machine) rel(dir string) string {
	r := strings.TrimPrefix(dir, m.mount)
	if r == "" {
		return "/"
	}
	return r
}

func (m *machine) Add(dir string, pid int) error {
	m.mu.Lock()
	if e, ok := m.refuse[dir]; ok {
		m.mu.Unlock()
		return e
	}
	rel := m.rel(dir)
	if !m.cgroups[rel] {
		m.mu.Unlock()
		return syscall.ENOENT
	}
	p, ok := m.procs[pid]
	if !ok {
		m.mu.Unlock()
		return syscall.ESRCH
	}
	// The write moves the pid's whole thread group, the leader's live tasks: a leader that exited stays.
	leader := pid
	if p.thread {
		leader = p.tgid
	}
	for tid, q := range m.procs {
		if (tid == leader || q.thread && q.tgid == leader) && q.state != 'Z' && q.state != 'X' {
			q.cgroup = rel
		}
	}
	m.adds = append(m.adds, fmt.Sprintf("%d>%s", pid, rel))
	hook := m.onAdd
	m.mu.Unlock()
	if hook != nil {
		hook(m, dir, pid)
	}
	return nil
}

func (m *machine) Procs(dir string) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rel := m.rel(dir)
	if !m.cgroups[rel] {
		return nil, syscall.ENOENT
	}
	var out []int
	for pid, p := range m.procs {
		if p.cgroup == rel && !p.thread {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out, nil
}

func (m *machine) Threads(dir string) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rel := m.rel(dir)
	if !m.cgroups[rel] {
		return nil, syscall.ENOENT
	}
	var out []int
	for tid, p := range m.procs {
		if p.cgroup == rel && p.state != 'Z' && p.state != 'X' {
			out = append(out, tid)
		}
	}
	sort.Ints(out)
	return out, nil
}

func (m *machine) Freeze(dir string, frozen bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen[m.rel(dir)] = frozen
	return nil
}

func (m *machine) Exists(dir string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cgroups[m.rel(dir)]
}

type fakeWatch struct {
	m   *machine
	pid int
}

func (m *machine) Watch(pid int) (Watch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.procs[pid]; !ok {
		return nil, syscall.ESRCH
	}
	return fakeWatch{m: m, pid: pid}, nil
}

func (w fakeWatch) Exited() bool {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	return w.m.exited[w.pid]
}

func (fakeWatch) Close() error { return nil }

// terminal is the usual fake: systemd (1), a user manager, a terminal holding a shell (100), the agent (200, the
// shell's child) and its children, and a sibling tab's shell (300), all of uid 1000 in one session scope, and the
// adopter's own process (900) elsewhere.
const session = "/user.slice/user-1000.slice/session-2.scope"

func terminal() *machine {
	m := newMachine()
	m.add(1, 0, "/init.scope", "/usr/lib/systemd/systemd", 0)
	m.add(50, 1, "/user.slice/user-1000.slice/user@1000.service/init.scope", "/usr/lib/systemd/systemd", 1000)
	m.add(90, 1, session, "/usr/sbin/sshd", 0)
	m.add(100, 90, session, "/usr/bin/bash", 1000)
	m.add(200, 100, session, "/usr/bin/node", 1000)
	m.add(201, 200, session, "/usr/bin/bash", 1000)
	m.add(202, 201, session, "/usr/bin/git", 1000)
	m.add(300, 90, session, "/usr/bin/bash", 1000)
	m.add(900, 1, "/system.slice/tego-guard.service", "/usr/local/bin/tego", 0)
	m.cgroups["/tego.slice/tego-a.slice/adopt-x.scope"] = true
	return m
}

const dest = "/sys/fs/cgroup/tego.slice/tego-a.slice/adopt-x.scope"
const destRel = "/tego.slice/tego-a.slice/adopt-x.scope"

func mustIdentify(m *machine, pid int) Process {
	p, err := Identify(m, pid)
	if err != nil {
		panic(err)
	}
	return p
}

func pidsOf(ps []Process) []int {
	var out []int
	for _, p := range ps {
		out = append(out, p.PID)
	}
	return out
}
