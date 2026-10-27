// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestMembersIsTheAgentsTreeAndNothingElse(t *testing.T) {
	m := terminal()
	// A child the agent placed in a cgroup of its own (systemd-run --scope), and that child's own child: neither is
	// followed. And a daemon the agent started, which outlived its parent and was reparented to init: only the caller
	// that followed it by fork events can name it (extra).
	m.add(203, 200, "/user.slice/user-1000.slice/user@1000.service/app.slice/run-x.scope", "/usr/bin/sleep", 1000)
	m.add(204, 203, "/user.slice/user-1000.slice/user@1000.service/app.slice/run-x.scope", "/usr/bin/sleep", 1000)
	m.add(205, 1, session, "/usr/bin/node", 1000)
	root := mustIdentify(m, 200)
	members, skipped, err := Members(m, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(members); !reflect.DeepEqual(got, []int{200, 201, 202}) {
		t.Errorf("members = %v, want the agent and its two descendants [200 201 202]", got)
	}
	if len(skipped) != 1 || skipped[0].PID != 203 || !strings.Contains(skipped[0].Why, SkipOtherCgroup) {
		t.Errorf("skipped = %+v, want 203 in another cgroup", skipped)
	}
	members, _, err = Members(m, root, []Identity{{PID: 205, Start: 1205}, {PID: 300, Start: 9}})
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(members); !reflect.DeepEqual(got, []int{200, 205, 201, 202}) {
		t.Errorf("members with a followed daemon = %v, want [200 205 201 202]; an identity that no longer matches "+
			"(300 with another start) is not taken", got)
	}
}

func TestMoveMovesOnlyTheAgentsTree(t *testing.T) {
	m := terminal()
	root := mustIdentify(m, 200)
	res, err := Move(m.env(), dest, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(res.Moved); !reflect.DeepEqual(got, []int{200, 201, 202}) {
		t.Fatalf("moved %v, want [200 201 202]", got)
	}
	for _, pid := range []int{200, 201, 202} {
		if cg := m.cgroupOf(pid); cg != destRel {
			t.Errorf("pid %d is in %s, want the run's cgroup", pid, cg)
		}
	}
	// The shell that started the agent, the sibling tab, sshd and the adopter stay where they are.
	for _, pid := range []int{100, 300, 90, 900} {
		if cg := m.cgroupOf(pid); cg == destRel {
			t.Errorf("pid %d was moved: only the agent's tree may move", pid)
		}
	}
	if m.adds[0] != "200>"+destRel {
		t.Errorf("the root did not move first: %v", m.adds)
	}
	if res.Rounds != 2 || res.Left != 0 {
		t.Errorf("rounds %d left %d, want 2 (one pass that moves, one that finds nothing) and 0", res.Rounds, res.Left)
	}
}

func TestMoveFollowsAChildForkedDuringTheMove(t *testing.T) {
	// Between the agent's own move and its child's, the child forks: the grandchild is born in the session cgroup,
	// since its parent was still there, and the next pass over /proc finds and moves it.
	m := terminal()
	forked := false
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 200 && !forked {
			forked = true
			m.add(210, 201, session, "/usr/bin/cat", 1000)
		}
	}
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(res.Moved); !reflect.DeepEqual(got, []int{200, 201, 202, 210}) {
		t.Fatalf("moved %v, want [200 201 202 210]", got)
	}
	if res.Rounds != 3 {
		t.Errorf("rounds = %d, want 3", res.Rounds)
	}
}

func TestMoveStopsAfterItsRounds(t *testing.T) {
	// A tree that forks a new child into the source cgroup on every move is not chased for ever: what is left is
	// counted.
	m := terminal()
	next := 1000
	m.onAdd = func(m *machine, dir string, pid int) {
		next++
		m.add(next, 202, session, "/usr/bin/true", 1000)
	}
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rounds != MaxRounds || res.Left == 0 {
		t.Errorf("rounds %d left %d, want %d and some left", res.Rounds, res.Left, MaxRounds)
	}
}

func TestMoveRechecksIdentityBeforeTheWrite(t *testing.T) {
	// The root exits between being identified and being moved, and its pid is reused: nothing moves, not the new
	// process and not the agent's children.
	m := terminal()
	root := mustIdentify(m, 200)
	m.procs[200].start = 7777
	res, err := Move(m.env(), dest, root, nil)
	if !errors.Is(err, ErrIdentityChanged) && !errors.Is(err, ErrGone) {
		t.Fatalf("err = %v, want ErrIdentityChanged or ErrGone", err)
	}
	if len(res.Moved) != 0 || len(m.adds) != 0 {
		t.Fatalf("moved %v (writes %v) for a root whose pid names another process", pidsOf(res.Moved), m.adds)
	}

	// The root is fine, but a child's pid is reused between the walk and its own write: that pid is skipped and
	// reported, the rest move.
	m = terminal()
	root = mustIdentify(m, 200)
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 200 {
			m.procs[201].start = 8888
		}
	}
	res, err = Move(m.env(), dest, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(res.Moved); !reflect.DeepEqual(got, []int{200, 202}) {
		t.Errorf("moved %v, want [200 202]", got)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].PID != 201 || res.Skipped[0].Why != SkipReused {
		t.Errorf("skipped %+v, want 201 as reused", res.Skipped)
	}
	if m.cgroupOf(201) == destRel {
		t.Error("a reused pid was moved")
	}
}

// TestMoveRechecksAMembersCgroupBeforeTheWrite: a member the walk listed in the root's cgroup that is elsewhere by its
// own write (a `tego run` the agent started moved it into that run's scope) is skipped, never written: pulling it out
// would take a process from another governed run, the governed rule applied to the tree.
func TestMoveRechecksAMembersCgroupBeforeTheWrite(t *testing.T) {
	const otherRun = "/tego.slice/tego-w.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope"
	m := terminal()
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 200 {
			m.mu.Lock()
			m.procs[201].cgroup = otherRun
			m.cgroups[otherRun] = true
			m.mu.Unlock()
		}
	}
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range m.adds {
		if strings.HasPrefix(a, "201>") {
			t.Fatalf("a member now in another run's scope was written: %v", m.adds)
		}
	}
	if cg := m.cgroupOf(201); cg != otherRun {
		t.Fatalf("pid 201 is in %s, want left in the other run's scope", cg)
	}
	var skipped bool
	for _, s := range res.Skipped {
		skipped = skipped || s.PID == 201 && strings.HasPrefix(s.Why, SkipOtherCgroup)
	}
	if !skipped {
		t.Errorf("skipped %+v, want 201 in another cgroup", res.Skipped)
	}
}

func TestMoveRefusesARootTheKernelWillNotMove(t *testing.T) {
	m := terminal()
	m.refuse[dest] = syscall.EBUSY
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err == nil || len(res.Moved) != 0 {
		t.Fatalf("err %v moved %v: a root that does not move must leave the whole tree", err, pidsOf(res.Moved))
	}
	for _, pid := range []int{200, 201, 202} {
		if m.cgroupOf(pid) != session {
			t.Errorf("pid %d left the session", pid)
		}
	}
}

func TestMoveCatchesAPidReusedWithinTheWrite(t *testing.T) {
	// The child exits as it is written, and a new process of someone else's is born under its pid inside the write:
	// the pidfd says the child exited, its pid now names another process, which the write moved. That process is
	// put back in its parent's cgroup and reported.
	m := terminal()
	m.add(950, 1, "/system.slice/cron.service", "/usr/sbin/cron", 0)
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 202 {
			m.mu.Lock()
			m.exited[202] = true
			p := m.procs[202]
			p.start, p.ppid, p.exe = 9999, 950, "/usr/bin/mail"
			m.mu.Unlock()
		}
	}
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Misplaced, []int{202}) {
		t.Fatalf("misplaced = %v, want [202]", res.Misplaced)
	}
	if cg := m.cgroupOf(202); cg != "/system.slice/cron.service" {
		t.Errorf("the reused pid is in %s, want its parent's cgroup", cg)
	}
	if got := pidsOf(res.Moved); !reflect.DeepEqual(got, []int{200, 201}) {
		t.Errorf("moved = %v", got)
	}
}

func TestMoveRefusesARootAlreadyInTheDestination(t *testing.T) {
	m := terminal()
	root := mustIdentify(m, 200)
	root.Cgroup = destRel
	if _, err := Move(m.env(), dest, root, nil); err == nil {
		t.Fatal("a root already in the run's cgroup was moved again")
	}
}

func TestReleaseFreezesAndMovesEverythingBack(t *testing.T) {
	m := terminal()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	// A child forked inside the run's cgroup after the adoption goes back too.
	m.add(220, 200, destRel, "/usr/bin/python3", 1000)
	var frozenDuring bool
	m.onAdd = func(m *machine, dir string, pid int) {
		m.mu.Lock()
		frozenDuring = m.frozen[destRel]
		m.mu.Unlock()
	}
	res := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if !res.Frozen || !frozenDuring || m.frozen[destRel] {
		t.Errorf("frozen %v during %v after %v: the run's cgroup is frozen while its processes leave, thawed after",
			res.Frozen, frozenDuring, m.frozen[destRel])
	}
	if len(res.Left) != 0 {
		t.Errorf("left %v", res.Left)
	}
	for _, pid := range []int{200, 201, 202, 220} {
		if m.cgroupOf(pid) != session {
			t.Errorf("pid %d is in %s after the release", pid, m.cgroupOf(pid))
		}
	}
	if got := res.To["/sys/fs/cgroup"+session]; len(got) != 4 {
		t.Errorf("released to the session: %v", res.To)
	}
}

func TestReleaseFallsBackWhenTheSourceIsGone(t *testing.T) {
	m := terminal()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	// The session scope ended while the agent ran adopted, and its slice takes no process (it has controllers on
	// for its children): the next ancestor that takes one does.
	delete(m.cgroups, session)
	m.cgroups["/user.slice/user-1000.slice"] = true
	m.refuse["/sys/fs/cgroup/user.slice/user-1000.slice"] = syscall.EBUSY
	m.cgroups["/user.slice"] = true
	res := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if len(res.To["/sys/fs/cgroup/user.slice"]) != 3 {
		t.Fatalf("released to %v, want /user.slice", res.To)
	}
	// With nothing that takes them, the processes stay where they are (never the root cgroup).
	m = terminal()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	delete(m.cgroups, session)
	res = Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if len(res.Left) != 3 {
		t.Errorf("left %v, want the three processes in place", res.Left)
	}
}

// staleProcs lists extra beside the cgroup's own processes: a pid read from cgroup.procs whose member died and whose
// pid another process took before the write.
type staleProcs struct {
	*machine
	extra int
}

func (s staleProcs) Procs(dir string) ([]int, error) {
	pids, err := s.machine.Procs(dir)
	if err == nil && dir == dest {
		pids = append(pids, s.extra)
	}
	return pids, err
}

// TestReleaseMovesOnlyTheScopesOwnProcesses: Release writes as root the pids it read from the scope's cgroup.procs. A
// member that died between the read and the write, its pid taken by another user's process elsewhere, used to have
// that process moved into the cgroup the tree came from. Each pid is now held by a pidfd and written only while it is
// still in the scope.
func TestReleaseMovesOnlyTheScopesOwnProcesses(t *testing.T) {
	m := terminal()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	m.add(950, 1, "/system.slice/cron.service", "/usr/sbin/cron", 0)
	env := m.env()
	env.FS = staleProcs{machine: m, extra: 950}
	res := Release(env, dest, ReleaseTargets(m.mount, session))
	if cg := m.cgroupOf(950); cg != "/system.slice/cron.service" {
		t.Fatalf("a process outside the scope, under a pid read from it, was moved to %s", cg)
	}
	for _, pid := range []int{200, 201, 202} {
		if m.cgroupOf(pid) != session {
			t.Errorf("pid %d is in %s after the release", pid, m.cgroupOf(pid))
		}
	}
	if got := res.To["/sys/fs/cgroup"+session]; !reflect.DeepEqual(got, []int{200, 201, 202}) {
		t.Errorf("released %v", res.To)
	}
}

// TestReleaseCatchesAPidReusedWithinTheWrite: a member exits as it is written, and another user's process is born
// under its pid inside the write: the pidfd says the member exited, its pid now names another process, which the
// write moved. That process is put back in its parent's cgroup and reported.
func TestReleaseCatchesAPidReusedWithinTheWrite(t *testing.T) {
	m := terminal()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	m.add(950, 1, "/system.slice/cron.service", "/usr/sbin/cron", 0)
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 202 && dir != dest {
			m.mu.Lock()
			m.exited[202] = true
			p := m.procs[202]
			p.start, p.ppid, p.exe = 9999, 950, "/usr/bin/mail"
			m.mu.Unlock()
		}
	}
	res := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if !reflect.DeepEqual(res.Misplaced, []int{202}) {
		t.Fatalf("misplaced = %v, want [202]", res.Misplaced)
	}
	if cg := m.cgroupOf(202); cg != "/system.slice/cron.service" {
		t.Errorf("the reused pid is in %s, want its parent's cgroup", cg)
	}
	if got := res.To["/sys/fs/cgroup"+session]; !reflect.DeepEqual(got, []int{200, 201}) {
		t.Errorf("released %v", res.To)
	}
}

func TestReleaseTargets(t *testing.T) {
	got := ReleaseTargets("/sys/fs/cgroup", "/user.slice/user-1000.slice/session-2.scope")
	want := []string{"/sys/fs/cgroup/user.slice/user-1000.slice/session-2.scope", "/sys/fs/cgroup/user.slice/user-1000.slice",
		"/sys/fs/cgroup/user.slice"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReleaseTargets = %v, want %v", got, want)
	}
	if got := ReleaseTargets("/sys/fs/cgroup", "/"); len(got) != 0 {
		t.Errorf("the root cgroup is never a target: %v", got)
	}
}

func TestRegistryHoldsAnIdentityOnce(t *testing.T) {
	r := NewRegistry(2)
	a, b, c := Identity{1, 1}, Identity{2, 2}, Identity{3, 3}
	if _, err := r.Claim(a, "x"); err != nil {
		t.Fatal(err)
	}
	if h, err := r.Claim(a, "y"); !errors.Is(err, ErrAdopting) || h != "x" {
		t.Fatalf("a second claim of one identity: %q %v, want ErrAdopting naming x", h, err)
	}
	// The same pid with another start time is another process.
	if _, err := r.Claim(Identity{1, 2}, "z"); err != nil {
		t.Fatalf("a reused pid is another process: %v", err)
	}
	if _, err := r.Claim(b, "w"); !errors.Is(err, ErrRegistryFull) {
		t.Fatalf("over the cap: %v", err)
	}
	r.Rename(a, "run-1")
	if h, _ := r.Claim(a, "q"); h != "run-1" {
		t.Errorf("holder after Rename = %q", h)
	}
	r.Drop(a)
	if _, err := r.Claim(c, "v"); err != nil || r.Len() != 2 {
		t.Errorf("after a drop: %v, len %d", err, r.Len())
	}
}

// leaderExitedTree is terminal() with a process of the agent's, 203 (python3, the agent's child), whose main thread
// has exited while its thread 2031 runs, and a child of that process, 204, forked by the thread: /proc names 204's
// parent 203, a zombie by its stat.
func leaderExitedTree() *machine {
	m := terminal()
	m.add(203, 200, session, "/usr/bin/python3", 1000)
	m.exitLeader(203, 2031)
	m.add(204, 203, session, "/usr/bin/sleep", 1000)
	return m
}

// TestAProcessWhoseLeaderExitedIsAMember: a process whose leader has exited reads as a zombie in /proc/<pid>/stat,
// but its other threads run its program and may fork. It is a member of the tree, identified through a thread that
// runs (its program, its cgroup), and so is its child.
func TestAProcessWhoseLeaderExitedIsAMember(t *testing.T) {
	m := leaderExitedTree()
	p, err := Identify(m, 203)
	if err != nil {
		t.Fatalf("identify a process whose leader exited: %v", err)
	}
	if p.Exe != "/usr/bin/python3" || p.Cgroup != session || p.Start != 1203 || p.Tgid != 203 {
		t.Errorf("identified %+v, want its program, cgroup and the leader's start time, read through thread 2031", p)
	}
	members, skipped, err := Members(m, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(members); !reflect.DeepEqual(got, []int{200, 201, 203, 202, 204}) {
		t.Errorf("members = %v, want [200 201 203 202 204]: the process whose leader exited and its child", got)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want none", skipped)
	}
	// A zombie is still gone: its group has no thread left, and it is neither a member nor skipped.
	m.mu.Lock()
	m.procs[2031].state = 'Z'
	delete(m.procs, 2031)
	m.mu.Unlock()
	if _, err := Identify(m, 203); !errors.Is(err, ErrGone) {
		t.Errorf("identify a zombie: %v, want ErrGone", err)
	}
}

// TestMoveMovesAProcessWhoseLeaderExited: the write of the process's pid moves its live threads (the kernel leaves
// the exited leader where it was), the process and its child are moved, and the next pass reads the process's
// cgroup through a thread that runs, so it is not taken for one left behind; the release finds it in the run's
// cgroup.threads, which is the only listing that names it there, and moves it back.
func TestMoveMovesAProcessWhoseLeaderExited(t *testing.T) {
	m := leaderExitedTree()
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(res.Moved); !reflect.DeepEqual(got, []int{200, 201, 203, 202, 204}) {
		t.Fatalf("moved %v, want [200 201 203 202 204]", got)
	}
	if len(res.Skipped) != 0 || res.Left != 0 || res.Rounds != 2 {
		t.Errorf("skipped %+v left %d rounds %d, want none, 0 and 2", res.Skipped, res.Left, res.Rounds)
	}
	for _, pid := range []int{2031, 204} {
		if cg := m.cgroupOf(pid); cg != destRel {
			t.Errorf("task %d is in %s, want the run's cgroup", pid, cg)
		}
	}
	rel := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	for _, pid := range []int{200, 2031, 204} {
		if cg := m.cgroupOf(pid); cg != session {
			t.Errorf("task %d is in %s after the release, want %s", pid, cg, session)
		}
	}
	if left, _ := m.Threads(dest); len(left) != 0 || len(rel.Left) != 0 {
		t.Errorf("after the release the run's cgroup holds tasks %v (left %v), want none", left, rel.Left)
	}
	if got := rel.To["/sys/fs/cgroup"+session]; !slices.Contains(got, 203) {
		t.Errorf("released %v, want 203 among them", rel.To)
	}
}

// TestReleaseOfAProcessWhoseLeaderExitedInTheScope: a process adopted whole whose leader then exits in the run's
// cgroup (pthread_exit in main once adopted) leaves its zombie leader listed in that cgroup's cgroup.procs while its
// group has a live thread, wherever the thread goes. Once the release has moved the thread out, nothing of the process
// is in the scope: it is not left there, or the scope and its record are kept and run_end says a process stayed.
func TestReleaseOfAProcessWhoseLeaderExitedInTheScope(t *testing.T) {
	m := terminal()
	m.add(203, 200, session, "/usr/bin/python3", 1000)
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	if cg := m.cgroupOf(203); cg != destRel {
		t.Fatalf("pid 203 is in %s after the move, want the run's cgroup", cg)
	}
	m.exitLeader(203, 2031)
	if procs, _ := m.Procs(dest); !slices.Contains(procs, 203) {
		t.Fatalf("the fake's cgroup.procs %v does not list the exited leader the kernel lists", procs)
	}
	rel := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if cg := m.cgroupOf(2031); cg != session {
		t.Errorf("thread 2031 is in %s after the release, want %s", cg, session)
	}
	if len(rel.Left) != 0 {
		t.Errorf("left %v, want none: no thread of the process is in the scope", rel.Left)
	}
	if got := rel.To["/sys/fs/cgroup"+session]; !slices.Contains(got, 203) {
		t.Errorf("released %v, want 203 among them", rel.To)
	}
}

// TestReleaseLeavesAProcessWhoseLeaderExitedCounted: a process whose leader exited before the move has its threads
// in the scope and its leader elsewhere, so cgroup.procs does not name it there; one no target takes is still left in
// the scope, and Left says so, or run_end would say the scope was empty.
func TestReleaseLeavesAProcessWhoseLeaderExitedCounted(t *testing.T) {
	m := leaderExitedTree()
	if _, err := Move(m.env(), dest, mustIdentify(m, 200), nil); err != nil {
		t.Fatal(err)
	}
	for _, target := range ReleaseTargets(m.mount, session) {
		m.refuse[target] = syscall.EBUSY
	}
	rel := Release(m.env(), dest, ReleaseTargets(m.mount, session))
	if !slices.Contains(rel.Left, 203) {
		t.Errorf("left %v, want 203, whose thread no target took", rel.Left)
	}
	if cg := m.cgroupOf(2031); cg != destRel {
		t.Errorf("thread 2031 is in %s, want left in the run's cgroup", cg)
	}
}

// TestMoveRechecksTheCgroupOfAProcessWhoseLeaderExited: the check right before the write reads the cgroup of the
// process's live threads, not the exited leader's (which stays where it died): threads someone placed in another
// cgroup after the walk are not pulled into the run by the write of the pid.
func TestMoveRechecksTheCgroupOfAProcessWhoseLeaderExited(t *testing.T) {
	const otherRun = "/tego.slice/tego-w.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope"
	m := leaderExitedTree()
	m.onAdd = func(m *machine, dir string, pid int) {
		if pid == 200 {
			m.mu.Lock()
			m.procs[2031].cgroup = otherRun
			m.cgroups[otherRun] = true
			m.mu.Unlock()
		}
	}
	res, err := Move(m.env(), dest, mustIdentify(m, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cg := m.cgroupOf(2031); cg != otherRun {
		t.Errorf("thread 2031 is in %s, want left in the other run's scope (writes %v)", cg, m.adds)
	}
	if !slices.ContainsFunc(res.Skipped, func(s Skip) bool { return s.PID == 203 && strings.HasPrefix(s.Why, SkipOtherCgroup) }) {
		t.Errorf("skipped %+v, want 203 in another cgroup", res.Skipped)
	}
}
