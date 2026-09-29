// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// The reaper (ADR 0020), run the way an operator runs tier 2: `tego run --tier cgroup` as root, from a binary
// built with the objects and the test hooks (reap_testhook.go in internal/runtime), whose reaper waits, once its
// launcher is gone, until the test creates the file TEGO_TEST_REAP_HOLD names. The agent double-forks a
// descendant that outlives its launcher, which is what a reaper exists for.

// reapAgent forks a descendant into a session of its own, which the launcher's PDEATHSIG does not reach, has it
// write its pid to out/descendant, and sleeps; with the argument "quick" it exits at once instead.
const reapAgent = `import os, sys, time
if len(sys.argv) > 1 and sys.argv[1] == "quick":
    sys.exit(0)
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        with open("out/descendant.tmp", "w") as f:
            f.write(str(os.getpid()))
        os.rename("out/descendant.tmp", "out/descendant")
        while True:
            time.sleep(1)
    os._exit(0)
os.waitpid(pid, 0)
time.sleep(600)
`

// reapContract has a net: section, so the run's cgroup links are attached (and pinned), and nothing else a
// reaper test needs.
const reapContract = `version: 0
name: t2-reap
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: summary
`

// reapEnv is one machine a reaper test runs on: the tagged binary with the test hooks, a project the sudo caller
// owns, a ledger root and a machine config; and the tier its runs ask for (cgroup unless a kill test's cell says
// otherwise) with the cell's environment (TEGO_TEST_PLANE), which every run it starts carries.
type reapEnv struct {
	bin, base, project, ledger, cfg, python string
	tier                                    string
	env                                     []string
}

// newReapEnv builds the binary and the project, or skips where tier 2 cannot run.
func newReapEnv(t *testing.T) reapEnv {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	if _, _, ok := sudoIDs(); !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	out := filepath.Join(reapDir(t, "tego-reap-bin-"), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-trimpath", "-o", out,
		"github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build the tegobpf,tegotesthooks tego binary: %v: %s", err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	requireTier(t, out, "cgroup")
	return reapEnv{bin: out, python: python, tier: "cgroup"}.fresh(t)
}

// reapDir is a new directory every uid can pass through, removed when t ends.
func reapDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fresh is e's binary, tier and environment with a project, a ledger root and a machine config of their own in a new
// directory, removed when t ends: a kill test's cells share one build of the binary.
func (e reapEnv) fresh(t *testing.T) reapEnv {
	t.Helper()
	uid, gid, _ := sudoIDs()
	base := reapDir(t, "tego-reap-")
	e.base, e.project, e.ledger, e.cfg = base, filepath.Join(base, "p"), filepath.Join(base, "ledger"),
		filepath.Join(base, "config.yaml")
	if err := os.MkdirAll(filepath.Join(e.project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"agent.py": reapAgent, "agent.yaml": reapContract} {
		if err := os.WriteFile(filepath.Join(e.project, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{e.project, filepath.Join(e.project, "out"), filepath.Join(e.project, "agent.py"),
		filepath.Join(e.project, "agent.yaml")} {
		if err := os.Lchown(p, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(e.ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", e.ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

// orphanRun is a run whose launcher the test can kill: the launcher, its run, its scope and its descendant.
type orphanRun struct {
	launcher   *exec.Cmd
	stderr     string // the launcher's stderr, a file: the descendant inherits it, and a pipe would hold Wait
	dir, id    string
	hash       string
	cgroupID   uint64
	scope      string
	descendant int
	hold       string
}

// launchWait bounds how long startOrphanable waits for the run's descendant while the launcher lives. It is not a
// budget: the launcher of a test's fresh binary has no run-probe cache entry (doctor.runCacheKey holds the binary's
// inode), so before its agent starts it probes the decision plane in each mode the boot offers, attaching and then
// closing every plane link, and each close of a trampoline link waits for an RCU-tasks grace period under ftrace's
// locks (ADR 0022). Measured in the KVM guests on 2026-10-16: over 30 s on both boots with the host at load 27-44 (the
// launcher's threads in synchronize_rcu_tasks under runPlaneProbe's planeRig.close), and 15-28 s with it at load 5-9.
// A launcher that exits is reported at once instead.
const launchWait = 3 * time.Minute

// startOrphanable starts `tego run --tier <e.tier>` of reapAgent with e.env and its reaper held, and waits for
// the run's descendant.
func (e reapEnv) startOrphanable(t *testing.T, extraEnv ...string) *orphanRun {
	t.Helper()
	r := &orphanRun{hold: filepath.Join(e.base, "release-reaper"), stderr: filepath.Join(e.base, "launcher.stderr")}
	errFile, err := os.Create(r.stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = errFile.Close() }()
	_ = os.Remove(filepath.Join(e.project, "out", "descendant"))
	r.launcher = exec.Command(e.bin, "run", "--tier", e.tier, filepath.Join(e.project, "agent.yaml"), "--",
		e.python, "./agent.py")
	r.launcher.Dir = e.project
	r.launcher.Env = append(append(testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg, "TEGO_TEST_REAP_HOLD="+r.hold,
		"GOTRACEBACK=all"), e.env...), extraEnv...)
	r.launcher.Stderr = errFile
	r.launcher.WaitDelay = 5 * time.Second
	if err := r.launcher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.launcher.Process.Kill()
		_ = os.WriteFile(r.hold, nil, 0o600)
		if r.descendant > 0 {
			_ = unix.Kill(r.descendant, unix.SIGKILL)
		}
		// The released reaper polls for the hold file: removing the test's directory before it has seen the file
		// (newReapEnv's cleanup runs next) would leave it held for good, with the run's scope, links, run-set row
		// and slot still in the build the next test's run shares.
		for deadline := time.Now().Add(15 * time.Second); r.id != "" && len(reapers(r.id)) > 0 && time.Now().Before(deadline); {
			time.Sleep(20 * time.Millisecond)
		}
	})
	started := time.Now()
	deadline := started.Add(launchWait)
	for {
		b, err := os.ReadFile(filepath.Join(e.project, "out", "descendant"))
		if err == nil && len(b) > 0 {
			r.descendant, _ = strconv.Atoi(string(b))
			break
		}
		if !alivePID(r.launcher.Process.Pid) {
			_ = r.launcher.Wait()
			b, _ := os.ReadFile(r.stderr)
			t.Fatalf("the launcher exited after %v with no descendant: %v\n%s", time.Since(started).Round(time.Millisecond),
				r.launcher.ProcessState, b)
		}
		if time.Now().After(deadline) {
			// What the launcher and its tree were doing, read before anything is signalled, then the launcher's
			// goroutines (GOTRACEBACK=all, SIGQUIT before it forwards signals to an agent).
			state := stuckLaunch(t, r.launcher.Process.Pid, e.ledger)
			_ = r.launcher.Process.Signal(syscall.SIGQUIT)
			exited := make(chan struct{})
			go func() { _ = r.launcher.Wait(); close(exited) }()
			select {
			case <-exited:
			case <-time.After(5 * time.Second): // a launcher that forwards SIGQUIT to an agent lives on
				_ = r.launcher.Process.Kill()
				<-exited
			}
			b, _ := os.ReadFile(r.stderr)
			t.Fatalf("no descendant within %v\n%s\nlauncher stderr:\n%s", launchWait, state, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("the run's descendant wrote its pid %v after the launcher started", time.Since(started).Round(time.Millisecond))
	dirs, err := filepath.Glob(filepath.Join(e.ledger, "r-*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("run directories %v (%v)", dirs, err)
	}
	for _, d := range dirs {
		if start := reapRunStart(t, d); start != nil {
			if _, ended := reapLastReason(t, d); ended {
				continue
			}
			r.dir, r.id = d, filepath.Base(d)
			r.hash, _ = start["bpf_hash"].(string)
			id, _ := start["cgroup"].(float64)
			r.cgroupID = uint64(id)
		}
	}
	if r.dir == "" || r.hash == "" || r.cgroupID == 0 {
		t.Fatalf("no live run with run_start naming its build and cgroup under %s", e.ledger)
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", r.descendant))
	if err != nil {
		t.Fatal(err)
	}
	// The unified hierarchy's line: a test may have mounted a named v1 hierarchy beside it.
	for _, line := range strings.Split(string(cg), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			r.scope = filepath.Join("/sys/fs/cgroup", rel)
		}
	}
	if r.scope == "" {
		t.Fatalf("the descendant's cgroups name no unified hierarchy:\n%s", cg)
	}
	return r
}

// stuckLaunch describes a launcher whose run never got going (or a doctor that never answered, planeSelected): each
// process of its tree (pid, name, state and the kernel function it sleeps in) with the kernel stacks of every thread of
// the tree, the host's file locks, whose waiters are marked "->", and the kinds of the ledger lines each run under
// ledger has written so far.
func stuckLaunch(t *testing.T, pid int, ledger string) string {
	var b strings.Builder
	tree := map[int]bool{pid: true}
	procs, _ := os.ReadDir("/proc")
	for grew := true; grew; {
		grew = false
		for _, p := range procs {
			q, err := strconv.Atoi(p.Name())
			if err != nil || tree[q] {
				continue
			}
			stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", q))
			s := string(stat)
			if i := strings.LastIndexByte(s, ')'); i >= 0 {
				f := strings.Fields(s[i+1:])
				if len(f) > 1 {
					if ppid, err := strconv.Atoi(f[1]); err == nil && tree[ppid] {
						tree[q], grew = true, true
					}
				}
			}
		}
	}
	for q := range tree {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", q))
		if err != nil {
			fmt.Fprintf(&b, "pid %d: gone\n", q)
			continue
		}
		wchan, _ := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", q))
		cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", q))
		s := string(stat)
		state := ""
		if i := strings.LastIndexByte(s, ')'); i >= 0 && len(s) > i+2 {
			state = s[i+2 : i+3]
		}
		fmt.Fprintf(&b, "pid %d state %s wchan %s: %s\n", q, state, wchan, strings.ReplaceAll(strings.TrimRight(string(cmd), "\x00"), "\x00", " "))
	}
	for q := range tree {
		tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", q))
		for _, task := range tasks {
			stack, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/stack", q, task.Name()))
			if st := strings.TrimSpace(string(stack)); st != "" {
				fmt.Fprintf(&b, "pid %d thread %s kernel stack:\n%s\n", q, task.Name(), st)
			}
		}
	}
	locks, _ := os.ReadFile("/proc/locks")
	fmt.Fprintf(&b, "/proc/locks:\n%s", locks)
	dirs, _ := filepath.Glob(filepath.Join(ledger, "r-*"))
	for _, d := range dirs {
		var kinds []string
		for _, ev := range reapEvents(t, d) {
			k, _ := ev["kind"].(string)
			kinds = append(kinds, k)
		}
		fmt.Fprintf(&b, "%s: %v\n", filepath.Base(d), kinds)
	}
	return b.String()
}

// kill SIGKILLs the launcher and reaps it.
func (r *orphanRun) kill(t *testing.T) {
	t.Helper()
	if err := r.launcher.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = r.launcher.Wait()
}

// links is the run's link directory under its build.
func (r *orphanRun) links() string {
	return filepath.Join(DefaultBPFFS, pinRoot, r.hash, pinLinks, runLinksPrefix+r.id)
}

// reapers are the pids of the processes whose argv is `tego __reap <id> ...`.
func reapers(id string) []int {
	var out []int
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		b, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
		args := strings.Split(string(b), "\x00")
		if len(args) > 2 && args[1] == "__reap" && args[2] == id {
			out = append(out, pid)
		}
	}
	return out
}

// reapEvents reads a run's ledger lines.
func reapEvents(t *testing.T, dir string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil
	}
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// reapRunStart is the run's run_start line, nil without one.
func reapRunStart(t *testing.T, dir string) map[string]any {
	for _, e := range reapEvents(t, dir) {
		if e["kind"] == "run_start" {
			return e
		}
	}
	return nil
}

// reapLastReason is the reason of the run's run_end, and whether it has one; ends counts them.
func reapLastReason(t *testing.T, dir string) (string, bool) {
	reason, ended := "", false
	for _, e := range reapEvents(t, dir) {
		if e["kind"] == "run_end" {
			reason, _ = e["reason"].(string)
			ended = true
		}
	}
	return reason, ended
}

// runEnds counts a run's run_end lines.
func runEnds(t *testing.T, dir string) int {
	n := 0
	for _, e := range reapEvents(t, dir) {
		if e["kind"] == "run_end" {
			n++
		}
	}
	return n
}

// alivePID reports whether pid exists and is not a zombie.
func alivePID(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || !strings.HasPrefix(s[i+1:], " Z")
}

// assertKept checks that a dead launcher's run keeps everything that enforces it while its descendant lives: the
// descendant, its scope, the run's pinned links, still attached to the scope, and its run-set row.
func (r *orphanRun) assertKept(t *testing.T, when string) {
	t.Helper()
	if !alivePID(r.descendant) {
		t.Fatalf("%s: the descendant %d is gone; the test proves nothing", when, r.descendant)
	}
	if _, err := os.Stat(r.scope); err != nil {
		t.Fatalf("%s: the run's scope is gone while its descendant lives: %v", when, err)
	}
	entries, err := os.ReadDir(r.links())
	if err != nil || len(entries) == 0 {
		t.Fatalf("%s: the run's pinned links %s: %v (%d), want them kept", when, r.links(), err, len(entries))
	}
	fd, err := unix.Open(r.scope, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	q, err := link.QueryPrograms(link.QueryOptions{Target: fd, Attach: ebpf.AttachCGroupInet4Connect})
	if err != nil {
		t.Fatalf("%s: query the scope's connect4 programs: %v", when, err)
	}
	if len(q.Programs) == 0 {
		t.Fatalf("%s: no connect4 program is attached to the run's scope: the launcher's death took the run's "+
			"network enforcement (E38)", when)
	}
	if !r.inRunSet(t) {
		t.Fatalf("%s: the run's cgroup %d is not in the run set while its descendant lives", when, r.cgroupID)
	}
}

// inRunSet reports whether the build's pinned run set holds a row for the run's cgroup.
func (r *orphanRun) inRunSet(t *testing.T) bool {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(DefaultBPFFS, pinRoot, r.hash, pinMaps, ebpfbindings.MapRunSet),
		&ebpf.LoadPinOptions{ReadOnly: true})
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	var row ebpfbindings.Run
	return m.Lookup(&r.cgroupID, &row) == nil
}

// waitPurged waits for everything of the run to go: its descendant, its scope, its links, its run-set row and its
// reapers.
func (r *orphanRun) waitPurged(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		_, scopeErr := os.Stat(r.scope)
		_, linksErr := os.Stat(r.links())
		left := []string{}
		if alivePID(r.descendant) {
			left = append(left, "descendant")
		}
		if scopeErr == nil {
			left = append(left, "scope")
		}
		if linksErr == nil {
			left = append(left, "links")
		}
		if r.inRunSet(t) {
			left = append(left, "run-set row")
		}
		if len(reapers(r.id)) > 0 {
			left = append(left, "reaper")
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %v the run still has: %v", within, left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTier2ReaperEndsAnOrphanOnlyOnceItsTreeIsGone is ADR 0020's kill test: the launcher is SIGKILLed while a
// test hook holds its reaper, and the run's pinned links stay attached to its scope, with its run-set row, for as
// long as its descendant lives (E38 closed); released, the reaper writes run_end reason=orphaned at once, and the
// descendant, the scope, the links and the row are all gone. It also checks the reaper as it runs: in tego's
// helper cgroup, holding descriptors 0-4 only.
func TestTier2ReaperEndsAnOrphanOnlyOnceItsTreeIsGone(t *testing.T) {
	e := newReapEnv(t)
	r := e.startOrphanable(t)
	pids := reapers(r.id)
	if len(pids) != 1 {
		t.Fatalf("reapers of run %s: %v, want one", r.id, pids)
	}
	cg, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pids[0]))
	if !strings.Contains(string(cg), "/tego.slice/helpers.scope") {
		t.Errorf("the reaper runs in %q, want tego.slice/helpers.scope", strings.TrimSpace(string(cg)))
	}
	fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pids[0]))
	var names []string
	for _, fd := range fds {
		l, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pids[0], fd.Name()))
		if l != "anon_inode:[eventpoll]" && l != "anon_inode:[eventfd]" {
			names = append(names, fd.Name()+"="+l)
		}
	}
	if len(names) != 5 {
		t.Errorf("the reaper holds %v, want descriptors 0-4 only", names)
	}
	r.assertKept(t, "before the launcher's death")

	r.kill(t)
	time.Sleep(500 * time.Millisecond)
	r.assertKept(t, "launcher dead, reaper held")
	if _, ended := reapLastReason(t, r.dir); ended {
		t.Fatal("the run has run_end while its reaper is held")
	}

	released := time.Now()
	if err := os.WriteFile(r.hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if reason, ended := reapLastReason(t, r.dir); ended {
			if reason != "orphaned" {
				t.Fatalf("run_end reason %q, want orphaned", reason)
			}
			break
		}
		if time.Since(released) > 10*time.Second {
			t.Fatal("no run_end 10 s after the reaper's release")
		}
		time.Sleep(2 * time.Millisecond)
	}
	ended := time.Since(released)
	r.waitPurged(t, 10*time.Second)
	t.Logf("released the reaper: run_end orphaned after %v, the run purged after %v", ended, time.Since(released))
	if ended > time.Second {
		t.Errorf("run_end came %v after the reaper's release; ADR 0020 expects milliseconds", ended)
	}
	if n := runEnds(t, r.dir); n != 1 {
		t.Errorf("%d run_end lines, want one", n)
	}
}

// TestTier2ConcurrentReapersEndAnOrphanOnce is ADR 0020 (3) under races: the run's own reaper, a second reaper of
// the same run (started by hand with the run's argv, a pidfd of a process that has exited and the run's
// directory) and a `tego gc`, all released at once, end the run exactly once, and everything of it goes.
func TestTier2ConcurrentReapersEndAnOrphanOnce(t *testing.T) {
	e := newReapEnv(t)
	r := e.startOrphanable(t)
	pids := reapers(r.id)
	if len(pids) != 1 {
		t.Fatalf("reapers of run %s: %v, want one", r.id, pids)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pids[0]))
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
	r.kill(t)

	// The second reaper's launcher: a process that has already exited, so its pidfd is readable at once.
	gone := exec.Command("true")
	if err := gone.Start(); err != nil {
		t.Fatal(err)
	}
	pfd, err := unix.PidfdOpen(gone.Process.Pid, 0)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	_ = gone.Wait()
	pidfd := os.NewFile(uintptr(pfd), "pidfd")
	defer func() { _ = pidfd.Close() }()
	dfd, err := unix.Open(r.dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(dfd), r.dir)
	defer func() { _ = dir.Close() }()
	second := exec.Command(e.bin, argv[1:]...)
	second.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TEGO_TEST_REAP_HOLD=" + r.hold}
	second.ExtraFiles = []*os.File{pidfd, dir}
	var secondErr bytes.Buffer
	second.Stderr = &secondErr
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	r.assertKept(t, "two reapers held")

	var wg sync.WaitGroup
	var gcOut []byte
	if err := os.WriteFile(r.hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		gc := exec.Command(e.bin, "gc")
		gc.Env = testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg)
		gcOut, _ = gc.CombinedOutput()
	}()
	if err := second.Wait(); err != nil {
		t.Errorf("the second reaper: %v\n%s", err, secondErr.String())
	}
	wg.Wait()
	t.Logf("tego gc:\n%s\nsecond reaper:\n%s", gcOut, secondErr.String())
	r.waitPurged(t, 15*time.Second)
	if reason, ended := reapLastReason(t, r.dir); !ended || reason != "orphaned" {
		t.Fatalf("run_end %q (%v), want orphaned", reason, ended)
	}
	if n := runEnds(t, r.dir); n != 1 {
		t.Fatalf("%d run_end lines after three sweepers raced, want one", n)
	}
}

// TestTier2AReapersDeathLeavesTheRunToTheSweep is ADR 0020 (7)'s residual: the launcher and its reaper are both
// killed. Nothing that enforces the run goes while its descendant lives, and the next `tego gc` ends the run,
// kills what is left and purges its links and rows.
func TestTier2AReapersDeathLeavesTheRunToTheSweep(t *testing.T) {
	e := newReapEnv(t)
	r := e.startOrphanable(t)
	r.kill(t)
	for _, pid := range reapers(r.id) {
		if err := unix.Kill(pid, unix.SIGKILL); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(reapers(r.id)) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if left := reapers(r.id); len(left) > 0 {
		t.Fatalf("reapers %v outlived SIGKILL", left)
	}
	time.Sleep(300 * time.Millisecond)
	r.assertKept(t, "launcher and reaper dead")

	gc := exec.Command(e.bin, "gc")
	gc.Env = testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg)
	out, err := gc.CombinedOutput()
	t.Logf("tego gc: %v\n%s", err, out)
	if err != nil {
		t.Fatalf("tego gc: %v", err)
	}
	r.waitPurged(t, 10*time.Second)
	if reason, ended := reapLastReason(t, r.dir); !ended || reason != "orphaned" {
		t.Fatalf("run_end %q (%v), want orphaned", reason, ended)
	}
}

// TestTier2RunRefusesWithoutItsReaper is ADR 0020 (4) in the fanotify fallback: a reaper that cannot be started
// (a test hook makes its start fail) fails the run before run_start, exit 125, rather than run a tier-2 run whose
// launcher's death would leave its opens unenforced (E15).
func TestTier2RunRefusesWithoutItsReaper(t *testing.T) {
	e := newReapEnv(t)
	cmd := exec.Command(e.bin, "run", "--tier", "cgroup", filepath.Join(e.project, "agent.yaml"), "--", e.python,
		"./agent.py", "quick")
	cmd.Dir = e.project
	cmd.Env = testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg, "TEGO_TEST_REAP_START_FAIL=1")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 125 {
		t.Fatalf("tego run with no reaper: %v, want exit 125\n%s", err, out)
	}
	if !strings.Contains(string(out), "reaper") {
		t.Errorf("the refusal does not name the reaper:\n%s", out)
	}
	dirs, _ := filepath.Glob(filepath.Join(e.ledger, "r-*"))
	for _, d := range dirs {
		if reapRunStart(t, d) != nil {
			t.Errorf("%s has run_start: the run started without a reaper", d)
		}
	}
}

// TestTier2ANormalRunLeavesNoReaper: a run its launcher ends leaves its reaper nothing to do; the reaper exits
// and the run's links, which Detach unpinned, are gone.
func TestTier2ANormalRunLeavesNoReaper(t *testing.T) {
	e := newReapEnv(t)
	cmd := exec.Command(e.bin, "run", "--tier", "cgroup", filepath.Join(e.project, "agent.yaml"), "--", e.python,
		"./agent.py", "quick")
	cmd.Dir = e.project
	cmd.Env = testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	dirs, _ := filepath.Glob(filepath.Join(e.ledger, "r-*"))
	if len(dirs) != 1 {
		t.Fatalf("run directories %v", dirs)
	}
	id := filepath.Base(dirs[0])
	start := reapRunStart(t, dirs[0])
	hash, _ := start["bpf_hash"].(string)
	deadline := time.Now().Add(5 * time.Second)
	for len(reapers(id)) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if left := reapers(id); len(left) > 0 {
		t.Errorf("the reaper of a run its launcher ended is still running: %v", left)
	}
	if _, err := os.Stat(filepath.Join(DefaultBPFFS, pinRoot, hash, pinLinks, runLinksPrefix+id)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the ended run's links are still pinned: %v", err)
	}
	if reason, _ := reapLastReason(t, dirs[0]); reason != "exit" {
		t.Errorf("run_end reason %q, want exit", reason)
	}
}
