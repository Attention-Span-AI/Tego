// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// The decision plane's process controls in a real `tego run` (enforce-plane §2.20; FEATURES E54):
// ptrace_access_check and ptrace_traceme keep a trace inside the run and its generation, key_permission refuses the
// kernel keyring unless the contract says `keyring: true`, and bpf refuses every bpf(2) command of a governed task.
// Doctor's known-answer probes and observe's decode tests covered each hook in isolation; these cells are the
// governed run, the agent's own syscalls through the real kernel and the ledger line each refusal leaves. They run in
// every plane mode the machine passes and at tier bpflsm, under record: full and off (a refusal is recorded under
// both, ADR 0016 (3)), and test/vm/root-suites.sh runs them in the KVM guest on both boots.
//
// Two of the four hooks sit behind an arm of the seccomp filter in a product run, which is why a cell needs the test
// build's filter seam (TEGO_TEST_FILTER_OMIT, landlock filterTestOmit): the filter answers bpf(2) with EPERM at tiers 2
// and 3 (ADR 0033) and notifies add_key, request_key and keyctl to the supervisor, which refuses them with EPERM
// unless the contract opts in (SEMANTICS §1), so neither reaches its hook. The cells run each of them both ways: the product
// filter, whose answer and silence they pin, and the filter with those arms left out, where only the plane answers.
// And one of the two ptrace hooks sits behind Landlock's own ptrace scope, which every tier's domain carries
// (ARCHITECTURE §11): an attach out of the run is refused by Landlock first wherever landlock precedes bpf in the LSM
// list (lsm mode, where the lsm=...,bpf boot appends bpf), so the plane's refusal there is reached only for a task
// Landlock admits, one of the agent's own descendants that is no longer in the run's cgroup.

// envFilterOmit is landlock.EnvTestFilterOmit, which a package that does not import landlock cannot name.
const envFilterOmit = "TEGO_TEST_FILTER_OMIT"

// controlOmitArms are the syscalls the filter's notify arm and root-tier arm answer in front of the plane's bpf and
// key_permission hooks.
const controlOmitArms = "bpf,add_key,request_key,keyctl"

// controlTiers are the tiers a plane mode decides at: tier cgroup in both modes, and tier bpflsm where the plane is
// the LSM mode's.
func controlTiers(mode string) []string {
	if mode == "lsm" {
		return []string{"cgroup", "bpflsm"}
	}
	return []string{"cgroup"}
}

// controlContract is a run of `python3 ./<script> <args>` that writes ./out/ and execs python3 alone. A net: section
// with no entries is there for every cell but the one that connects to a socket of the test's, which has none and sets
// host_sockets: true instead: the unix-only state of a contract with no net: section refuses a socket the run did not
// bind (ADR 0070, rule host-sockets). pass names the variables the run keeps beside PATH, HOME and
// PYTHONDONTWRITEBYTECODE.
func controlContract(name, script, recording string, keyring, withNet bool, pass []string, args ...string) string {
	quote := func(s []string) string {
		q := make([]string, len(s))
		for i, v := range s {
			q[i] = strconv.Quote(v)
		}
		return strings.Join(q, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "version: 0\nname: %s\ncommand: [%s]\n", name, quote(append([]string{"python3", "./" + script}, args...)))
	b.WriteString("fs:\n  write: [\"./out/\"]\nexec:\n  allow: [\"python3\"]\n")
	if withNet {
		b.WriteString("net:\n  allow: []\n")
	} else {
		b.WriteString("host_sockets: true\n")
	}
	fmt.Fprintf(&b, "env:\n  pass: [%s]\n", quote(append([]string{"PATH", "HOME", "PYTHONDONTWRITEBYTECODE"}, pass...)))
	if keyring {
		b.WriteString("keyring: true\n")
	}
	fmt.Fprintf(&b, "record: %s\n", recording)
	return b.String()
}

// wantControl is one refused line the plane's control hooks write: the op the hook names, its target (a pid, a
// bpf command or a key permission, as a pattern), and the rule and reason the closed set gives it.
type wantControl struct {
	op, rule, reason string
	target           *regexp.Regexp
}

// controlTargetIs is the target a hook names when it is the number n.
func controlTargetIs(prefix string, n int) *regexp.Regexp {
	return regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + strconv.Itoa(n) + "$")
}

// controlLines are the refused lines of the plane's four control hooks in events.
func controlLines(events []map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range events {
		if e["kind"] != "refused" || e["mechanism"] != "plane" {
			continue
		}
		if op, _ := e["op"].(string); op == "ptrace" || op == "ptrace_traceme" || op == "bpf" || op == "key_permission" {
			out = append(out, e)
		}
	}
	return out
}

// controlSummary lists the plane's control lines of events as "op target", for the log of a cell that passed.
func controlSummary(events []map[string]any) string {
	var out []string
	for _, e := range controlLines(events) {
		out = append(out, fmt.Sprintf("%v %v", e["op"], e["target"]))
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// expectControlLines fails the test unless the plane's control lines in events are exactly want, in any order: one
// line for each refused action or, for key_permission, each refused check (enforce-plane I8), from the kernel with
// the plane as its mechanism and the mode as its decision_plane, written for the agent's own pid, and nothing else
// with the plane's control ops.
func expectControlLines(t *testing.T, events []map[string]any, mode string, agentPID int, want []wantControl) {
	t.Helper()
	got := controlLines(events)
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, e := range got {
			if used[i] || e["op"] != w.op || e["rule"] != w.rule || e["reason"] != w.reason || !w.target.MatchString(fmt.Sprint(e["target"])) {
				continue
			}
			used[i], found = true, true
			if e["source"] != "kernel" || e["mechanism"] != "plane" || e["decision_plane"] != mode || e["pid"] != float64(agentPID) {
				t.Errorf("control line %v: want source kernel, mechanism plane, decision_plane %s, pid %d", e, mode, agentPID)
			}
			break
		}
		if !found {
			t.Errorf("no plane control line op=%s target~%s rule=%s reason=%s; the plane's lines: %v", w.op, w.target, w.rule, w.reason, got)
		}
	}
	for i, e := range got {
		if !used[i] {
			t.Errorf("a plane control line no agent action accounts for: %v", e)
		}
	}
}

// controlMessage is the failure text of a cell: the agent's output and its run's ledger.
func controlMessage(out string, ledger string) string {
	return fmt.Sprintf("the agent said:\n%s\nledger:\n%s", out, ledger)
}

// controlRunning is a `tego run` a cell started and is talking to: what it printed, and whether it has ended.
type controlRunning struct {
	out    lockedBuffer
	done   chan struct{} // closed once the run has ended
	copied chan struct{} // closed once everything it printed is in out, or an orphan holding its output kept it open
	err    error         // how it ended, set before done closes
}

// startControlRun starts cmd with its output on a pipe the cell reads.
func startControlRun(t *testing.T, cmd *exec.Cmd) *controlRunning {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r := &controlRunning{done: make(chan struct{}), copied: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = wr, wr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = wr.Close()
	go func() {
		_, _ = io.Copy(&r.out, rd)
		_ = rd.Close()
		close(r.copied)
	}()
	go func() {
		r.err = cmd.Wait()
		close(r.done)
	}()
	return r
}

// answer waits for the agent's RESULT line of one step. A run that ends without it fails the cell at once, with
// what it printed, rather than after the minute the line is waited for.
func (r *controlRunning) answer(t *testing.T, step string) string {
	t.Helper()
	deadline := time.After(time.Minute)
	for {
		if got := agentResults(t, r.out.String())[step]; got != "" {
			return got
		}
		select {
		case <-r.done:
			r.drain()
			if got := agentResults(t, r.out.String())[step]; got != "" {
				return got
			}
			t.Fatalf("the run ended (%v) before the agent said %s:\n%s", r.err, step, r.out.String())
		case <-deadline:
			t.Fatalf("no RESULT %s within a minute; the run said:\n%s", step, r.out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// drain waits until what the run printed before it ended is all in out; an orphan that still holds the pipe open
// does not hold the cell for more than a few seconds.
func (r *controlRunning) drain() {
	select {
	case <-r.copied:
	case <-time.After(5 * time.Second):
	}
}

// wait is how the run ended, once all it printed is read.
func (r *controlRunning) wait() error {
	<-r.done
	r.drain()
	return r.err
}

// runControlAgent runs project p's agent.yaml once at tier under the plane pin mode, with env added to the launcher's,
// and returns what the agent reported and the run's ledger.
func runControlAgent(t *testing.T, bin string, p *planeProject, tier, mode string, env ...string) (map[string]string, []map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, nil)
	cmd.Env = append(cmd.Env, env...)
	r := startControlRun(t, cmd)
	if err := r.wait(); err != nil {
		t.Fatalf("tego run (%s@%s): %v\n%s", tier, mode, err, controlMessage(r.out.String(), ledgerDump(p.ledger)))
	}
	return agentResults(t, r.out.String()), runEvents(t, p.ledger)
}

// controlAgentPID is the pid the agent reported for itself.
func controlAgentPID(t *testing.T, res map[string]string) int {
	t.Helper()
	pid, err := strconv.Atoi(res["agent"])
	if err != nil || pid <= 0 {
		t.Fatalf("the agent reported no pid: %q", res["agent"])
	}
	return pid
}

// controlPtraceAgent is run A's agent. It forks three sleepers (its own child, which stays in its cgroup, and two the
// test moves out of it while the agent waits), tries to attach to a host process, to run B's agent, to each sleeper,
// then asks to be traced by its own parent inside the run and by its parent outside it, the launcher. Every
// answer is a RESULT line; a refusal says its errno. The agent ends itself last, since a TRACEME that succeeded would
// leave the launcher its tracer.
const controlPtraceAgent = `import ctypes, os, time

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
TRACEME, ATTACH, DETACH = 0, 16, 17

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def refused(errno):
    return "refused errno=%d" % errno

def attach(name, pid):
    if libc.ptrace(ATTACH, pid, None, None) != 0:
        result(name, refused(ctypes.get_errno()))
        return
    try:
        os.waitpid(pid, 0)
    finally:
        libc.ptrace(DETACH, pid, None, None)
    result(name, "ok")

def sleeper():
    pid = os.fork()
    if pid == 0:
        time.sleep(600)
        os._exit(0)
    return pid

own, away_host, away_run = sleeper(), sleeper(), sleeper()
result("agent", os.getpid())
result("parent", os.getppid())
result("children", "%d %d %d" % (own, away_host, away_run))
open("out/ready", "w").close()
while not os.path.exists("out/go"):
    time.sleep(0.02)
attach("attach-host", int(os.environ["E54_HOST_PID"]))
attach("attach-other-run", int(os.environ["E54_OTHER_PID"]))
attach("attach-away-host", away_host)
attach("attach-away-run", away_run)
attach("attach-own-child", own)
os.kill(own, 9)  # a run waits for its whole cgroup to empty, and a sleeper left in it would hold the run for 600 s
os.waitpid(own, 0)
child = os.fork()
if child == 0:
    os._exit(0 if libc.ptrace(TRACEME, 0, None, None) == 0 else ctypes.get_errno())
_, status = os.waitpid(child, 0)
code = os.waitstatus_to_exitcode(status)
result("traceme-own-parent", "ok" if code == 0 else refused(code))
if libc.ptrace(TRACEME, 0, None, None) == 0:
    result("traceme-outside-parent", "ok")
else:
    result("traceme-outside-parent", refused(ctypes.get_errno()))
result("done", 1)
os._exit(0)
`

// controlWaitAgent is run B's agent: it says its pid, says it is ready, and waits to be told to stop.
const controlWaitAgent = `import os, time
print("RESULT pid", os.getpid(), flush=True)
open("out/ready-b", "w").close()
while not os.path.exists("out/stop-b"):
    time.sleep(0.05)
`

// moveTask puts pid in the cgroup dir the way root does from outside the run: a write to its cgroup.procs.
func moveTask(t *testing.T, dir string, pid int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatalf("move %d into %s: %v", pid, dir, err)
	}
}

// controlCgroupOf is the cgroup directory pid is in.
func controlCgroupOf(t *testing.T, pid int) string {
	t.Helper()
	rel, err := cgroupPathOfPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join("/sys/fs/cgroup", rel)
}

// controlKillOnCleanup ends pid with SIGKILL when the cell does, and again at once if the cell asks.
func controlKillOnCleanup(t *testing.T, pid int) func() {
	kill := func() { _ = syscall.Kill(pid, syscall.SIGKILL) }
	t.Cleanup(kill)
	return kill
}

// controlScratchCgroup makes a cgroup in no run, for the cell to move one of its own tasks into, and returns its
// directory. The kernel refuses to remove a cgroup with a task in it, and runCgroupUnderSelf removes this one in a
// cleanup of its own. Cleanups run last-registered first, so the one registered here runs before that: it kills the task
// (kill) and then waits for the cgroup to empty. It is registered before any task is moved in, so a cell that ends with
// the task still there, a t.Fatalf between the move and the cell's own kill included, leaves no cgroup behind. One that
// did would fail every later cell of the binary at runCgroupUnderSelf ("file exists") and hide what had failed.
func controlScratchCgroup(t *testing.T, kill func()) string {
	t.Helper()
	rel, _, _ := runCgroupUnderSelf(t, "e54")
	dir := filepath.Join("/sys/fs/cgroup", rel)
	t.Cleanup(func() {
		kill() // the task first: while it is alive the cgroup neither empties nor can be removed
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if b, _ := os.ReadFile(filepath.Join(dir, "cgroup.procs")); len(strings.TrimSpace(string(b))) == 0 {
				return
			}
		}
		t.Errorf("%s still holds a task 5 s after it was killed, so it cannot be removed", dir)
	})
	return dir
}

// controlOutsideIsNotDecided is TIER3-PLAN §9's "allows outside the run" for the process controls, asked while runs
// are live: the test is a process of no run, and attaches to a process, uses the kernel keyring and makes a BPF map,
// none of which the plane's hooks answer, since each looks the run up first and returns 0 on a miss (R1). The
// attach, its wait and its detach are on one thread, which is the tracer, and so is the keyring: a process keyring
// is installed on the credentials of the thread that asks for it.
func controlOutsideIsNotDecided(t *testing.T, victim int) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(victim); err != nil {
		t.Errorf("a process of no run attaches to another process: %v", err)
	} else {
		var status unix.WaitStatus
		stopped := false
		for deadline := time.Now().Add(5 * time.Second); !stopped && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if pid, err := unix.Wait4(victim, &status, unix.WNOHANG, nil); err == nil && pid == victim {
				stopped = status.Stopped()
				break
			}
		}
		if !stopped {
			t.Errorf("the process a process of no run attached to did not stop (%v)", status)
		}
		if err := unix.PtraceDetach(victim); err != nil {
			t.Errorf("detach: %v", err)
		}
	}
	ring, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_PROCESS_KEYRING, true)
	if err != nil {
		t.Errorf("a process of no run asks for its keyring: %v", err)
	} else if key, err := unix.AddKey("user", "tego-e54-outside", []byte("x"), ring); err != nil {
		t.Errorf("a process of no run adds a key: %v", err)
	} else if _, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, key, 0, 0, 0); err != nil {
		t.Errorf("a process of no run revokes its key: %v", err)
	}
	_ = rlimit.RemoveMemlock()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Errorf("a process of no run makes a map: %v", err)
		return
	}
	_ = m.Close()
}

// TestPlaneRunControlPtraceIsRunScoped is enforce-plane §2.20's ptrace_access_check (ATTACH mode) and ptrace_traceme
// in a real run. Run A's agent, in a run of its own, attaches to: a process of its uid outside every
// run; the agent of a second run B; a descendant of its own that root has moved out of the run's cgroup, and one
// root has moved into B's cgroup, both still in its Landlock domain so that only the plane can refuse them; and its
// own child, in the run. It then asks to be traced by a child's parent in the run, and by its own parent, the
// launcher outside it. The plane refuses what is not its own run and generation with EACCES, one `refused` line each
// (op ptrace or ptrace_traceme, rule process-scope, reason landlock-topology, the peer's pid), and allows the child
// and the parent in the run, with no line. The first two attaches are answered by Landlock's scope, or by Yama's
// ptrace_scope, before the plane where the LSM order puts either first (planeAnswersFirst, planeAttachRefusers): EPERM
// and no line, which the cell expects exactly then. The two moved descendants are admitted by both.
//
// Spec: docs/p0/enforce-plane.md R1, R3, R22, R23.
func TestPlaneRunControlPtraceIsRunScoped(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		for _, tier := range controlTiers(mode) {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) { controlPtraceCell(t, bin, uid, gid, tier, mode, recording) })
			}
		}
	}
}

func controlPtraceCell(t *testing.T, bin string, uid, gid int, tier, mode, recording string) {
	p := newPlaneProject(t, uid, gid, map[string]string{
		"agent.py": controlPtraceAgent, "waitb.py": controlWaitAgent,
		"agent.yaml": controlContract("e54-ptrace", "agent.py", recording, false, true, []string{"E54_HOST_PID", "E54_OTHER_PID"}),
		"other.yaml": controlContract("e54-other", "waitb.py", recording, false, true, nil),
	}, []string{"out"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Run B, whose agent only waits to be attached to, with a ledger of its own.
	pb := newPlaneProjectConfig(t, p)
	b := startControlRun(t, pb.runAt(ctx, bin, tier, "other.yaml", mode, nil))
	otherPID, err := strconv.Atoi(b.answer(t, "pid"))
	if err != nil {
		t.Fatalf("run B's agent said no pid: %v", err)
	}
	waitFile(t, filepath.Join(p.project, "out", "ready-b"), time.Minute, nil, nil)
	stopB := func() {
		_ = os.WriteFile(filepath.Join(p.project, "out", "stop-b"), nil, 0o644)
		_ = b.wait()
	}
	defer stopB()

	// A process of the agent's uid outside every run.
	host := exec.Command("sleep", "600")
	host.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Process.Kill(); _ = host.Wait() })

	// Run A.
	cmdA := p.runAt(ctx, bin, tier, "agent.yaml", mode, nil)
	cmdA.Env = append(cmdA.Env, "E54_HOST_PID="+strconv.Itoa(host.Process.Pid), "E54_OTHER_PID="+strconv.Itoa(otherPID))
	a := startControlRun(t, cmdA)
	pids := strings.Fields(a.answer(t, "children"))
	if len(pids) != 3 {
		t.Fatalf("the agent's children: %v", pids)
	}
	var own, awayHost, awayRun int
	for i, dst := range []*int{&own, &awayHost, &awayRun} {
		if *dst, err = strconv.Atoi(pids[i]); err != nil {
			t.Fatalf("the agent's children %v: %v", pids, err)
		}
	}
	killHost, killRun := controlKillOnCleanup(t, awayHost), controlKillOnCleanup(t, awayRun)
	// A run ends only once its whole cgroup is empty, so the child moved into run B's is killed here, ahead of the
	// deferred stopB that waits for B, as well as at cleanup: a cell that failed after the move would otherwise sit in
	// stopB until its context ended.
	defer killRun()
	waitFile(t, filepath.Join(p.project, "out", "ready"), time.Minute, nil, nil)

	// Root moves two of the agent's children out of its cgroup: one to a cgroup in no run, one to run B's.
	scratch := controlScratchCgroup(t, killHost)
	moveTask(t, scratch, awayHost)
	moveTask(t, controlCgroupOf(t, otherPID), awayRun)
	controlOutsideIsNotDecided(t, host.Process.Pid)
	if err := os.WriteFile(filepath.Join(p.project, "out", "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	a.answer(t, "done")
	killHost()
	killRun()
	if err := a.wait(); err != nil {
		t.Fatalf("run A (%s@%s): %v\n%s", tier, mode, err, controlMessage(a.out.String(), ledgerDump(p.ledger)))
	}
	res := agentResults(t, a.out.String())
	events := runEvents(t, p.ledger)
	agentPID, parentPID := controlAgentPID(t, res), 0
	if parentPID, err = strconv.Atoi(res["parent"]); err != nil || parentPID <= 0 {
		t.Fatalf("the agent reported no parent: %q", res["parent"])
	}

	// What each step must answer. An attach out of the run is Landlock's or Yama's EPERM where either is first, the
	// plane's EACCES where the plane is; the two it can only refuse, and the traceme under the launcher (which Landlock
	// admits: an unconfined parent may trace a confined child), are the plane's in both modes.
	const eperm, eacces = "refused errno=1", "refused errno=13"
	out := eperm
	if planeAnswersFirst(mode, planeAttachRefusers()...) {
		out = eacces
	}
	steps := []struct {
		name, outcome string
		peer          int
		op            string
	}{
		{"attach-host", out, host.Process.Pid, "ptrace"},
		{"attach-other-run", out, otherPID, "ptrace"},
		{"attach-away-host", eacces, awayHost, "ptrace"},
		{"attach-away-run", eacces, awayRun, "ptrace"},
		{"attach-own-child", "ok", own, "ptrace"},
		{"traceme-own-parent", "ok", agentPID, "ptrace_traceme"},
		{"traceme-outside-parent", eacces, parentPID, "ptrace_traceme"},
	}
	var want []wantControl
	for _, s := range steps {
		if res[s.name] != s.outcome {
			t.Errorf("%s: %q, want %q", s.name, res[s.name], s.outcome)
		}
		if s.outcome == eacces {
			want = append(want, wantControl{op: s.op, rule: "process-scope", reason: "landlock-topology", target: controlTargetIs("", s.peer)})
		}
	}
	expectControlLines(t, events, mode, agentPID, want)
	t.Logf("%s@%s/%s: the agent's attaches and tracemes %v; plane control lines %s", tier, mode, recording,
		[]string{res["attach-host"], res["attach-other-run"], res["attach-away-host"], res["attach-away-run"], res["attach-own-child"],
			res["traceme-own-parent"], res["traceme-outside-parent"]}, controlSummary(events))

	// A run that is only attached to is not decided: B, the target of two of the attaches, has no control line.
	stopB()
	expectControlLines(t, runEvents(t, pb.ledger), mode, 0, nil)
	if t.Failed() {
		t.Logf("%s", controlMessage(a.out.String(), ledgerDump(p.ledger)))
	}
}

// TestPlaneRunControlScratchCgroupGoesWithItsLiveTask is the cleanup order the ptrace cell relies on when it fails
// between moving a task into its scratch cgroup and killing it: a cell that ends with the task still alive, as a
// t.Fatalf there makes it end, leaves no cgroup behind. One that did would fail every later cell of the binary at
// runCgroupUnderSelf ("file exists"), and hide what had failed.
func TestPlaneRunControlScratchCgroupGoesWithItsLiveTask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a task is moved into a cgroup of its own as root")
	}
	var dir string
	t.Run("a cell that ends with its task alive", func(t *testing.T) {
		sleeper := exec.Command("sleep", "600")
		if err := sleeper.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
		dir = controlScratchCgroup(t, func() { _ = sleeper.Process.Kill() })
		moveTask(t, dir, sleeper.Process.Pid)
	})
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("%s outlived the cell that ended with a live task in it", dir)
		_ = os.Remove(dir)
	}
}

// The key_need_perm values (include/linux/key.h) the permission checks of keyctl(GET_KEYRING_ID) and add_key name.
const (
	keyNeedWrite  = 3
	keyNeedSearch = 4
)

// controlKeyringAgent runs the keyring steps argv names, in order, and reports each as a RESULT line: id is
// keyctl(GET_KEYRING_ID, process keyring, create), add an add_key into it, read a keyctl(READ) of the added key,
// request a request_key of it.
const controlKeyringAgent = `import ctypes, os, sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
ADD_KEY, REQUEST_KEY, KEYCTL = {"x86_64": (248, 249, 250), "aarch64": (217, 218, 219)}[os.uname().machine]
PROCESS_KEYRING = -2
GET_KEYRING_ID, READ = 0, 11

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def call(name, nr, *args):
    cargs = [ctypes.c_char_p(a) if isinstance(a, bytes) else ctypes.c_long(a) for a in args]
    r = libc.syscall(ctypes.c_long(nr), *cargs)
    result(name, "ok" if r >= 0 else "refused errno=%d" % ctypes.get_errno())
    return r

result("agent", os.getpid())
buf = ctypes.create_string_buffer(32)
key = -1
for step in sys.argv[1:]:
    if step == "id":
        call(step, KEYCTL, GET_KEYRING_ID, PROCESS_KEYRING, 1)
    elif step == "add":
        key = call(step, ADD_KEY, b"user", b"tego-e54", b"payload", 7, PROCESS_KEYRING)
    elif step == "read":
        call(step, KEYCTL, READ, key, ctypes.addressof(buf), 32)
    elif step == "request":
        call(step, REQUEST_KEY, b"user", b"tego-e54", 0, 0)
`

// TestPlaneRunControlKeyringIsTheContractsOptIn is enforce-plane §2.20's key_permission in a real run.
// The documented behaviour is the contract's `keyring: true` and nothing finer: the hook admits every key
// permission check of a run whose slot carries the flag, and refuses every one of a run that does not (read-denied).
//   - Without the opt-in the supervisor refuses the three syscalls first, EPERM, with its own refused line (rule
//     keyring, source supervisor) and no plane line: the hook is not reached.
//   - With it the supervisor continues them, the plane's hook admits them (the flag reached the slot), and the use is
//     recorded as the supervisor's gap lines keyring-<syscall>, once per syscall; no refusal, no plane line.
//   - Without it and with the filter's keyring arms left out, only the plane answers: EACCES to each syscall and a
//     key_permission line (rule keyring, reason read-denied, the permission asked for) for each refused permission
//     check, and no supervisor line. The hook is per check, not per syscall: keyctl(GET_KEYRING_ID) asks to search the
//     keyring and add_key to write it, one check each and so one line each, where keyctl(DESCRIBE) makes three (the
//     view, then two searches for an authorisation token) and would leave three lines for its one refusal.
//
// Spec: docs/p0/enforce-plane.md R3, R23.
func TestPlaneRunControlKeyringIsTheContractsOptIn(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		for _, tier := range controlTiers(mode) {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) {
					run := func(keyring bool, env []string, steps ...string) (map[string]string, []map[string]any) {
						p := newPlaneProject(t, uid, gid, map[string]string{
							"agent.py":   controlKeyringAgent,
							"agent.yaml": controlContract("e54-keyring", "agent.py", recording, keyring, true, nil, steps...),
						}, []string{"out"}, nil)
						return runControlAgent(t, bin, p, tier, mode, env...)
					}
					// The supervisor's workers answer concurrently, so its lines are in no order the agent's calls fix.
					refusedLines := func(events []map[string]any) (ops []string) {
						for _, e := range events {
							if e["kind"] == "refused" && e["rule"] == "keyring" && e["source"] == "supervisor" && e["reason"] == "read-denied" {
								ops = append(ops, fmt.Sprint(e["op"]))
							}
						}
						slices.Sort(ops)
						return ops
					}
					gapWhys := func(events []map[string]any) (whys []string) {
						for _, e := range events {
							if e["kind"] == "gap" && e["what"] == "record" && strings.HasPrefix(fmt.Sprint(e["why"]), "keyring-") {
								whys = append(whys, fmt.Sprint(e["why"]))
							}
						}
						slices.Sort(whys)
						return whys
					}

					// No opt-in, the filter as a product has it: the supervisor's refusals.
					res, events := run(false, nil, "id", "add", "request")
					for _, step := range []string{"id", "add", "request"} {
						if res[step] != "refused errno=1" {
							t.Errorf("%s without keyring: %q, want EPERM from the supervisor", step, res[step])
						}
					}
					if ops := refusedLines(events); !slices.Equal(ops, []string{"add_key", "keyctl", "request_key"}) {
						t.Errorf("the supervisor's refused lines %v, want add_key, keyctl and request_key once each", ops)
					}
					expectControlLines(t, events, mode, 0, nil)

					// The opt-in: allowed by the supervisor and the plane, and recorded as gaps.
					res, events = run(true, nil, "id", "add", "read", "request")
					for _, step := range []string{"id", "add", "read", "request"} {
						if res[step] != "ok" {
							t.Errorf("%s with keyring: true: %q, want ok", step, res[step])
						}
					}
					if ops := refusedLines(events); len(ops) != 0 {
						t.Errorf("refused keyring lines %v with keyring: true", ops)
					}
					if whys := gapWhys(events); !slices.Equal(whys, []string{"keyring-add_key", "keyring-keyctl", "keyring-request_key"}) {
						t.Errorf("keyring gap lines %v, want keyring-add_key, keyring-keyctl and keyring-request_key once each", whys)
					}
					expectControlLines(t, events, mode, 0, nil)

					// No opt-in, the filter's keyring arms left out: only the plane answers.
					res, events = run(false, []string{envFilterOmit + "=" + controlOmitArms}, "id", "add")
					var want []wantControl
					for step, perm := range map[string]int{"id": keyNeedSearch, "add": keyNeedWrite} {
						if res[step] != "refused errno=13" {
							t.Errorf("%s without keyring and without the filter's arm: %q, want EACCES from the plane", step, res[step])
						}
						want = append(want, wantControl{op: "key_permission", rule: "keyring", reason: "read-denied", target: controlTargetIs("permission ", perm)})
					}
					expectControlLines(t, events, mode, controlAgentPID(t, res), want)
					if ops := refusedLines(events); len(ops) != 0 {
						t.Errorf("the supervisor refused %v although the filter's arms were left out", ops)
					}
					t.Logf("%s@%s/%s: plane control lines with the filter's arms left out %s", tier, mode, recording, controlSummary(events))
				})
			}
		}
	}
}

// controlBPFAgent receives a map's descriptor over SCM_RIGHTS from the test, which holds it as root outside every run,
// and runs three bpf(2) commands on it: a lookup, an update (to 0xe54) and a get-next-key. The commands need no
// capability to run on a descriptor the caller holds, so nothing but the kernel's security_bpf stands between the
// agent and the map once the filter lets bpf(2) through.
const controlBPFAgent = `import ctypes, os, socket, struct

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
SYS_BPF = {"x86_64": 321, "aarch64": 280}[os.uname().machine]
LOOKUP, UPDATE, NEXT_KEY = 1, 2, 4

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

result("agent", os.getpid())
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(os.environ["E54_SOCK"])
_, fds, _, _ = socket.recv_fds(sock, 8, 4)
fd = fds[0]
key = ctypes.create_string_buffer(4)
value = ctypes.create_string_buffer(struct.pack("=I", 0xE54), 4)
other = ctypes.create_string_buffer(4)

def bpf(name, cmd, addr):
    attr = ctypes.create_string_buffer(struct.pack("=IxxxxQQQ", fd, ctypes.addressof(key), addr, 0), 128)
    r = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(cmd), attr, ctypes.c_long(128))
    result(name, "ok" if r >= 0 else "refused errno=%d" % ctypes.get_errno())

bpf("lookup", LOOKUP, ctypes.addressof(other))
bpf("update", UPDATE, ctypes.addressof(value))
bpf("next-key", NEXT_KEY, ctypes.addressof(other))
`

// controlMapServer holds a one-entry array map as root and hands its descriptor to whoever connects to the socket
// it returns the path of, over SCM_RIGHTS. The socket's directory is the test's own and short, since a unix path
// holds 107 bytes.
func controlMapServer(t *testing.T) (path string, m *ebpf.Map) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("remove memlock: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatalf("a map outside the run: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	dir, err := os.MkdirTemp("", "e54-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			_, _, _ = c.WriteMsgUnix([]byte{'m'}, unix.UnixRights(m.FD()), nil)
			_ = c.Close()
		}
	}()
	return path, m
}

// TestPlaneRunControlBPFIsRefused is enforce-plane §2.20's bpf hook in a real run. The agent holds a
// map descriptor the test passed in over SCM_RIGHTS and runs three bpf(2) commands on it.
//   - With the filter as a product has it, the root-tier arm answers each with EPERM before the kernel is asked
//     (ADR 0033) and the plane writes nothing: the hook is a second layer a run cannot reach.
//   - With the arm left out, security_bpf is reached and the plane refuses each command with EACCES, one `bpf` line
//     each naming the command, and the map is as the test left it (the update did not happen). BPF_MAP_CREATE is not a
//     cell: kernel.unprivileged_bpf_disabled refuses it with EPERM ahead of the hook, where the sysctl is set.
//
// Spec: docs/p0/enforce-plane.md R3, R23.
func TestPlaneRunControlBPFIsRefused(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		for _, tier := range controlTiers(mode) {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) {
					run := func(env ...string) (map[string]string, []map[string]any, *ebpf.Map) {
						sock, m := controlMapServer(t)
						p := newPlaneProject(t, uid, gid, map[string]string{
							"agent.py": controlBPFAgent,
							// No net: section, and host_sockets: true: the test's socket is one the run did not bind.
							"agent.yaml": controlContract("e54-bpf", "agent.py", recording, false, false, []string{"E54_SOCK"}),
						}, []string{"out"}, nil)
						res, events := runControlAgent(t, bin, p, tier, mode, append(env, "E54_SOCK="+sock)...)
						return res, events, m
					}
					mapValue := func(m *ebpf.Map) uint32 {
						var v uint32
						if err := m.Lookup(uint32(0), &v); err != nil {
							t.Fatal(err)
						}
						return v
					}

					// The filter as a product has it.
					res, events, m := run()
					for _, step := range []string{"lookup", "update", "next-key"} {
						if res[step] != "refused errno=1" {
							t.Errorf("%s with the product filter: %q, want EPERM from its root-tier arm", step, res[step])
						}
					}
					expectControlLines(t, events, mode, 0, nil)
					if v := mapValue(m); v != 0 {
						t.Errorf("the map holds %#x after the product filter's refusals", v)
					}

					// The arm left out: the plane's hook alone.
					res, events, m = run(envFilterOmit + "=" + controlOmitArms)
					var want []wantControl
					for step, cmd := range map[string]int{"lookup": 1, "update": 2, "next-key": 4} {
						if res[step] != "refused errno=13" {
							t.Errorf("%s without the filter's arm: %q, want EACCES from the plane", step, res[step])
						}
						want = append(want, wantControl{op: "bpf", rule: "bpf", reason: "landlock-topology", target: controlTargetIs("command ", cmd)})
					}
					expectControlLines(t, events, mode, controlAgentPID(t, res), want)
					if v := mapValue(m); v != 0 {
						t.Errorf("the map holds %#x: an update the plane refused took effect", v)
					}
					t.Logf("%s@%s/%s: plane control lines with the filter's arm left out %s", tier, mode, recording, controlSummary(events))
				})
			}
		}
	}
}
