// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// cliProc is the /proc an adoption reads in these tests: processes by pid, each with an owner and a cgroup.
type cliProc struct {
	mu    sync.Mutex
	procs map[int]cliProcess
}

type cliProcess struct {
	ppid   int
	exe    string
	cgroup string
	uid    int
	// leaderExited makes the process's stat a zombie that counts threads + 1 tasks (its leader exited while they run).
	leaderExited bool
	threads      int
	// zombie makes a thread entry an exited task its tracer has not reaped.
	zombie bool
	// tgid, when set, makes the entry a thread of process tgid other than its leader: no listing of /proc names it.
	tgid int
}

func newCLIProc() *cliProc { return &cliProc{procs: map[int]cliProcess{}} }

func (c *cliProc) add(pid, ppid int, exe, cg string, uid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.procs[pid] = cliProcess{ppid: ppid, exe: exe, cgroup: cg, uid: uid}
}

func (c *cliProc) get(pid int) (cliProcess, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.procs[pid]
	if !ok {
		return p, fmt.Errorf("pid %d: %w", pid, proc.ErrGone)
	}
	return p, nil
}

// set changes process pid with f; a pid it does not hold is added as f makes it.
func (c *cliProc) set(pid int, f func(*cliProcess)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.procs[pid]
	f(&p)
	c.procs[pid] = p
}

func (c *cliProc) del(pid int) { c.mu.Lock(); delete(c.procs, pid); c.mu.Unlock() }

func (c *cliProc) PIDs() ([]int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int
	for pid, p := range c.procs {
		if p.tgid == 0 {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out, nil
}

func (c *cliProc) Stat(pid int) (proc.Stat, error) {
	p, err := c.get(pid)
	if err != nil {
		return proc.Stat{}, err
	}
	// The same start time newFakeProcRoot writes, so the watcher's identity and the adoption's agree.
	st := proc.Stat{PID: pid, Comm: filepath.Base(p.exe), State: 'S', PPID: p.ppid, StartTicks: uint64(5000 + pid), NumThreads: 1}
	if p.leaderExited {
		st.State, st.NumThreads = 'Z', p.threads+1
	}
	if p.zombie {
		st.State = 'Z'
	}
	return st, nil
}

func (c *cliProc) Exe(pid int) (string, error) {
	p, err := c.get(pid)
	return p.exe, err
}

func (c *cliProc) Argv(pid int) ([]string, error) {
	p, err := c.get(pid)
	return []string{p.exe}, err
}

func (c *cliProc) Cgroup(pid int) (string, error) {
	p, err := c.get(pid)
	return p.cgroup, err
}

func (c *cliProc) Status(pid int) (adopt.Status, error) {
	p, err := c.get(pid)
	tgid := pid
	if p.tgid != 0 {
		tgid = p.tgid
	}
	return adopt.Status{Tgid: tgid, UID: [3]int{p.uid, p.uid, p.uid}, GID: [3]int{p.uid, p.uid, p.uid}}, err
}

func (c *cliProc) ExeFile(pid int) (adopt.FileID, error) {
	return adopt.FileID{Dev: 9, Ino: uint64(pid)}, nil
}
func (c *cliProc) Namespace(int, string) (uint64, error) { return 1, nil }
func (c *cliProc) Cwd(int) (string, error)               { return "/", nil }
func (c *cliProc) FDs(int) ([]adopt.FD, error)           { return nil, nil }
func (c *cliProc) Tasks(pid int) ([]int, error) {
	if _, err := c.get(pid); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tids := []int{pid}
	for tid, p := range c.procs {
		if p.tgid == pid {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return tids, nil
}

// sandboxAdopt makes the adoption seams this test's: privilege, /proc, this process's own identity (a tego under
// sudo in the terminal of pid 300), the preparation and the run, whose calls it records.
type adoptCalls struct {
	mu    sync.Mutex
	specs []tegoruntime.AdoptSpec
	// block makes each run wait for its context, as a real adoption waits for its agent or its release.
	block bool
}

func (c *adoptCalls) roots() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int
	for _, s := range c.specs {
		out = append(out, s.Root.PID)
	}
	return out
}

func sandboxAdopt(t *testing.T, p *cliProc, privileged bool) *adoptCalls {
	t.Helper()
	calls := &adoptCalls{}
	prevP, prevProc, prevSelf, prevPrep, prevRun := adoptPrivileged, adoptProc, adoptSelf, adoptPrepare, adoptRun
	prevUID := adoptInvokingUID
	adoptInvokingUID = func() int { return 1000 } // sudo, run by the operator (uid 1000)
	adoptPrivileged = func() bool { return privileged }
	adoptProc = func() adopt.Proc { return p }
	adoptSelf = func(adopt.Proc) (adopt.Self, error) {
		return adopt.Self{PID: 801, Ancestors: []int{800, 300, 90, 1}, ExeFile: adopt.FileID{Dev: 9, Ino: 801},
			Exe: "/usr/local/bin/tego", CgroupNS: 1, PidNS: 1}, nil
	}
	adoptPrepare = func(_ context.Context, m *config.Machine, o adoptOptions, tp adopt.Process, owner int, _ io.Writer) (*preparedAdoption, int) {
		rt := &agent.RuleTable{Contract: &agent.Contract{Name: "adopt-claude"}, Tier: backend.TierCgroup, Record: agent.RecordFull}
		return &preparedAdoption{rt: rt, m: m, cleanup: func() {}, boundary: o.boundary != ""}, identity.ExitOK
	}
	adoptRun = func(ctx context.Context, _ *agent.RuleTable, spec tegoruntime.AdoptSpec, _ tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
		calls.mu.Lock()
		calls.specs = append(calls.specs, spec)
		block := calls.block
		calls.mu.Unlock()
		run := fmt.Sprintf("r-0a1b2c3d-0123456789abc-xyz%03d", spec.Root.PID%1000)
		if spec.Started != nil {
			spec.Started(tegoruntime.AdoptStarted{RunID: run, From: spec.Root.Cgroup, Moved: []adopt.Process{spec.Root},
				Window: 42 * time.Millisecond})
		}
		reason := record.RunEndExit
		if block {
			<-ctx.Done()
			reason = record.RunEndStopped
		}
		return tegoruntime.Result{RunID: run, Reason: reason}, nil
	}
	t.Cleanup(func() {
		adoptPrivileged, adoptProc, adoptSelf, adoptPrepare, adoptRun = prevP, prevProc, prevSelf, prevPrep, prevRun
		adoptInvokingUID = prevUID
	})
	return calls
}

// terminalProcs is a machine with sshd (90) holding a session: the operator's shell (300), sudo (800) and this tego
// (801) in it, and the agent (500, uid 1000), the shell's child.
func terminalProcs() *cliProc {
	p := newCLIProc()
	const sess = "/user.slice/user-1000.slice/session-2.scope"
	p.add(1, 0, "/usr/lib/systemd/systemd", "/init.scope", 0)
	p.add(90, 1, "/usr/sbin/sshd", sess, 0)
	p.add(300, 90, "/usr/bin/bash", sess, 1000)
	p.add(800, 300, "/usr/bin/sudo", sess, 0)
	p.add(801, 800, "/usr/local/bin/tego", sess, 0)
	p.add(500, 300, "/usr/bin/claude", sess, 1000)
	return p
}

func runAdoptCmd(t *testing.T, ctx context.Context, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = mainWith(ctx, append([]string{"tego", "adopt"}, args...), &o, &e, []Command{cmdAdopt()})
	return code, o.String(), e.String()
}

func TestAdoptCommandUsageAndPrivilege(t *testing.T) {
	sandboxAdopt(t, terminalProcs(), true)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "--pid <pid> is required"},
		{[]string{"--pid", "0"}, "--pid <pid> is required"},
		{[]string{"--pid", "5", "x"}, "no arguments"},
		{[]string{"--pid", "5", "--release", "--boundary", "c.yaml"}, "--release takes --pid alone"},
		{[]string{"--pid", "5", "--release", "--uid", "1000"}, "--release takes --pid alone"},
		{[]string{"--pid", "5", "--uid", "x"}, `"x" is not a uid`},
		{[]string{"--pid", "5", "--record", "loud"}, "not full, summary or off"},
		{[]string{"--pid", "5", "--boundary", ""}, "--boundary is an empty string"},
		{[]string{"--pid", "5", "--boundary="}, "--boundary is an empty string"},
	} {
		if code, _, errs := runAdoptCmd(t, t.Context(), tc.args...); code != identity.ExitUsage || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: code %d stderr %q, want usage containing %q", tc.args, code, errs, tc.want)
		}
	}
	sandboxAdopt(t, terminalProcs(), false)
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
	if code != identity.ExitLauncher || !strings.Contains(errs, "needs root") || !strings.HasSuffix(strings.TrimSpace(errs), "[privilege]") {
		t.Fatalf("unprivileged: code %d stderr %q", code, errs)
	}
}

func TestAdoptCommandRefusesWhatIsNeverAdopted(t *testing.T) {
	p := terminalProcs()
	p.add(2, 0, "", "/", 0)
	p.add(600, 1, "/usr/bin/claude", "/tego.slice/tego-adopt-claude.slice/adopt-r-0a1b2c3d-0123456789abc-xyz123.scope", 1000)
	calls := sandboxAdopt(t, p, true)
	for pid, rule := range map[int]string{
		1:   adopt.RefuseInit,
		2:   adopt.RefuseKernel,
		300: adopt.RefuseAncestor, // the operator's own shell
		90:  adopt.RefuseAncestor, // sshd
		800: adopt.RefuseAncestor, // sudo
		801: adopt.RefuseTego,     // this tego
		600: adopt.RefuseGoverned, // adopted already
	} {
		code, _, errs := runAdoptCmd(t, t.Context(), "--pid", fmt.Sprint(pid))
		if code != identity.ExitLauncher || !strings.Contains(errs, "("+rule+")") || !strings.Contains(errs, "[adopt-refused]") {
			t.Errorf("pid %d: code %d stderr %q, want a refusal under %s", pid, code, errs, rule)
		}
	}
	if code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "4242"); code != identity.ExitLauncher || !strings.Contains(errs, "no process 4242") {
		t.Errorf("no such process: code %d stderr %q", code, errs)
	}
	if roots := calls.roots(); len(roots) != 0 {
		t.Fatalf("a refused process was adopted: %v", roots)
	}
}

// The refusal of the machine config names the command refused: tego adopt and tego agents --adopt said tego run, whose
// function (configRefused) they share.
func TestAdoptConfigRefusalNamesTheCommand(t *testing.T) {
	t.Setenv("TEGO_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	refusal := func(errs string) string {
		for _, line := range strings.Split(errs, "\n") {
			if strings.Contains(line, "[config-untrusted]") {
				return line
			}
		}
		return ""
	}
	calls := sandboxAdopt(t, terminalProcs(), true)
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
	if line := refusal(errs); code != identity.ExitConfig || !strings.HasPrefix(line, "tego adopt: ") || len(calls.roots()) != 0 {
		t.Errorf("tego adopt under a missing $TEGO_CONFIG: exit %d, %d adopted, want %d and a refusal led by tego adopt:\n%s",
			code, len(calls.roots()), identity.ExitConfig, errs)
	}
	sandboxAgents(t, t.TempDir(), true)
	code, _, errs = runAgentsCmd(t, "--follow", "--adopt", "--uid", "1000")
	if line := refusal(errs); code != identity.ExitConfig || !strings.HasPrefix(line, "tego agents: ") {
		t.Errorf("tego agents --adopt under a missing $TEGO_CONFIG: exit %d, want %d and a refusal led by tego agents:\n%s",
			code, identity.ExitConfig, errs)
	}
}

func TestAdoptCommandAdoptsAndSaysWhat(t *testing.T) {
	calls := sandboxAdopt(t, terminalProcs(), true)
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
	if code != identity.ExitOK {
		t.Fatalf("code %d stderr %q", code, errs)
	}
	for _, want := range []string{
		"pid 500 (/usr/bin/claude) runs as uid 1000",
		"nothing else moves",
		"never: what it did before the attach",
		"adopted pid 500 as run r-0a1b2c3d-0123456789abc-xyz500: 1 process(es) moved from /user.slice/user-1000.slice/session-2.scope",
		"recording since 42 ms after it was found",
		"ended (exit)",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr %q lacks %q", errs, want)
		}
	}
	if roots := calls.roots(); len(roots) != 1 || roots[0] != 500 {
		t.Fatalf("adopted %v", roots)
	}
}

// TestAdoptCommandEscapesWhatTheUserNames: the program's path and a cgroup's name below a delegated one are the
// adopted user's to choose, so a control byte in either is escaped on root's terminal, never written raw.
func TestAdoptCommandEscapesWhatTheUserNames(t *testing.T) {
	p := terminalProcs()
	p.add(500, 300, "/tmp/\x1b]0;owned\x07\x1b[2Jclaude", "/user.slice/user-1000.slice/session-2.scope/\x1b[31mred", 1000)
	sandboxAdopt(t, p, true)
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
	if code != identity.ExitOK {
		t.Fatalf("code %d stderr %q", code, errs)
	}
	if strings.ContainsAny(errs, "\x1b\x07") {
		t.Fatalf("a control byte reached the terminal raw: %q", errs)
	}
	for _, want := range []string{`/tmp/\x1b]0;owned\a\x1b[2Jclaude`, `session-2.scope/\x1b[31mred`} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr %q lacks the escaped %q", errs, want)
		}
	}
}

// compileAdoptTable compiles a contract for the unenforceable-rule check.
func compileAdoptTable(t *testing.T, body string) *agent.RuleTable {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"ws", "x"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	y := "version: 0\nname: b\ncommand: [\"/bin/true\"]\n" + strings.ReplaceAll(body, "{dir}", dir)
	c, _, err := agent.LoadBytes(filepath.Join(dir, "b.yaml"), []byte(y), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rt, _, err := agent.Compile(c, config.Builtin(), agent.WithCwd(dir), agent.WithHome(dir), agent.Offline())
	if err != nil {
		t.Fatalf("compile %q: %v", body, err)
	}
	return rt
}

func TestUnenforceableForAdoptionNamesEachRule(t *testing.T) {
	held := compileAdoptTable(t, "fs:\n  write: [\"{dir}/ws\", \"/dev/null\"]\n  deny_read: [\"{dir}/secret\"]\nexec:\n  allow: [\"/usr/bin/git\"]\n")
	if got := unenforceableForAdoption(held); len(got) != 0 {
		t.Fatalf("a contract the plane holds whole was refused: %v", got)
	}
	for body, want := range map[string]string{
		"net:\n  allow: [\"tcp://127.0.0.1:443\"]\n": "net.allow tcp://127.0.0.1:443",
		"net: {}\n":                                            "net: a net section refuses every connect",
		"env:\n  set: {A: \"1\"}\n":                            "env: a running process's environment cannot be changed",
		"limits:\n  memory: 1GiB\n  wall: 1h\n":                "limits.memory",
		"fs:\n  write: [\"{dir}/ws\"]\n  ask: [\"{dir}/x\"]\n": "fs.ask ",
		"tier: landlock\n":                                     "tier: landlock",
		"capture: uprobe\n":                                    "capture: uprobe",
		// Command rules are argv rules, the supervisor's: an adoption has none.
		"exec:\n  deny: [\"git push\"]\n":                                       "exec.deny git push: argv rules",
		"exec:\n  allow: [\"/bin/sh\", \"/usr/bin/rm\"]\n  deny: [\"rm -r\"]\n": "exec.deny rm -r",
		"exec:\n  allow: [\"/bin/sh\"]\n  ask: [\"rm -r\"]\n":                   "exec.ask rm -r",
		"exec:\n  allow: [\"/bin/sh\", \"/usr/bin/rm -f\"]\n":                   "exec.allow /usr/bin/rm -f",
	} {
		got := unenforceableForAdoption(compileAdoptTable(t, body))
		if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), want) {
			t.Errorf("%q: refused %q, want a line naming %q", body, got, want)
		}
	}
	got := unenforceableForAdoption(compileAdoptTable(t, "limits:\n  memory: 1GiB\n  wall: 1h\n"))
	if len(got) != 2 {
		t.Errorf("two limits are two lines: %q", got)
	}
	// One line per command pattern, and a refused table is never one whose run_start would list exec.rules/argv as
	// a best-effort cell nothing decides.
	rt := compileAdoptTable(t, "exec:\n  allow: [\"/bin/sh\", \"/usr/bin/rm\"]\n  deny: [\"rm -r\", \"git push\"]\n  ask: [\"rm -f\"]\n")
	if got := unenforceableForAdoption(rt); len(got) != 3 {
		t.Errorf("three command patterns are three lines: %q", got)
	}
	if cells := held.BestEffortCells(); len(cells) != 0 {
		t.Errorf("the held table lists best-effort cells %v", cells)
	}
}

func TestAgentsAdoptUsage(t *testing.T) {
	sandboxAgents(t, t.TempDir(), true)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--adopt", "--uid", "1000"}, "--adopt needs --follow"},
		{[]string{"--follow", "--adopt"}, "--adopt needs at least one --uid"},
		{[]string{"--follow", "--uid", "1000"}, "need --adopt"},
		{[]string{"--follow", "--boundary", "c.yaml"}, "need --adopt"},
		{[]string{"--follow", "--adopt", "--uid", "x"}, `"x" is not a uid`},
		{[]string{"--follow", "--adopt", "--uid", "1000", "--record", "loud"}, "not full, summary or off"},
		{[]string{"--follow", "--adopt", "--uid", "1000", "--boundary", ""}, "--boundary is an empty string"},
	} {
		code, out, errs := runAgentsCmd(t, tc.args...)
		if code != identity.ExitUsage || out != "" || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: code %d stdout %q stderr %q, want usage containing %q", tc.args, code, out, errs, tc.want)
		}
	}
}

// guardLines are the guard's output lines, by event.
func guardLines(t *testing.T, out string) map[string][]watcher.Sighting {
	t.Helper()
	got := map[string][]watcher.Sighting{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var s watcher.Sighting
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		got[s.Event] = append(got[s.Event], s)
	}
	return got
}

// TestGuardAdoptsOnlyListedOwnersOutsideRuns is the guard against a machine where any user can call a program
// claude: an agent of a listed uid outside every run is adopted; one of another uid, root's without --uid 0, one
// inside a governed run and one above the guard itself are not, and each but the governed one is reported.
func TestGuardAdoptsOnlyListedOwnersOutsideRuns(t *testing.T) {
	const term = "/user.slice/user-1000.slice/session-2.scope"
	const inRun = "/tego.slice/tego-w.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope"
	p := terminalProcs()
	f := newFakeProcRoot(t)
	sandboxAgents(t, f.root, true)
	calls := sandboxAdopt(t, p, true)
	calls.block = true
	src := &chanSource{ch: make(chan []procconn.Event), done: make(chan struct{}), ready: make(chan struct{})}
	agentsOpen = func() (watcher.Source, error) { return src, nil }

	var out, errs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- mainWith(ctx, []string{"tego", "agents", "--follow", "--adopt", "--uid", "1000", "--json"}, &out, &errs,
			[]Command{cmdAgents()})
	}()
	<-src.ready
	agents := []struct {
		pid, uid int
		cg       string
	}{
		{510, 1000, term},  // adopted
		{511, 1001, term},  // another user's: refused (uid)
		{512, 0, term},     // root's, 0 not listed: refused (uid)
		{513, 1000, inRun}, // inside a governed run: not considered
	}
	for _, a := range agents {
		f.add(a.pid, 300, "claude", "claude", []string{"claude"}, a.cg, "")
		p.add(a.pid, 300, filepath.Join(f.bin, "claude"), a.cg, a.uid)
		src.ch <- []procconn.Event{{Kind: procconn.Exec, PID: int32(a.pid), TGID: int32(a.pid)}}
	}
	// An agent that is this guard's own ancestor (it runs the guard under itself) is never adopted.
	f.add(300, 90, "claude", "claude", []string{"claude"}, term, "")
	p.add(300, 90, filepath.Join(f.bin, "claude"), term, 1000)
	src.ch <- []procconn.Event{{Kind: procconn.Exec, PID: 300, TGID: 300}}
	waitFor(t, func() bool {
		l := guardLines(t, out.String())
		return len(l[watcher.EventAdopted]) == 1 && len(l[watcher.EventAdoptionRefused]) == 3
	})
	cancel()
	select {
	case code := <-done:
		if code != identity.ExitOK {
			t.Fatalf("code %d stderr %q", code, errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the guard did not stop")
	}
	l := guardLines(t, out.String())
	if a := l[watcher.EventAdopted]; len(a) != 1 || a[0].PID != 510 || *a[0].UID != 1000 || a[0].Moved != 1 || *a[0].WindowMS != 42 {
		t.Fatalf("adopted lines %+v", a)
	}
	refused := map[int32]watcher.Sighting{}
	for _, s := range l[watcher.EventAdoptionRefused] {
		refused[s.PID] = s
	}
	if s := refused[511]; s.Rule != adopt.RefuseUID || !strings.Contains(s.Note, "uid 1001") {
		t.Errorf("another user's agent: %+v", s)
	}
	if s := refused[512]; s.Rule != adopt.RefuseUID || !strings.Contains(s.Note, "--uid 0") {
		t.Errorf("root's agent: %+v", s)
	}
	if s := refused[300]; s.Rule != adopt.RefuseAncestor {
		t.Errorf("the guard's ancestor: %+v", s)
	}
	if _, ok := refused[513]; ok {
		t.Error("an agent inside a governed run was considered")
	}
	if roots := calls.roots(); len(roots) != 1 || roots[0] != 510 {
		t.Fatalf("adoptions of %v, want [510]", roots)
	}
	if e := l[watcher.EventAdoptionEnded]; len(e) != 1 || e[0].Reason != record.RunEndStopped {
		t.Errorf("ended lines %+v: the guard's stop releases its adoption", e)
	}
	if !strings.Contains(errs.String(), "1 agent(s) adopted, 3 refused, 0 failed") {
		t.Errorf("summary: %q", errs.String())
	}
}

// TestGuardNeverAdoptsOneProcessTwice: two reports of one process (a rescan, a second watcher line) start one
// adoption; the second is refused while the first holds it.
func TestGuardNeverAdoptsOneProcessTwice(t *testing.T) {
	p := terminalProcs()
	calls := sandboxAdopt(t, p, true)
	calls.block = true
	var out bytes.Buffer
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(t.Context())
	g := &guard{ctx: ctx, uids: adopt.UIDs{1000}, p: p, reg: adopt.NewRegistry(0), watches: map[int][]*exitWatch{},
		emit: func(s watcher.Sighting) error {
			mu.Lock()
			defer mu.Unlock()
			b, _ := json.Marshal(s)
			out.Write(append(b, '\n'))
			return nil
		}}
	g.self, _ = adoptSelf(p)
	outside := true
	s := watcher.Sighting{Event: watcher.EventAgentStarted, PID: 500, Start: 5500, OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"}
	g.observe(s)
	waitFor(t, func() bool { return len(calls.roots()) == 1 })
	g.observe(s)
	cancel()
	st := g.wait()
	if roots := calls.roots(); len(roots) != 1 {
		t.Fatalf("one process adopted %d times", len(roots))
	}
	if st.adopted != 1 || st.refused != 1 {
		t.Fatalf("stats %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(out.String(), `"rule":"busy"`) {
		t.Errorf("the second report was not refused as busy: %s", out.String())
	}
	// Once the adoption has ended the identity is free again: a later report would be considered afresh.
	if g.reg.Len() != 0 {
		t.Errorf("the registry still holds %d", g.reg.Len())
	}
}

// TestGuardExitStatusIsTheAdoptedAgentsOwn: the exit status an adoption's run_end carries is the adopted agent's own,
// read from the watcher's events (the guard is its Tap) from the moment the agent was identified. An exit of an earlier
// process with the same pid is not handed to a later adoption, nothing of an ended adoption is kept, and an agent
// whose main thread exits first ends with its last thread: the guard used to take the watcher's agent_exited, which
// was the main thread's exit, as the agent's.
func TestGuardExitStatusIsTheAdoptedAgentsOwn(t *testing.T) {
	p := terminalProcs()
	sandboxAdopt(t, p, true)
	type status struct {
		code, sig int
		ok        bool
	}
	got := make(chan status, 1)
	ask := make(chan struct{})
	adoptRun = func(ctx context.Context, _ *agent.RuleTable, spec tegoruntime.AdoptSpec, _ tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
		<-ask
		c, sig, ok := spec.ExitStatus()
		got <- status{c, sig, ok}
		return tegoruntime.Result{RunID: "r-0a1b2c3d-0123456789abc-xyz500", Reason: record.RunEndExit}, nil
	}
	g := &guard{ctx: t.Context(), uids: adopt.UIDs{1000}, p: p, reg: adopt.NewRegistry(0), watches: map[int][]*exitWatch{},
		emit: func(watcher.Sighting) error { return nil }}
	g.self, _ = adoptSelf(p)
	outside := true
	started := func(session uint64) watcher.Sighting {
		return watcher.Sighting{Event: watcher.EventAgentStarted, Session: session, PID: 500, Start: 5500,
			OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"}
	}
	exit := func(tid int32, code uint32) procconn.Event {
		return procconn.Event{Kind: procconn.Exit, PID: tid, TGID: 500, ExitCode: code}
	}
	claude := func() { p.add(500, 300, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000) }

	// An earlier process of pid 500 exited 3 before this agent was seen: no watch held the pid then.
	g.Event(exit(500, 3<<8))
	g.observe(started(8))
	g.Lost()
	p.del(500)
	g.Lost() // the kernel dropped events once the agent was gone: its end may have been among them
	g.Event(exit(500, 3<<8))
	ask <- struct{}{}
	if st := <-got; st.ok {
		t.Fatalf("an exit read after events were lost with the agent gone was handed to the adoption: %+v", st)
	}
	g.wait()

	// The adopted agent's own exit is its run_end's.
	claude()
	g.observe(started(9))
	p.del(500)
	g.Event(exit(500, 4<<8))
	ask <- struct{}{}
	if st := <-got; !st.ok || st.code != 4 {
		t.Fatalf("the adopted agent's own exit status: %+v, want code 4", st)
	}
	g.wait()

	// Its main thread exits while thread 510 runs, and the thread later ends it with exit_group(3): the codes disagree.
	claude()
	g.observe(started(10))
	p.set(500, func(c *cliProcess) { c.leaderExited, c.threads = true, 1 })
	p.add(510, 300, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000)
	p.set(510, func(c *cliProcess) { c.tgid = 500 })
	g.Event(procconn.Event{Kind: procconn.Fork, PID: 510, TGID: 500, ParentTGID: 300})
	g.Event(exit(500, 0))
	p.del(510)
	p.del(500)
	g.Event(exit(510, 3<<8))
	ask <- struct{}{}
	if st := <-got; st.ok {
		t.Fatalf("an agent whose main thread exited first: status %+v, want unknown (0 then 3)", st)
	}
	g.wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.watches) != 0 {
		t.Fatalf("an ended adoption's exit watch is kept: %v", g.watches)
	}
}

// TestRecordOnlyAdoptionRefusesNothing: the compiler read-denies tego's own records whatever the contract says, and
// a record-only adoption's table drops that row (at tier 2 with no plane it would be a fanotify mark that refuses the
// agent's reads and arms the adopter); every other row stays.
// TestAdoptNoticeNamesWhatOnlyTheFilterHolds: a boundary contract refuses System V IPC unless it sets ipc: true, and
// tier 1's filter admits only the socket families the network rules govern; neither is held on an adopted process,
// and the notice says so before anything moves.
func TestAdoptNoticeNamesWhatOnlyTheFilterHolds(t *testing.T) {
	p := adopt.Process{Identity: adopt.Identity{PID: 500}, Exe: "/usr/bin/claude"}
	n := adoptNotice(p, true, agent.RecordFull)
	for _, want := range []string{"System V IPC", "socket families outside the network rules", "io_uring", "a gap says so",
		"new mount or user namespaces", "setns and mount(2)", "bind mount", "an overlay that reads a deny_read directory",
		"open_by_handle_at", "clone3"} {
		if !strings.Contains(n, want) {
			t.Errorf("the boundary notice %q lacks %q", n, want)
		}
	}
	if n := adoptNotice(p, false, agent.RecordFull); strings.Contains(n, "System V IPC") {
		t.Errorf("the record-only notice, which holds nothing, names a filter's refusal: %q", n)
	}
}

func TestRecordOnlyAdoptionRefusesNothing(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{
		{Path: "/root/.tego", Kind: agent.FSDenyRead, BuiltIn: true},
		{Path: "/tmp/runs", Kind: agent.FSImplicit},
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead},
		{Path: "/home/u/w", Kind: agent.FSWatch},
	}}
	got := recordOnly(rt)
	if len(got.FS) != 2 || got.FS[0].Kind != agent.FSImplicit || got.FS[1].Kind != agent.FSWatch {
		t.Fatalf("record-only rows %+v", got.FS)
	}
	if len(rt.FS) != 4 {
		t.Fatal("recordOnly changed the table it was given")
	}
}

// TestStopReleasesAnAdoptionWithoutSignallingItsAdopter: `tego stop <run>` of an adoption is a release request for
// that run alone. The run's lock holder, which for the guard is the guard itself, holding other adoptions, is not
// signalled, and no stop marker or backstop kill follows: an adoption never kills.
func TestStopReleasesAnAdoptionWithoutSignallingItsAdopter(t *testing.T) {
	_, id, _ := liveRun(t)
	prevAdopted, prevRelease, prevSignal, prevEscalate := stopAdopted, adoptRelease, signalTarget, escalateRun
	t.Cleanup(func() {
		stopAdopted, adoptRelease, signalTarget, escalateRun = prevAdopted, prevRelease, prevSignal, prevEscalate
	})
	stopAdopted = func(run string) bool { return run == id }
	var asked []string
	adoptRelease = func(_ context.Context, _ string, run, by string, _ *slog.Logger) (tegoruntime.ReleaseReport, error) {
		asked = append(asked, run+" by "+by)
		return tegoruntime.ReleaseReport{Run: run, Adopter: 4242}, nil
	}
	signalled, escalated := false, false
	signalTarget = func(*tegoruntime.StopTarget, syscall.Signal) error { signalled = true; return nil }
	escalateRun = func(string, string, io.Writer) { escalated = true }
	code, out, errs := run(t, "stop", id, "--grace", "1s")
	if code != identity.ExitOK || !strings.Contains(out, id+": released by its adopter (pid 4242)") {
		t.Fatalf("tego stop of an adoption: exit %d stdout %q stderr %q", code, out, errs)
	}
	if signalled || escalated {
		t.Fatalf("tego stop signalled (%v) or killed (%v) an adoption's adopter", signalled, escalated)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], id+" by tego stop (pid ") {
		t.Errorf("release requests %q", asked)
	}
	// An ended adoption that left processes in its scope: the release moves them out and says so, naming no adopter.
	adoptRelease = func(_ context.Context, _ string, run, _ string, _ *slog.Logger) (tegoruntime.ReleaseReport, error) {
		return tegoruntime.ReleaseReport{Run: run, Again: true, Orphan: &tegoruntime.OrphanRelease{Removed: true}}, nil
	}
	if code, out, errs := run(t, "stop", id); code != identity.ExitOK ||
		!strings.Contains(out, id+": the run had ended with process(es) left in its scope; they are released now") {
		t.Fatalf("tego stop of an ended adoption's leftovers: exit %d stdout %q stderr %q", code, out, errs)
	}
	// An adoption that failed before it recorded, leaving processes in its scope: no run had ended, and it says so.
	adoptRelease = func(_ context.Context, _ string, run, _ string, _ *slog.Logger) (tegoruntime.ReleaseReport, error) {
		return tegoruntime.ReleaseReport{Run: run, Again: true, Unstarted: true, Orphan: &tegoruntime.OrphanRelease{Removed: true}}, nil
	}
	if code, out, errs := run(t, "stop", id); code != identity.ExitOK ||
		!strings.Contains(out, id+": the adoption had failed before it recorded, leaving process(es) in its scope") {
		t.Fatalf("tego stop of a failed adoption's leftovers: exit %d stdout %q stderr %q", code, out, errs)
	}
	// A live adopter whose release left processes in the scope: an error, never "released".
	adoptRelease = func(_ context.Context, _ string, run, _ string, _ *slog.Logger) (tegoruntime.ReleaseReport, error) {
		return tegoruntime.ReleaseReport{Run: run, Adopter: 4242, Left: 2}, errors.New("adopter 4242 released the agent " +
			"and its run ended, but 2 process(es) stay in /x")
	}
	if code, out, errs := run(t, "stop", id); code != identity.ExitError || strings.Contains(out, "released") ||
		!strings.Contains(errs, "2 process(es) stay in") {
		t.Fatalf("tego stop whose release left processes: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestAdoptCommandAdoptsAnotherUsersProcessOnlyWithUID: root naming a pid is not consent to move another user's
// process. Without --uid only the invoking user's own process is adopted (sudo's caller, uid 1000 here; uid 0 when
// root runs tego directly); --uid names any other owner.
func TestAdoptCommandAdoptsAnotherUsersProcessOnlyWithUID(t *testing.T) {
	p := terminalProcs()
	const sess = "/user.slice/user-1000.slice/session-2.scope"
	p.add(510, 300, "/usr/bin/claude", sess, 1001)
	calls := sandboxAdopt(t, p, true)
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "510")
	if code != identity.ExitLauncher || !strings.Contains(errs, "(uid)") || !strings.Contains(errs, "--uid 1001") ||
		!strings.Contains(errs, "[adopt-refused]") {
		t.Fatalf("uid 1001's agent with no --uid: code %d stderr %q, want a refusal naming --uid 1001", code, errs)
	}
	if code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "510", "--uid", "1001"); code != identity.ExitOK {
		t.Fatalf("with --uid 1001: code %d stderr %q", code, errs)
	}
	// Root running tego directly acts for uid 0: the operator's own agent then needs --uid too.
	adoptInvokingUID = func() int { return 0 }
	if code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500"); code != identity.ExitLauncher || !strings.Contains(errs, "(uid)") {
		t.Fatalf("root without sudo, uid 1000's agent, no --uid: code %d stderr %q", code, errs)
	}
	if roots := calls.roots(); len(roots) != 1 || roots[0] != 510 {
		t.Fatalf("adopted %v, want only the one --uid named", roots)
	}
}

// TestAdoptCommandRechecksBeforeTheMove: the run is handed the same rules as a Recheck, which refuses the process if,
// by the move, it runs tego, runs as another user, or sits inside a run.
// TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome: a boundary adoption of another user's agent (every guard
// adoption under its root unit, `sudo tego adopt --uid`) compiled the built-in deny_read list against the adopter's
// home: the agent read its own ~/.ssh while run_start claimed fs.deny_read. The table now compiles against the
// passwd home of the process's owner, and an owner with no home there is refused, named.
func TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome(t *testing.T) {
	agentHome := filepath.Join(t.TempDir(), "agent-home")
	for _, d := range []string{filepath.Join(agentHome, ".ssh"), filepath.Join(testHome, ".ssh")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(testHome, ".ssh")) })
	key := filepath.Join(agentHome, ".ssh", "id_ed25519")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The owner's own tego records (its earlier runs' events and blobs), which its own launched run read-denies
	// (R6a), stay denied while the ledger and the anchor are the adopter's.
	ownerRun := filepath.Join(agentHome, ".tego", "runs", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.MkdirAll(ownerRun, 0o700); err != nil {
		t.Fatal(err)
	}
	ownerEvents := filepath.Join(ownerRun, "events.jsonl")
	if err := os.WriteFile(ownerEvents, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(t.TempDir(), "boundary.yaml")
	y := "version: 0\nname: boundary\ncommand: [\"/bin/sh\"]\nrecord: full\nfs:\n  write: [\"" + ws + "\"]\nexec:\n  allow: [\"/bin/sh\"]\n"
	if err := os.WriteFile(contract, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	// uid 1001 has a home and has never run tego: no ~/.tego yet.
	bareHome := filepath.Join(t.TempDir(), "bare-home")
	if err := os.MkdirAll(bareHome, 0o700); err != nil {
		t.Fatal(err)
	}
	// uid 1002's passwd home does not exist (a service user's /nonexistent).
	noHome := filepath.Join(t.TempDir(), "nonexistent")
	// uid 1003's passwd home is one it may not write (a service account's /, /var/www): owned by the test's uid, mode
	// 0700, while 1003 is in no group of it.
	foreignHome := filepath.Join(t.TempDir(), "foreign-home")
	if err := os.Mkdir(foreignHome, 0o700); err != nil {
		t.Fatal(err)
	}
	prevHome, prevGroup, prevGroups, prevEUID := adoptHomeOf, adoptGroupOf, adoptGroupsOf, adoptEUID
	homeOf := func(uid int) (string, error) {
		switch uid {
		case 1000:
			return agentHome, nil
		case 1001:
			return bareHome, nil
		case 1002:
			return noHome, nil
		case 1003:
			return foreignHome, nil
		}
		return "", fmt.Errorf("user: unknown userid %d", uid)
	}
	adoptHomeOf = homeOf
	// The passwd database of the test's own, so the path root takes (in a KVM guest, root-suites.sh) chowns to these
	// uids and gids rather than look them up on a machine that has none of them.
	adoptGroupOf = func(uid int) (int, error) {
		if uid < 1000 || uid > 1003 {
			return 0, fmt.Errorf("user: unknown userid %d", uid)
		}
		return uid, nil
	}
	adoptGroupsOf = func(uid int) ([]int, error) {
		g, err := adoptGroupOf(uid)
		return []int{g}, err
	}
	t.Cleanup(func() {
		adoptHomeOf, adoptGroupOf, adoptGroupsOf, adoptEUID = prevHome, prevGroup, prevGroups, prevEUID
	})
	if os.Geteuid() == 0 {
		// As root a home is made into only where its owner may write it (makeOwnRecords): these are the owners'.
		for _, h := range []struct {
			dir string
			uid int
		}{{agentHome, 1000}, {bareHome, 1001}} {
			if err := os.Chown(h.dir, h.uid, h.uid); err != nil {
				t.Fatal(err)
			}
		}
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	a := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1000}
	rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs)
	if rt == nil {
		t.Fatalf("compile: exit %d stderr %q", code, errs.String())
	}
	if rt.Home != agentHome || a.home != agentHome {
		t.Errorf("compiled against %q (recorded %q), want the owner's home %q, not the adopter's %q", rt.Home, a.home,
			agentHome, m.Home)
	}
	covered, records := false, false
	for _, r := range rt.FS {
		if r.Kind != agent.FSDenyRead {
			continue
		}
		covered = covered || agent.Covers(r.Path, key)
		records = records || agent.Covers(r.Path, ownerEvents)
		if agent.Covers(filepath.Join(testHome, ".ssh"), r.Path) {
			t.Errorf("a deny_read row %s is the adopter's", r.Path)
		}
	}
	if !covered {
		t.Errorf("the agent owner's %s is under no deny_read row of the boundary table", key)
	}
	// No Landlock domain holds an adopted process, so no absent row's name is left out, and the models must not
	// refuse its reads.
	if len(rt.AbsentDenyRead) != 0 {
		t.Errorf("the boundary table keeps %d absent built-in rows, which no ruleset enforces on an adopted process", len(rt.AbsentDenyRead))
	}
	if !records {
		t.Errorf("the agent owner's own tego records (%s) are under no deny_read row of the boundary table", ownerEvents)
	}
	if a.stale() {
		t.Error("a table compiled with the owner's ~/.tego present is stale")
	}
	// An owner who has never run tego: R6a's deny attaches only to a directory, and an adoption keeps its table while
	// it runs, so the owner's first run's records would be readable to the agent for the rest of the adoption. The
	// compile makes ~/.tego first, 0700, as that run would, and denies it.
	errs.Reset()
	a = &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1001}
	if rt, code = compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs); rt == nil {
		t.Fatalf("compile for uid 1001: exit %d stderr %q", code, errs.String())
	}
	bareRecords := filepath.Join(bareHome, ".tego")
	if fi, err := os.Lstat(bareRecords); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("the owner's ~/.tego after the compile: %v %v, want a directory of mode 0700", fi, err)
	}
	firstRun := filepath.Join(bareRecords, "runs", "r-1", "events.jsonl")
	if !slices.ContainsFunc(rt.FS, func(r agent.FSRule) bool { return r.Kind == agent.FSDenyRead && agent.Covers(r.Path, firstRun) }) {
		t.Errorf("the records of the owner's first run (%s) are under no deny_read row of the boundary table", firstRun)
	}
	if a.stale() {
		t.Error("a table compiled with the ~/.tego it made is stale")
	}
	// The runtime requires the plane's row for it at the directory compiled against (AdoptSpec.Keyed): one removed or
	// replaced before Prepare keyed it fails the adoption.
	a.rt = rt
	resolved, _ := filepath.EvalSymlinks(bareRecords)
	if k := a.keyed(); len(k) != 1 || k[0].Path != resolved || k[0].ID != a.records || a.records == (adopt.FileID{}) {
		t.Errorf("keyed %+v, want the owner's ~/.tego %s at %v", k, resolved, a.records)
	}
	// The path required is the one the plane's fill keys the row at (a row of decide.CompilePlane), or every real
	// boundary would fail as gone; a home reached through a link included, whose row is at the resolved path.
	linkedHome := filepath.Join(t.TempDir(), "linked-home")
	if err := os.Symlink(bareHome, linkedHome); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{bareHome, linkedHome} {
		adoptHomeOf = func(uid int) (string, error) { return home, nil }
		errs.Reset()
		la := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1001}
		lrt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, la, &errs)
		if lrt == nil {
			t.Fatalf("compile against %s: exit %d stderr %q", home, code, errs.String())
		}
		la.rt = lrt
		rows, err := decide.CompilePlane(lrt)
		if err != nil {
			t.Fatal(err)
		}
		k := la.keyed()
		if len(k) != 1 || !slices.ContainsFunc(rows.FS, func(r decide.PlaneRow) bool { return r.Path == k[0].Path }) {
			t.Errorf("home %s: keyed %+v is no fs row of the plane's (%d rows)", home, k, len(rows.FS))
			continue
		}
		// The name checked once armed is the one the owner's next run writes at, through the link: a link above
		// ~/.tego moved to another home after the compile leaves the row on a directory no longer at that name.
		if want := filepath.Join(home, ".tego"); k[0].Name != want {
			t.Errorf("home %s: keyed name %q, want %q", home, k[0].Name, want)
		}
	}
	adoptHomeOf = homeOf
	// A boundary that declares deny_read of the owner's ~/.tego itself: the compiler adds no built-in row beside the
	// declared one, which is R6a's deny all the same, so it is the row required, or a directory replaced before Prepare
	// would leave it on nothing, unsaid.
	for _, declared := range []string{"~/.tego", bareRecords, bareRecords + "/"} {
		dc := filepath.Join(t.TempDir(), "declared.yaml")
		dy := "version: 0\nname: boundary\ncommand: [\"/bin/sh\"]\nrecord: full\nfs:\n  write: [\"" + ws + "\"]\n  deny_read: [\"" +
			declared + "\"]\nexec:\n  allow: [\"/bin/sh\"]\n"
		if err := os.WriteFile(dc, []byte(dy), 0o600); err != nil {
			t.Fatal(err)
		}
		errs.Reset()
		da := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1001}
		drt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: dc}, adopt.Process{}, da, &errs)
		if drt == nil {
			t.Fatalf("compile with deny_read %s: exit %d stderr %q", declared, code, errs.String())
		}
		da.rt = drt
		if k := da.keyed(); len(k) != 1 || k[0].Path != resolved || k[0].ID != da.records || da.records == (adopt.FileID{}) {
			t.Errorf("deny_read %s declared: keyed %+v, want the owner's ~/.tego %s at %v", declared, k, resolved, da.records)
		}
	}
	// The directory replaced after the compile (removed and made again, or a link to another): the deny is on the old
	// one, so the table is stale and the guard compiles it again before its next adoption.
	if err := os.Rename(bareRecords, bareRecords+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bareRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	if !a.stale() {
		t.Error("the owner's ~/.tego was replaced after the compile and the table is not stale")
	}
	// A ~/.tego that is no directory (a file, a dangling link) cannot be denied: the boundary is refused, named. Nor
	// can one that is a link to a directory: the row keys the target, the link itself is under no row, and under a
	// write entry over the home the agent could replace the link with a fresh directory once armed, where the owner's
	// next run would write its records.
	realRecords := filepath.Join(bareHome, "real-records")
	if err := os.Mkdir(realRecords, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mk := range []func(string) error{
		func(p string) error { return os.WriteFile(p, nil, 0o600) },
		func(p string) error { return os.Symlink(filepath.Join(bareHome, "nowhere"), p) },
		func(p string) error { return os.Symlink(realRecords, p) },
		func(p string) error { return os.Symlink("real-records", p) },
	} {
		if err := os.RemoveAll(bareRecords); err != nil {
			t.Fatal(err)
		}
		if err := mk(bareRecords); err != nil {
			t.Fatal(err)
		}
		errs.Reset()
		a = &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1001}
		if rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs); rt != nil ||
			code != identity.ExitLauncher || !strings.Contains(errs.String(), "is not a directory") ||
			!strings.Contains(errs.String(), "[adopt-refused]") {
			t.Errorf("a ~/.tego that is no directory: table %v, exit %d, stderr %q; want a named refusal", rt != nil, code, errs.String())
		}
	}
	// An owner whose passwd home does not exist (nobody's /nonexistent) has no records there to deny, and tego makes
	// no home for it: the boundary compiles, makes nothing, and the table is stale once the home exists, so the guard
	// compiles it again, making ~/.tego then.
	errs.Reset()
	a = &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1002}
	if rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs); rt == nil {
		t.Fatalf("compile for uid 1002, whose home does not exist: exit %d stderr %q", code, errs.String())
	}
	if _, err := os.Lstat(noHome); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the compile made the owner's missing home: %v", err)
	}
	if a.stale() {
		t.Error("a table compiled for a home that does not exist is stale while it still does not")
	}
	if err := os.Mkdir(noHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if !a.stale() {
		t.Error("the owner's home was made after the compile and the table is not stale")
	}
	// As root for an owner whose home it may not write, no ~/.tego is made: making one
	// would hand the owner a writable directory it could not make, and no run of its own can have made records there.
	// The boundary compiles with no deny of it, requires no row of it, and the table is stale once one appears.
	adoptEUID = func() int { return 0 }
	errs.Reset()
	a = &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 1003}
	if rt, code = compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs); rt == nil {
		t.Fatalf("compile for uid 1003, whose home it may not write: exit %d stderr %q", code, errs.String())
	}
	a.rt = rt
	if _, err := os.Lstat(ownRecords(foreignHome)); !errors.Is(err, os.ErrNotExist) || !a.homeNotOwners {
		t.Errorf("a home the owner may not write: ~/.tego %v, homeNotOwners %v; want none made", err, a.homeNotOwners)
	}
	if a.stale() || a.keyed() != nil {
		t.Errorf("a table with no ~/.tego to deny: stale %v, keyed %v; want neither", a.stale(), a.keyed())
	}
	if err := os.Mkdir(ownRecords(foreignHome), 0o700); err != nil {
		t.Fatal(err)
	}
	if !a.stale() {
		t.Error("a ~/.tego appeared in a home the owner may not write and the table is not stale")
	}
	adoptEUID = prevEUID
	errs.Reset()
	a = &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: 4242}
	if rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: contract}, adopt.Process{}, a, &errs); rt != nil ||
		code != identity.ExitLauncher || !strings.Contains(errs.String(), "uid 4242 has none") ||
		!strings.Contains(errs.String(), "[adopt-refused]") {
		t.Fatalf("an owner with no home: table %v, exit %d, stderr %q; want a named refusal", rt != nil, code, errs.String())
	}
}

// TestMakeOwnRecordsGivesAwayOnlyTheDirectoryItMade: as root for another uid, makeOwnRecords chowns ~/.tego to the
// owner through a descriptor it opens after the mkdirat. The owner can rename a directory of its home into that name
// meanwhile, so what the descriptor opens is chowned only when it is what a mkdirat by tego makes: tego's own,
// empty, with no group or other bits; anything else is refused, named, and left as it is. Run unprivileged, tego's
// uid stands in for root (adoptEUID) and the owner is the test's own uid,
// which may chown to itself; as root (root-suites.sh), a directory of another uid swapped in is refused too.
func TestMakeOwnRecordsGivesAwayOnlyTheDirectoryItMade(t *testing.T) {
	owner, group := os.Getuid(), os.Getgid()
	if owner == 0 {
		owner, group = 4242, 4343
	}
	prevEUID, prevGroup, prevMade := adoptEUID, adoptGroupOf, adoptOwnRecordsMade
	adoptEUID = func() int { return 0 }
	adoptGroupOf = func(uid int) (int, error) {
		if uid != owner {
			return 0, fmt.Errorf("user: unknown userid %d", uid)
		}
		return group, nil
	}
	t.Cleanup(func() { adoptEUID, adoptGroupOf, adoptOwnRecordsMade = prevEUID, prevGroup, prevMade })
	newHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		if err := os.Chown(home, owner, group); err != nil {
			t.Fatal(err)
		}
		return home
	}
	// The directory made, with nothing swapped in: the owner's, 0700.
	home := newHome(t)
	adoptOwnRecordsMade = func(string) {}
	if err := makeOwnRecords(home, owner); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(ownRecords(home)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 ||
		fi.Sys().(*syscall.Stat_t).Uid != uint32(owner) {
		t.Errorf("the owner's ~/.tego: %v %v, want a directory of mode 0700 owned by %d", fi, err, owner)
	}
	// A ~/.tego already there needs no group: nothing is made or chowned, so a uid whose passwd group cannot be found
	// is not refused for it (the group lookup before the mkdirat is only for what is made).
	adoptGroupOf = func(int) (int, error) { return 0, errors.New("user: unknown group") }
	if err := makeOwnRecords(home, owner); err != nil {
		t.Errorf("a ~/.tego already there, for a uid whose group cannot be found: %v, want it left as it is", err)
	}
	adoptGroupOf = func(uid int) (int, error) {
		if uid != owner {
			return 0, fmt.Errorf("user: unknown userid %d", uid)
		}
		return group, nil
	}
	type swapped struct {
		name string
		make func(t *testing.T, dir string)
	}
	cases := []swapped{
		{"a directory with a file in it", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "kept"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory others may read", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	if os.Geteuid() == 0 {
		cases = append(cases, swapped{"an empty 0700 directory of another uid", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dir, 4444, 4444); err != nil {
				t.Fatal(err)
			}
		}})
	} else {
		t.Log("the row of a directory of another uid swapped in needs root to make one: root-suites.sh runs it")
	}
	for _, c := range cases {
		home := newHome(t)
		other := filepath.Join(home, "other")
		c.make(t, other)
		var before syscall.Stat_t
		if err := syscall.Stat(other, &before); err != nil {
			t.Fatal(err)
		}
		// The owner swaps its directory in at the name between tego's mkdirat and its open.
		adoptOwnRecordsMade = func(home string) {
			if err := os.Rename(ownRecords(home), filepath.Join(home, "made")); err != nil {
				t.Error(err)
			}
			if err := os.Rename(other, ownRecords(home)); err != nil {
				t.Error(err)
			}
		}
		err := makeOwnRecords(home, owner)
		if err == nil || !strings.Contains(err.Error(), "not the directory") {
			t.Errorf("%s swapped in: %v, want a refusal saying it is not the directory tego made", c.name, err)
		}
		var after syscall.Stat_t
		if err := syscall.Stat(ownRecords(home), &after); err != nil {
			t.Errorf("%s swapped in: it is no longer at the name: %v", c.name, err)
			continue
		}
		if after.Ino != before.Ino || after.Uid != before.Uid || after.Gid != before.Gid || after.Mode != before.Mode {
			t.Errorf("%s swapped in: now uid %d gid %d mode %o, was uid %d gid %d mode %o; want it left as it is", c.name,
				after.Uid, after.Gid, after.Mode, before.Uid, before.Gid, before.Mode)
		}
	}
}

// TestHomeWritableByIsTheModeTheOwnerHas: root makes the owner's ~/.tego only in a home the owner may make a name in
// by its mode: its own (whatever the bits, it may chmod them), one others may write, or
// one its group may write when it is in that group; a group lookup that fails is an error, never a guess.
func TestHomeWritableByIsTheModeTheOwnerHas(t *testing.T) {
	prev := adoptGroupsOf
	t.Cleanup(func() { adoptGroupsOf = prev })
	adoptGroupsOf = func(uid int) ([]int, error) {
		if uid == 1001 {
			return []int{1001, 50}, nil
		}
		return nil, errors.New("user: unknown userid")
	}
	for _, c := range []struct {
		name     string
		st       unix.Stat_t
		uid      int
		want     bool
		wantsErr bool
	}{
		{"its own, 0700", unix.Stat_t{Uid: 1001, Gid: 1001, Mode: unix.S_IFDIR | 0o700}, 1001, true, false},
		{"its own, 0500", unix.Stat_t{Uid: 1001, Gid: 1001, Mode: unix.S_IFDIR | 0o500}, 1001, true, false},
		{"root's /, 0755", unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFDIR | 0o755}, 1001, false, false},
		{"root's, group 50 may write", unix.Stat_t{Uid: 0, Gid: 50, Mode: unix.S_IFDIR | 0o775}, 1001, true, false},
		{"root's, group 60 may write", unix.Stat_t{Uid: 0, Gid: 60, Mode: unix.S_IFDIR | 0o775}, 1001, false, false},
		{"root's, others may write", unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFDIR | 0o1777}, 1001, true, false},
		{"root's, group writable, groups unknown", unix.Stat_t{Uid: 0, Gid: 50, Mode: unix.S_IFDIR | 0o770}, 1002, false, true},
	} {
		got, err := homeWritableBy(c.st, c.uid)
		if got != c.want || (err != nil) != c.wantsErr {
			t.Errorf("%s: %v %v, want %v (error %v)", c.name, got, err, c.want, c.wantsErr)
		}
	}
}

// TestGuardBoundaryTableIsTheAgentOwners: the guard compiles its boundary once per listed uid, against that uid's home,
// and adopts each agent under its owner's table; the recheck before the move refuses a root whose owner changed since,
// even to another listed uid, whose table it was not prepared with.
func TestGuardBoundaryTableIsTheAgentOwners(t *testing.T) {
	p := terminalProcs()
	p.add(510, 300, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1001)
	calls := sandboxAdopt(t, p, true)
	var prepared []int
	adoptPrepare = func(_ context.Context, m *config.Machine, o adoptOptions, _ adopt.Process, owner int, _ io.Writer) (*preparedAdoption, int) {
		prepared = append(prepared, owner)
		rt := &agent.RuleTable{Contract: &agent.Contract{Name: fmt.Sprintf("b-%d", owner)}, Tier: backend.TierCgroup}
		return &preparedAdoption{rt: rt, m: m, cleanup: func() {}, boundary: true, owner: owner}, identity.ExitOK
	}
	var mu sync.Mutex
	tables := map[int]string{}
	run := adoptRun
	adoptRun = func(ctx context.Context, rt *agent.RuleTable, spec tegoruntime.AdoptSpec, d tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
		mu.Lock()
		tables[spec.Root.PID] = rt.Contract.Name
		mu.Unlock()
		return run(ctx, rt, spec, d)
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	g, err := newGuard(ctx, m, []int{1000, 1001, 1000}, adoptOptions{boundary: "b.yaml"},
		func(watcher.Sighting) error { return nil }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prepared, []int{1000, 1001}) {
		t.Fatalf("tables prepared for %v, want one per listed uid", prepared)
	}
	outside := true
	for _, pid := range []int32{500, 510} {
		g.observe(watcher.Sighting{Event: watcher.EventAgentStarted, PID: pid, OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"})
	}
	waitFor(t, func() bool { return len(calls.roots()) == 2 })
	cancel()
	g.wait()
	mu.Lock()
	defer mu.Unlock()
	if tables[500] != "b-1000" || tables[510] != "b-1001" {
		t.Fatalf("adopted under %v, want each agent under its owner's table", tables)
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	for _, spec := range calls.specs {
		changed := spec.Root
		if spec.Root.Owner() == 1000 {
			changed.UID = [3]int{1001, 1001, 1001}
		} else {
			changed.UID = [3]int{1000, 1000, 1000}
		}
		if rule, ok := adopt.IsRefusal(spec.Recheck(changed)); !ok || rule != adopt.RefuseUID {
			t.Errorf("pid %d: a recheck of its root under another listed uid: rule %q, want %s", spec.Root.PID, rule, adopt.RefuseUID)
		}
		if err := spec.Recheck(spec.Root); err != nil {
			t.Errorf("pid %d: the recheck refuses the root as identified: %v", spec.Root.PID, err)
		}
	}
}

// TestGuardRecompilesATableWhoseOwnersRecordsChanged: the guard compiles each uid's boundary table once, at its start,
// and R6a's deny of the owner's ~/.tego attaches to the directory that compile found. One replaced since (removed and
// made again by the owner's next run) had every later agent adopted under a table that left the new one's records
// readable. The guard compiles such a table again before the next adoption, once,
// and adopts under the new one; a table that cannot be compiled again fails the adoption rather than adopt under the
// stale one.
func TestGuardRecompilesATableWhoseOwnersRecordsChanged(t *testing.T) {
	p := terminalProcs()
	const sess = "/user.slice/user-1000.slice/session-2.scope"
	p.add(510, 300, "/usr/bin/claude", sess, 1000)
	p.add(520, 300, "/usr/bin/claude", sess, 1000)
	p.add(530, 300, "/usr/bin/claude", sess, 1000)
	calls := sandboxAdopt(t, p, true)
	home := t.TempDir()
	var mu sync.Mutex
	prepared, failNext := 0, false
	adoptPrepare = func(_ context.Context, m *config.Machine, o adoptOptions, _ adopt.Process, owner int, _ io.Writer) (*preparedAdoption, int) {
		mu.Lock()
		defer mu.Unlock()
		if failNext {
			return nil, identity.ExitLauncher
		}
		prepared++
		records, _ := ownRecordsDir(home)
		rt := &agent.RuleTable{Contract: &agent.Contract{Name: fmt.Sprintf("b-%d", prepared)}, Tier: backend.TierCgroup}
		return &preparedAdoption{rt: rt, m: m, cleanup: func() {}, boundary: true, owner: owner, home: home,
			records: records}, identity.ExitOK
	}
	records := filepath.Join(home, ".tego")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	tables := map[int]string{}
	run := adoptRun
	adoptRun = func(ctx context.Context, rt *agent.RuleTable, spec tegoruntime.AdoptSpec, d tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
		mu.Lock()
		tables[spec.Root.PID] = rt.Contract.Name
		mu.Unlock()
		return run(ctx, rt, spec, d)
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var sightings []watcher.Sighting
	g, err := newGuard(ctx, m, []int{1000}, adoptOptions{boundary: "b.yaml"}, func(s watcher.Sighting) error {
		mu.Lock()
		sightings = append(sightings, s)
		mu.Unlock()
		return nil
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	outside := true
	sight := func(pid int32) {
		g.observe(watcher.Sighting{Event: watcher.EventAgentStarted, PID: pid, OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"})
	}
	sight(500)
	waitFor(t, func() bool { return len(calls.roots()) == 1 })
	if err := os.Rename(records, records+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	sight(510)
	waitFor(t, func() bool { return len(calls.roots()) == 2 })
	sight(520)
	waitFor(t, func() bool { return len(calls.roots()) == 3 })
	mu.Lock()
	if tables[500] != "b-1" || tables[510] != "b-2" || tables[520] != "b-2" || prepared != 2 {
		t.Errorf("adopted under %v with %d compiles; want 500 under the first table, 510 and 520 under the one compiled "+
			"again once the owner's ~/.tego was replaced", tables, prepared)
	}
	mu.Unlock()

	// A stale table that cannot be compiled again: the adoption fails, nothing is adopted under the stale table.
	g.sharedMu.Lock()
	g.shared[1000].records = adopt.FileID{}
	g.sharedMu.Unlock()
	mu.Lock()
	failNext = true
	mu.Unlock()
	sight(530)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range sightings {
			if s.PID == 530 && s.Event == watcher.EventAdoptionFailed {
				return strings.Contains(s.Note, "could not be compiled again")
			}
		}
		return false
	})
	cancel()
	g.wait()
	if roots := calls.roots(); len(roots) != 3 {
		t.Errorf("adopted %v; the agent whose table could not be compiled again was adopted", roots)
	}
}

// TestGuardSelectsAgainWhenFmodRetLapses: the guard prepares each uid's boundary backend once and adopts many agents
// under it, so a backend selected with the plane in fmod_ret mode would keep the mode after root changed the kernel's
// preemption mode (a 2026-11-03 review). Before each adoption the guard reads the mode again (ADR 0024 (16)): a
// backend whose fmod_ret mode the kernel no longer admits is prepared again, which selects again, and an adoption is
// never made under it; one that cannot be prepared again fails the adoption.
func TestGuardSelectsAgainWhenFmodRetLapses(t *testing.T) {
	p := terminalProcs()
	const sess = "/user.slice/user-1000.slice/session-2.scope"
	p.add(510, 300, "/usr/bin/claude", sess, 1000)
	p.add(520, 300, "/usr/bin/claude", sess, 1000)
	p.add(530, 300, "/usr/bin/claude", sess, 1000)
	calls := sandboxAdopt(t, p, true)
	var mu sync.Mutex
	prepared, failNext, refused := 0, false, ""
	refusedNow := adoptFmodRetRefused
	adoptFmodRetRefused = func() string { mu.Lock(); defer mu.Unlock(); return refused }
	t.Cleanup(func() { adoptFmodRetRefused = refusedNow })
	adoptPrepare = func(_ context.Context, m *config.Machine, o adoptOptions, _ adopt.Process, owner int, _ io.Writer) (*preparedAdoption, int) {
		mu.Lock()
		defer mu.Unlock()
		if failNext {
			return nil, identity.ExitLauncher
		}
		prepared++
		rt := &agent.RuleTable{Contract: &agent.Contract{Name: fmt.Sprintf("b-%d", prepared)}, Tier: backend.TierCgroup}
		// Doctor selects fmod_ret mode while the kernel admits it, else another mode.
		return &preparedAdoption{rt: rt, m: m, cleanup: func() {}, boundary: true, owner: owner, fmodRet: refused == ""},
			identity.ExitOK
	}
	tables := map[int]string{}
	run := adoptRun
	adoptRun = func(ctx context.Context, rt *agent.RuleTable, spec tegoruntime.AdoptSpec, d tegoruntime.AdoptDeps) (tegoruntime.Result, error) {
		mu.Lock()
		tables[spec.Root.PID] = rt.Contract.Name
		mu.Unlock()
		return run(ctx, rt, spec, d)
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var sightings []watcher.Sighting
	g, err := newGuard(ctx, m, []int{1000}, adoptOptions{boundary: "b.yaml"}, func(s watcher.Sighting) error {
		mu.Lock()
		sightings = append(sightings, s)
		mu.Unlock()
		return nil
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	outside := true
	sight := func(pid int32) {
		g.observe(watcher.Sighting{Event: watcher.EventAgentStarted, PID: pid, OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"})
	}
	sight(500)
	waitFor(t, func() bool { return len(calls.roots()) == 1 })
	mu.Lock()
	refused = "this kernel preempts kernel code (preemption full, from /sys/kernel/debug/sched/preempt)"
	mu.Unlock()
	sight(510)
	waitFor(t, func() bool { return len(calls.roots()) == 2 })
	sight(520)
	waitFor(t, func() bool { return len(calls.roots()) == 3 })
	mu.Lock()
	if tables[500] != "b-1" || tables[510] != "b-2" || tables[520] != "b-2" || prepared != 2 {
		t.Errorf("adopted under %v with %d preparations; want 500 under the fmod_ret backend, 510 and 520 under the one "+
			"prepared again once the kernel no longer admitted fmod_ret mode", tables, prepared)
	}
	mu.Unlock()

	// A backend in fmod_ret mode the kernel no longer admits, which cannot be prepared again: the adoption fails.
	g.sharedMu.Lock()
	g.shared[1000].fmodRet = true
	g.sharedMu.Unlock()
	mu.Lock()
	failNext = true
	mu.Unlock()
	sight(530)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range sightings {
			if s.PID == 530 && s.Event == watcher.EventAdoptionFailed {
				return strings.Contains(s.Note, "no longer admits")
			}
		}
		return false
	})
	cancel()
	g.wait()
	if roots := calls.roots(); len(roots) != 3 {
		t.Errorf("adopted %v; the agent whose fmod_ret backend lapsed was adopted under it", roots)
	}
}

func TestAdoptCommandRechecksBeforeTheMove(t *testing.T) {
	calls := sandboxAdopt(t, terminalProcs(), true)
	if code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500"); code != identity.ExitOK {
		t.Fatalf("code %d stderr %q", code, errs)
	}
	calls.mu.Lock()
	spec := calls.specs[0]
	calls.mu.Unlock()
	if spec.Recheck == nil {
		t.Fatal("the run was handed no Recheck")
	}
	if err := spec.Recheck(spec.Root); err != nil {
		t.Fatalf("Recheck refuses the process as identified: %v", err)
	}
	for name, change := range map[string]func(*adopt.Process){
		adopt.RefuseTego: func(p *adopt.Process) { p.Exe, p.ExeFile = "/usr/local/bin/tego", adopt.FileID{Dev: 9, Ino: 801} },
		adopt.RefuseUID:  func(p *adopt.Process) { p.UID = [3]int{1001, 1001, 1001} },
		adopt.RefuseGoverned: func(p *adopt.Process) {
			p.Cgroup = "/tego.slice/tego-a.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope"
		},
	} {
		p := spec.Root
		change(&p)
		if rule, ok := adopt.IsRefusal(spec.Recheck(p)); !ok || rule != name {
			t.Errorf("Recheck of a process changed to fail %s: rule %q", name, rule)
		}
	}
}

// exitSource is a proc connector that hands out the batches and errors a test queues.
type exitSource struct {
	ch   chan exitBatch
	done chan struct{}
	once sync.Once
}

type exitBatch struct {
	before func() // runs before the batch is read: what /proc shows by the time the kernel has sent its events
	evs    []procconn.Event
	err    error
}

func newExitSource(batches ...exitBatch) *exitSource {
	s := &exitSource{ch: make(chan exitBatch, len(batches)+2), done: make(chan struct{})}
	for _, b := range batches {
		s.ch <- b
	}
	return s
}

func (s *exitSource) Recv() ([]procconn.Event, error) {
	select {
	case b := <-s.ch:
		if b.before != nil {
			b.before()
		}
		for i := range b.evs {
			if b.evs[i].TimestampNS == 0 {
				b.evs[i].TimestampNS = procconn.Monotonic() // filled as read, after the watch's listing: the kernel's clock
			}
		}
		return b.evs, b.err
	case <-s.done:
		return nil, procconn.ErrClosed
	}
}

// pending is how many batches are still to be read.
func (s *exitSource) pending() int { return len(s.ch) }

func (s *exitSource) Close() error { s.once.Do(func() { close(s.done) }); return nil }

// TestExitWatchKeepsTheAdoptedRootsOwnExit: tego adopt's run_end carries the adopted root's exit status as the proc
// connector reported it. The watch used to keep the last exit of the pid, so a later process that reused it (the root
// exited early while its descendants kept the run going) put its own status in run_end. It keeps the root's end, read
// after the root is found alive under the subscribed listener, and leaves the status unknown when the root was gone
// before that, or gone when the kernel dropped events.
func TestExitWatchKeepsTheAdoptedRootsOwnExit(t *testing.T) {
	p := newCLIProc()
	add := func() { p.add(4242, 1, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000) }
	root := adopt.Identity{PID: 4242, Start: 5000 + 4242}
	exit := func(code int, before func()) exitBatch {
		return exitBatch{before: before, evs: []procconn.Event{{Kind: procconn.Exit, PID: 4242, TGID: 4242, ExitCode: uint32(code << 8)}}}
	}
	gone := func() { p.del(4242) }
	prev := agentsOpen
	t.Cleanup(func() { agentsOpen = prev })
	for _, tc := range []struct {
		name    string
		root    adopt.Identity
		batches []exitBatch
		code    int
		ok      bool
	}{
		{"the root's exit, then a reused pid's", root, []exitBatch{exit(3, gone), exit(9, nil)}, 3, true},
		{"the root's exit, a reused pid's fork, its thread's exit", root, []exitBatch{exit(3, gone), {evs: []procconn.Event{
			{Kind: procconn.Fork, PID: 4242, TGID: 4242, ParentTGID: 1},
			{Kind: procconn.Exit, PID: 4243, TGID: 4242, ExitCode: 9}}}}, 3, true},
		{"the root gone before the listener", adopt.Identity{PID: 4242, Start: 1}, []exitBatch{exit(9, gone)}, 0, false},
		{"events dropped while the root still runs", root, []exitBatch{{err: unix.ENOBUFS}, exit(3, gone)}, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			add()
			src := newExitSource(tc.batches...)
			agentsOpen = func() (watcher.Source, error) { return src, nil }
			w := watchExit(p, tc.root)
			defer w.stop()
			code, _, ok := w.status()
			if code != tc.code || ok != tc.ok {
				t.Fatalf("status = code %d ok %v, want code %d ok %v", code, ok, tc.code, tc.ok)
			}
		})
	}
	// The kernel drops events once the root is gone: its exit may have been among them, so a later exit of the pid is
	// not taken for it. The pid is removed before the overrun is handed out, so the watch reads it gone then.
	add()
	src := newExitSource()
	agentsOpen = func() (watcher.Source, error) { return src, nil }
	w := watchExit(p, root)
	defer w.stop()
	gone()
	src.ch <- exitBatch{err: unix.ENOBUFS}
	src.ch <- exit(9, nil)
	if code, _, ok := w.status(); ok {
		t.Fatalf("after dropped events with the root gone: status code %d ok %v, want unknown", code, ok)
	}
}

// TestExitWatchTakesTheEndOfTheWholeProcess: the adopted root's main thread exits (pthread_exit, code 0) while a
// thread of it runs on and later ends the process with exit_group(3). The watch kept the main thread's exit, so
// run_end said 0 for a process wait(2) says ended 3. The end is the last
// thread's, and as the codes disagree (0, then 3: exit_group(3) gives 3, the thread's own exit(3) gives 0) the status
// is unknown; codes that agree give the status, a signal like any other code (a task can be killed alone). The end
// is the events', however late they are read: a zapped main thread's
// exit read once the process had gone used to end it with 0 for a program that exited 3, and an exec that failed after
// the zap, or a thread's exit read before the main thread's next one, the same (s5-1, s5-2, c5-2).
func TestExitWatchTakesTheEndOfTheWholeProcess(t *testing.T) {
	p := newCLIProc()
	root := adopt.Identity{PID: 4242, Start: 5000 + 4242}
	leaderExit := func(code uint32) procconn.Event {
		return procconn.Event{Kind: procconn.Exit, PID: 4242, TGID: 4242, ExitCode: code}
	}
	threadExit := func(code uint32) procconn.Event {
		return procconn.Event{Kind: procconn.Exit, PID: 4250, TGID: 4242, ExitCode: code}
	}
	// The leader exits: a zombie that counts the thread 4250, which runs.
	leaderGoes := func() {
		p.set(4242, func(c *cliProcess) { c.leaderExited, c.threads = true, 1 })
		p.add(4250, 1, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000)
		p.set(4250, func(c *cliProcess) { c.tgid = 4242 })
	}
	allGo := func() { p.del(4250); p.del(4242) }
	fork := procconn.Event{Kind: procconn.Fork, PID: 4250, TGID: 4242, ParentTGID: 1}
	execd := procconn.Event{Kind: procconn.Exec, PID: 4242, TGID: 4242}
	prev := agentsOpen
	t.Cleanup(func() { agentsOpen = prev })
	for _, tc := range []struct {
		name      string
		batches   []exitBatch
		code, sig int
		ok        bool
	}{
		{"the main thread first, then exit_group(3) from its thread", []exitBatch{
			{before: leaderGoes, evs: []procconn.Event{fork, leaderExit(0)}},
			{before: allGo, evs: []procconn.Event{threadExit(3 << 8)}}}, 0, 0, false},
		{"the main thread first, then the thread's exit(0)", []exitBatch{
			{before: leaderGoes, evs: []procconn.Event{fork, leaderExit(0)}},
			{before: allGo, evs: []procconn.Event{threadExit(0)}}}, 0, 0, true},
		{"the main thread first, then SIGKILL or the thread killed alone: unknown", []exitBatch{
			{before: leaderGoes, evs: []procconn.Event{fork, leaderExit(0)}},
			{before: allGo, evs: []procconn.Event{threadExit(9)}}}, 0, 0, false},
		{"the leader's exit read once the group had gone, then its thread's with another code", []exitBatch{
			{before: allGo, evs: []procconn.Event{fork, leaderExit(0), threadExit(3 << 8)}}}, 0, 0, false},
		{"the main thread first, then its thread exits and stays a zombie for a tracer", []exitBatch{
			{before: leaderGoes, evs: []procconn.Event{fork, leaderExit(0)}},
			{before: func() { p.set(4250, func(c *cliProcess) { c.zombie = true }) }, evs: []procconn.Event{threadExit(0)}}},
			0, 0, true},
		{"the main thread first, then its thread runs a program and exits 4", []exitBatch{
			{before: leaderGoes, evs: []procconn.Event{fork, leaderExit(0)}},
			{before: func() { p.del(4250); p.set(4242, func(c *cliProcess) { c.leaderExited = false }) },
				evs: []procconn.Event{execd}},
			{before: allGo, evs: []procconn.Event{leaderExit(4 << 8)}}}, 4, 0, true},
		{"exit_group(2) from the leader, its thread's exit read after", []exitBatch{
			{before: allGo, evs: []procconn.Event{fork, leaderExit(2 << 8), threadExit(2 << 8)}}}, 2, 0, true},
		{"a thread's exec zaps the main thread, the program exits 3, all read once it had gone (s5-1)", []exitBatch{
			{before: allGo, evs: []procconn.Event{fork, leaderExit(0), execd, leaderExit(3 << 8)}}}, 3, 0, true},
		{"the same, the zap and the exec in one read, the program's exit in the next (s5-1)", []exitBatch{
			{evs: []procconn.Event{fork}},
			{before: allGo, evs: []procconn.Event{leaderExit(0), execd}},
			{evs: []procconn.Event{leaderExit(11)}}}, 0, 11, true},
		{"an exec that fails after the zap: SIGSEGV with no exec event (s5-2)", []exitBatch{
			{before: allGo, evs: []procconn.Event{fork, leaderExit(0), leaderExit(11)}}}, 0, 11, true},
		{"exit_group(3) from the thread, its event read alone once the process had gone (c5-2)", []exitBatch{
			{evs: []procconn.Event{fork}},
			{before: allGo, evs: []procconn.Event{threadExit(3 << 8)}},
			{evs: []procconn.Event{leaderExit(3 << 8)}}}, 3, 0, true},
		{"a thread whose fork the kernel dropped is listed after the loss", []exitBatch{
			{before: func() {
				p.add(4250, 1, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000)
				p.set(4250, func(c *cliProcess) { c.tgid = 4242 })
			}, err: unix.ENOBUFS},
			{before: func() { p.set(4242, func(c *cliProcess) { c.leaderExited, c.threads = true, 1 }) },
				evs: []procconn.Event{leaderExit(0)}},
			{before: allGo, evs: []procconn.Event{threadExit(3 << 8)}}}, 0, 0, false},
		{"the main thread killed alone by SIGSYS, then the thread's exit_group(0) (c5-1)", []exitBatch{
			{evs: []procconn.Event{fork, leaderExit(31)}},
			{before: allGo, evs: []procconn.Event{threadExit(0)}}}, 0, 0, false},
		{"a zapped main thread's exit filled before the watch listed the root and read after it says nothing (s6-1)",
			[]exitBatch{
				{evs: []procconn.Event{{Kind: procconn.Exit, PID: 4242, TGID: 4242, ExitCode: 0, TimestampNS: 1}}},
				{before: allGo, evs: []procconn.Event{leaderExit(3 << 8)}}}, 3, 0, true},
		{"a thread's exit_group(3) read before the slow main thread's own exit(0): unknown (c6-1, s6-2)", []exitBatch{
			{evs: []procconn.Event{fork, threadExit(3 << 8)}},
			{before: allGo, evs: []procconn.Event{leaderExit(0)}}}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.add(4242, 1, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000)
			src := newExitSource(tc.batches...)
			agentsOpen = func() (watcher.Source, error) { return src, nil }
			w := watchExit(p, root)
			defer w.stop()
			for deadline := time.Now().Add(2 * time.Second); src.pending() > 0 && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond) // the batches are read (a watch that stops reading leaves some)
			}
			code, sig, ok := w.status()
			if code != tc.code || sig != tc.sig || ok != tc.ok {
				t.Fatalf("status = code %d signal %d ok %v, want code %d signal %d ok %v", code, sig, ok, tc.code, tc.sig, tc.ok)
			}
		})
	}
}
