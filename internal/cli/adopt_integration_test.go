// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The adoption's tests on the real kernel, as root (ADR 0055): the tego binary (tier 2's objects
// embedded) adopts a script started in a cgroup that stands in for a terminal's session scope, with the script's
// parent shell and a sibling process beside it. Each test says what it proves; together they are deliverable 4 of the
// adoption package: the tree is adopted and only the tree, its later actions are in the ledger with the right
// processes, a release leaves the agent running where it came from, a killed adopter leaves nothing attached, and a
// busy agent's adoption records its gaps rather than losing events silently.

// adoptAgentScript is the stand-in agent, a shell script named claude: one command per line from the fifo
// $AGENT_CMDS, each acknowledged with its own line in $AGENT_ACKS. "open" reads $AGENT_FILE with the shell's own
// redirection (the agent's own process opens it), "exec" runs /bin/true, "connect" connects to 127.0.0.1:$AGENT_PORT
// from a python3 child, "fork" starts a sleeping child, "exit" exits 7.
const adoptAgentScript = `#!/bin/sh
exec 3<>"$AGENT_CMDS"
while IFS= read -r line <&3; do
	case "$line" in
	open) read -r _ <"$AGENT_FILE" ;;
	exec) /bin/true ;;
	connect) python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2).close()' "$AGENT_PORT" ;;
	fork) sleep 600 & echo "$!" >"$AGENT_CHILD" ;;
	write) echo x >"$AGENT_WRITE" ;;
	writeout) echo x >"$AGENT_OUTSIDE" ;;
	secret) read -r _ <"$AGENT_SECRET" ;;
	mountns) unshare --mount /bin/true ;;
	exit) exit 7 ;;
	esac
	echo "$line $?" >>"$AGENT_ACKS"
done
`

// adoptStormScript is a busy agent: it reads $AGENT_FILE through cat as fast as it can until $AGENT_STOP exists,
// notes how many it had made when $AGENT_MARK appeared, and writes "<total> <at mark>" to $AGENT_COUNT.
const adoptStormScript = `#!/bin/sh
n=0
m=-1
while [ ! -e "$AGENT_STOP" ]; do
	cat "$AGENT_FILE" >/dev/null
	n=$((n+1))
	if [ "$m" -lt 0 ] && [ -e "$AGENT_MARK" ]; then m=$n; fi
done
echo "$n $m" >"$AGENT_COUNT"
`

// adoptEnv is one test's machine: a "terminal" cgroup holding a shell and a sibling, the tego binary, its config and
// ledger root, and the agent's files.
type adoptEnv struct {
	t        *testing.T
	dir      string // the agent's files
	state    string // tego's: the ledger root, the chain anchor, the own log
	tego     string
	config   string
	ledger   string
	term     string // the terminal's cgroup, absolute
	termRel  string
	sibling  *exec.Cmd
	cmds     string
	acks     string
	file     string
	child    string
	agentPID int
	shell    *exec.Cmd
	adopter  *adopter
	// tegoEnv is added to every tego command's environment (a test's own pin, such as TEGO_TEST_PLANE).
	tegoEnv []string
}

// requireAdoption skips unless this is root on a cgroup2 host with the BPF objects and a bpf filesystem.
func requireAdoption(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: an adoption moves processes between cgroups and loads tier 2's programs")
	}
	if !ebpfbindings.Available() {
		t.Skip("untagged: needs the BPF objects (tier 2's trace programs record the adopted tree); add -tags tegobpf")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skip("needs the cgroup v2 hierarchy at /sys/fs/cgroup")
	}
}

func newAdoptEnv(t *testing.T) *adoptEnv {
	t.Helper()
	requireAdoption(t)
	// Under /tmp, not the test's own temporary directory, whose parent is 0700: the boundary test's agent runs as
	// another user and must reach its files.
	dir, err := os.MkdirTemp("/tmp", "tego-adopt-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Three directories apart, as tego wants them: the agent's files, tego's state (its ledger root, whose parent the
	// compiler read-denies to every run, its chain anchor and its own log) and the config.
	agentDir, state := filepath.Join(dir, "agent"), filepath.Join(dir, "state")
	if err := os.Mkdir(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &adoptEnv{t: t, dir: agentDir, state: state, ledger: filepath.Join(state, "runs"), cmds: filepath.Join(agentDir, "cmds"),
		acks: filepath.Join(agentDir, "acks"), file: filepath.Join(agentDir, "input.txt"), child: filepath.Join(agentDir, "child")}
	e.tego = buildTegoForAdoption(t, dir)
	confDir := filepath.Join(filepath.Dir(agentDir), "conf")
	if err := os.Mkdir(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.config = filepath.Join(confDir, "config.yaml")
	if err := os.WriteFile(e.config, []byte("version: 0\nledger_root: "+e.ledger+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.file, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(e.cmds, 0o644); err != nil {
		t.Fatal(err)
	}
	e.termRel = fmt.Sprintf("/adopt-it-term-%d-%d.scope", os.Getpid(), time.Now().UnixNano()%100000)
	e.term = filepath.Join("/sys/fs/cgroup", e.termRel)
	if err := os.Mkdir(e.term, 0o755); err != nil {
		t.Skipf("cannot make a cgroup for the terminal: %v", err)
	}
	t.Cleanup(func() { e.cleanup() })
	e.sibling = e.inTerm(exec.Command("sleep", "600"))
	if err := e.sibling.Start(); err != nil {
		t.Fatal(err)
	}
	return e
}

// buildTegoForAdoption builds cmd/tego with the objects and the test hooks (its chain anchor and own log in the
// test's directory); test/vm/go-shim.sh serves the prebuilt one in the KVM guest.
func buildTegoForAdoption(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "tego")
	cmd := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", out, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the tegobpf tego binary: %v: %s", err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// inTerm places cmd in the terminal's cgroup at clone time.
func (e *adoptEnv) inTerm(cmd *exec.Cmd) *exec.Cmd {
	fd, err := unix.Open(e.term, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = unix.Close(fd) })
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	return cmd
}

// startAgent starts `sh -c '<script>; exec sleep 600'` in the terminal: the shell is the agent's parent, as a
// terminal's is, and stays there. It returns once the agent (the shell's only child) exists.
func (e *adoptEnv) startAgent(script string, env ...string) {
	e.t.Helper()
	path := filepath.Join(e.dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.shell = e.inTerm(exec.Command("/bin/sh", "-c", `"$0"; exec sleep 600`, path))
	e.shell.Env = append([]string{"PATH=/usr/bin:/bin", "AGENT_CMDS=" + e.cmds, "AGENT_ACKS=" + e.acks, "AGENT_FILE=" + e.file,
		"AGENT_CHILD=" + e.child}, env...)
	if err := e.shell.Start(); err != nil {
		e.t.Fatal(err)
	}
	waitFor(e.t, func() bool {
		kids := childrenOf(e.shell.Process.Pid)
		if len(kids) == 1 {
			e.agentPID = kids[0]
			return true
		}
		return false
	})
}

// childrenOf reads /proc for pid's children.
func childrenOf(pid int) []int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func cgroupOfPID(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return p
		}
	}
	return ""
}

// send writes a command to the agent and waits for its acknowledgement; it returns the command's exit status.
func (e *adoptEnv) send(cmd string) int {
	e.t.Helper()
	f, err := os.OpenFile(e.cmds, os.O_WRONLY, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	before := e.ackCount()
	if _, err := f.WriteString(cmd + "\n"); err != nil {
		e.t.Fatal(err)
	}
	_ = f.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		lines := e.acks0()
		if len(lines) > before {
			last := strings.Fields(lines[len(lines)-1])
			if len(last) == 2 && last[0] == cmd {
				status, _ := strconv.Atoi(last[1])
				return status
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the agent did not acknowledge %q: %s", cmd, e.diag())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// diag is what a stuck test needs to know: the agent's state and cgroup, its acknowledgements, the adopter's words.
func (e *adoptEnv) diag() string {
	var b strings.Builder
	st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", e.agentPID))
	wchan, _ := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", e.agentPID))
	acks, _ := os.ReadFile(e.acks)
	fmt.Fprintf(&b, "agent %d stat %q wchan %q cgroup %q; acks %q", e.agentPID, strings.TrimSpace(string(st)), wchan,
		cgroupOfPID(e.agentPID), acks)
	if e.adopter != nil {
		fmt.Fprintf(&b, "; adopter said: %s", e.adopter.text())
	}
	return b.String()
}

// post writes a command without waiting for an acknowledgement (exit, which ends the agent before it could ack).
func (e *adoptEnv) post(cmd string) {
	e.t.Helper()
	f, err := os.OpenFile(e.cmds, os.O_WRONLY, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = f.WriteString(cmd + "\n")
	_ = f.Close()
}

func (e *adoptEnv) acks0() []string {
	b, _ := os.ReadFile(e.acks)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (e *adoptEnv) ackCount() int {
	b, _ := os.ReadFile(e.acks)
	if len(strings.TrimSpace(string(b))) == 0 {
		return 0
	}
	return len(e.acks0())
}

// tegoCmd is the tego binary run as root with this test's config, chain anchor and own log.
func (e *adoptEnv) tegoCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(e.tego, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TEGO_CONFIG=" + e.config,
		"TEGO_TEST_CHAIN_ANCHOR=" + filepath.Join(e.state, "chain.log"), "TEGO_TEST_OWN_LOG_HOME=" + filepath.Join(e.state, "ownlog")}
	// Preserve the root suite's explicit waiver in this tegotesthooks binary too: a product build on a kernel
	// that preempts kernel code offers no fmod_ret mode, so the boundary test would exercise no plane there.
	cmd.Env = append(cmd.Env, "TEGO_TEST_PLANE_PREEMPT="+os.Getenv("TEGO_TEST_PLANE_PREEMPT"))
	cmd.Env = append(cmd.Env, e.tegoEnv...)
	return cmd
}

// adopter is a running `tego adopt` and what it has said.
type adopter struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	stderr strings.Builder
	done   chan error
}

func (a *adopter) text() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stderr.String()
}

// adopt starts `tego adopt --pid <agent> args...` and waits until it says the run records.
func (e *adoptEnv) adopt(args ...string) (*adopter, string) {
	e.t.Helper()
	a, run, ok := e.tryAdopt(args...)
	if !ok {
		e.t.Fatalf("tego adopt ended before it recorded: %s", a.text())
	}
	return a, run
}

// tryAdopt is adopt that returns ok false, instead of failing, when tego adopt ends before it records.
func (e *adoptEnv) tryAdopt(args ...string) (*adopter, string, bool) {
	e.t.Helper()
	a := &adopter{cmd: e.tegoCmd(append([]string{"adopt", "--pid", strconv.Itoa(e.agentPID)}, args...)...), done: make(chan error, 1)}
	e.adopter = a
	pipe, err := a.cmd.StderrPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := a.cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			a.mu.Lock()
			a.stderr.WriteString(sc.Text() + "\n")
			a.mu.Unlock()
		}
		a.done <- a.cmd.Wait()
	}()
	e.t.Cleanup(func() {
		_ = a.cmd.Process.Kill()
	})
	var run string
	deadline := time.Now().Add(60 * time.Second)
	for run == "" {
		if time.Now().After(deadline) {
			e.t.Fatalf("tego adopt did not start recording: %s", a.text())
		}
		select {
		case err := <-a.done:
			a.done <- err
			return a, "", false
		case <-time.After(50 * time.Millisecond):
		}
		for _, l := range strings.Split(a.text(), "\n") {
			if i := strings.Index(l, " as run "); i >= 0 && strings.Contains(l, "adopted pid") {
				run = strings.TrimSuffix(strings.Fields(l[i+len(" as run "):])[0], ":")
			}
		}
	}
	return a, run, true
}

// wait waits for the adopter to end and returns its exit code.
func (a *adopter) wait(t *testing.T) int {
	t.Helper()
	select {
	case err := <-a.done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("tego adopt: %v", err)
		}
		return 0
	case <-time.After(60 * time.Second):
		t.Fatalf("tego adopt did not end: %s", a.text())
	}
	return -1
}

// lines reads a run's ledger.
func (e *adoptEnv) lines(run string) []*record.Event {
	e.t.Helper()
	r, err := ledger.OpenReader(filepath.Join(e.ledger, run))
	if err != nil {
		e.t.Fatalf("open the run's ledger: %v", err)
	}
	defer r.Close()
	var out []*record.Event
	for ev, err := range r.Iter() {
		if err != nil {
			e.t.Fatalf("read the ledger: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// scopeOf is the adoption's cgroup for run, absolute.
func (e *adoptEnv) scopeOf(run string) string {
	matches, _ := filepath.Glob("/sys/fs/cgroup/tego.slice/*/" + adopt.ScopeName(run))
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

// leftovers says what of run is still in the kernel: its run-set row, its pinned link directory, its scope, its
// adoption record.
func (e *adoptEnv) leftovers(run, hash string, scopeID uint64) []string {
	var out []string
	if hash != "" {
		m, err := ebpf.LoadPinnedMap(filepath.Join("/sys/fs/bpf/tego", hash, "maps", ebpfbindings.MapRunSet), nil)
		if err == nil {
			var v ebpfbindings.Run
			if m.Lookup(&scopeID, &v) == nil {
				out = append(out, "a run-set row")
			}
			_ = m.Close()
		}
		if _, err := os.Stat(filepath.Join("/sys/fs/bpf/tego", hash, "links", "run-"+run)); err == nil {
			out = append(out, "pinned run links")
		}
	}
	if s := e.scopeOf(run); s != "" {
		out = append(out, "the scope "+s)
	}
	if _, err := os.Stat(filepath.Join(tegoruntime.AdoptStateDir, run+".json")); err == nil {
		out = append(out, "the adoption record")
	}
	return out
}

func (e *adoptEnv) cleanup() {
	for _, c := range []*exec.Cmd{e.shell, e.sibling} {
		if c != nil && c.Process != nil {
			_ = c.Process.Kill()
			_, _ = c.Process.Wait()
		}
	}
	if b, err := os.ReadFile(e.child); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if e.agentPID > 0 {
		_ = syscall.Kill(e.agentPID, syscall.SIGKILL)
	}
	if left := e.killAgentTree(5 * time.Second); len(left) > 0 {
		e.t.Errorf("the agent's processes %v outlived the test's cleanup", left)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if os.Remove(e.term) == nil || errors.Is(os.Remove(e.term), os.ErrNotExist) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// agentProcesses are the live processes whose command line names this test's agent script: the agent, and every
// copy of it the script forked as a background job or a subshell, wherever they are now.
func (e *adoptEnv) agentProcesses() []int {
	script := filepath.Join(e.dir, "claude")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, d := range entries {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		// A process that is gone or a zombie has no command line to read.
		argv, err := os.ReadFile(filepath.Join("/proc", d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		for _, arg := range strings.Split(string(argv), "\x00") {
			if arg == script {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}

// killAgentTree kills agentProcesses until none is left or budget has passed, and returns those still there. The
// kills of the shell and of the agent above leave the script's background jobs running with init as their parent,
// and a test that ends before its release leaves them inside an adoption whose adopter the cleanup killed: they
// then never read the file that tells them to stop, and every later test that looks for agents on this machine
// finds them (the adoption skip test's eight readers, on a kernel that preempts no task inside a program).
func (e *adoptEnv) killAgentTree(budget time.Duration) []int {
	deadline := time.Now().Add(budget)
	for {
		pids := e.agentProcesses()
		if len(pids) == 0 || !time.Now().Before(deadline) {
			return pids
		}
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAdoptEnvCleanupEndsTheAgentsBackgroundJobs pins the cleanup every adoption test relies on: an agent script
// whose background jobs never end by themselves leaves no process naming it once the cleanup has run.
func TestAdoptEnvCleanupEndsTheAgentsBackgroundJobs(t *testing.T) {
	e := newAdoptEnv(t)
	e.startAgent("#!/bin/sh\nfor i in 1 2 3; do ( while :; do sleep 1; done ) & done\nwait\n")
	waitFor(t, func() bool { return len(e.agentProcesses()) >= 4 })
	// What the cleanup did before: the shell and the agent, by their pids. The jobs live on under init.
	_ = e.shell.Process.Kill()
	_, _ = e.shell.Process.Wait()
	_ = syscall.Kill(e.agentPID, syscall.SIGKILL)
	waitFor(t, func() bool { return syscall.Kill(e.agentPID, 0) != nil || len(e.agentProcesses()) == 3 })
	if left := e.agentProcesses(); len(left) != 3 {
		t.Fatalf("the agent's three background jobs after the kill of the shell and the agent: %v, want three", left)
	}
	e.shell = nil
	e.cleanup()
	if left := e.agentProcesses(); len(left) != 0 {
		t.Fatalf("processes naming the agent script after the cleanup: %v", left)
	}
}

// runStartOf decodes run_start.
func runStartOf(t *testing.T, evs []*record.Event) (record.RunStartPayload, uint64) {
	t.Helper()
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatal("no run_start")
	}
	var p record.RunStartPayload
	if err := evs[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p, evs[0].Cgroup
}

func lastRunEnd(t *testing.T, evs []*record.Event) record.RunEndPayload {
	t.Helper()
	last := evs[len(evs)-1]
	if last.Kind != record.KindRunEnd {
		t.Fatalf("the ledger ends with %s, not run_end", last.Kind)
	}
	var p record.RunEndPayload
	if err := last.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIntegrationAdoptRecordsAScriptFromTheKernel: a script started outside any run, in a terminal's cgroup beside
// its shell and a sibling, is adopted by `tego adopt --pid`: only its tree moves, its later open (its own), exec and
// connect (its children's) are in the ledger with the right processes, a release (`tego stop <run>`, a release
// request its adopter answers) moves it back where it came from and leaves it running, and nothing of the run is
// left in the kernel.
func TestIntegrationAdoptRecordsAScriptFromTheKernel(t *testing.T) {
	e := newAdoptEnv(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	e.startAgent(adoptAgentScript, "AGENT_PORT="+strconv.Itoa(port))
	if s := e.send("fork"); s != 0 {
		t.Fatalf("fork: %d", s)
	}
	b, _ := os.ReadFile(e.child)
	before, _ := strconv.Atoi(strings.TrimSpace(string(b)))

	a, run := e.adopt()
	scope := e.scopeOf(run)
	if scope == "" {
		t.Fatalf("no scope adopt-%s.scope: %s", run, a.text())
	}
	scopeRel := strings.TrimPrefix(scope, "/sys/fs/cgroup")
	for pid, want := range map[int]string{e.agentPID: scopeRel, before: scopeRel, e.shell.Process.Pid: e.termRel,
		e.sibling.Process.Pid: e.termRel} {
		if got := cgroupOfPID(pid); got != want {
			t.Errorf("pid %d is in %s, want %s: only the agent's tree moves", pid, got, want)
		}
	}
	if !strings.Contains(a.text(), "runs as uid 0") {
		t.Errorf("the owner was not printed: %s", a.text())
	}
	// After the adoption: the agent opens a file itself, runs a program, makes a connection, forks a child.
	for _, c := range []string{"open", "exec", "connect", "fork"} {
		if s := e.send(c); s != 0 {
			t.Fatalf("%s: exit %d", c, s)
		}
	}
	b, _ = os.ReadFile(e.child)
	after, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if got := cgroupOfPID(after); got != scopeRel {
		t.Errorf("a child forked after the adoption is in %s, want the run's cgroup", got)
	}
	time.Sleep(500 * time.Millisecond) // the recorder's read interval

	// `tego stop <run>`: an adoption's is a release request, which its adopter answers; nothing is signalled or
	// killed.
	if out, err := e.tegoCmd("stop", run).CombinedOutput(); err != nil ||
		!strings.Contains(string(out), run+": released by its adopter (pid "+strconv.Itoa(a.cmd.Process.Pid)+")") {
		t.Fatalf("tego stop %s: %v: %s", run, err, out)
	}
	if code := a.wait(t); code != 0 {
		t.Fatalf("tego adopt exit %d: %s", code, a.text())
	}
	if !strings.Contains(a.text(), "ended (stopped)") {
		t.Errorf("stderr: %s", a.text())
	}
	if syscall.Kill(e.agentPID, 0) != nil {
		t.Fatal("the release killed the agent")
	}
	for _, pid := range []int{e.agentPID, before, after} {
		if got := cgroupOfPID(pid); got != e.termRel {
			t.Errorf("after the release pid %d is in %s, want the terminal's %s", pid, got, e.termRel)
		}
	}
	if s := e.send("open"); s != 0 {
		t.Error("the released agent no longer answers")
	}

	evs := e.lines(run)
	start, scopeID := runStartOf(t, evs)
	if left := e.leftovers(run, start.BPFHash, scopeID); len(left) != 0 {
		t.Errorf("left after the release: %v", left)
	}
	if start.Tier != "cgroup" || start.Capture != "off" || len(start.Command) == 0 || !strings.HasSuffix(start.Command[len(start.Command)-1], "claude") {
		t.Errorf("run_start %+v", start)
	}
	agentExec := ""
	var sawOpen, sawTrue, sawConnect, sawPreAttach bool
	for _, ev := range evs {
		switch ev.Kind {
		case record.KindExec:
			var p record.ExecPayload
			_ = ev.DecodePayload(&p)
			if p.By == tegoruntime.AdoptionBy && ev.PID == e.agentPID {
				agentExec = p.ExecID
			}
			if p.Path == "/bin/true" && p.ParentExecID != "" && p.ParentExecID == agentExec && ev.Source == record.SourceKernel {
				sawTrue = true
			}
		case record.KindFS:
			var p record.FSPayload
			_ = ev.DecodePayload(&p)
			if p.Path == e.file && ev.PID == e.agentPID {
				sawOpen = true
			}
		case record.KindNet:
			var p record.NetPayload
			_ = ev.DecodePayload(&p)
			if p.Dst == fmt.Sprintf("127.0.0.1:%d", port) && ev.PID != e.agentPID {
				sawConnect = true
			}
		case record.KindGap:
			var g record.GapPayload
			_ = ev.DecodePayload(&g)
			if g.Why == tegoruntime.GapAdoptionPreAttach && g.Count >= 2 {
				sawPreAttach = true
			}
		}
	}
	if agentExec == "" {
		t.Error("no exec line by adoption for the agent")
	}
	if !sawOpen {
		t.Error("the agent's own open after the adoption is not in the ledger under its pid")
	}
	if !sawTrue {
		t.Error("the exec of /bin/true by the agent's child is not in the ledger under the agent's exec")
	}
	if !sawConnect {
		t.Error("the connect after the adoption is not in the ledger")
	}
	if !sawPreAttach {
		t.Error("no adoption-pre-attach gap naming the agent and the child it held")
	}
	if end := lastRunEnd(t, evs); end.Reason != record.RunEndStopped || !strings.Contains(end.Detail, "released at the request of tego stop") {
		t.Errorf("run_end %+v", end)
	}
	// `tego status` reads it as a normal run.
	out, err := e.tegoCmd("status", run).CombinedOutput()
	if err != nil || !strings.Contains(string(out), run) {
		t.Errorf("tego status %s: %v %s", run, err, out)
	}
}

// TestIntegrationAdoptKilledAdopterLeavesNothingAttached: the adopter is SIGKILLed with the agent adopted; its
// reaper releases the agent (back in the terminal's cgroup, still running), writes run_end orphaned, and removes
// the scope, the run-set row, the record and the lock: nothing of the run is left attached.
func TestIntegrationAdoptKilledAdopterLeavesNothingAttached(t *testing.T) {
	e := newAdoptEnv(t)
	e.startAgent(adoptAgentScript)
	a, run := e.adopt()
	evs := e.lines(run)
	start, scopeID := runStartOf(t, evs)
	if left := e.leftovers(run, start.BPFHash, scopeID); len(left) < 3 {
		t.Fatalf("while adopted the kernel holds %v, want the row, the scope and the record", left)
	}
	_ = a.cmd.Process.Signal(syscall.SIGKILL)
	_ = a.wait(t)
	waitFor(t, func() bool { return cgroupOfPID(e.agentPID) == e.termRel })
	waitFor(t, func() bool { return len(e.leftovers(run, start.BPFHash, scopeID)) == 0 })
	if syscall.Kill(e.agentPID, 0) != nil {
		t.Fatal("the agent died with its adopter")
	}
	if s := e.send("open"); s != 0 {
		t.Error("the released agent no longer answers")
	}
	waitFor(t, func() bool {
		evs := e.lines(run)
		return evs[len(evs)-1].Kind == record.KindRunEnd
	})
	if end := lastRunEnd(t, e.lines(run)); end.Reason != record.RunEndOrphaned || !strings.Contains(end.Detail, "the adopter died") {
		t.Errorf("run_end %+v", end)
	}
	if _, err := os.Stat(filepath.Join(tegoruntime.AdoptStateDir, fmt.Sprintf("target-%d-", e.agentPID))); err == nil {
		t.Error("the lock file outlived the adoption")
	}
}

// TestIntegrationAdoptBusyAgentRecordsTheGap: an agent busy starting a program and reading a file thousands of
// times a second is adopted mid-run. What it did before the attach is a gap of the run's (adoption-pre-attach); from
// the mark the test sets once the run records, every iteration's exec is either in the ledger or counted by a
// ringbuf-full gap: none is lost silently.
func TestIntegrationAdoptBusyAgentRecordsTheGap(t *testing.T) {
	e := newAdoptEnv(t)
	stop, mark, count := filepath.Join(e.dir, "stop"), filepath.Join(e.dir, "mark"), filepath.Join(e.dir, "count")
	e.startAgent(adoptStormScript, "AGENT_STOP="+stop, "AGENT_MARK="+mark, "AGENT_COUNT="+count)
	time.Sleep(300 * time.Millisecond) // it is busy before the adoption
	a, run := e.adopt()
	if err := os.WriteFile(mark, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := os.WriteFile(stop, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { b, _ := os.ReadFile(count); return len(strings.Fields(string(b))) == 2 })
	b, _ := os.ReadFile(count)
	var total, atMark int
	if _, err := fmt.Sscanf(string(b), "%d %d", &total, &atMark); err != nil || atMark < 0 {
		t.Fatalf("count %q: %v", b, err)
	}
	waitFor(t, func() bool { return cgroupOfPID(e.agentPID) == "" || syscall.Kill(e.agentPID, 0) != nil })
	if code := a.wait(t); code != 0 {
		t.Fatalf("tego adopt exit %d: %s", code, a.text())
	}
	var cats, lost int
	var preAttach bool
	for _, ev := range e.lines(run) {
		switch ev.Kind {
		case record.KindExec:
			var p record.ExecPayload
			_ = ev.DecodePayload(&p)
			if filepath.Base(p.Path) == "cat" && p.By == "" {
				cats++
			}
		case record.KindGap:
			var g record.GapPayload
			_ = ev.DecodePayload(&g)
			switch g.Why {
			case tegoruntime.GapAdoptionPreAttach:
				preAttach = true
			case "ringbuf-full", "channel-full":
				lost += g.Count
			}
		}
	}
	after := total - atMark
	t.Logf("%d iterations, %d after the mark; %d cat execs recorded, %d samples counted lost", total, after, cats, lost)
	if !preAttach {
		t.Error("no adoption-pre-attach gap for a busy agent's unrecorded start")
	}
	if cats+lost < after {
		t.Errorf("%d execs after the mark, %d recorded and %d counted lost: some were lost silently", after, cats, lost)
	}
	if end := lastRunEnd(t, e.lines(run)); end.Reason != record.RunEndExit {
		t.Errorf("run_end %+v: the agent's tree ended by itself", end)
	}
}

// TestIntegrationAdoptBoundaryRefusesThroughThePlane: an agent of an unprivileged user is adopted under a boundary
// (a workspace, a denied file, two allowed programs) and the decision plane, in the mode this boot offers, refuses in
// the kernel what the boundary refuses (a read of the denied file, a write outside the workspace, an unlisted
// program), each refusal in the ledger with the plane as its mechanism; what the boundary allows still works.
func TestIntegrationAdoptBoundaryRefusesThroughThePlane(t *testing.T) {
	e := newAdoptEnv(t)
	ws := filepath.Join(e.dir, "ws")
	secret := filepath.Join(e.dir, "secret")
	if err := os.Mkdir(ws, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(ws, 0o777)
	if err := os.WriteFile(secret, []byte("s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The agent acknowledges into the workspace: a write anywhere else is the boundary's to refuse.
	e.acks = filepath.Join(ws, "acks")
	contractDir := filepath.Join(filepath.Dir(e.dir), "contract")
	if err := os.Mkdir(contractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(contractDir, "boundary.yaml")
	y := fmt.Sprintf("version: 0\nname: boundary\ncommand: [\"/bin/sh\"]\nrecord: full\nfs:\n  write: [%q, \"/dev/null\"]\n"+
		"  deny_read: [%q]\nexec:\n  allow: [\"/usr/bin/sleep\", \"/bin/sh\"]\n", ws, secret)
	if err := os.WriteFile(contract, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{e.cmds, e.file} {
		_ = os.Chmod(p, 0o666)
	}
	outside := filepath.Join(e.dir, "outside")
	e.startAgentAs(65534, adoptAgentScript, "AGENT_WRITE="+filepath.Join(ws, "out"), "AGENT_OUTSIDE="+outside,
		"AGENT_SECRET="+secret)
	// Root naming the pid of another user's process is refused unless --uid names its owner (this tego runs as
	// root with no sudo, so it acts for uid 0).
	out, err := e.tegoCmd("adopt", "--pid", strconv.Itoa(e.agentPID), "--boundary", contract).CombinedOutput()
	if code := exitCode(err); code != 125 || !strings.Contains(string(out), "(uid)") || !strings.Contains(string(out), "--uid 65534") {
		t.Fatalf("adopting uid 65534's agent with no --uid: exit %d (want 125, refused under uid): %s", code, out)
	}
	// A command rule is argv's, which only a supervisor decides: the same contract with exec.deny is refused, named,
	// before anything moves, rather than adopted with the rule held by nothing.
	withDeny := filepath.Join(contractDir, "deny.yaml")
	if err := os.WriteFile(withDeny, []byte(strings.Replace(y, "exec:\n", "exec:\n  deny: [\"rm -r\"]\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = e.tegoCmd("adopt", "--pid", strconv.Itoa(e.agentPID), "--uid", "65534", "--boundary", withDeny).CombinedOutput()
	if code := exitCode(err); code != 125 || !strings.Contains(string(out), "exec.deny rm -r: argv rules") ||
		!strings.Contains(string(out), "[adopt-refused]") {
		t.Fatalf("a boundary with exec.deny: exit %d (want 125, the command rule refused): %s", code, out)
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Fatalf("the refused boundary moved the agent: it is in %s, not %s", got, e.termRel)
	}
	a, run, ok := e.tryAdopt("--uid", "65534", "--boundary", contract)
	if !ok {
		if os.Getenv("TEGO_TEST_PLANE_PREEMPT") == "waive" || !strings.Contains(a.text(), "no decision plane decides") {
			t.Fatalf("tego adopt --boundary ended before it recorded: %s", a.text())
		}
		t.Skipf("no plane mode decides tier cgroup on this boot, so no boundary holds on an adopted process: %s", a.text())
	}
	if !strings.Contains(a.text(), "held by the decision plane") {
		t.Fatalf("a boundary adoption without the plane: %s", a.text())
	}
	if s := e.send("secret"); s == 0 {
		t.Error("a read of the denied file was allowed")
	}
	if s := e.send("write"); s != 0 {
		t.Errorf("a write in the workspace was refused (%d)", s)
	}
	if s := e.send("writeout"); s == 0 {
		t.Error("a write outside the workspace was allowed")
	}
	if s := e.send("exec"); s == 0 {
		t.Error("an unlisted program ran")
	}
	time.Sleep(500 * time.Millisecond)
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	if code := a.wait(t); code != 0 {
		t.Fatalf("exit %d: %s", code, a.text())
	}
	var deniedRead, deniedWrite, deniedExec bool
	for _, ev := range e.lines(run) {
		if ev.Verdict != record.VerdictRefused {
			continue
		}
		switch ev.Kind {
		case record.KindFS:
			var p record.FSPayload
			_ = ev.DecodePayload(&p)
			deniedRead = deniedRead || p.Path == secret && p.Mechanism == record.MechanismPlane
			deniedWrite = deniedWrite || p.Path == outside && p.Mechanism == record.MechanismPlane
		case record.KindExec:
			var p record.ExecPayload
			_ = ev.DecodePayload(&p)
			deniedExec = deniedExec || p.Path == "/bin/true" && p.Mechanism == record.MechanismPlane
		}
	}
	if !deniedRead || !deniedWrite || !deniedExec {
		t.Errorf("refusals in the ledger: read %v write %v exec %v", deniedRead, deniedWrite, deniedExec)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Error("the write outside the workspace happened")
	}
}

// startAgentAs is startAgent as uid (and its gid) instead of root.
func (e *adoptEnv) startAgentAs(uid int, script string, env ...string) {
	e.t.Helper()
	_ = os.Chmod(e.dir, 0o755)
	if err := os.WriteFile(e.acks, nil, 0o666); err != nil {
		e.t.Fatal(err)
	}
	_ = os.Chmod(e.acks, 0o666)
	e.startAgentWith(func(c *exec.Cmd) {
		c.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}
		c.Dir = "/"
	}, script, env...)
}

// startAgentWith is startAgent with the shell's command adjusted by edit.
func (e *adoptEnv) startAgentWith(edit func(*exec.Cmd), script string, env ...string) {
	e.t.Helper()
	path := filepath.Join(e.dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.shell = e.inTerm(exec.Command("/bin/sh", "-c", `"$0"; exec sleep 600`, path))
	e.shell.Env = append([]string{"PATH=/usr/bin:/bin", "AGENT_CMDS=" + e.cmds, "AGENT_ACKS=" + e.acks, "AGENT_FILE=" + e.file,
		"AGENT_CHILD=" + e.child}, env...)
	edit(e.shell)
	if err := e.shell.Start(); err != nil {
		e.t.Fatal(err)
	}
	waitFor(e.t, func() bool {
		kids := childrenOf(e.shell.Process.Pid)
		if len(kids) == 1 {
			e.agentPID = kids[0]
			return true
		}
		return false
	})
}

// TestIntegrationGuardAdoptsAnAgentAsItStarts: `tego agents --follow --adopt --uid 0` adopts a script named
// claude the moment it starts outside any run, and a second one beside it; `tego stop` of the second's run releases
// that agent alone (the guard, the run's lock holder, runs on, and so does its other adoption); the first's run ends
// with it, its exit status read from the kernel; and the guard stops cleanly.
func TestIntegrationGuardAdoptsAnAgentAsItStarts(t *testing.T) {
	e := newAdoptEnv(t)
	guard := e.tegoCmd("agents", "--follow", "--adopt", "--uid", "0", "--json")
	stdout, err := guard.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errs lockedBuffer
	guard.Stderr = &errs
	if err := guard.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Process.Kill(); _ = guard.Wait() })
	var mu sync.Mutex
	var lines []watcher.Sighting
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			var s watcher.Sighting
			if json.Unmarshal(sc.Bytes(), &s) == nil {
				mu.Lock()
				lines = append(lines, s)
				mu.Unlock()
			}
		}
	}()
	find := func(event string, pid int) (watcher.Sighting, bool) {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range lines {
			if s.Event == event && int(s.PID) == pid {
				return s, true
			}
		}
		return watcher.Sighting{}, false
	}
	waitFor(t, func() bool { return strings.Contains(errs.String(), "adopting each one") })
	time.Sleep(300 * time.Millisecond)
	e.startAgent(adoptAgentScript)
	waitFor(t, func() bool { _, ok := find(watcher.EventAdopted, e.agentPID); return ok })
	adopted, _ := find(watcher.EventAdopted, e.agentPID)
	if adopted.Run == "" || adopted.UID == nil || *adopted.UID != 0 || adopted.WindowMS == nil {
		t.Fatalf("adopted line %+v", adopted)
	}
	if got := cgroupOfPID(e.agentPID); !strings.HasSuffix(got, adopt.ScopeName(adopted.Run)) {
		t.Fatalf("the agent is in %s", got)
	}
	if s := e.send("exec"); s != 0 {
		t.Fatal("exec after the adoption failed")
	}

	// A second agent beside the first: the guard holds both adoptions.
	two := filepath.Join(e.dir, "two")
	if err := os.Mkdir(two, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(two, "claude"), []byte("#!/bin/sh\nwhile :; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	second := e.inTerm(exec.Command(filepath.Join(two, "claude")))
	second.Env = []string{"PATH=/usr/bin:/bin"}
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Process.Kill(); _ = second.Wait() })
	waitFor(t, func() bool { _, ok := find(watcher.EventAdopted, second.Process.Pid); return ok })
	adopted2, _ := find(watcher.EventAdopted, second.Process.Pid)
	out, err := e.tegoCmd("stop", adopted2.Run).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "released by its adopter (pid "+strconv.Itoa(guard.Process.Pid)+")") {
		t.Fatalf("tego stop %s of the guard's adoption: %v: %s", adopted2.Run, err, out)
	}
	waitFor(t, func() bool { _, ok := find(watcher.EventAdoptionEnded, second.Process.Pid); return ok })
	if ended2, _ := find(watcher.EventAdoptionEnded, second.Process.Pid); ended2.Reason != record.RunEndStopped {
		t.Errorf("adoption_ended %+v, want stopped", ended2)
	}
	if got := cgroupOfPID(second.Process.Pid); got != e.termRel {
		t.Errorf("the released agent is in %s, want the terminal's %s", got, e.termRel)
	}
	if syscall.Kill(second.Process.Pid, 0) != nil {
		t.Fatal("the release killed the agent")
	}
	if syscall.Kill(guard.Process.Pid, 0) != nil {
		t.Fatalf("tego stop of one adoption ended the guard: %s", errs.String())
	}
	if got := cgroupOfPID(e.agentPID); !strings.HasSuffix(got, adopt.ScopeName(adopted.Run)) {
		t.Fatalf("tego stop of one adoption released another: the first agent is in %s", got)
	}
	if end := lastRunEnd(t, e.lines(adopted2.Run)); end.Reason != record.RunEndStopped ||
		!strings.Contains(end.Detail, "at the request of tego stop") {
		t.Errorf("the released run's run_end %+v", end)
	}

	e.post("exit") // the agent ends with status 7, and its run with it
	waitFor(t, func() bool { _, ok := find(watcher.EventAdoptionEnded, e.agentPID); return ok })
	ended, _ := find(watcher.EventAdoptionEnded, e.agentPID)
	if ended.Reason != record.RunEndExit {
		t.Errorf("adoption_ended %+v", ended)
	}
	if end := lastRunEnd(t, e.lines(adopted.Run)); end.ExitCode != 7 {
		t.Errorf("run_end %+v: the agent's exit status, from the kernel's process events", end)
	}
	_ = guard.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- guard.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the guard: %v; stderr %s", err, errs.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the guard did not stop")
	}
	if !strings.Contains(errs.String(), "2 agent(s) adopted") {
		t.Errorf("summary: %s", errs.String())
	}
}

// TestIntegrationAdoptReleaseCommand: `tego adopt --release --pid <pid>` asks a live adopter to release its agent
// (a release request: the adopter is not signalled). With the adopter and its reaper both killed nothing records the
// agent, and the run reads lost, never ended, while the scope holds it: a root `tego gc` releases it from the
// adoption's root-only record and only then ends the run orphaned, never killing it; and, again, `tego adopt
// --release` releases such an orphan itself.
func TestIntegrationAdoptReleaseCommand(t *testing.T) {
	e := newAdoptEnv(t)
	e.startAgent(adoptAgentScript)
	a, run := e.adopt()
	out, err := e.tegoCmd("adopt", "--release", "--pid", strconv.Itoa(e.agentPID)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "released by its adopter") {
		t.Fatalf("tego adopt --release with a live adopter: %v: %s", err, out)
	}
	if code := a.wait(t); code != 0 {
		t.Fatalf("the adopter exit %d: %s", code, a.text())
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Fatalf("after the release the agent is in %s", got)
	}
	if end := lastRunEnd(t, e.lines(run)); end.Reason != record.RunEndStopped ||
		!strings.Contains(end.Detail, "at the request of tego adopt --release") {
		t.Errorf("run_end %+v", end)
	}

	// Again, and this time the reaper dies first, then the adopter: nothing releases the agent, and the run reads lost.
	orphan := func() string {
		t.Helper()
		a, run := e.adopt()
		reaper := findProcess(t, tegoruntime.AdoptReapCommand, run)
		if reaper == 0 {
			t.Fatalf("no reaper for run %s", run)
		}
		_ = syscall.Kill(reaper, syscall.SIGKILL)
		_ = a.cmd.Process.Signal(syscall.SIGKILL)
		_ = a.wait(t)
		time.Sleep(500 * time.Millisecond)
		if got := cgroupOfPID(e.agentPID); !strings.HasSuffix(got, adopt.ScopeName(run)) {
			t.Fatalf("with no adopter and no reaper the agent is in %s, still adopted", got)
		}
		if evs := e.lines(run); evs[len(evs)-1].Kind == record.KindRunEnd {
			t.Fatalf("run %s ended while its scope still holds the agent", run)
		}
		return run
	}
	run = orphan()
	// Root's sweep releases it from the record, then ends it: the run_end comes after the agent is out, and the agent
	// is never killed.
	out, err = e.tegoCmd("gc").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ended 1 orphaned") {
		t.Fatalf("tego gc of a lost adoption: %v: %s", err, out)
	}
	if syscall.Kill(e.agentPID, 0) != nil {
		t.Fatal("a sweep killed the adopted agent")
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Fatalf("after the sweep the agent is in %s, want released", got)
	}
	evs := e.lines(run)
	start, scopeID := runStartOf(t, evs)
	if left := e.leftovers(run, start.BPFHash, scopeID); len(left) != 0 {
		t.Errorf("left after the sweep's release: %v", left)
	}
	if end := lastRunEnd(t, evs); end.Reason != record.RunEndOrphaned {
		t.Errorf("run_end %+v", end)
	}

	// And `tego adopt --release` of such an orphan releases it itself.
	run = orphan()
	out, err = e.tegoCmd("adopt", "--release", "--pid", strconv.Itoa(e.agentPID)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "released here") {
		t.Fatalf("tego adopt --release of an orphan: %v: %s", err, out)
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Fatalf("after the orphan's release the agent is in %s", got)
	}
	evs = e.lines(run)
	start, scopeID = runStartOf(t, evs)
	if left := e.leftovers(run, start.BPFHash, scopeID); len(left) != 0 {
		t.Errorf("left after the orphan's release: %v", left)
	}
	if end := lastRunEnd(t, evs); end.Reason != record.RunEndOrphaned {
		t.Errorf("run_end %+v", end)
	}
	if s := e.send("open"); s != 0 {
		t.Error("the released agent no longer answers")
	}
}

// findProcess is the pid of the process whose argv holds every one of words, 0 when there is none.
func findProcess(t *testing.T, words ...string) int {
	t.Helper()
	ents, _ := os.ReadDir("/proc")
	for _, en := range ents {
		pid, err := strconv.Atoi(en.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		argv := strings.Split(string(b), "\x00")
		all := true
		for _, w := range words {
			found := false
			for _, a := range argv {
				if a == w {
					found = true
				}
			}
			all = all && found
		}
		if all {
			return pid
		}
	}
	return 0
}

// exitCode is a finished command's exit code: 0 for no error, -1 for one that did not run or exit.
func exitCode(err error) int {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	return -1
}

// NET09: the watcher gives a running agent the same topology floor as explicit
// adoption. Prove the command works before adoption and after release, and that
// the intervening refusal is the plane's capability decision in the ledger.
func TestIntegrationAdoptBoundaryRefusesThroughThePlaneWatcher(t *testing.T) {
	e := newAdoptEnv(t)
	// Give the agent CAP_SYS_ADMIN in its own user namespace, with an
	// unprivileged host owner whose passwd home is absent in the guest. This
	// exercises the namespace boundary without creating records in root's home.
	const uid = 65534
	for _, path := range []string{e.dir, e.cmds} {
		if err := os.Chown(path, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	e.startAgentWith(func(c *exec.Cmd) {
		c.SysProcAttr.Cloneflags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS
		c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}
		c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}
		c.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}
		c.Dir = "/"
	}, adoptAgentScript)
	if status := e.send("mountns"); status != 0 {
		t.Fatalf("unconfined mount-namespace control: exit %d", status)
	}
	contract := filepath.Join(filepath.Dir(e.dir), "boundary.yaml")
	y := fmt.Sprintf("version: 0\nname: topology\ncommand: [\"/bin/sh\"]\nrecord: full\nfs:\n  write: [%q]\n", e.dir)
	if err := os.WriteFile(contract, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := e.tegoCmd("agents", "--follow", "--adopt", "--uid", strconv.Itoa(uid), "--boundary", contract, "--json")
	var out, errs lockedBuffer
	guard.Stdout, guard.Stderr = &out, &errs
	if err := guard.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- guard.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = guard.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("guard stdout: %s; stderr: %s", out.String(), errs.String())
		}
	})
	var run string
	// A cold boundary adoption runs doctor's kernel probes before it can arm;
	// allow the same startup budget as adoptStart, including when run alone.
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for run == "" {
		for _, line := range strings.Split(out.String(), "\n") {
			var s watcher.Sighting
			if json.Unmarshal([]byte(line), &s) == nil && s.Event == watcher.EventAdopted && int(s.PID) == e.agentPID {
				run = s.Run
			}
		}
		if run != "" {
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("guard exited before adoption: %v", err)
		case <-deadline.C:
			t.Fatal("the guard did not adopt the agent")
		case <-tick.C:
		}
	}
	if status := e.send("mountns"); status != 1 {
		t.Errorf("adopted mount-namespace creation: exit %d, want unshare's EPERM exit 1", status)
	}
	_ = guard.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("guard: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the guard did not release the agent")
	}
	if status := e.send("mountns"); status != 0 {
		t.Errorf("released mount-namespace control: exit %d", status)
	}
	found := false
	for _, ev := range e.lines(run) {
		if ev.Kind == record.KindRefused {
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			found = found || p.Op == "capable" && p.Rule == "mount-topology" && p.Target == "capability 21" &&
				p.Mechanism == record.MechanismPlane && p.DecisionPlane != ""
		}
	}
	if !found {
		t.Error("the watcher boundary recorded no plane topology refusal")
	}
}
