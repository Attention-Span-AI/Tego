// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The pieces both runners share: materializing a fixture in a project directory, building the actor and the
// tego binary, and driving `tego compile --test`. Nothing here touches the invoking user's ~/.tego: the
// binary is built with tegotesthooks, and its chain anchor and own log are pointed into the test's directory.

// script is the list the actor reads.
type script struct {
	ID   string `json:"id"`
	Op   string `json:"op"`
	Path string `json:"path,omitempty"`
	Dest string `json:"dest,omitempty"`
	Addr string `json:"addr,omitempty"`
	// Target is a process op's peer (Cell.Target), TargetHost filled in with the host process's pid.
	Target string `json:"target,omitempty"`
	// Argv is an exec's whole vector (Cell.Argv); empty for the actor's own [path, "noop"].
	Argv []string `json:"argv,omitempty"`
}

// env is one fixture materialized: where it lives and what its templates were filled with.
type env struct {
	base, project string
	ports         [2]int
	// hostPID is the process of the agent's uid outside every run that a cell's TargetHost names (startHost); 0
	// where no cell names it.
	hostPID int
	// hostSock and hostAbstract are the host daemon sockets a cell's HostSocket and HostAbstract name (hostSockets),
	// "" where no cell names them.
	hostSock, hostAbstract string
	// controls are the fixture's controls that passed (env.passed), which runFixture holds to controlsAsked.
	controls map[string]bool
}

func (e *env) subst(s string) string {
	s = strings.ReplaceAll(s, "{{P}}", e.project)
	s = strings.ReplaceAll(s, "{{PORT}}", fmt.Sprint(e.ports[0]))
	s = strings.ReplaceAll(s, "{{PORT2}}", fmt.Sprint(e.ports[1]))
	s = strings.ReplaceAll(s, TargetHost, fmt.Sprint(e.hostPID))
	s = strings.ReplaceAll(s, HostSocket, e.hostSock)
	s = strings.ReplaceAll(s, HostAbstract, e.hostAbstract)
	if strings.Contains(s, "{{LOADER}}") {
		loader, err := Loader()
		if err != nil {
			panic(err) // materialize checked it
		}
		s = strings.ReplaceAll(s, "{{LOADER}}", loader)
	}
	return s
}

// path is where a cell's path lies: relative to the project, or the machine's own path ({{LOADER}}).
func (e *env) path(rel string) string {
	if rel = e.subst(rel); filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(e.project, rel)
}

// listen starts a loopback listener that accepts and closes; a connect that succeeds is a connect the run let
// through.
func listen(t *testing.T) (port int, closeFn func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { _ = l.Close() }
}

// hostSockets binds a pathname unix listener in base, beside the project and outside every write entry, and an abstract
// one, as a host daemon's sockets (ADR 0070), each accepting and closing; it returns their names as a connect-unix
// cell's addr spells them. The pathname socket is world-connectable, so an agent of another uid reaches it where the
// run lets it through.
func hostSockets(t *testing.T, base string) (path, abstract string) {
	t.Helper()
	path = filepath.Join(base, "host.sock")
	abstract = "@tego-conformance-host-" + strconv.Itoa(os.Getpid()) + "-" + filepath.Base(base)
	for _, name := range []string{path, abstract} {
		l, err := net.Listen("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	return path, abstract
}

// materialize lays a fixture out under a fresh directory in dir: project/ with the fixture's files, a copy of
// the actor as bin/actor, the contract, and the script of every cell.
func materialize(t *testing.T, dir string, fx *Fixture, actor string) *env {
	t.Helper()
	base, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The machine config's directory must not be group or other writable, and the agent (another uid in a
	// root run) must reach the project through it.
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	e := &env{base: base, project: filepath.Join(base, "project")}
	if fx.Net {
		for i := range e.ports {
			p, c := listen(t)
			e.ports[i] = p
			t.Cleanup(c)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(fx.Contract, "{{LOADER}}") || slices.ContainsFunc(fx.Cells, func(c Cell) bool { return strings.Contains(c.Path, "{{LOADER}}") }) {
		_, err := Loader()
		must(err)
	}
	data, err := os.ReadFile(actor)
	must(err)
	must(Layout(e.project, fx, data, e.subst))
	if slices.ContainsFunc(fx.Cells, func(c Cell) bool { return c.Target == TargetHost }) {
		e.hostPID = startHost(t, e.path("bin/actor"))
	}
	if slices.ContainsFunc(fx.Cells, func(c Cell) bool { return c.Addr == HostSocket || c.Addr == HostAbstract }) {
		e.hostSock, e.hostAbstract = hostSockets(t, base)
	}
	must(os.WriteFile(e.path("agent.yaml"), []byte(e.subst(fx.Contract)), 0o644))
	var list []script
	if len(fx.Later) > 0 { // the runner writes the later files once the actor waits (runAwaiting)
		list = append(list, script{Op: OpAwaitLater, Path: e.path(AwaitGo)})
	}
	for i := range fx.Cells {
		c := &fx.Cells[i]
		argv := make([]string, len(c.Argv))
		for i, a := range c.Argv {
			argv[i] = e.subst(a)
		}
		list = append(list, script{ID: fx.ID(c), Op: c.Op, Path: e.subst(c.Path), Dest: e.subst(c.Dest), Addr: e.subst(c.Addr),
			Target: e.subst(c.Target), Argv: argv})
	}
	data, err = json.Marshal(list)
	must(err)
	must(os.WriteFile(e.path("script.json"), data, 0o644))
	return e
}

// awaitWriter keeps a run's stdout and closes ready once it holds the actor's AwaitReady line (the await handshake).
type awaitWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	seen  bool
}

func newAwaitWriter() *awaitWriter { return &awaitWriter{ready: make(chan struct{})} }

func (w *awaitWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if !w.seen && bytes.Contains(w.buf.Bytes(), []byte(AwaitReady+"\n")) {
		w.seen = true
		close(w.ready)
	}
	return n, err
}

func (w *awaitWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// runAwaiting runs cmd, its stdout out. With later set (a fixture's later files) it calls later once the actor has
// printed AwaitReady, so later runs after the run's compile and fill and before the first cell; a run that ends before
// the line comes is returned as it ended, later not called, and its cells have no results.
func runAwaiting(cmd *exec.Cmd, out *awaitWriter, later func()) error {
	if later == nil {
		return cmd.Run()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-out.ready:
	}
	later()
	return <-done
}

// sudoIDs are the sudo caller's uid and gid, the agent a root run drops to.
func sudoIDs() (uid, gid int, ok bool) {
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || u <= 0 {
		return 0, 0, false
	}
	return u, g, true
}

// asAgent runs cmd as the agent: the sudo caller under root (the uid a root run drops the agent to), this process's
// own uid otherwise. Its callers give the actor an empty environment: it reads no variable.
func asAgent(cmd *exec.Cmd) {
	if uid, gid, ok := sudoIDs(); ok && os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
}

// startHost starts a process outside every run with the agent's uid, which a ptrace cell's TargetHost names: the
// actor's host stage, which lets its uid trace it (PR_SET_PTRACER_ANY) before it says "ready", so Yama's ptrace_scope
// 1 does not refuse an attach to it and only the run can (the kernel runner's hostControl proves it). It sleeps
// until the test ends.
func startHost(t *testing.T, actor string) int {
	t.Helper()
	cmd := exec.Command(actor, "host")
	cmd.Env = []string{}
	asAgent(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("the host process a ptrace cell names: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("the host process a ptrace cell names said %q, not ready", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host process a ptrace cell names was not ready in 10 s")
	}
	return cmd.Process.Pid
}

// outsideRun performs one action with the fixture's actor as the agent, outside every run: the control that shows an
// answer a cell wants of the run is not the machine's own (hostControl).
func outsideRun(t *testing.T, e *env, a script) (Outcome, error) {
	t.Helper()
	data, err := json.Marshal([]script{a})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.base, "outside-"+a.ID+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(e.path("bin/actor"), "run", path)
	cmd.Env = []string{} // the actor reads no variable; an empty Env also keeps isocheck's GO-5 satisfied
	asAgent(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return Outcome{}, fmt.Errorf("actor: %v: %s", err, stderr.String())
	}
	var r struct {
		ID    string `json:"id"`
		OK    bool   `json:"ok"`
		Errno int    `json:"errno"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &r); err != nil || r.ID != a.ID {
		return Outcome{}, fmt.Errorf("actor said %q: %v", stdout.String(), err)
	}
	return Outcome{OK: r.OK, Errno: r.Errno, Value: r.Value}, nil
}

// unprivBPF is the sysctl that refuses an unprivileged BPF_MAP_CREATE: 0 lets it through, 2 (the distributions'
// default) refuses it until an administrator lowers it, 1 refuses it until reboot.
const unprivBPF = "/proc/sys/kernel/unprivileged_bpf_disabled"

// disposableHost names the throwaway machine this process runs on, or is "" on any other (runtime's helper of the
// name, ADR 0042's 2026-10-06 note): test/vm/root-suites.sh sets TEGO_DISPOSABLE_HOST in its KVM guests and, under
// VM_HOST=sudo, on a GitHub Actions runner or where its caller set it; GitHub Actions sets GITHUB_ACTIONS=true.
func disposableHost() string {
	if v := os.Getenv("TEGO_DISPOSABLE_HOST"); v != "" {
		return v
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return "github-actions"
	}
	return ""
}

// The controls a fixture's cells need before its run (runFixture checks each ran, missingControls).
const (
	controlHost  = "host"  // a cell names TargetHost: hostControl
	controlBPF   = "bpf"   // a bpf(2) cell under root: bpfControl
	controlMemfd = "memfd" // an anonymous-image cell: memfdControl
)

// controlsAsked names the controls fx's cells need, root saying whether the runner is root (without root no axis
// asks a bpf cell, and bpfControl has nothing to lower).
func controlsAsked(fx *Fixture, root bool) []string {
	var out []string
	if slices.ContainsFunc(fx.Cells, func(c Cell) bool { return c.Target == TargetHost }) {
		out = append(out, controlHost)
	}
	if root && slices.ContainsFunc(fx.Cells, func(c Cell) bool { return c.Op == OpBPF }) {
		out = append(out, controlBPF)
	}
	if slices.ContainsFunc(fx.Cells, func(c Cell) bool {
		return c.Op == OpMemfdCreate || c.Op == OpMemfdExec || c.Op == OpMemfdMapExec
	}) {
		out = append(out, controlMemfd)
	}
	return out
}

// missingControls is what controlsAsked names for fx and no control marked passed in e: a fixture whose control
// did not run could pass in vain on a machine that refuses its cells' action itself (deleting a control's call left
// every test green).
func missingControls(e *env, fx *Fixture, root bool) []string {
	var out []string
	for _, c := range controlsAsked(fx, root) {
		if !e.controls[c] {
			out = append(out, c)
		}
	}
	return out
}

// passed marks one of the fixture's controls passed.
func (e *env) passed(control string) {
	if e.controls == nil {
		e.controls = map[string]bool{}
	}
	e.controls[control] = true
}

// bpfHolds counts, by sysctl path, the fixtures running with it lowered: the first lowers it and the last puts it
// back, so a fixture running beside another never has it raised again under its run.
var bpfHolds = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// bpfControl is a bpf(2) cell's control. kernel.unprivileged_bpf_disabled refuses an unprivileged BPF_MAP_CREATE with
// EPERM and no line ahead of every hook (and, before 6.5, every bpf(2) command), which is the cell's own want at tiers 2
// and 3 (ADR 0033's filter arm), so a cell asked on a machine that sets it could not fail. Under root the runner lowers
// 2 to 0 for the fixture's run and puts 2 back when the fixture ends; then the agent's uid, outside every run, must
// create the map, or the fixture fails (1 cannot be lowered until reboot). Without root no axis asks a bpf cell.
//
// The sysctl is host-wide, and the fixture's cleanup is what puts it back: a run that times out or is killed never
// reaches it and leaves unprivileged bpf(2) open on the machine until reboot. So it is lowered only on a disposable
// host (disposableHost: a KVM guest, a GitHub Actions runner); on any other machine a 2 fails the fixture, naming
// TEGO_DISPOSABLE_HOST, so a developer's VM_HOST=sudo run never changes the host and is not mistaken for a full one
// (ADR 0042's rule for host state a test cannot isolate).
func bpfControl(t *testing.T, e *env, fx *Fixture) {
	t.Helper()
	if os.Geteuid() != 0 || !slices.Contains(controlsAsked(fx, true), controlBPF) {
		return
	}
	restore, err := bpfCheck(unprivBPF, disposableHost(), func() (Outcome, error) {
		return outsideRun(t, e, script{ID: "bpf-control", Op: OpBPF})
	})
	if restore != nil {
		t.Cleanup(func() {
			if err := restore(); err != nil {
				t.Errorf("the bpf control: %s left at 0: %v", unprivBPF, err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	e.passed(controlBPF)
}

// bpfCheck is bpfControl on the sysctl at path: it lowers a 2 to 0 where disposable names a throwaway machine and
// refuses to elsewhere, then runs the control map create (outside) and fails unless it succeeded. restore is non-nil
// when this call holds the lowering, and puts 2 back once no other holder remains.
func bpfCheck(path, disposable string, outside func() (Outcome, error)) (restore func() error, err error) {
	bpfHolds.Lock()
	b, err := os.ReadFile(path)
	if err != nil {
		bpfHolds.Unlock()
		return nil, fmt.Errorf("the bpf control: %v", err)
	}
	was := strings.TrimSpace(string(b))
	release := func() error {
		bpfHolds.Lock()
		defer bpfHolds.Unlock()
		if bpfHolds.n[path]--; bpfHolds.n[path] > 0 {
			return nil
		}
		delete(bpfHolds.n, path)
		return os.WriteFile(path, []byte("2"), 0o644)
	}
	switch {
	case bpfHolds.n[path] > 0: // lowered by a fixture running beside this one
		bpfHolds.n[path]++
		restore = release
	case was == "2" && disposable == "":
		bpfHolds.Unlock()
		return nil, fmt.Errorf("the bpf control: %s is 2, and this is no disposable host (TEGO_DISPOSABLE_HOST unset, not "+
			"a GitHub Actions runner): lowering that host-wide sysctl for the fixture would leave unprivileged bpf(2) open "+
			"if the run were killed, and leaving it would make a bpf cell's refusal the machine's, so the fixture fails "+
			"(run it in a KVM guest, or set TEGO_DISPOSABLE_HOST on a throwaway machine)", path)
	case was == "2":
		if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
			bpfHolds.Unlock()
			return nil, fmt.Errorf("the bpf control: lowering %s from 2: %v", path, err)
		}
		bpfHolds.n[path] = 1
		restore = release
	}
	bpfHolds.Unlock()
	o, err := outside()
	if err != nil {
		return restore, fmt.Errorf("the bpf control: %v", err)
	}
	if !o.OK {
		return restore, fmt.Errorf("the bpf control: the agent's uid, outside every run, cannot create a BPF map (errno %d, "+
			"%s %s): a bpf cell's refusal would be the kernel's, not the run's", o.Errno, path, was)
	}
	return restore, nil
}

// memfdControl is the anonymous-image cells' control. vm.memfd_noexec 1 seals every memfd created without MFD_EXEC
// against exec, and 2 refuses its creation, each with EACCES and no line: the memfd cells' own want where the run's
// filter refuses them (enforce-landlock R11a), so a cell asked on such a machine could not fail. Each memfd op the
// fixture asks is performed first as the agent outside every run, and must succeed, or the fixture fails.
func memfdControl(t *testing.T, e *env, fx *Fixture) {
	t.Helper()
	asked := map[string]bool{}
	for _, c := range fx.Cells {
		if (c.Op == OpMemfdCreate || c.Op == OpMemfdExec || c.Op == OpMemfdMapExec) && !asked[c.Op] {
			asked[c.Op] = true
			o, err := outsideRun(t, e, script{ID: "memfd-control-" + c.Op, Op: c.Op})
			if err != nil {
				t.Fatalf("the memfd control %s: %v", c.Op, err)
			}
			if !o.OK {
				t.Fatalf("the memfd control: the agent's uid, outside every run, cannot %s (errno %d): the machine refuses it "+
					"(vm.memfd_noexec above 0?), so a memfd cell's refusal would not be the run's", c.Op, o.Errno)
			}
		}
	}
	if len(asked) > 0 {
		e.passed(controlMemfd)
	}
}

// hostControl is a ptrace cell's control: the agent's uid, outside every run, attaches to the host process. A
// refusal there is the machine's (Yama's ptrace_scope 2 or 3, which no opt-out lifts), and a cell's refusal of the
// same attach from the run could not be told from it, so the fixture fails rather than pass in vain.
func hostControl(t *testing.T, e *env) {
	t.Helper()
	if e.hostPID == 0 {
		return
	}
	if err := hostCheck(t, e); err != nil {
		t.Fatal(err)
	}
	e.passed(controlHost)
}

// hostCheck is hostControl's attach, failing unless it succeeded.
func hostCheck(t *testing.T, e *env) error {
	t.Helper()
	o, err := outsideRun(t, e, script{ID: "host-control", Op: OpPtraceAttach, Target: strconv.Itoa(e.hostPID)})
	if err != nil {
		return fmt.Errorf("the host control: %v", err)
	}
	if !o.OK {
		return fmt.Errorf("the host control: the agent's uid, outside every run, cannot attach to the host process %d (errno %d): the "+
			"machine refuses it (kernel.yama.ptrace_scope above 1?), so a ptrace cell's refusal would not be the run's", e.hostPID, o.Errno)
	}
	return nil
}

// machineConfig writes a machine config whose ledger root and chain anchor lie under base, and returns the
// environment a tego binary built with tegotesthooks needs to touch nothing else.
func machineConfig(t *testing.T, e *env) []string {
	t.Helper()
	state := filepath.Join(e.base, "state")
	ledger := filepath.Join(state, "ledger")
	if err := os.MkdirAll(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(state, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(state, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: [\"127.0.0.2\"]\n", ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	return append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(state, "chain.log"),
		"TEGO_TEST_OWN_LOG_HOME="+home)
}

var (
	actorOnce sync.Once
	actorPath string
	actorErr  error
)

// buildActor builds the static actor once per test run (in the KVM guest test/vm/go-shim.sh serves the copy
// root-suites.sh built on the host).
func buildActor(t *testing.T) string {
	t.Helper()
	actorOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-actor-")
		if err != nil {
			actorErr = err
			return
		}
		actorPath = filepath.Join(dir, "actor")
		cmd := exec.Command("go", "build", "-o", actorPath, "github.com/attention-span-ai/tego/test/conformance/cmd/actor")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			actorErr = fmt.Errorf("go build actor: %v: %s", err, out)
		}
	})
	if actorErr != nil {
		t.Fatal(actorErr)
	}
	return actorPath
}

// buildTego builds cmd/tego with the given tags, always with tegotesthooks so it never reads or writes the
// invoking user's own ~/.tego.
func buildTego(dir string, tags ...string) (string, error) {
	out := filepath.Join(dir, "tego-"+strings.Join(tags, "-"))
	all := strings.Join(append([]string{"tegotesthooks"}, tags...), ",")
	cmd := exec.Command("go", "build", "-tags", all, "-trimpath", "-o", out, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build tego -tags %s: %v: %s", all, err, b)
	}
	return out, nil
}

// compileAction is a cell's row in a compile --test table; ok is false for an op compile --test has no action
// for.
func compileAction(c *Cell) (string, bool) {
	switch c.Op {
	case OpRead:
		return "fs.read", true
	case OpWriteOpen, OpCreate, OpCreat, OpOpenTrunc, OpTruncate, OpSymlink, OpMknod:
		return "fs.write", true
	case OpUnlink, OpRmdir:
		return "fs.delete", true
	case OpMkdir:
		return "fs.mkdir", true
	case OpRename:
		return "fs.rename", true
	case OpExec, OpExecLoader, OpExecveatFD, OpExecProcFD:
		return "exec", true
	case OpMapExec, OpMapExecRIE, OpMprotectExec, OpMprotectRIE:
		return "exec.map", true
	case OpConnectTCP, OpConnectUDP, OpSendUDP, OpConnectUnix: // a datagram's destination is decided as a connect to it is
		return "net.connect", true
	case OpLink:
		return "fs.link", true
	case OpChmod, OpChown, OpSetxattr, OpSetfacl: // fs.attr is a mode, an owner or an extended attribute, an ACL included
		return "fs.attr", true
	}
	return "", false
}

// noCompileAction is every op compile --test has no row for, with the reason. A cell that takes one carries a
// NoCompile marker; ADR 0017's 2026-10-16 note names each.
var noCompileAction = map[string]string{
	OpExchange: "a rename row has no RENAME_EXCHANGE",
	// A memfd has no path a row can name; execmod and execmem are decided on the mapping (its copied pages, its prot
	// and privacy), which no row names (ADR 0017 space 2).
	OpMemfdCreate: "a memfd has no path a compile --test row can name", OpMemfdExec: "a memfd has no path a compile --test row can name",
	OpMemfdMapExec: "a memfd has no path a compile --test row can name",
	OpExecmod:      "execmod is decided on the mapping's copied pages, which no compile --test row names",
	OpExecmem:      "execmem is decided on the mapping's prot and privacy, which no compile --test row names",
	// A race is one action of thousands, against a tree the actor changes while it acts (ADR 0017 space 4).
	OpRaceSymlinkRead:  "a race: thousands of opens through a link the actor swaps, against no fixed tree",
	OpRaceSymlinkWrite: "a race: thousands of opens through a link the actor swaps, against no fixed tree",
	OpRaceArgvExec:     "a race: the agent rewrites its argv while the supervisor reads it",
	// The process and control calls (ADR 0017's control fixtures, FEATURES E54): no compile --test action names one.
	OpPtraceAttach: "compile --test has no process-control action", OpPtraceTraceme: "compile --test has no process-control action",
	OpKeyctl: "compile --test has no keyring action", OpAddKey: "compile --test has no keyring action",
	OpRequestKey: "compile --test has no keyring action", OpBPF: "compile --test has no bpf(2) action",
}

// TestEveryCellHasACompileAction is plans/adr0017 C9 (ADR 0019: compile --test answers every action a run can take):
// every op a cell performs maps onto a compile --test action, so the compile runner asks it unless the cell names why
// the answer cannot be compared (NoCompile). Hard links and chmod had no action, and their cells were skipped. The
// ops in noCompileAction are the stated exceptions: their cells must say so, and an op that gains a row leaves the
// list.
func TestEveryCellHasACompileAction(t *testing.T) {
	for op := range noCompileAction {
		if _, ok := compileAction(&Cell{Op: op}); ok {
			t.Errorf("op %q has a compile --test action and is still listed in noCompileAction", op)
		}
	}
	for _, fx := range Fixtures() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			if _, ok := compileAction(c); !ok {
				if why, listed := noCompileAction[c.Op]; !listed {
					t.Errorf("%s: op %q has no compile --test action", fx.ID(c), c.Op)
				} else if c.NoCompile == "" {
					t.Errorf("%s: op %q has no compile --test action (%s) and the cell has no NoCompile marker", fx.ID(c), c.Op, why)
				}
			}
		}
	}
}

// hasCompileRow reports whether some cell of fx is a compile --test row.
func hasCompileRow(fx *Fixture) bool {
	for i := range fx.Cells {
		if _, ok := compileAction(&fx.Cells[i]); ok && fx.Cells[i].NoCompile == "" {
			return true
		}
	}
	return false
}

func q(s string) string { b, _ := json.Marshal(s); return string(b) }

// rowName names a cell's row in one tier.
func rowName(id string, t Tier) string { return id + "@" + string(t) }

// compileTable renders a fixture's cells as a compile --test table, one row per cell and tier.
func compileTable(e *env, fx *Fixture) string { return tableOf(e, fx, "") }

// columnTable is compileTable for one tier: the rows the kernel runner reads that tier's column from.
func columnTable(e *env, fx *Fixture, only Tier) string { return tableOf(e, fx, only) }

func tableOf(e *env, fx *Fixture, only Tier) string {
	var b bytes.Buffer
	b.WriteString("version: 0\ntests:\n")
	for i := range fx.Cells {
		c := &fx.Cells[i]
		action, ok := compileAction(c)
		if !ok || c.NoCompile != "" {
			continue
		}
		for _, t := range c.Tiers() {
			if only != "" && t != only {
				continue
			}
			w := wantOf(c, t)
			fmt.Fprintf(&b, "  - name: %s\n    action: %s\n", q(rowName(fx.ID(c), t)), action)
			switch c.Op {
			case OpConnectTCP, OpConnectUDP, OpSendUDP:
				fmt.Fprintf(&b, "    host_port: %s\n", q(e.subst(c.Addr)))
				if c.Op != OpConnectTCP {
					b.WriteString("    proto: udp\n")
				}
			case OpConnectUnix:
				fmt.Fprintf(&b, "    path: %s\n", q("unix:"+e.subst(c.Addr)))
			case OpExec, OpExecLoader, OpExecveatFD, OpExecProcFD:
				fmt.Fprintf(&b, "    path: %s\n", q(e.subst(c.Path)))
				if c.Script != "" {
					fmt.Fprintf(&b, "    script: %s\n", q(e.subst(c.Script)))
				}
				if c.ScriptArg != "" {
					fmt.Fprintf(&b, "    script_arg: %s\n", q(c.ScriptArg))
				}
				if len(c.Argv) > 0 {
					argv := make([]string, len(c.Argv))
					for i, a := range c.Argv {
						argv[i] = q(a)
					}
					fmt.Fprintf(&b, "    argv: [%s]\n", strings.Join(argv, ", "))
				}
			default:
				fmt.Fprintf(&b, "    path: %s\n", q(c.Path))
				if c.Op == OpRename || c.Op == OpLink {
					fmt.Fprintf(&b, "    dest: %s\n", q(c.Dest))
				}
			}
			if c.Generated {
				w = Want{Verdict: Allow} // a placeholder: a generated cell's answer is read, never held to a want
			}
			fmt.Fprintf(&b, "    tier: %s\n    expect: %s\n", t, w.Verdict)
			if w.Rule != "" {
				fmt.Fprintf(&b, "    rule: %s\n", q(e.subst(w.Rule)))
			}
		}
	}
	return b.String()
}

// wantOf is the cell's expectation at a tier, whichever mode it came from (compile --test has no mode column
// yet, ADR 0019's condition: each mode becomes a column once modes differ).
func wantOf(c *Cell, t Tier) Want {
	for _, m := range []Mode{ModeNone, ModeFanotify, ModeLSM, ModeFmodRet} {
		if w, ok := c.Want[Key{t, m}]; ok {
			return w
		}
	}
	return Want{}
}

type compileCell struct {
	Tier    string `json:"tier"`
	Verdict string `json:"verdict"`
	Rule    string `json:"rule"`
}

type compileRow struct {
	Name    string        `json:"name"`
	Columns []compileCell `json:"columns"`
}

// compileAnswers runs `tego compile agent.yaml --test <table> --json` in the project and returns each row's
// answer by row name.
func compileAnswers(t *testing.T, bin string, e *env, environ []string, table string) map[string]compileCell {
	t.Helper()
	tablePath := filepath.Join(e.base, "verdicts.yaml")
	if err := os.WriteFile(tablePath, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "compile", "agent.yaml", "--test", tablePath, "--json", "--offline")
	cmd.Dir, cmd.Env = e.project, environ
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // a failing row exits 1; the JSON is still complete
	out, err := answersOf(table, stdout.Bytes())
	if err != nil {
		t.Fatalf("compile --test --json: %v\nstdout:\n%s\nstderr:\n%s\ntable:\n%s", err, stdout.String(), stderr.String(), table)
	}
	return out
}

// answersOf reads compile --test --json's report of table: each row's one column, by row name. Every reader of
// compile --test goes through it, so a report that leaves a row of the table unanswered, answers one with
// anything but allow or refused, or answers a row the table never asked is an error: no compile check of a cell
// (the compile runner's, the over-grant feed's, the kernel runner's column) is skipped for want of an answer.
func answersOf(table string, report []byte) (map[string]compileCell, error) {
	var asked struct {
		Tests []struct {
			Name string `yaml:"name"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal([]byte(table), &asked); err != nil {
		return nil, fmt.Errorf("the table: %w", err)
	}
	var rep struct {
		V    int          `json:"v"`
		Rows []compileRow `json:"rows"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		return nil, err
	}
	if rep.V != 1 {
		return nil, fmt.Errorf("report version %d, want 1", rep.V)
	}
	out := map[string]compileCell{}
	for _, r := range rep.Rows {
		if len(r.Columns) != 1 {
			return nil, fmt.Errorf("row %q has %d columns, want the one its tier: names", r.Name, len(r.Columns))
		}
		if _, dup := out[r.Name]; dup {
			return nil, fmt.Errorf("row %q is answered twice", r.Name)
		}
		if v := r.Columns[0].Verdict; v != Allow && v != Refused {
			return nil, fmt.Errorf("row %q is answered %q, neither %s nor %s", r.Name, v, Allow, Refused)
		}
		out[r.Name] = r.Columns[0]
	}
	for _, a := range asked.Tests {
		if _, ok := out[a.Name]; !ok {
			return nil, fmt.Errorf("row %q of the table has no answer", a.Name)
		}
	}
	if len(out) != len(asked.Tests) {
		return nil, fmt.Errorf("%d rows answered, the table asks %d", len(out), len(asked.Tests))
	}
	return out, nil
}

// compileJSON is `tego compile agent.yaml --json --offline` in the project: the compiled table, with its per-entry
// markers (capability.go). A contract compile refuses has no table, and fails the test.
// compileReach is the reach compile --json reports (agent.RuleTable.Reach), as a set.
func compileReach(t *testing.T, table []byte) map[Tier]bool {
	t.Helper()
	var tbl struct {
		Reach []string `json:"reach"`
	}
	if err := json.Unmarshal(table, &tbl); err != nil {
		t.Fatalf("compile --json: %v", err)
	}
	reach := map[Tier]bool{}
	for _, r := range tbl.Reach {
		reach[Tier(r)] = true
	}
	return reach
}

func compileJSON(t *testing.T, bin string, e *env, environ []string) []byte {
	t.Helper()
	cmd := exec.Command(bin, "compile", "agent.yaml", "--json", "--offline")
	cmd.Dir, cmd.Env = e.project, environ
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compile --json: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

// projectRel maps an absolute path to the model's spelling: relative to the project, with every symlink followed
// (the model names what an entry governs), "" for a path outside the project.
func projectRel(project string) func(string) string {
	root, err := filepath.EvalSymlinks(project)
	if err != nil {
		root = project
	}
	return func(abs string) string {
		p, err := filepath.EvalSymlinks(abs)
		if err != nil {
			p = filepath.Clean(abs)
		}
		r, err := filepath.Rel(root, p)
		if err != nil || r == ".." || strings.HasPrefix(r, "../") {
			return ""
		}
		return r
	}
}

// selectedFixtures is the fixtures of the spaces SpacesEnv selects, and whether those are every space.
func selectedFixtures(t testing.TB) ([]Fixture, bool) {
	t.Helper()
	spaces, every, err := SelectedSpaces()
	if err != nil {
		t.Fatal(err)
	}
	var out []Fixture
	for _, sp := range spaces {
		out = append(out, sp.Fixtures()...)
	}
	return out, every
}

// generated reports whether fx is a generated fixture (gen.go), whose cells have no want.
func generated(fx *Fixture) bool { return len(fx.Cells) > 0 && fx.Cells[0].Generated }

// generatedColumns asks compile --test once for every generated fixture's columns, on a tree of its own laid out as
// a run's is: the kernel runner reads each axis' column from it, before any run and outside every axis' budget.
func generatedColumns(t *testing.T, bin, actor string, fixtures []Fixture) map[string]map[string]compileCell {
	t.Helper()
	out := map[string]map[string]compileCell{}
	for i := range fixtures {
		fx := &fixtures[i]
		if !generated(fx) {
			continue
		}
		e := materialize(t, t.TempDir(), fx, actor)
		out[fx.Name] = compileAnswers(t, bin, e, machineConfig(t, e), compileTable(e, fx))
	}
	return out
}

// compileOverGrants feeds each allow compile --test answers for a generated cell to the invariants as if the kernel
// had allowed it (plan C5): a violation is the decide core granting what the contract refuses, a fail-open no
// baseline can hold, found without root.
func compileOverGrants(fx *Fixture, got map[string]compileCell) []string {
	var out []string
	for i := range fx.Cells {
		c := &fx.Cells[i]
		for _, tier := range c.Tiers() {
			// answersOf: every row is answered, allow or refused; only an allow can over-grant.
			a := got[rowName(fx.ID(c), tier)]
			if a.Verdict != Allow {
				continue
			}
			if v := Invariant(fx.Model, c, tier, Outcome{OK: true}); v != "" {
				out = append(out, fmt.Sprintf("%s at %s: compile --test allows via %q, but %s", fx.ID(c), tier, a.Rule, v))
			}
		}
	}
	return out
}

// compileFailures asks compile --test about every compile-able cell of every tier and returns the ones whose
// answer is not the cell's, keyed for the baseline. A generated cell has no answer of its own to be held to: its
// compile answers are held to the invariants instead (compileOverGrants), whose violations are returned apart.
//
// reach is the tiers compile's table can land at for this process (compile --json's reach). A table compiles its
// name entries only where it may land at tier cgroup or bpflsm (ADR 0043 Consequence 11), and an auto contract
// compiled by a process that is not root lands at tier landlock alone (doctor.AutoTiers), so compile --test answers
// such a process's root columns as if no name entry existed. A cell a name entry decides (its want names a name
// entry's rule, `/**/`) is compared there only at the tiers in reach; the kernel runner, which compiles as root,
// compares its root columns.
func compileFailures(t *testing.T, bin string, e *env, environ []string, fx *Fixture, reach map[Tier]bool) (fails map[string]string, overGrants []string) {
	t.Helper()
	got := compileAnswers(t, bin, e, environ, compileTable(e, fx))
	fails = map[string]string{}
	if generated(fx) {
		return fails, compileOverGrants(fx, got)
	}
	for i := range fx.Cells {
		c := &fx.Cells[i]
		if _, ok := compileAction(c); !ok || c.NoCompile != "" {
			continue
		}
		for _, tier := range c.Tiers() {
			w := wantOf(c, tier)
			if len(fx.Model.Names) > 0 && !reach[tier] && strings.Contains(w.Rule, "/**/") {
				continue
			}
			a := got[rowName(fx.ID(c), tier)] // answersOf: every row the table asks is answered
			rule := e.subst(w.Rule)
			if a.Verdict != w.Verdict || (rule != "" && a.Rule != rule) {
				fails[FailureKey(RunnerCompile, fx.ID(c), tier)] = fmt.Sprintf("compile --test says %s via %q, the cell wants %s via %q",
					a.Verdict, a.Rule, w.Verdict, rule)
			}
		}
	}
	return fails, nil
}

func TestAxisRequired(t *testing.T) {
	for _, c := range []struct {
		list, axis string
		want       bool
	}{
		{"", "cgroup", false},
		{"cgroup,fmod_ret", "cgroup", true},
		{"cgroup, fmod_ret", "fmod_ret", true},
		{"cgroup,fmod_ret", "lsm", false},
		{"cgroups", "cgroup", false},
	} {
		if got := AxisRequired(c.list, c.axis); got != c.want {
			t.Errorf("AxisRequired(%q, %q) = %v, want %v", c.list, c.axis, got, c.want)
		}
	}
}
