// SPDX-License-Identifier: Apache-2.0

//go:build integration

// The tests here start real agents under a real Landlock ruleset and a real seccomp listener, in
// the run's own cgroup. Everything they use is unprivileged on a 6.x kernel with a delegated cgroup
// v2 subtree, so they run as the invoking user (uid 1000 on the development box); a machine without
// Landlock or without delegation skips them with the reason, never a false pass.
package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// tegoBinary builds cmd/tego once per test run: the launcher execs it as the child stage, and the
// CLI tests drive it as a subprocess. `go test` runs a test binary that has no __child dispatch of
// its own, so the launcher is pointed at this one instead of /proc/self/exe.
func tegoBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-bin-")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "tego")
		// tegotesthooks lets writeMachineConfig point the binary's chain anchor and its own log into the
		// fixture (internal/cli/anchor_testhook.go, ownlog_testhook.go): the product anchors and logs in
		// the invoking user's own ~/.tego, which a test must neither write nor depend on being writable.
		cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", binPath, "github.com/attention-span-ai/tego/cmd/tego")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("go build: %v: %s", err, out)
		}
	})
	if binErr != nil {
		t.Skipf("cannot build the tego binary: %v", binErr)
	}
	return binPath
}

// testProfiles resolves no profile: the test contracts never use extends.
type testProfiles struct{}

// Resolve always misses.
func (testProfiles) Resolve(name string) (string, []byte, error) {
	return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
}

// fixture is one prepared run environment: a project directory with a contract, a ledger root
// outside it, and the compiled table plus the machine config a run needs.
type fixture struct {
	dir     string
	out     string
	root    string
	machine *config.Machine
	rt      *agent.RuleTable
	yaml    []byte
	backend enforce.Backend
	// logHome is the home the tego binary keeps its own log under (<logHome>/.tego/tego.log), set by
	// writeMachineConfig.
	logHome string
}

// newFixture writes contract into a project directory and compiles it for this machine.
func newFixture(t *testing.T, contract string) *fixture {
	return newFixtureWithMachine(t, contract, nil)
}

// newFixtureWithMachine is newFixture with a hook that edits the machine config before Compile
// applies its ceilings, which is the only way to reach a ceiling a contract cannot express.
func newFixtureWithMachine(t *testing.T, contract string, tweak func(*config.Machine)) *fixture {
	t.Helper()
	return newFixtureIn(t, t.TempDir(), contract, tweak)
}

// newFixtureIn is newFixtureWithMachine with the project directory the caller made, for a test whose paths must
// stay short whatever TMPDIR is (TestUnixForeign's sockets: sun_path holds 107 bytes).
func newFixtureIn(t *testing.T, project, contract string, tweak func(*config.Machine)) *fixture {
	t.Helper()
	requireLandlock(t)
	root := t.TempDir() // the ledger root lives outside every write entry (invariant: the agent
	// can never rewrite its own record)
	out := filepath.Join(project, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	// As root under sudo the agent runs as the invoking user, so the project has to be reachable and
	// its write directory that user's, as it is on a real `sudo tego run` (KVM-11).
	agentReaches(t, out)
	agentOwns(t, out)
	path := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(path, []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home = project
	m.LedgerRoot = config.Setting[string]{Value: root}
	m.StopGrace = config.Setting[time.Duration]{Value: 2 * time.Second}

	if tweak != nil {
		tweak(m)
	}

	c, ds, err := agent.Load(path, testProfiles{})
	if err != nil {
		t.Fatalf("load: %v (%v)", err, ds)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithPATH(os.Getenv("PATH")), agent.WithHome(project),
		agent.WithCwd(project), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v (%v)", err, ds)
	}
	b, sel := enforce.Select(m, rt, backend.Probe{backend.TierLandlock: true})
	if b == nil {
		t.Skipf("no backend for this machine: %v", sel)
	}
	yaml, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: project, out: out, root: root, machine: m, rt: rt, yaml: yaml, backend: b}
}

// deps is what the fixture hands runtime.Run; signals is nil unless the test drives the handler.
func (f *fixture) deps(t *testing.T, signals <-chan os.Signal) Deps {
	t.Helper()
	tty := false
	return Deps{
		Config:       f.machine,
		Enforce:      f.backend,
		Build:        Build{Version: "test", Commit: "0000000", Kernel: "test"},
		Stdio:        agentOutput(t),
		Launcher:     &launch.Launcher{Exe: tegoBinary(t)},
		ContractYAML: f.yaml,
		Cwd:          f.dir,
		Environ:      []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.dir},
		Signals:      signals,
		StdinIsTTY:   &tty,
	}
}

// agentOutput is where a fixture run's agent writes: this test binary's own stdout and stderr, which go test hands it
// as a pipe, so the agent's output lands in the test's. Where they are a terminal instead (the KVM guest's console, under
// test/vm/root-suites.sh), a run whose agent ends by a signal writes G1's terminal reset into it (ttyrestore.go), as it
// must on a person's terminal, and the reset, which ends in no newline, glues itself to the next "--- PASS" line, which
// test2json then reads as no result: the root suites counted eleven passing tests as failed. There the agent writes a
// file of the test's own instead, which a failed test logs.
func agentOutput(t *testing.T) Stdio {
	t.Helper()
	std := Stdio{Out: os.Stdout, Err: os.Stderr}
	if saveTerminal(std) == nil {
		return std
	}
	name := filepath.Join(t.TempDir(), "agent-output")
	out, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = out.Close() // written by the agent alone, and read back by name below
		if b, err := os.ReadFile(name); t.Failed() && err == nil {
			t.Logf("the agent's output:\n%s", b)
		}
	})
	return Stdio{Out: out, Err: out}
}

// requireLandlock skips when the machine cannot run a tier-1 run at all, or when this process cannot place
// one: it runs outside its delegated subtree (a login over ssh, a service such as a CI runner's steps), where
// every run is refused before it starts (runtime-launch.md case 41).
func requireLandlock(t *testing.T) {
	t.Helper()
	fs, err := cgroup.Detect(os.Geteuid())
	if err != nil {
		t.Skipf("no delegated cgroup v2 subtree: %v", err)
	}
	if err := fs.CanPlace(); err != nil {
		t.Skipf("no run can be placed from this process: %v", err)
	}
}

// contractFor renders a contract with the given command and exec allow-list.
func contractFor(name string, command []string, allow []string) string {
	q := func(ss []string) string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	return fmt.Sprintf(`version: 0
name: %s
command: %s
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: %s
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: summary
`, name, q(command), q(allow))
}

// runDirs lists the run directories under a ledger root.
func runDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read ledger root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && ledger.IsRunID(e.Name()) {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out
}

// kinds lists the event kinds of a run in order.
func kinds(evs []*record.Event) []record.Kind {
	out := make([]record.Kind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

// has reports whether a kind appears.
func has(evs []*record.Event, k record.Kind) bool {
	for _, e := range evs {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func TestIntegrationRunTrue(t *testing.T) {
	f := newFixture(t, contractFor("itrue", []string{"/bin/true"}, []string{"/bin/true"}))
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || res.Reason != record.RunEndExit {
		t.Fatalf("result %+v, want exit 0", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	if evs[0].Kind != record.KindRunStart {
		t.Fatalf("first event is %s, want run_start", evs[0].Kind)
	}
	if last := evs[len(evs)-1]; last.Kind != record.KindRunEnd {
		t.Fatalf("last event is %s, want run_end (%v)", last.Kind, kinds(evs))
	}
	if !has(evs, record.KindExec) {
		t.Fatalf("no exec event: %v", kinds(evs))
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Tier != string(backend.TierLandlock) || start.LauncherPID != os.Getpid() {
		t.Fatalf("run_start %+v", start)
	}
	if start.Limits == nil || start.Limits.StallAfter != "" && start.Limits.Tokens == nil {
		t.Logf("run_start limits %+v", start.Limits)
	}
	// The run directory is outside every write entry and the run's cgroup is gone again.
	if _, err := os.Stat(filepath.Join(dirs[0], ledger.ContractFile)); err != nil {
		t.Fatalf("the contract copy is part of the record: %v", err)
	}
	assertCgroupRemoved(t, f, filepath.Base(dirs[0]), "itrue")
	// The run was listed in the live index while it ran and cleared once run_end was written.
	if listed, err := os.ReadDir(filepath.Join(f.root, ledger.LiveDir)); err != nil || len(listed) != 0 {
		t.Fatalf("live index after a clean run: %v %v, want it there and empty", listed, err)
	}
}

// assertCgroupRemoved checks that shutdown removed the run's scope (R8's tail).
func assertCgroupRemoved(t *testing.T, f *fixture, runID, agentName string) {
	t.Helper()
	m, err := cgroup.Detect(os.Geteuid())
	if err != nil {
		return
	}
	id, err := identity.ParseAgentID(agentName)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Root(), identity.TopSlice, identity.AgentSlice(id),
		identity.RunScope(identity.RunID(runID)))
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the run cgroup %s survived shutdown (%v)", path, err)
	}
}

func TestIntegrationRefusedWriteOutsideTheContract(t *testing.T) {
	f := newFixture(t, contractFor("iwrite", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/echo"}))
	outside := filepath.Join(t.TempDir(), "forbidden.txt")
	script := filepath.Join(f.dir, "writer.sh")
	body := fmt.Sprintf(`#!/bin/sh
echo inside > %q || exit 10
if echo outside > %q 2>/dev/null; then exit 11; fi
exit 7
`, filepath.Join(f.out, "inside.txt"), outside)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit %d, want the agent's own 7 (reason %s)", res.ExitCode, res.Reason)
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Landlock let the write outside the contract through: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.out, "inside.txt")); err != nil {
		t.Fatalf("the declared write dir must stay writable: %v", err)
	}
	evs := events(t, runDirs(t, f.root)[0])
	if !has(evs, record.KindRefused) {
		t.Fatalf("no refused event: %v", kinds(evs))
	}
	var allowed, refused int
	for _, e := range evs {
		if e.Kind != record.KindFS {
			continue
		}
		switch e.Verdict {
		case record.VerdictAllow:
			allowed++
		case record.VerdictRefused:
			refused++
			if e.Reason != record.ReasonWriteOutsideContract {
				t.Errorf("refusal reason %q", e.Reason)
			}
			if e.Rule != UnmatchedRule {
				t.Errorf("rule %q, want %q", e.Rule, UnmatchedRule)
			}
		}
	}
	if allowed == 0 || refused == 0 {
		t.Fatalf("fs verdicts: %d allowed, %d refused", allowed, refused)
	}
	// Where /bin/sh is bash (the RHEL family), the shell opens /dev/tty at start (O_RDWR|O_NONBLOCK), which the
	// contract does not give it, and where nsswitch.conf names sss it looks its user up through nscd's and sssd's
	// sockets (nssSockets): those refusals are true lines of the shell's, not of the write (AlmaLinux 9.8).
	var refusedOutside int
	for _, e := range evs {
		if e.Kind == record.KindRefused {
			var p record.RefusedPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			switch {
			case p.Target == outside:
				refusedOutside++
			case p.Target == "/dev/tty":
				t.Logf("refused line %s: the shell's own open of its terminal", e.Payload)
			case nssSockets[p.Target]:
				t.Logf("refused line %s: the shell's user lookup through NSS", e.Payload)
			default:
				t.Fatalf("refused target %q, want %q", p.Target, outside)
			}
		}
	}
	if refusedOutside == 0 {
		t.Fatalf("no refused line names %s", outside)
	}
}

func TestIntegrationTwoConcurrentRuns(t *testing.T) {
	f := newFixture(t, contractFor("iconc", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
	var wg sync.WaitGroup
	results := make([]Result, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = Run(context.Background(), f.rt,
				[]string{"/bin/sh", "-c", "sleep 0.3; exit 0"}, f.deps(t, nil))
		}()
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("run %d: %v", i, errs[i])
		}
		if results[i].ExitCode != 0 {
			t.Fatalf("run %d: exit %d (%s)", i, results[i].ExitCode, results[i].Reason)
		}
	}
	if results[0].RunID == results[1].RunID {
		t.Fatal("two runs must have distinct ids")
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 2 {
		t.Fatalf("run directories %v, want two", dirs)
	}
	for _, d := range dirs {
		if got := lastKind(t, d); got != record.KindRunEnd {
			t.Fatalf("%s ended with %s", d, got)
		}
	}
}

// waitForRunDir waits until a run directory whose lock is held appears under root. It deliberately
// returns as early as the lock exists — before run_start — so a stop racing a starting launcher is
// exercised rather than avoided.
func waitForRunDir(t *testing.T, root string, d time.Duration) string {
	t.Helper()
	return waitForRun(t, root, d, false)
}

// waitForStartedRun additionally waits for the run's first line, which is what makes a killed
// launcher an orphan rather than an empty directory retention will simply remove.
func waitForStartedRun(t *testing.T, root string, d time.Duration) string {
	t.Helper()
	return waitForRun(t, root, d, true)
}

// hasRunStart reports whether a run's first line is already on disk. A locked run directory with no
// line yet still reads as ledger.StateRunning, so the state alone cannot answer this.
func hasRunStart(dir string) bool {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return false
	}
	defer r.Close()
	for e, err := range r.Iter() {
		if err != nil {
			return false
		}
		if e.Kind == record.KindRunStart {
			return true
		}
	}
	return false
}

func waitForRun(t *testing.T, root string, d time.Duration, started bool) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if dir := liveRun(t, root, started); dir != "" {
			return dir
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no live run appeared under %s within %s", root, d)
	return ""
}

// liveRun is a run directory under root whose lock is held (and, when started, that holds its run_start line), or "".
func liveRun(t *testing.T, root string, started bool) string {
	t.Helper()
	for _, dir := range runDirs(t, root) {
		if held, _, err := ProbeLock(dir); err != nil || !held {
			continue
		}
		if !started || hasRunStart(dir) {
			return dir
		}
	}
	return ""
}

func TestIntegrationStopASleepingRun(t *testing.T) {
	f := newFixture(t, contractFor("istop", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	signals := make(chan os.Signal, 1)
	done := make(chan Result, 1)
	go func() {
		res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "60"}, f.deps(t, signals))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	dir := waitForRunDir(t, f.root, 10*time.Second)
	if err := RequestStop(dir); err != nil {
		t.Fatalf("RequestStop: %v", err)
	}
	signals <- syscall.SIGTERM
	select {
	case res := <-done:
		if res.Reason != record.RunEndStopped {
			t.Fatalf("reason %q, want stopped", res.Reason)
		}
		if res.ExitCode != identity.ExitStoppedTerm && res.ExitCode != identity.ExitStoppedKill {
			t.Fatalf("exit %d, want 143 or 137", res.ExitCode)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not stop")
	}
	var end record.RunEndPayload
	evs := events(t, dir)
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndStopped || end.Signal == 0 {
		t.Fatalf("run_end %+v", end)
	}
}

func TestIntegrationStopEscalatesToCgroupKill(t *testing.T) {
	f := newFixture(t, contractFor("iesc", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
	f.machine.StopGrace = config.Setting[time.Duration]{Value: time.Second}
	script, trapped := stubbornAgent(t, f)
	signals := make(chan os.Signal, 1)
	done := make(chan Result, 1)
	go func() {
		res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script, trapped}, f.deps(t, signals))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	dir := waitForRunDir(t, f.root, 10*time.Second)
	waitForFile(t, trapped, 10*time.Second) // the agent must be ignoring SIGTERM before the stop lands
	if err := RequestStop(dir); err != nil {
		t.Fatalf("RequestStop: %v", err)
	}
	signals <- syscall.SIGTERM
	select {
	case res := <-done:
		// R9: the agent ignored SIGTERM, so stop_grace expired and cgroup.kill ended the tree.
		if res.Reason != record.RunEndStopped || res.ExitCode != identity.ExitStoppedKill {
			t.Fatalf("result %+v, want stopped/137", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the escalation never happened")
	}
	var end record.RunEndPayload
	evs := events(t, dir)
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if !end.Escalated {
		t.Fatalf("run_end must record the escalation: %+v", end)
	}
}

func TestIntegrationPidsCapEndsTheRun(t *testing.T) {
	// A refused fork is fatal, not advisory. The contract caps the run at 16 processes and
	// the agent asks for sixty, so pids.events.max moves and the run ends with reason=pids and
	// exit 137 whatever the shell itself would have exited with.
	f := newFixture(t, strings.Replace(
		contractFor("ipids", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}),
		"  pids: 128", "  pids: 16", 1))
	script := filepath.Join(f.dir, "forky.sh")
	body := `#!/bin/sh
i=0
while [ $i -lt 60 ]; do /bin/sleep 2 & i=$((i+1)); done
wait
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndPids || res.ExitCode != identity.ExitStoppedKill {
		t.Fatalf("result %+v, want pids/137", res)
	}
	var end record.RunEndPayload
	evs := events(t, runDirs(t, f.root)[0])
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndPids {
		t.Fatalf("run_end %+v", end)
	}
}

func TestIntegrationSweepEndsAKilledLauncher(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("iorphan", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	cfg := writeMachineConfig(t, f)
	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sleep", "120")
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	dir := waitForStartedRun(t, f.root, 20*time.Second)
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = cmd.Wait()
	// PDEATHSIG ends the agent, but no run_end was written: the run reads as lost until a sweep.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if held, _, err := ProbeLock(dir); err == nil && !held {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := lastKind(t, dir); got == record.KindRunEnd {
		t.Fatal("a killed launcher cannot have written run_end")
	}
	// The launcher listed its run before run_start, and nothing cleared it: the sweep `run` and `stop`
	// make finds it through the live index alone.
	entry := filepath.Join(f.root, ledger.LiveDir, filepath.Base(dir))
	if _, err := os.Lstat(entry); err != nil {
		t.Fatalf("the killed launcher's run is not in the live index: %v", err)
	}
	res, err := SweepLive(context.Background(), f.root)
	if err != nil {
		t.Fatalf("SweepLive: %v", err)
	}
	if _, err := os.Lstat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the swept run is still listed: %v", err)
	}
	if res.Orphaned != 1 {
		r, rerr := ledger.OpenReader(dir)
		if rerr == nil {
			st, serr := r.State()
			t.Logf("state %q err %v", st, serr)
			_ = r.Close()
		}
		for _, e := range events(t, dir) {
			t.Logf("event %d %s", e.Seq, e.Kind)
		}
		t.Fatalf("swept %d/%d run(s), want 1 (errs %v)", res.Orphaned, res.Scanned, res.Errs)
	}
	if got := lastReason(t, dir); got != record.RunEndOrphaned {
		t.Fatalf("run ended with %q, want orphaned", got)
	}
	assertCgroupRemoved(t, f, filepath.Base(dir), "iorphan")
}

// writeMachineConfig writes a trusted machine config naming the fixture's ledger root.
func writeMachineConfig(t *testing.T, f *fixture) string {
	t.Helper()
	// config.Load refuses a layer whose file or directory is group or other writable; the test
	// framework's temporary directory is 0775, so it is tightened here the way a real install is.
	if err := os.Chmod(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "config.yaml")
	body := fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 2s\n", f.root)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// The callers pass os.Environ() to the binary, so these reach it with TEGO_CONFIG: the tegotesthooks build keeps
	// its chain anchor and its own log in the test's directories, never in the invoking user's ~/.tego
	// (internal/cli/anchor_testhook.go, ownlog_testhook.go).
	t.Setenv("TEGO_TEST_CHAIN_ANCHOR", filepath.Join(t.TempDir(), "chain.log"))
	f.logHome = t.TempDir()
	t.Setenv("TEGO_TEST_OWN_LOG_HOME", f.logHome)
	return path
}

// isolatedEnv is the environment a tego subprocess of f's runs with: os.Environ() read after writeMachineConfig has
// set the test-hook variables, with TEGO_CONFIG appended. Reading it first, as append(os.Environ(), "TEGO_CONFIG="+
// writeMachineConfig(t, f)) does (Go evaluates the arguments left to right), passes the binary neither variable, and
// it anchors in the invoking user's real ~/.tego/chain.log.
func isolatedEnv(t *testing.T, f *fixture) []string {
	t.Helper()
	cfg := writeMachineConfig(t, f)
	env := append(os.Environ(), "TEGO_CONFIG="+cfg)
	requireIsolatedEnv(t, env)
	return env
}

// requireIsolatedEnv fails the test before a tego subprocess starts with env unless env carries, as its last value
// of each, the chain anchor and own-log home writeMachineConfig set in this process: a binary started without them
// writes to the invoking user's real ~/.tego.
func requireIsolatedEnv(t *testing.T, env []string) {
	t.Helper()
	for _, name := range []string{"TEGO_TEST_CHAIN_ANCHOR", "TEGO_TEST_OWN_LOG_HOME"} {
		want, got := os.Getenv(name), ""
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, name+"="); ok {
				got = v // the last value wins, as exec.Cmd dedups the environment
			}
		}
		if want == "" || got != want {
			t.Fatalf("the tego subprocess would run with %s=%q, not the test's %q: it would write outside the test, in the invoking user's ~/.tego when unset", name, got, want)
		}
	}
}

func TestIntegrationCLIRunStatusStop(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("icli", []string{"/bin/true"}, []string{"/bin/true", "/bin/sleep"}))
	cfg := writeMachineConfig(t, f)
	env := append(os.Environ(), "TEGO_CONFIG="+cfg)

	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/true")
	run.Dir = f.dir
	run.Env = env
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v", dirs)
	}
	runID := filepath.Base(dirs[0])

	status := exec.Command(bin, "status", runID, "--json")
	status.Env = env
	out, err = status.Output()
	if err != nil {
		t.Fatalf("tego status: %v (%s)", err, out)
	}
	var snap struct {
		Run        string `json:"run"`
		State      string `json:"state"`
		ExitReason string `json:"exit_reason"`
		LockHeld   bool   `json:"lock_held"`
	}
	if err := json.Unmarshal(out, &snap); err != nil {
		t.Fatalf("status --json %q: %v", out, err)
	}
	if snap.Run != runID || snap.State != "done" || snap.ExitReason != record.RunEndExit || snap.LockHeld {
		t.Fatalf("status %+v", snap)
	}

	// `stop` on a finished run reports "not running" and signals nothing (§6 case 11).
	stop := exec.Command(bin, "stop", runID)
	stop.Env = env
	out, err = stop.Output()
	if err != nil {
		t.Fatalf("tego stop: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "not running") {
		t.Fatalf("stop said %q", out)
	}
	if _, err := os.Stat(filepath.Join(dirs[0], StopRequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stop must not mark a run that is not running")
	}
}

func TestIntegrationCLIStopASleepingRun(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("iclistop", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	cfg := writeMachineConfig(t, f)
	env := append(os.Environ(), "TEGO_CONFIG="+cfg)

	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sleep", "120")
	run.Dir = f.dir
	run.Env = env
	if err := run.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	dir := waitForRunDir(t, f.root, 20*time.Second)
	stop := exec.Command(bin, "stop", filepath.Base(dir))
	stop.Env = env
	out, err := stop.CombinedOutput()
	if err != nil {
		t.Fatalf("tego stop: %v\n%s", err, out)
	}
	err = run.Wait()
	code := exitCodeOf(t, err)
	if code != identity.ExitStoppedTerm && code != identity.ExitStoppedKill {
		t.Fatalf("tego run exited %d, want 143 or 137", code)
	}
	if got := lastReason(t, dir); got != record.RunEndStopped {
		for _, e := range events(t, dir) {
			t.Logf("event %d %s %s", e.Seq, e.Kind, e.Payload)
		}
		t.Fatalf("run ended with %q, want stopped (stop said %q)", got, out)
	}
}

// exitCodeOf extracts a process exit code from exec's error.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("not an exit error: %v", err)
	return -1
}

// TestIntegrationLedgerIsReadableAsLines is a smoke check that the ledger a real run produced is
// exactly what `tego events --json` will print: one JSON object per line, run_end last.
func TestIntegrationLedgerIsReadableAsLines(t *testing.T) {
	f := newFixture(t, contractFor("ilines", []string{"/bin/true"}, []string{"/bin/true"}))
	if _, err := Run(context.Background(), f.rt, []string{"/bin/true"}, f.deps(t, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(runDirs(t, f.root)[0], ledger.EventsFile)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var lines int
	var lastKind string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			t.Fatalf("line %d is not JSON: %v", lines+1, err)
		}
		lastKind, _ = obj["kind"].(string)
		lines++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if lines < 3 || lastKind != string(record.KindRunEnd) {
		t.Fatalf("%d lines, last kind %q", lines, lastKind)
	}
}

// usageSource is a capture source that feeds the run one ssl_response per tick. P0 wires no real
// capture into internal/cli yet, so this stands in for the producer whose events R1 and R2 are
// computed from: it is the only way to cross a token or cost ceiling in a real run today.
type usageSource struct {
	every  time.Duration
	tokens int
	done   chan struct{}
	once   sync.Once
}

// Name identifies the source in the run's logs.
func (s *usageSource) Name() string { return "usage-test" }

// Start emits until the run's context ends or Stop is called, so nothing it starts outlives the run.
func (s *usageSource) Start(ctx context.Context, _ source.RunRef, sink source.Sink) error {
	s.done = make(chan struct{})
	go func() {
		t := time.NewTicker(s.every)
		defer t.Stop()
		for seq := uint64(0); ; seq++ {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				return
			case <-t.C:
			}
			ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}
			if err := ev.SetPayload(record.SSLResponsePayload{RequestSeq: new(seq), Status: 200,
				Model: "claude-sonnet-4-5-20250929", ParserVersion: "1",
				Usage: &record.Usage{Input: s.tokens, Output: 0}}); err != nil {
				return
			}
			sink.Emit(ev)
		}
	}()
	return nil
}

// Stop ends the emitter; the facade calls it once, before the group is waited on.
func (s *usageSource) Stop() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

// Gaps reports nothing: this source covers exactly what it claims to.
func (s *usageSource) Gaps() []source.Gap { return nil }

// limitEvent returns a run's one limit event.
func limitEvent(t *testing.T, evs []*record.Event) record.LimitPayload {
	t.Helper()
	var out record.LimitPayload
	found := false
	for _, e := range evs {
		if e.Kind != record.KindLimit {
			continue
		}
		if found {
			t.Fatal("two limit events for one run (limits-check-doctor-cli.md I1)")
		}
		if err := e.DecodePayload(&out); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no limit event: %v", kinds(evs))
	}
	return out
}

func TestIntegrationTokenCeilingEndsTheRun(t *testing.T) {
	// Through the facade: a contract whose token ceiling is 100, a producer
	// feeding 60 uncached tokens a tick, and an agent that would otherwise sleep for half a minute.
	// The second response crosses R1, the watcher appends its limit event and kills the cgroup, and
	// the facade turns the terminal reason into run_end reason=limit and exit 124 (§4 trip, §7).
	f := newFixture(t, strings.Replace(
		contractFor("itokens", []string{"/bin/sleep"}, []string{"/bin/sleep"}),
		"  pids: 128", "  pids: 128\n  tokens: 100", 1))
	if f.rt.Limits.Tokens != 100 {
		t.Fatalf("the compiled table carries tokens %d, want 100", f.rt.Limits.Tokens)
	}
	deps := f.deps(t, nil)
	deps.Capture = []source.Source{&usageSource{every: 50 * time.Millisecond, tokens: 60}}

	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "30"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	evs := events(t, runDirs(t, f.root)[0])
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitTokens || lim.Value <= lim.Ceiling || lim.Ceiling != 100 {
		t.Fatalf("limit payload %+v, want tokens over a ceiling of 100", lim)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndLimit || end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v, want limit/124", end)
	}
}

func TestIntegrationWallCeilingEndsTheRun(t *testing.T) {
	// The clock-only half (R3): no producer says anything, the watcher's own goroutine crosses the
	// ceiling, and the run ends the same way. This is what proves the watcher is a member of the
	// run's worker group and not merely a pipeline stage.
	f := newFixture(t, strings.Replace(
		contractFor("iwall", []string{"/bin/sleep"}, []string{"/bin/sleep"}),
		"  pids: 128", "  pids: 128\n  wall: 1s", 1))
	started := time.Now()
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "30"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the wall ceiling took %s to fire", elapsed)
	}
	lim := limitEvent(t, events(t, runDirs(t, f.root)[0]))
	if lim.Which != record.LimitWall || lim.Ceiling != 1 {
		t.Fatalf("limit payload %+v, want wall over a ceiling of 1s", lim)
	}
}

// modelUpstream is the model endpoint a capture run proxies to: TLS on loopback, answering
// /v1/messages with one Anthropic message and a usage object worth 60 tokens. It returns the host and
// port a models[] entry names and the PEM file the launcher trusts it through.
//
// The certificate reaches the launcher by $SSL_CERT_FILE rather than a machine trust store: the
// forwarder's upstream leg verifies the model's own certificate (R20), and a test that disabled that
// verification would be testing a transport the product never builds.
func modelUpstream(t *testing.T) (host string, port int, caFile string) {
	t.Helper()
	return modelUpstreamAnswering(t, `[{"type":"text","text":"pong"}]`, "end_turn")
}

// modelUpstreamAnswering is modelUpstream with the message's content blocks and stop_reason chosen by the
// caller: a looping model is one that answers every call with the same tool_use (limits R5).
func modelUpstreamAnswering(t *testing.T, content, stopReason string) (host string, port int, caFile string) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", fmt.Sprintf("req_%03d", n))
		_, _ = fmt.Fprintf(w, `{"id":"msg_%03d","type":"message","role":"assistant",`+
			`"model":"claude-test-1","stop_reason":%q,`+
			`"content":%s,`+
			`"usage":{"input_tokens":40,"output_tokens":20,`+
			`"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`, n, stopReason, content)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "upstream-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), p, caFile
}

// modelAgentBinary builds test/workloads/model-agent once per test run: the agent of a capture run has
// to make a real HTTP request to whatever base URL it was handed, which no stock /bin utility does.
var (
	modelAgentOnce sync.Once
	modelAgentPath string
	modelAgentErr  error
)

func modelAgentBinary(t *testing.T) string {
	t.Helper()
	modelAgentOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-model-agent-")
		if err != nil {
			modelAgentErr = err
			return
		}
		modelAgentPath = filepath.Join(dir, "model-agent")
		cmd := exec.Command("go", "build", "-o", modelAgentPath,
			"github.com/attention-span-ai/tego/test/workloads/model-agent")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			modelAgentErr = fmt.Errorf("go build model-agent: %v: %s", err, out)
		}
	})
	if modelAgentErr != nil {
		t.Fatal(modelAgentErr)
	}
	agentReaches(t, modelAgentPath)
	return modelAgentPath
}

// modelContract is a capture contract: capture: forwarder, one declared models[] entry, and a net:
// section that allows nothing of its own — the only destination the agent may reach is the forwarder
// port the run itself admits (R38).
func modelContract(name, agentBin, host string, port int, extraLimits string) string {
	return fmt.Sprintf(`version: 0
name: %s
command: [%q]
tier: landlock
capture: forwarder
record: full
models:
  - provider: anthropic
    host: %s
    port: %d
fs:
  write: ["./out/"]
exec:
  allow: [%q]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "MODEL_CALLS", "MODEL_DIRECT"]
limits:
  pids: 128%s
`, name, agentBin, host, port, agentBin, extraLimits)
}

// sslPairs returns the ssl_request/ssl_response payload pairs of a run's ledger, matched by request id.
func sslPairs(t *testing.T, evs []*record.Event) (reqs []record.SSLRequestPayload, resps []record.SSLResponsePayload) {
	t.Helper()
	for _, e := range evs {
		switch e.Kind {
		case record.KindSSLRequest:
			var p record.SSLRequestPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatalf("ssl_request payload: %v", err)
			}
			reqs = append(reqs, p)
		case record.KindSSLResponse:
			var p record.SSLResponsePayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatalf("ssl_response payload: %v", err)
			}
			resps = append(resps, p)
		}
	}
	return reqs, resps
}

// TestIntegrationForwarderCapturesTheModelCall is the whole wire this ticket closed, driven through the
// real CLI: `tego run` selects the forwarder, the run admits its loopback port and names it in the
// agent's environment, the agent calls the model through it, and the ledger gains the
// ssl_request/ssl_response pair the uprobe path would have produced for the same call — with the usage
// object measure's token columns read (docs/p0/capture-derive.md §4, R19, R38, spec/identity R7).
func TestIntegrationForwarderCapturesTheModelCall(t *testing.T) {
	bin := tegoBinary(t)
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstream(t)
	f := newFixture(t, modelContract("icapture", agentBin, host, port, ""))
	cfg := writeMachineConfig(t, f)

	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile,
		"MODEL_CALLS=2", "MODEL_DIRECT="+net.JoinHostPort(host, strconv.Itoa(port)))
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ANTHROPIC_BASE_URL=http://127.0.0.1:") {
		t.Fatalf("the agent was handed no forwarder base URL:\n%s", out)
	}
	if !strings.Contains(string(out), "direct connect refused") {
		t.Fatalf("the upstream was reachable around the forwarder (R38):\n%s", out)
	}

	evs := events(t, runDirs(t, f.root)[0])
	reqs, resps := sslPairs(t, evs)
	if len(reqs) != 2 || len(resps) != 2 {
		t.Fatalf("the ledger holds %d ssl_request and %d ssl_response events, want 2 and 2: %v",
			len(reqs), len(resps), kinds(evs))
	}
	for i, q := range reqs {
		if q.Method != "POST" || q.Path != "/v1/messages" || q.Endpoint != "anthropic" || q.Host != host {
			t.Fatalf("ssl_request %d is %+v", i, q)
		}
	}
	for i, p := range resps {
		if p.Status != 200 || p.Model != "claude-test-1" || p.ParserVersion == "" {
			t.Fatalf("ssl_response %d is %+v", i, p)
		}
		if p.Usage == nil || p.Usage.Input != 40 || p.Usage.Output != 20 {
			t.Fatalf("ssl_response %d carries usage %+v, want 40 in and 20 out", i, p.Usage)
		}
	}
	// Two halves of R38 in one ledger: the forwarder's own port admitted by the rule the run added,
	// and the upstream refused because nothing names it.
	var admitted, refused bool
	for _, e := range evs {
		if e.Kind != record.KindNet {
			continue
		}
		var p record.NetPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		switch {
		// The loopback entry is a runtime grant, named net.capture[<addr>] rather than after a
		// net.allow index the contract does not have (agent.IsRuntimeRule).
		case e.Verdict == record.VerdictAllow && agent.IsRuntimeRule(e.Rule):
			admitted = true
		case e.Verdict == record.VerdictRefused && p.Dst == net.JoinHostPort(host, strconv.Itoa(port)):
			refused = true
		}
	}
	if !admitted {
		t.Fatal("no net event names the forwarder's own rule: the port was admitted by something else")
	}
	if !refused {
		t.Fatal("the direct connect to the upstream was not recorded as refused")
	}

	// A run that captures model traffic derives turns from it and attributes actions to them
	// (P0-DESIGN §5's M1 to M2 step). Walking the ledger in order is what makes the assertion exact:
	// an action recorded before the first request cannot belong to a turn and must carry step 0,
	// and one recorded after must carry the step that was open when it happened. This workload
	// front-loads its actions, so step 0 on them is the correct answer rather than a missing one;
	// what would be wrong is method none, which would mean no attribution was attempted at all.
	open, actions := 0, 0
	for _, e := range evs {
		if e.Kind == record.KindSSLRequest {
			open++
			continue
		}
		if !e.Kind.IsAction() {
			continue
		}
		actions++
		if e.Attr == nil {
			t.Fatalf("action %d (%s) reached the ledger with no attribution", e.Seq, e.Kind)
		}
		if e.Attr.Method != record.MethodTime {
			t.Errorf("action %d (%s) carries method %q, want %q: the run had turns to derive from",
				e.Seq, e.Kind, e.Attr.Method, record.MethodTime)
		}
		if e.Attr.Step != open {
			t.Errorf("action %d (%s) is attributed to step %d, want %d: %d turns had opened by then",
				e.Seq, e.Kind, e.Attr.Step, open, open)
		}
	}
	if actions == 0 {
		t.Fatal("the run recorded no action to attribute")
	}
	if open != 2 {
		t.Errorf("%d turns opened, want 2", open)
	}
}

// TestIntegrationTokenCeilingEndsARealModelRun is the acceptance on real model traffic rather than a
// synthetic producer: the tokens come from responses the forwarder captured and derive read, so R1's
// ceiling trips on the run's own record (limits-check-doctor-cli.md §4 trip, R11 of the exit table).
func TestIntegrationTokenCeilingEndsARealModelRun(t *testing.T) {
	bin := tegoBinary(t)
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstream(t)
	f := newFixture(t, modelContract("icapturelimit", agentBin, host, port, "\n  tokens: 100"))
	cfg := writeMachineConfig(t, f)

	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile, "MODEL_CALLS=8")
	out, err := run.CombinedOutput()
	if code := exitCodeOf(t, err); code != identity.ExitLimit {
		t.Fatalf("tego run exited %d, want %d\n%s", code, identity.ExitLimit, out)
	}
	evs := events(t, runDirs(t, f.root)[0])
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitTokens || lim.Ceiling != 100 || lim.Value <= lim.Ceiling {
		t.Fatalf("limit payload %+v, want tokens over a ceiling of 100", lim)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndLimit || end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v, want limit/124", end)
	}
}

// listenerDiesSource stands in for the tier-2 enforce listener dying while the sources start: its Start fails a
// member of the run's group, waits until the cancellation is visible, and returns nil, as a worker that dies on
// its own thread does between two prepare steps.
type listenerDiesSource struct{ r *runner }

func (s *listenerDiesSource) Name() string { return "listener-dies-test" }

func (s *listenerDiesSource) Start(ctx context.Context, _ source.RunRef, _ source.Sink) error {
	s.r.group.Go("enforce-listener", func() error { return errors.New("listener died") })
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
	}
	return nil
}

func (s *listenerDiesSource) Stop() error        { return nil }
func (s *listenerDiesSource) Gaps() []source.Gap { return nil }

// A worker that dies while the sources start cancels the group; the agent must not be released, and the run must
// fail before run_start (runtime-launch.md §7: exit 125, no ledger), not exec the agent and end reason=error.
func TestIntegrationWorkerDyingDuringSourceStartNeverReleasesTheAgent(t *testing.T) {
	f := newFixture(t, contractFor("iworkerdies", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	marker := filepath.Join(t.TempDir(), "ran")
	r, err := newRunner(f.rt, []string{"/bin/sh", "-c", "echo x > " + marker}, f.deps(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	r.deps.Capture = []source.Source{&listenerDiesSource{r: r}}
	res, err := r.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listener died") {
		t.Fatalf("run: %v, want an error naming the dead worker", err)
	}
	if res.ExitCode != identity.ExitLauncher {
		t.Fatalf("result %+v, want exit 125", res)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the agent ran: it was released although a worker had already failed")
	}
	for _, d := range runDirs(t, f.root) {
		for _, e := range events(t, d) {
			if e.Kind == record.KindRunStart {
				t.Fatal("run_start was written for a run that failed before its agent was released")
			}
		}
	}
}
