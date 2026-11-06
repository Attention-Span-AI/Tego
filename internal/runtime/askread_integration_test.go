// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The fs.ask_read and alternate end to end at tier landlock (POC 2026-10-06): the real tego binary runs a real
// contract whose agent, a shell script, reads a secret under fs.ask_read; a person answers from separate tego
// processes (`tego ask`, `tego alternate|approve|deny [--always]`) over the run's real broker socket, or does not
// answer at all. Everything is unprivileged: Landlock, the seccomp listener and the run's delegated cgroup.

const (
	realSecret  = "REAL-SECRET\n"
	standInBody = "FAKE-STAND-IN\n"
)

// askReadScene is one run's world: the secret outside the project, the stand-in outside both, the tego binary and
// the environment that keeps its anchor, own log and ledger in the test's directories.
type askReadScene struct {
	f       *fixture
	bin     string
	env     []string
	secret  string
	standIn string
	// said is what `tego run` printed, whole once the run is over (finish).
	said *strings.Builder
	// run is the scene's one `tego run` (start); ended is closed once the scene's one Wait of it returned, with its
	// error in waitErr.
	run     *exec.Cmd
	ended   chan struct{}
	waitErr error
}

// sceneOutputGrace is how long a scene reads `tego run`'s output after it exits (exec.Cmd.WaitDelay). A run's processes
// end with it, so its output pipe still open that long after is held by a process that outlived the run, and the Wait
// returns exec.ErrWaitDelay instead of waiting on it for good.
const sceneOutputGrace = 10 * time.Second

func newAskReadScene(t *testing.T, timeout string, reads int) *askReadScene {
	t.Helper()
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	for i := 1; i <= reads; i++ {
		fmt.Fprintf(&script, "cat \"$SECRET\" > out/got%d.txt 2> out/err%d.txt; echo $? > out/rc%d\n", i, i, i)
	}
	return newScene(t, timeout, "", script.String())
}

// newScene writes the secret, the stand-in, the contract (fs.ask_read on the secret, with extraFS lines under fs:)
// and the agent's script, in which $SECRET is the secret's path.
func newScene(t *testing.T, timeout, extraFS, script string) *askReadScene {
	t.Helper()
	bin := tegoBinary(t)
	vault, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin, secret: filepath.Join(vault, "token"), standIn: filepath.Join(elsewhere, "fake-token")}
	if err := os.WriteFile(s.secret, []byte(realSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.standIn, []byte(standInBody), 0o600); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: iaskread
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  ask_read: [%q]
%sexec:
  allow: ["/bin/sh", "/bin/cat", "/bin/echo"]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: %s
limits:
  pids: 64
record: summary
`, s.secret, extraFS, timeout)
	s.f = newFixture(t, contract)
	script = strings.ReplaceAll(script, "$SECRET", s.secret)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// As root (the KVM root suites) the run drops the agent to the invoking user, who owns a real secret and
	// stand-in: the held read and the alternate open run with that user's credentials.
	agentReaches(t, s.secret)
	agentReaches(t, s.standIn)
	agentOwns(t, s.secret, s.standIn, filepath.Join(s.f.dir, "agent.sh"))
	// isolatedEnv runs writeMachineConfig, which sets TEGO_TEST_CHAIN_ANCHOR and TEGO_TEST_OWN_LOG_HOME with
	// t.Setenv, before it reads os.Environ(): an os.Environ() argument written before the call is evaluated before it
	// and holds neither, which ran the binary against the developer's own ~/.tego/chain.log (2026-10-06).
	s.env = isolatedEnv(t, s.f)
	return s
}

// tego is `tego <args...>` with the scene's environment, refused before it starts unless that environment keeps
// the binary's anchor and own log in the test's directories (requireIsolatedEnv).
func (s *askReadScene) tego(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	requireIsolatedEnv(t, s.env)
	cmd := exec.Command(s.bin, args...)
	cmd.Env = s.env
	return cmd
}

// anchored fails the test unless the run whose directory is dir appended its chain head to the test's own anchor,
// the file TEGO_TEST_CHAIN_ANCHOR names in this process: a binary that anchored elsewhere wrote a real ~/.tego.
func anchored(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("TEGO_TEST_CHAIN_ANCHOR"))
	if err != nil || !strings.Contains(string(b), filepath.Base(dir)) {
		t.Fatalf("the test's chain anchor has no line of run %s (%v): the binary anchored somewhere else", filepath.Base(dir), err)
	}
}

// start launches `tego run` on the scene's contract and returns the command and the run's directory. The scene waits
// for the command itself, once (ended): finish reads how it ended, and a test that ends with it still running has the
// whole run killed (kill).
func (s *askReadScene) start(t *testing.T) (*exec.Cmd, string) {
	t.Helper()
	if s.run != nil {
		t.Fatal("a scene starts one run")
	}
	run := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	run.Dir = s.f.dir
	out := &strings.Builder{}
	s.said = out
	run.Stdout, run.Stderr = out, out
	run.WaitDelay = sceneOutputGrace
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	s.run, s.ended = run, ended
	go func() { s.waitErr = run.Wait(); close(ended) }()
	var dir string // the run's directory, once start has seen it live
	t.Cleanup(func() {
		select {
		case <-ended:
		default:
			s.kill(t, dir)
		}
		select {
		case <-ended:
			if t.Failed() {
				t.Logf("tego run said:\n%s", out.String())
			}
		default: // its output is still being copied, so it is not read; kill said why
		}
	})
	wait := askSceneStartWait()
	begun := time.Now()
	for deadline := begun.Add(wait); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if dir = liveRun(t, s.f.root, true); dir != "" {
			t.Logf("tego run started its run in %v", time.Since(begun).Round(time.Millisecond))
			return run, dir
		}
		select {
		case <-ended:
			t.Fatalf("tego run ended before its run started under %s (%v)", s.f.root, s.waitErr)
		default:
		}
	}
	t.Fatalf("no live run appeared under %s within %s", s.f.root, wait)
	return nil, ""
}

// kill ends for good the run of a test that ended with it still running: SIGKILL to the run's own cgroup, found as
// `tego stop`'s backstop finds it (RunScope), then to tego run, and it waits for the scene's Wait. Killing tego run
// alone did not end the run: the launcher's PDEATHSIG ends only the agent's first process (launch/child.go), so a
// process the agent's script started in the background outlived it, as a run whose launcher died runs on until the
// next `tego run`, `tego stop` or `tego gc` sweep ends it as orphaned (limits-check-doctor-cli.md), and it held tego
// run's output pipe, so the Wait never returned. On 2026-11-06 TestIntegrationPauseWaitsForAnAnsweredAsk failed on CI
// and its cleanup then waited 7m21s on the agent's heartbeat, which spun on the syscalls the dead launcher's listener
// no longer answered, until go test's 10 m deadline killed the package with its test's failure unprinted (run
// 42184797264).
func (s *askReadScene) kill(t *testing.T, dir string) {
	t.Helper()
	m, scopes, err := killRuns(s.f.root, dir)
	if err != nil {
		t.Errorf("the run's own cgroup was not killed, so its processes may outlive the test: %v", err)
	}
	_ = s.run.Process.Kill()
	bound := sceneOutputGrace + 10*time.Second
	select {
	case <-s.ended:
		if errors.Is(s.waitErr, exec.ErrWaitDelay) {
			t.Errorf("a process held tego run's output %s after tego run and its run's cgroup were killed", sceneOutputGrace)
		}
	case <-time.After(bound):
		t.Errorf("tego run did not end within %s of its kill", bound)
	}
	// The killed launcher removes no scope: each is removed here once its processes are gone.
	for _, c := range scopes {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := m.Remove(ctx, c); err != nil {
			t.Logf("the killed run's cgroup %s stays: %v", c.Path, err)
		}
		cancel()
	}
}

// killRuns SIGKILLs, through its own cgroup, the run whose directory is dir, or each run under the ledger root root
// when dir is "" (a start that never saw its run live), and returns the cgroups it killed. A run with no run_start
// names no agent, and one with no scope left ended with it: neither is killed, and neither is an error.
func killRuns(root, dir string) (*cgroup.FS, []cgroup.Cgroup, error) {
	dirs := []string{dir}
	if dir == "" {
		ents, err := os.ReadDir(root)
		if err != nil {
			return nil, nil, err
		}
		dirs = nil
		for _, e := range ents {
			if e.IsDir() && ledger.IsRunID(e.Name()) {
				dirs = append(dirs, filepath.Join(root, e.Name()))
			}
		}
	}
	m, err := cgroup.Detect(os.Geteuid())
	if err != nil {
		return nil, nil, err
	}
	var killed []cgroup.Cgroup
	var errs []error
	for _, d := range dirs {
		agent := runAgentOf(d)
		if agent == "" {
			continue
		}
		c, ok, err := RunScope(m, filepath.Dir(d), filepath.Base(d), agent)
		if err != nil || !ok {
			errs = append(errs, err)
			continue
		}
		if err := m.Kill(c); err != nil {
			errs = append(errs, err)
			continue
		}
		killed = append(killed, c)
	}
	return m, killed, errors.Join(errs...)
}

// runAgentOf is the agent the run_start of the run whose directory is dir names, "" when it has none.
func runAgentOf(dir string) string {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return ""
	}
	defer r.Close()
	for e, err := range r.Iter() {
		if err != nil || e.Kind != record.KindRunStart {
			return ""
		}
		return e.Agent
	}
	return ""
}

// askSceneStartWait bounds `tego run`'s start up to its run_start line. It is no budget, only the point past which a
// start that never comes fails; a launcher that exits first fails the subtest at once (the scene's Wait returned). As
// root, 5 minutes: the first tier-2 or tier-3 run after a KVM guest boots probes and loads the plane cold, as
// dnsCLIReportWait measures: 21 to 30 s for TestRootAskUnix's first cgroup cell on 2026-10-19 (a loaded host), where
// the 30 s this was expired in three of six runs of the lsm-bpf boot. Unprivileged, 2 minutes: such a run loads no
// plane, and the 41 scene starts of this package's unprivileged suite took 95 to 216 ms at a load average of 19 to 20
// (2026-11-02; start's log line says how long each took). The bound must also end before go test's own: CI's build-test
// runs this package's integration suite unprivileged in about 320 s (d9e6cec, 2026-11-02) of go test's 600 s, so at 5
// minutes a start that never came outlived that deadline, and go test killed the binary with no test failed and its
// FAIL line the only word, as it killed this package's on 40de30f (which test hung there is not known). At 2 minutes
// the test fails on its own message, with what tego run said, and the package's other tests still report.
func askSceneStartWait() time.Duration {
	if os.Geteuid() == 0 {
		return 5 * time.Minute
	}
	return 2 * time.Minute
}

// pending waits for the one request the run holds, through `tego ask --json`.
func (s *askReadScene) pending(t *testing.T, runID string) map[string]any {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		cmd := s.tego(t, "ask", runID, "--json")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		var list struct {
			Pending []map[string]any `json:"pending"`
		}
		if json.Unmarshal(out, &list) != nil || len(list.Pending) != 1 {
			continue
		}
		// The list cuts a long target; the detail has it whole.
		detail := s.tego(t, "ask", runID, list.Pending[0]["ask_id"].(string), "--json")
		if out, err = detail.Output(); err != nil {
			t.Fatalf("tego ask %s %s: %v", runID, list.Pending[0]["ask_id"], err)
		}
		var one struct {
			Request map[string]any `json:"request"`
		}
		if err = json.Unmarshal(out, &one); err != nil {
			t.Fatal(err)
		}
		return one.Request
	}
	t.Fatal("no request was held")
	return nil
}

// answer runs `tego <args...>` as the person and returns what it printed.
func (s *askReadScene) answer(t *testing.T, args ...string) string {
	t.Helper()
	cmd := s.tego(t, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tego %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// try runs `tego <args...>` as the person and returns what it printed and its exit code.
func (s *askReadScene) try(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := s.tego(t, args...)
	out, err := cmd.CombinedOutput()
	return string(out), exitCodeOf(t, err)
}

// runStartPayload is the run_start payload of a run's ledger.
func runStartPayload(t *testing.T, evs []*record.Event) record.RunStartPayload {
	t.Helper()
	var p record.RunStartPayload
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart || evs[0].DecodePayload(&p) != nil {
		t.Fatalf("the ledger has no run_start first: %v", evs)
	}
	return p
}

// finish waits for the run, the one start returned, and returns its ledger.
func (s *askReadScene) finish(t *testing.T, run *exec.Cmd, dir string) []*record.Event {
	t.Helper()
	if run == nil || run != s.run {
		t.Fatal("finish: not the run this scene started")
	}
	select {
	case <-s.ended:
		if errors.Is(s.waitErr, exec.ErrWaitDelay) {
			t.Fatalf("tego run exited, and a process held its output %s later: it outlived the run\n%s",
				sceneOutputGrace, s.diagnose(t, dir))
		}
		if code := exitCodeOf(t, s.waitErr); code != 0 {
			t.Fatalf("tego run exited %d\n%s", code, s.diagnose(t, dir))
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the run did not end\n%s", s.diagnose(t, dir))
	}
	anchored(t, dir)
	return events(t, dir)
}

// diagnose is what a failed scene's run left: the binary's own log, the first five human-answered fs lines that
// delivered no descriptor, and the run's other ledger lines, the last 40 of them.
func (s *askReadScene) diagnose(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	own, err := os.ReadFile(filepath.Join(s.f.logHome, ".tego", "tego.log"))
	fmt.Fprintf(&b, "own log (%v):\n%s\n", err, own)
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		fmt.Fprintf(&b, "ledger: %v\n", err)
		return b.String()
	}
	var kept, undelivered []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.Contains(l, `"kind":"fs"`) && strings.Contains(l, `"authority":"human"`) {
			if !strings.Contains(l, `"fd_delivered":true`) && len(undelivered) < 5 {
				undelivered = append(undelivered, l)
			}
			continue
		}
		kept = append(kept, l)
	}
	fmt.Fprintf(&b, "the first human fs lines with no descriptor delivered:\n%s\n", strings.Join(undelivered, "\n"))
	if len(kept) > 40 {
		kept = kept[len(kept)-40:]
	}
	fmt.Fprintf(&b, "ledger, %d bytes; its last lines but the human fs ones:\n%s\n", len(raw), strings.Join(kept, "\n"))
	return b.String()
}

// runToEnd runs `tego run` on the scene's contract to its end and returns the one run's ledger: for an agent too
// short-lived for start, which needs the run still live when it polls for it.
func (s *askReadScene) runToEnd(t *testing.T) []*record.Event {
	t.Helper()
	run := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	run.Dir = s.f.dir
	out, err := run.CombinedOutput()
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("tego run exited %d:\n%s", code, out)
	}
	dirs := runDirs(t, s.f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, out)
	}
	anchored(t, dirs[0])
	return events(t, dirs[0])
}

// out reads a file the agent wrote, "" when it wrote none.
func (s *askReadScene) out(name string) string {
	b, _ := os.ReadFile(filepath.Join(s.f.out, name))
	return string(b)
}

// lines is the run's lines of kind, payloads decoded, with the common fields in "_rule", "_reason", "_verdict",
// "_authority".
func lines(t *testing.T, evs []*record.Event, kind record.Kind) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range evs {
		if e.Kind != kind {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal(e.Payload, &m); err != nil {
			t.Fatal(err)
		}
		m["_rule"], m["_reason"], m["_verdict"], m["_authority"] = e.Rule, string(e.Reason), string(e.Verdict), string(e.Authority)
		out = append(out, m)
	}
	return out
}

// heldAndPaused checks the request is the secret's read and that the agent is paused in it: its shell opened the
// output file, and wrote no status, before the person answers.
func (s *askReadScene) heldAndPaused(t *testing.T, req map[string]any) {
	t.Helper()
	if req["op"] != "read" || req["hold"] != "open" || req["target"] != s.secret || req["rule"] != "fs.ask_read["+s.secret+"]" {
		t.Fatalf("the held request %v: want a read of the secret under its entry", req)
	}
	time.Sleep(300 * time.Millisecond)
	if s.out("rc1") != "" {
		t.Fatalf("the agent was not paused: it wrote its status %q while the read was held", s.out("rc1"))
	}
}

// The person names a stand-in: the agent's read of the secret gets the stand-in's bytes, never the secret's; the
// ask line names the secret, the answer line the stand-in, and the delivered open's line the stand-in with the
// secret it stands for.
func TestIntegrationAskReadAlternateGivesTheAgentTheStandIn(t *testing.T) {
	s := newAskReadScene(t, "30s", 1)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	s.heldAndPaused(t, req)
	said := s.answer(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", s.standIn)
	if !strings.Contains(said, "gave "+s.standIn+" in place of the file the agent asked for") {
		t.Fatalf("tego alternate said %q", said)
	}
	evs := s.finish(t, run, dir)
	if got := s.out("got1.txt"); got != standInBody || strings.TrimSpace(s.out("rc1")) != "0" {
		t.Fatalf("the agent read %q (status %q); want the stand-in's bytes", got, s.out("rc1"))
	}
	if b, _ := os.ReadFile(s.secret); string(b) != realSecret {
		t.Fatal("the secret changed")
	}
	// An fs.ask_read entry outside the built-in list relaxes nothing, and run_start says nothing of it (ADR 0057 D4).
	if rs := runStartPayload(t, evs); len(rs.AskReadRelaxes) != 0 {
		t.Fatalf("run_start ask_read_relaxes %+v for an entry that relaxes no built-in", rs.AskReadRelaxes)
	}
	asks, answers, fs := lines(t, evs, record.KindAsk), lines(t, evs, record.KindAnswer), lines(t, evs, record.KindFS)
	if len(asks) != 1 || asks[0]["target"] != s.secret || asks[0]["op"] != "read" {
		t.Fatalf("ask lines %v", asks)
	}
	if len(answers) != 1 || answers[0]["alternate"] != s.standIn || answers[0]["approved"] != false || answers[0]["answer_reason"] != nil {
		t.Fatalf("answer lines %v: want the stand-in, nothing approved, nothing refused", answers)
	}
	// ADR 0057 D1: the stand-in's identity, as the person's command opened it, and the person's authority.
	var st unix.Stat_t
	if err := unix.Stat(s.standIn, &st); err != nil {
		t.Fatal(err)
	}
	if answers[0]["alternate_ino"] != float64(st.Ino) || answers[0]["alternate_dev"] != float64(st.Dev) || !strings.HasPrefix(answers[0]["by"].(string), "uid:") {
		t.Fatalf("answer line %v: want the stand-in's dev %d and ino %d and the person's uid", answers[0], st.Dev, st.Ino)
	}
	delivered := 0
	for _, l := range fs {
		if l["_authority"] == "human" {
			delivered++
			if l["path"] != s.standIn || l["alternate_for"] != s.secret || l["fd_delivered"] != true || l["_verdict"] != "allow" {
				t.Fatalf("the delivered open's line %v", l)
			}
		}
		if l["path"] == s.secret && l["_verdict"] == "allow" {
			t.Fatalf("a line says the secret was opened: %v", l)
		}
	}
	if delivered != 1 {
		t.Fatalf("%d human fs lines, want 1: %v", delivered, fs)
	}
}

// Approve, deny, and nobody answering: the read gets the secret, is refused ask-denied, or is refused ask-timeout
// once ask.timeout passes; each with its ask and answer pair.
func TestIntegrationAskReadApproveDenyAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name, verb, timeout string
		got, reason, by     string
	}{
		{"approve", "approve", "30s", realSecret, "", "uid:"},
		{"deny", "deny", "30s", "", "ask-denied", "uid:"},
		{"nobody answers", "", "2s", "", "ask-timeout", "timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAskReadScene(t, tc.timeout, 1)
			run, dir := s.start(t)
			req := s.pending(t, filepath.Base(dir))
			s.heldAndPaused(t, req)
			if tc.verb != "" {
				s.answer(t, tc.verb, filepath.Base(dir), req["ask_id"].(string))
			}
			evs := s.finish(t, run, dir)
			if got := s.out("got1.txt"); got != tc.got {
				t.Fatalf("the agent read %q; want %q", got, tc.got)
			}
			if rc := strings.TrimSpace(s.out("rc1")); (tc.reason == "") != (rc == "0") {
				t.Fatalf("cat exited %s", rc)
			}
			answers := lines(t, evs, record.KindAnswer)
			if len(answers) != 1 || !strings.HasPrefix(answers[0]["by"].(string), tc.by) || (tc.reason != "" && answers[0]["answer_reason"] != tc.reason) {
				t.Fatalf("answer lines %v", answers)
			}
			if tc.reason == "" {
				return
			}
			refused := false
			for _, l := range lines(t, evs, record.KindFS) {
				refused = refused || (l["path"] == s.secret && l["_verdict"] == "refused" && l["_reason"] == tc.reason && l["_rule"] == "fs.ask_read["+s.secret+"]")
			}
			if !refused {
				t.Fatalf("no refused line for the read, %s", tc.reason)
			}
		})
	}
}

// ask.on_timeout: refuse_always (custom-agent POC, item 3): nobody answers the first read, which is refused
// ask-timeout once ask.timeout passes, and the agent's two retries of the same read are refused at once, each its own
// ask and answer pair citing the timed-out ask, reason ask-timeout. Under the default each retry was held again for
// the whole timeout.
func TestIntegrationAskReadTimeoutStandsUnderRefuseAlways(t *testing.T) {
	s := newAskReadScene(t, "2s\n  on_timeout: refuse_always", 3)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	s.heldAndPaused(t, req)
	evs := s.finish(t, run, dir)
	for i := 1; i <= 3; i++ {
		if got, rc := s.out(fmt.Sprintf("got%d.txt", i)), strings.TrimSpace(s.out(fmt.Sprintf("rc%d", i))); got != "" || rc == "0" || rc == "" {
			t.Fatalf("read %d: got %q, status %q; want refused", i, got, rc)
		}
	}
	id := req["ask_id"].(string)
	answers := lines(t, evs, record.KindAnswer)
	if len(answers) != 3 || answers[0]["by"] != "timeout always" || answers[0]["answer_reason"] != "ask-timeout" {
		t.Fatalf("answer lines %v: want the timeout that stands, then two citing it", answers)
	}
	for _, a := range answers[1:] {
		if a["by"] != "standing:"+id || a["answer_reason"] != "ask-timeout" || a["after_s"].(float64) >= 1 {
			t.Fatalf("a retry's answer %v: want an immediate ask-timeout by standing:%s", a, id)
		}
	}
	if len(lines(t, evs, record.KindAsk)) != 3 {
		t.Fatal("a retry left no ask line of its own")
	}
	refused := 0
	for _, l := range lines(t, evs, record.KindFS) {
		if l["path"] == s.secret && l["_verdict"] == "refused" && l["_reason"] == "ask-timeout" {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("%d refused ask-timeout lines for the read, want 3", refused)
	}
}

// --always for reads: approve, deny or an alternate stands for the same read of the same file, so the agent's second
// read is answered at once, as its own recorded pair naming the person's answer.
func TestIntegrationAskReadAlwaysAnswersTheNextReadAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(s *askReadScene, run, id string) []string
		got  string
	}{
		{"approve --always", func(_ *askReadScene, run, id string) []string { return []string{"approve", run, id, "--always"} }, realSecret},
		{"deny --always", func(_ *askReadScene, run, id string) []string { return []string{"deny", run, id, "--always"} }, ""},
		{"alternate --always", func(s *askReadScene, run, id string) []string {
			return []string{"alternate", run, id, "--file", s.standIn, "--always"}
		}, standInBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAskReadScene(t, "30s", 2)
			run, dir := s.start(t)
			req := s.pending(t, filepath.Base(dir))
			s.heldAndPaused(t, req)
			said := s.answer(t, tc.args(s, filepath.Base(dir), req["ask_id"].(string))...)
			if !strings.Contains(said, "every later request for the same operation, rule and target in this run") {
				t.Fatalf("the answer said %q", said)
			}
			evs := s.finish(t, run, dir)
			for _, n := range []string{"got1.txt", "got2.txt"} {
				if got := s.out(n); got != tc.got {
					t.Fatalf("%s = %q; want %q", n, got, tc.got)
				}
			}
			answers := lines(t, evs, record.KindAnswer)
			if len(answers) != 2 || !strings.HasSuffix(answers[0]["by"].(string), " always") || answers[1]["by"] != "standing:"+req["ask_id"].(string) {
				t.Fatalf("answer lines %v: want the person's always answer, then one by standing:%s", answers, req["ask_id"])
			}
			if len(lines(t, evs, record.KindAsk)) != 2 {
				t.Fatal("the second read left no ask line of its own")
			}
		})
	}
}

// An fs.ask write-open answered with an alternate writes into the stand-in, never into the held target: the agent's
// redirect lands in the person's file, and the target keeps its bytes. The stand-in lies beneath the write entry in
// the project (the contract file's directory refuses no file beneath a write entry), and a git hook of a repository
// outside every entry, offered first, is refused (ADR 0057 D2): no write alternate is a file that runs code outside
// the run, nor one outside every write entry and fs.ask scope.
func TestIntegrationAskWriteAlternateWritesIntoTheStandIn(t *testing.T) {
	s := newScene(t, "30s", "  ask: [\"./held/\"]\n", "#!/bin/sh\necho AGENT-WROTE > held/config; echo $? > out/rc1\n")
	held := filepath.Join(s.f.dir, "held")
	if err := os.Mkdir(held, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "config"), []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, held, filepath.Join(held, "config"))
	hooks := filepath.Join(filepath.Dir(s.standIn), "otherrepo", ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(hooks, "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, hook)
	agentOwns(t, hook)
	standIn := filepath.Join(s.f.out, "stand-in")
	if err := os.WriteFile(standIn, []byte(standInBody), 0o600); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, standIn)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != "open" || req["target"] != filepath.Join(held, "config") {
		t.Fatalf("the held request %v: want the write-open of held/config", req)
	}
	said, code := s.try(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", hook)
	if code == 0 || !strings.Contains(said, "git hooks, which runs code outside the run") {
		t.Fatalf("tego alternate of a git hook exited %d: %q", code, said)
	}
	said = s.answer(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", standIn)
	if !strings.Contains(said, "gave "+standIn) {
		t.Fatalf("tego alternate said %q", said)
	}
	evs := s.finish(t, run, dir)
	if b, _ := os.ReadFile(standIn); string(b) != "AGENT-WROTE\n" || strings.TrimSpace(s.out("rc1")) != "0" {
		t.Fatalf("the stand-in holds %q (status %q); want the agent's write", b, s.out("rc1"))
	}
	if b, _ := os.ReadFile(filepath.Join(held, "config")); string(b) != "ORIGINAL\n" {
		t.Fatalf("the held target changed: %q", b)
	}
	if b, _ := os.ReadFile(hook); string(b) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("the refused hook changed: %q", b)
	}
	if answers := lines(t, evs, record.KindAnswer); len(answers) != 1 || answers[0]["alternate"] != standIn {
		t.Fatalf("answer lines %v", answers)
	}
}

// The launcher hands the supervisor $XDG_RUNTIME_DIR/tego, which the compiled table does not name (ADR 0057 D2): a
// person's alternate beneath it (the last-refusal mirror's directory, a run's CODEX_HOME) is refused as tego's own
// state, and the held read is still the person's to answer.
func TestIntegrationAskReadAlternateRefusedFromTheRuntimeDirectory(t *testing.T) {
	s := newAskReadScene(t, "30s", 1)
	xdg, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(xdg, "tego", "planted")
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte(standInBody), 0o600); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, planted)
	agentOwns(t, planted)
	s.env = append(s.env, "XDG_RUNTIME_DIR="+xdg)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	s.heldAndPaused(t, req)
	said, code := s.try(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", planted)
	if code == 0 || !strings.Contains(said, "tego's own state "+filepath.Join(xdg, "tego")) {
		t.Fatalf("tego alternate of a file under $XDG_RUNTIME_DIR/tego exited %d: %q", code, said)
	}
	s.answer(t, "deny", filepath.Base(dir), req["ask_id"].(string))
	evs := s.finish(t, run, dir)
	if got := s.out("got1.txt"); got != "" {
		t.Fatalf("the agent read %q", got)
	}
	if answers := lines(t, evs, record.KindAnswer); len(answers) != 1 || answers[0]["alternate"] != nil || answers[0]["answer_reason"] != "ask-denied" {
		t.Fatalf("answer lines %v: want the denial alone", answers)
	}
}

// ADR 0057 D4 in the record: a top-level fs.ask_read entry at the project's .env, a file of the built-in deny_read
// list, replaces the built-in entry, and the run's run_start names it in ask_read_relaxes.
func TestIntegrationRunStartNamesTheRelaxedBuiltIn(t *testing.T) {
	var env string
	f := newFixtureWithMachine(t, `version: 0
name: irelax
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  ask_read: ["./.env"]
exec:
  allow: ["/bin/sh"]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, func(m *config.Machine) {
		env = filepath.Join(m.Home, ".env") // the fixture's project, which compile scans for .env files
		if err := os.WriteFile(env, []byte("TOKEN=real\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	s := &askReadScene{f: f, bin: tegoBinary(t)}
	s.env = isolatedEnv(t, f)
	if err := os.WriteFile(filepath.Join(f.dir, "agent.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(f.dir, "agent.sh"))
	// The agent exits at once, so the run is found after it ends: start's poll for a live run can miss it.
	got := runStartPayload(t, s.runToEnd(t)).AskReadRelaxes
	if len(got) != 1 || got[0].Rule != "fs.ask_read[./.env]" || got[0].BuiltIn != env || got[0].How != "replaces" {
		t.Fatalf("run_start ask_read_relaxes = %+v; want the built-in %s, replaced by fs.ask_read[./.env]", got, env)
	}
}

// An observe run cannot ask, a held read included: `tego run --observe` of an fs.ask_read contract is refused
// before the agent starts (exit 125), never run with the entry silently left unenforced.
func TestIntegrationAskReadObserveRunIsRefused(t *testing.T) {
	s := newAskReadScene(t, "30s", 1)
	run := s.tego(t, "run", "--observe", filepath.Join(s.f.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	run.Dir = s.f.dir
	out, err := run.CombinedOutput()
	if code := exitCodeOf(t, err); code != 125 || !strings.Contains(string(out), "fs.ask_read") {
		t.Fatalf("tego run --observe exited %d:\n%s", code, out)
	}
	if s.out("rc1") != "" {
		t.Fatal("the agent ran")
	}
}

// A file the contract's gate refuses is never an alternate, read or write, and the delivered open's
// line carries the gate's decision on the file delivered. Read: `fs.read matches "*.pem"` at 90, a .pem
// beside the stand-in offered first is refused by `tego alternate`, naming the gate, and the stand-in that follows
// is delivered with score 0. Write: `fs.write outside worktree` at 90 and an fs.ask scope outside the project; the
// held write of held/config answered with a file in that scope, outside the worktree, is refused, and the file keeps
// its bytes; the stand-in in ./out/ that follows is written.
func TestIntegrationAlternateIsPutToTheGate(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		s := newScene(t, "30s", "gate:\n  rules:\n    - 'fs.read matches \"*.pem\"': 90\n",
			"#!/bin/sh\ncat \"$SECRET\" > out/got1.txt 2> out/err1.txt; echo $? > out/rc1\n")
		pem := filepath.Join(filepath.Dir(s.standIn), "x.pem")
		if err := os.WriteFile(pem, []byte("GATE-REFUSED-PEM\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, pem)
		run, dir := s.start(t)
		req := s.pending(t, filepath.Base(dir))
		s.heldAndPaused(t, req)
		said, code := s.try(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", pem)
		if code == 0 || !strings.Contains(said, "refused by the contract's gate (gate.rules[0], score 90)") {
			t.Fatalf("tego alternate of a file the read gate refuses exited %d: %q", code, said)
		}
		s.answer(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", s.standIn)
		evs := s.finish(t, run, dir)
		if got := s.out("got1.txt"); got != standInBody {
			t.Fatalf("the agent read %q; want the stand-in's bytes", got)
		}
		delivered := 0
		for _, l := range lines(t, evs, record.KindFS) {
			if l["_authority"] != "human" {
				continue
			}
			delivered++
			if l["path"] != s.standIn || l["score"] != float64(0) || l["gate_rule"] != nil || l["gate_outcome"] != "ask" {
				t.Fatalf("the delivered open's line %v: want the stand-in's own gate decision, score 0", l)
			}
		}
		if delivered != 1 {
			t.Fatalf("%d delivered lines, want 1", delivered)
		}
	})
	t.Run("write", func(t *testing.T) {
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s := newScene(t, "30s", fmt.Sprintf("  ask: [\"./held/\", %q]\ngate:\n  rules:\n    - fs.write outside worktree: 90\n", outside+"/"),
			"#!/bin/sh\necho AGENT-WROTE > held/config; echo $? > out/rc1\n")
		held := filepath.Join(s.f.dir, "held")
		if err := os.Mkdir(held, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(held, "config"), []byte("ORIGINAL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		far := filepath.Join(outside, "x")
		if err := os.WriteFile(far, []byte("ORIGINAL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		standIn := filepath.Join(s.f.out, "stand-in")
		if err := os.WriteFile(standIn, []byte(standInBody), 0o600); err != nil {
			t.Fatal(err)
		}
		agentReaches(t, far)
		agentOwns(t, held, filepath.Join(held, "config"), outside, far, standIn)
		run, dir := s.start(t)
		req := s.pending(t, filepath.Base(dir))
		if req["op"] != "open" || req["target"] != filepath.Join(held, "config") {
			t.Fatalf("the held request %v: want the write-open of held/config", req)
		}
		said, code := s.try(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", far)
		if code == 0 || !strings.Contains(said, "refused by the contract's gate (gate.rules[0], score 90)") {
			t.Fatalf("tego alternate of a file the write gate refuses exited %d: %q", code, said)
		}
		s.answer(t, "alternate", filepath.Base(dir), req["ask_id"].(string), "--file", standIn)
		s.finish(t, run, dir)
		if b, _ := os.ReadFile(far); string(b) != "ORIGINAL\n" {
			t.Fatalf("the file the gate refuses was written: %q", b)
		}
		if b, _ := os.ReadFile(standIn); string(b) != "AGENT-WROTE\n" {
			t.Fatalf("the stand-in holds %q; want the agent's write", b)
		}
	})
}
