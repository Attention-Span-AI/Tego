// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

// machineNothing says, for this test, that none of the agents' programs is on PATH.
func machineNothing(t *testing.T) {
	t.Helper()
	prev := guideLookPath
	t.Cleanup(func() { guideLookPath = prev })
	guideLookPath = func(string) (string, error) { return "", errors.New("not on PATH") }
}

// TestGuideFirstChoiceFollowsTheMachine: what the first question offers first depends on what this machine has. An agent
// that is installed and signed in comes first, and nothing else may; with none, the demonstration agent comes first and
// the guide says why in one line. Each agent's line says what the guide found.
func TestGuideFirstChoiceFollowsTheMachine(t *testing.T) {
	const why = "No agent here is installed and signed in, so the demonstration agent is first: it needs no account and no network."
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, home string)
		first string
		says  map[string]string // an agent's label, and the words its line must hold
		why   bool
	}{
		{"nothing is installed", func(t *testing.T, _ string) { machineNothing(t) }, guideDemo.label,
			map[string]string{"Claude Code": "not installed", "Codex": "not installed"}, true},
		{"installed, not signed in", func(t *testing.T, _ string) { fakeProgram(t, "claude") }, guideDemo.label,
			map[string]string{"Claude Code": "installed, not signed in", "Codex": "not installed"}, true},
		{"signed in but not installed", func(t *testing.T, _ string) {
			machineNothing(t)
			t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
		}, guideDemo.label, map[string]string{"Claude Code": "not installed"}, true},
		{"installed and signed in", func(t *testing.T, _ string) {
			fakeProgram(t, "claude")
			t.Setenv("ANTHROPIC_API_KEY", "x")
		}, "Claude Code", map[string]string{"Claude Code": "installed, signed in", "Codex": "not installed"}, false},
		{"installed and signed in with a saved login", func(t *testing.T, home string) {
			fakeProgram(t, "codex")
			if err := saveLogin(home, "CODEX_API_KEY", "saved-token"); err != nil {
				t.Fatal(err)
			}
		}, "Codex", map[string]string{"Codex": "installed, signed in", "Claude Code": "not installed"}, false},
		{"two agents ready keep their order", func(t *testing.T, _ string) {
			fakeProgram(t, "claude")
			fakeProgram(t, "codex")
			t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
			t.Setenv("CODEX_API_KEY", "y")
		}, "Claude Code", map[string]string{"Claude Code": "installed, signed in", "Codex": "installed, signed in"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			tt.setup(t, f.Home)
			items, agents, why1 := agentChoices(f.Home)
			if agents[0].label != tt.first {
				t.Errorf("first choice is %q, want %q", agents[0].label, tt.first)
			}
			if !items[0].recommended || items[1].recommended {
				t.Errorf("recommended marks: %+v", items)
			}
			if (why1 == why) != tt.why || (why1 != "" && why1 != why) {
				t.Errorf("the one-line reason is %q, want it %v: %q", why1, tt.why, why)
			}
			if strings.Contains(why1, "\n") {
				t.Errorf("the reason is not one line: %q", why1)
			}
			for i, a := range agents {
				if want, ok := tt.says[a.label]; ok && !strings.Contains(items[i].desc, want) {
					t.Errorf("%s: %q lacks %q", a.label, items[i].desc, want)
				}
			}
			// The same through the guide's own output: the line is printed above the question, once.
			_, out, _ := runGuide(t, "1\n")
			if got := strings.Count(out, why); got != map[bool]int{true: 1, false: 0}[tt.why] {
				t.Errorf("the reason is printed %d times:\n%s", got, out)
			}
			if strings.Contains(strings.ToLower(out), "coding") {
				t.Errorf("a word for code agents only:\n%s", out)
			}
		})
	}
}

// demoGuide runs the guide for a person who takes the first choice on a machine with nothing in it, and returns what
// it printed.
func demoGuide(t *testing.T, answers string) (home, out string) {
	t.Helper()
	f := onFixture(t, "fresh")
	noLogins(t)
	machineNothing(t)
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, answers)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	return f.Home, out
}

// TestGuideFirstRunWithNoAccount: with nothing installed the first choice is the demonstration agent, and taking it
// ends with a governed run: no question about a login, a program or a project, and the rules are the demonstration's.
func TestGuideFirstRunWithNoAccount(t *testing.T) {
	home, out := demoGuide(t, "1\n")
	sample := filepath.Join(home, guideSample)
	wantAll(t, "first run", out,
		"No agent here is installed and signed in, so the demonstration agent is first",
		"1/4  Agent", "Demonstration agent (recommended)", "2/4  Login", "Nothing to log in to: the demonstration agent runs on this machine, with no account and no network",
		"3/4  Project", "✓ Created ~/tego-sample", "4/4  Rules", "✓ Created agent tego-demo", "Writes only in demo-out/ · never reads secrets · reaches no host",
		"Ready", "Agent       tego-demo · Demonstration agent", "Rules       Demonstration rules",
		"First run", "The demonstration run finished. One action was allowed and one refused",
		"Next steps", "tego session show --last", "cd "+sample+" && tego run tego-demo", "tego rules edit tego-demo", "tego start")
	for _, no := range []string{"How do you want to log in", "Which project", "Which rules", "Install "} {
		if strings.Contains(out, no) {
			t.Errorf("the demonstration asked %q:\n%s", no, out)
		}
	}
	if !reflect.DeepEqual(demoRuns, []string{sample + " tego-demo"}) {
		t.Errorf("the guide ran %q, want the demonstration once in the test project", demoRuns)
	}
	// The saved rules: the one command tego init writes, one folder to write in, no network, no whole-project write.
	rules := savedRules(t, guideDemoName)
	wantAll(t, "demonstration rules", rules, `name: "tego-demo"`, "./"+guideDemoOut+"/", "tego/no-secrets", "tego/no-prod", "tego/repo-only-writes",
		"allowed", "refused by repo-only-writes")
	if strings.Contains(rules, `- "./"`) || strings.Contains(rules, home+`/"`) {
		t.Errorf("the demonstration may write the whole project:\n%s", rules)
	}
	if _, err := os.Stat(filepath.Join(sample, guideDemoOut)); err != nil {
		t.Errorf("the folder the demonstration writes in was not made: %v", err)
	}
	// The saved file is one tego run compiles from the project, with the shell as its program and nothing else to start.
	t.Chdir(sample)
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	rt, _, _, code := compileForRun(t.Context(), runOptions{contract: guideDemoName, offline: true}, m, &diagnostics)
	if code != identity.ExitOK {
		t.Fatalf("compile exit %d: %s", code, &diagnostics)
	}
	if got := commandFor(runOptions{}, rt); len(got) < 3 || got[0] != "/bin/sh" || got[1] != "-c" {
		t.Errorf("the demonstration's command is %q", got)
	}
	if len(rt.Net) != 0 {
		t.Errorf("the demonstration may reach hosts: %+v", rt.Net)
	}
}

// TestGuideDemonstrationKeepsEditedRules: the second time, the agent's rules are kept unless the person replaces them,
// as for any agent, and the demonstration still runs.
func TestGuideDemonstrationKeepsEditedRules(t *testing.T) {
	home, _ := demoGuide(t, "1\n")
	path := filepath.Join(home, ".config/tego/agents", guideDemoName+".yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	demoRuns = nil
	code, out, errs := runGuide(t, "1\n1\n") // the first question, then "No" to replacing the rules
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "second run", out, "Agent tego-demo already exists. Replace its rules?", "✓ Kept agent tego-demo", "The demonstration run finished")
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Errorf("kept rules changed")
	}
	if len(demoRuns) != 1 {
		t.Errorf("runs: %q", demoRuns)
	}
}

// TestGuideDemonstrationRunFailure: a run that fails is said so, the next steps still show how to run it again, and the
// guide ends with a finding rather than at a dead end.
func TestGuideDemonstrationRunFailure(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	machineNothing(t)
	t.Chdir(f.Home)
	guideDemoRun = func(context.Context, string, string) error { return errors.New("exit status 125") }
	code, out, errs := runGuide(t, "1\n")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "failed run", out, "✗ The demonstration run did not finish: exit status 125", "Run it again", "tego run tego-demo")
}

// TestGuideNoAgentInstalledOffersAWayBack: a person who picks an agent they have no account for is never left at its
// login: the question has a way back to the first question, and the demonstration agent ends the walk in a first run.
func TestGuideNoAgentInstalledOffersAWayBack(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	// Claude Code is second (installed, not signed in); at its login the last choice goes back; then the demonstration.
	code, out, errs := runGuide(t, "2\n3\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "way back", out, "How do you want to log in to Claude Code?", "Choose another agent", "The demonstration run finished")
	if got := strings.Count(out, "1/4  Agent"); got != 2 {
		t.Errorf("the first question was asked %d times, want 2:\n%s", got, out)
	}
	if !reflect.DeepEqual(demoRuns, []string{filepath.Join(f.Home, guideSample) + " tego-demo"}) {
		t.Errorf("runs: %q", demoRuns)
	}
}

// TestGuideSignInLeftReturnsToTheQuestion: a sign-in that ends without a login (the person left it with Ctrl-C, or it
// failed) asks the login question again, and the next try goes on.
func TestGuideSignInLeftReturnsToTheQuestion(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	calls := 0
	prev := guideSetupToken
	t.Cleanup(func() { guideSetupToken = prev })
	guideSetupToken = func(context.Context, string, string) (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New("exit status 130")
		}
		return "sk-ant-oat01-second-try-0123456789", nil
	}
	code, out, errs := runGuide(t, "2\n1\n1\n2\n1\n1\n")
	if code != identity.ExitOK || calls != 2 {
		t.Fatalf("exit %d after %d sign-ins\n%s\n%s", code, calls, out, errs)
	}
	wantAll(t, "left sign-in", out, "Claude Code's sign-in ended without a login. Tego asks again.", "✓ Logged in to Claude Code")
	if got := strings.Count(out, "How do you want to log in to Claude Code?"); got != 2 {
		t.Errorf("the login question was asked %d times, want 2:\n%s", got, out)
	}
}

// TestGuideLeavable: the key that leaves a step ends the step's context and not the guide's; the guide's own stop wins
// over it; a step nobody pressed a key in is not left; and once the step is over the key is the guide's again. The
// installer and the sign-in going back to their question on a real terminal is TestGuideLeavesWhatItStarted.
func TestGuideLeavable(t *testing.T) {
	var out bytes.Buffer
	g := newWalk(strings.NewReader(""), &out, false)
	g.terminal = &guideTerminal{}
	left, err := g.leavable(context.Background(), func(ctx context.Context) {
		if !g.terminal.leaving() {
			t.Error("no step is running that a key could leave")
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second): // a step the key did not end: the test fails, it does not hang
			t.Error("the key did not end the step")
		}
	})
	if !left || err != nil {
		t.Errorf("a step the key left: left=%v err=%v", left, err)
	}
	if g.terminal.leaving() {
		t.Error("the key still leaves a step that is over")
	}
	if left, err = g.leavable(context.Background(), func(context.Context) {}); left || err != nil {
		t.Errorf("a step that finished: left=%v err=%v", left, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	left, err = g.leavable(ctx, func(context.Context) { stop(); g.terminal.leaving() })
	if left || !errors.Is(err, errStopped) {
		t.Errorf("the guide's own stop: left=%v err=%v", left, err)
	}
}

// TestGuideWordsFitEveryAgent: nothing the guide says at a step takes the agent for one that writes code.
func TestGuideWordsFitEveryAgent(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, "1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, word := range []string{"coding", "developer", "edits and tests"} {
		if strings.Contains(strings.ToLower(out), word) {
			t.Errorf("the guide says %q:\n%s", word, out)
		}
	}
}

// guideStateRoutes are the three machine states driven through a real terminal to the end of the guide. Each step waits
// for text after the previous step's and then types its keys.
func guideStateRoutes() map[string]struct {
	steps []guidePTYStep
	wants []string
} {
	return map[string]struct {
		steps []guidePTYStep
		wants []string
	}{
		// Nothing installed: the first choice is the demonstration agent, and the first run follows.
		"nothing": {[]guidePTYStep{{"Which agent do you want to supervise?", "\r"}},
			[]string{"[demo-ran tego-sample tego-demo]", "The demonstration run finished", "Next steps", "tego start"}},
		// Installed, not signed in: Claude Code's sign-in is left with one key, the login question comes back, the way
		// back leads to the first question, and the demonstration ends the walk in a first run.
		"unsigned": {[]guidePTYStep{
			{"Which agent do you want to supervise?", "\x1b[B\r"},
			{"How do you want to log in to Claude Code?", "\r"},
			{"[signin-ready]", "\x03"},
			{"sign-in ended without a login", ""},
			{"How do you want to log in to Claude Code?", "\x1b[B\x1b[B\r"},
			{"1/4  Agent", ""},
			{"Which agent do you want to supervise?", "\r"}},
			[]string{"[demo-ran tego-sample tego-demo]", "The demonstration run finished", "Next steps"}},
		// Signed in: the agent stays first and the guide ends with the command that starts its first session.
		"signedin": {[]guidePTYStep{
			{"Which agent do you want to supervise?", "\r"},
			{"Which project should Claude Code work in?", "\r"},
			{"Which rules should Claude Code follow?", "\r"}},
			[]string{"✓ Logged in to Claude Code", "Ready", "Next steps", "tego run tego-sample"}},
	}
}

// TestGuideMachineStates drives the guide on a terminal for each state of the machine, and every walk ends in a first run
// or in the guide's own end, with the terminal as it was and no process left behind.
func TestGuideMachineStates(t *testing.T) {
	if state := os.Getenv("TEGO_TEST_GUIDE_STATE"); state != "" {
		guideStateHelper(t, state)
		return
	}
	for name, route := range guideStateRoutes() {
		t.Run(name, func(t *testing.T) { t.Parallel(); runGuideToEnd(t, name, route.steps, route.wants) })
	}
}

// guideStateHelper is the guide in the child process of TestGuideMachineStates: this machine's state is made, what the
// guide would start is replaced by stand-ins, and the guide runs on the real terminal it was given.
func guideStateHelper(t *testing.T, state string) {
	t.Helper()
	f := onFixture(t, "fresh")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	noLogins(t)
	prevDashboard, prevDemo, prevLook, prevInstall := guideDashboard, guideDemoRun, guideLookPath, guideInstall
	t.Cleanup(func() {
		guideDashboard, guideDemoRun, guideLookPath, guideInstall = prevDashboard, prevDemo, prevLook, prevInstall
	})
	guideDashboard = func(context.Context, string) string { return "" }
	guideInstall = func(context.Context, string, io.Writer) error {
		t.Error("the guide ran an installer")
		return errStopped
	}
	guideDemoRun = func(_ context.Context, dir, agent string) error {
		fmt.Printf("[demo-ran %s %s]\n", filepath.Base(dir), agent)
		return nil
	}
	switch state {
	case "nothing":
		guideLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	case "unsigned":
		// Claude Code is installed. Its own sign-in waits on the terminal until the person's Ctrl-C ends it.
		bin := t.TempDir()
		program := filepath.Join(bin, "claude")
		text := "#!/bin/sh\n[ \"$1\" = setup-token ] || exit 0\necho $$ > \"$TEGO_TEST_GUIDE_CHILD_PID\"\nprintf '[signin-ready]' > /dev/tty\nexec sleep 300\n"
		if err := os.WriteFile(program, []byte(text), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
		look := guideLookPath
		guideLookPath = func(name string) (string, error) {
			switch name {
			case "claude":
				return program, nil
			case "script":
				return "", os.ErrNotExist
			}
			return look(name)
		}
		guideSetupToken = realGuideChildLogin
	case "signedin":
		fakeProgram(t, "claude")
		t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-login")
	default:
		t.Fatal("unknown state")
	}
	t.Chdir(f.Home)
	ctx, stop := notifyContext()
	defer stop()
	if code := runSetupGuide(ctx, os.Stdin, os.Stdout, os.Stderr, true); code != identity.ExitOK {
		t.Fatalf("the guide ended with exit %d, not at a first run or its own end", code)
	}
}

// runGuideToEnd runs this test binary's helper for state on a pseudo-terminal, types each step's keys once its text is
// on the screen, and holds the walk to its end: exit 0, each wanted text printed, the terminal's modes as they were, and
// the sign-in's process gone.
func runGuideToEnd(t *testing.T, state string, steps []guidePTYStep, wants []string) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("pseudo-terminal unavailable: %v", err)
	}
	master := os.NewFile(uintptr(fd), "pty")
	defer func() { _ = master.Close() }()
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("pseudo-terminal unlock unavailable: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slave.Close() }()
	if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		t.Fatal(err)
	}
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childPID := filepath.Join(t.TempDir(), "pid")
	t.Cleanup(func() {
		b, _ := os.ReadFile(childPID)
		for _, value := range strings.Fields(string(b)) {
			if pid, _ := strconv.Atoi(value); pid > 1 {
				_ = unix.Kill(-pid, unix.SIGKILL)
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
	})
	c := exec.Command(self, "-test.run=^TestGuideMachineStates$")
	c.Env = append(os.Environ(), "TEGO_TEST_GUIDE_STATE="+state, "TEGO_TEST_GUIDE_CHILD_PID="+childPID, "TERM=xterm-256color")
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var childErr error
	go func() { childErr = c.Wait(); close(done) }()
	defer func() { _ = c.Process.Kill(); <-done }()
	var (
		mu      sync.Mutex
		trace   bytes.Buffer
		changed = make(chan struct{}, 1)
		readEnd = make(chan struct{})
	)
	snapshot := func() string { mu.Lock(); defer mu.Unlock(); return trace.String() }
	go func() {
		defer close(readEnd)
		b := make([]byte, 4096)
		// The terminal answers the three capability queries a form asks (as xterm does), once each however split.
		queries := []struct {
			q, a string
			seen int
		}{{"\x1b[?2026$p", "\x1b[?2026;2$y", 0}, {"\x1b[?2027$p", "\x1b[?2027;0$y", 0}, {"\x1b[?u", "\x1b[?0u", 0}}
		for {
			n, e := master.Read(b)
			if n > 0 {
				mu.Lock()
				trace.Write(b[:n])
				current := trace.String()
				mu.Unlock()
				select {
				case changed <- struct{}{}:
				default:
				}
				for i := range queries {
					q := &queries[i]
					for count := strings.Count(current, q.q); q.seen < count; q.seen++ {
						if _, err := master.Write([]byte(q.a)); err != nil {
							return
						}
					}
				}
			}
			if e != nil {
				return
			}
		}
	}()
	defer func() {
		_ = master.Close()
		select {
		case <-readEnd:
		case <-time.After(15 * time.Second):
			t.Error("PTY reader did not finish")
		}
	}()
	pos := 0
	for _, step := range steps {
		deadline := time.NewTimer(guidePromptHangGuard)
		for {
			out := snapshot()
			if i := strings.Index(out[pos:], step.prompt); i >= 0 {
				pos += i + len(step.prompt)
				break
			}
			select {
			case <-changed:
			case <-done:
				deadline.Stop()
				t.Fatalf("the guide ended before %q: %v\n%s", step.prompt, childErr, snapshot())
			case <-deadline.C:
				t.Fatalf("no %q within the hang guard:\n%s", step.prompt, snapshot())
			}
		}
		deadline.Stop()
		if step.keys != "" {
			if _, err := master.Write([]byte(step.keys)); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case <-done:
		if childErr != nil {
			t.Fatalf("the guide did not end well: %v\n%s", childErr, snapshot())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the guide did not end:\n%s", snapshot())
	}
	out := snapshot()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("the walk's output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Stopped. Run tego start") {
		t.Errorf("the walk ended at a stop:\n%s", out)
	}
	if b, err := os.ReadFile(childPID); err == nil {
		for _, value := range strings.Fields(string(b)) {
			pid, _ := strconv.Atoi(value)
			for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil || strings.Contains(string(st), ") Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the sign-in's process %d is still running", pid)
				}
			}
		}
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored: before %+v after %+v", before, after)
	}
}
