// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

type guidePTYStep struct{ prompt, keys string }
type guidePTYRoute struct {
	name  string
	steps []guidePTYStep
}

// These routes reach every question, including the alternate login and rules
// paths. Every external action is a stand-in; the real guide owns the forms.
func guidePTYRoutes() []guidePTYRoute {
	agent := guidePTYStep{"Which agent do you want to supervise?", "\r"}
	// With no login in the shell, Claude Code is installed but not signed in, so the demonstration agent is first and
	// Claude Code is the second item.
	claude := agent
	claude.keys = "\x1b[B\r"
	shellAgent := agent
	shellAgent.keys = "\t/zzzz\r\x7f\x7f\x7f\x7fClaude\r"
	project := guidePTYStep{"Which project should Claude Code work in?", "\x1b[B\r"}
	rules := guidePTYStep{"Which rules should Claude Code follow?", "\r"}
	return []guidePTYRoute{
		{"shell", []guidePTYStep{shellAgent, project, rules}},
		{"login", []guidePTYStep{claude,
			{"How do you want to log in to Claude Code?", "\x1b[B\r"},
			{"Paste your Anthropic API key", "\r\x1b[200~test-token\x1b[201~\t\r"},
			{"Save the login for later sessions?", "\x1b[B\r"},
			{project.prompt, "\x1b[B\x1b[B\r"},
			{"Path to the project", "~/missing\r\x15~/bot\r"},
			{rules.prompt, "\x1b[B\x1b[B\r"},
			{"Which rules?", "/no\r\r"},
			{"Other hosts it may reach", "api.github.com\r"}}},
		{"command", []guidePTYStep{{agent.prompt, "\x1b[B\x1b[B\r"}, {"What command starts it?", "claude\r"},
			{"Which project should claude work in?", "\x1b[B\r"}, {"Which rules should claude follow?", "\r"}}},
		{"install", []guidePTYStep{claude, {"Install Claude Code now?", "\r"}}},
		{"saved", []guidePTYStep{agent, {"Use your saved Claude Code login?", "\r"}}},
		{"secret", []guidePTYStep{claude, {"How do you want to log in to Claude Code?", "\x1b[B\r"},
			{"Paste your Anthropic API key", "test-token\r/SECOND_SECRET"},
			{"Save the login for later sessions?", "\x1b[B\r"}, project}},
		{"subscription", []guidePTYStep{claude, {"How do you want to log in to Claude Code?", "\r"},
			{"Paste the token Claude Code printed", "test-token\r"}}},
		{"file", []guidePTYStep{agent, project, {rules.prompt, "\x1b[B\x1b[B\x1b[B\r"}, {"Path to the rules file", "~/own.yaml\r"}}},
		{"replace", []guidePTYStep{agent, project, rules, {"Agent bot already exists. Replace its rules?", "\r"}}},
	}
}

func TestGuideInterruptRestoresTerminal(t *testing.T) {
	if route := os.Getenv("TEGO_TEST_GUIDE_INTERRUPT"); route != "" {
		guidePTYHelper(t, route)
		return
	}
	// Preserve the original reproduction, including the separately delivered down
	// arrow and Enter. Also interrupt each distinct question by key and signal.
	seen := map[string]bool{}
	for _, route := range guidePTYRoutes() {
		for i, step := range route.steps {
			if seen[step.prompt] {
				continue
			}
			seen[step.prompt] = true
			for _, how := range []string{"key", "signal", "hup"} {
				t.Run(route.name+"/"+strconv.Itoa(i)+"/"+how, func(t *testing.T) { t.Parallel(); runGuidePTY(t, route, i, how, false) })
			}
		}
	}
	// Navigate every boundary both on the first paint and before the next form
	// starts reading. The final prompt is interrupted before any files are saved.
	for _, before := range []bool{false, true} {
		for _, route := range guidePTYRoutes() {
			t.Run(fmt.Sprintf("typed-ahead/%s/%t", route.name, before), func(t *testing.T) { t.Parallel(); runGuidePTY(t, route, len(route.steps)-1, "key", before) })
		}
	}
	t.Run("typed-ahead/burst", func(t *testing.T) {
		t.Parallel()
		route := guidePTYRoutes()[0]
		runGuidePTY(t, route, len(route.steps)-1, "burst", false)
	})

}

// guidePTYOutput can hold the guide between questions, after the previous form
// returned but before the next one starts. The parent queues a real terminal key
// before releasing it, without a timing sleep or a product test hook.
type guidePTYOutput struct {
	*os.File
	steps []guidePTYStep
	gate  *os.File
	next  int
	mu    sync.Mutex
}

func (w *guidePTYOutput) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func (w *guidePTYOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.next < len(w.steps) {
		first := w.next == 0 && bytes.Contains(b, []byte(w.steps[0].prompt))
		boundary := w.next > 0 && bytes.Contains(b, []byte(w.steps[w.next-1].prompt+"  "))
		if first || boundary {
			if _, err := fmt.Fprintf(w.File, "[before:%s]", w.steps[w.next].prompt); err != nil {
				return 0, err
			}
			var ack [1]byte
			if _, err := io.ReadFull(w.gate, ack[:]); err != nil {
				return 0, err
			}
			w.next++
		}
	}
	return w.File.Write(b)
}

// guideLeaveSteps is, for a route whose last step runs something the guide started, the line the guide prints when one
// key leaves it and the question it then asks again.
var guideLeaveSteps = map[string]struct{ marker, question string }{
	"child-installer": {"Stopped the installer.", "Install Claude Code now?"},
	"child-signin":    {"sign-in ended without a login", "How do you want to log in to Claude Code?"},
}

func guidePTYHelper(t *testing.T, routeName string) {
	t.Helper()
	var route guidePTYRoute
	for _, r := range append(append(append(append(guidePTYRoutes(), guideChildRoutes()...), guideDumbRoutes()...), guideHandoffRoutes()...), guideSigninRoute()) {
		if r.name == routeName {
			route = r
		}
	}
	if len(route.steps) == 0 {
		t.Fatal("unknown route")
	}
	f := onFixture(t, "fresh")
	term := "xterm-256color"
	if routeName == "dumb" {
		term = "dumb"
	}
	t.Setenv("TERM", term)
	t.Setenv("NO_COLOR", "1")
	noLogins(t)
	fakeProgram(t, "claude")
	if routeName != "login" && routeName != "subscription" && routeName != "secret" && routeName != "dumb" && !strings.HasPrefix(routeName, "handoff-") {
		t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-login")
	}
	previousLogin, previousDashboard, previousLook, previousInstall := guideSetupToken, guideDashboard, guideLookPath, guideInstall
	t.Cleanup(func() {
		guideSetupToken, guideDashboard, guideLookPath, guideInstall = previousLogin, previousDashboard, previousLook, previousInstall
	})
	guideSetupToken = func(context.Context, string, string) (string, error) {
		if strings.HasPrefix(routeName, "handoff-") {
			return guideHandoffToken(t)
		}
		return "", nil
	}
	guideDashboard = func(context.Context, string) string { t.Error("interrupted guide started dashboard"); return "" }
	guideInstall = func(context.Context, string, io.Writer) error {
		t.Error("interrupted guide ran installer")
		return errStopped
	}
	if routeName == "install" {
		guideLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	}
	if routeName == "saved" {
		if err := saveLogin(f.Home, "CLAUDE_CODE_OAUTH_TOKEN", "saved-token"); err != nil {
			t.Fatal(err)
		}
	}
	if routeName == "replace" {
		if code, out, errs := runGuide(t, "1\n2\n1\n"); code != identity.ExitOK {
			t.Fatalf("initial rules: %d %s %s", code, out, errs)
		}
	}
	if strings.HasPrefix(routeName, "child-") {
		guideChildActions(routeName)
		prepareGuideChild(t, routeName)
	}
	before := guidePTYFiles(t, f.Home)
	var out io.Writer = os.Stdout
	if os.Getenv("TEGO_TEST_GUIDE_AHEAD") == "1" {
		gate := os.NewFile(3, "guide-test-gate")
		defer func() { _ = gate.Close() }()
		out = &guidePTYOutput{File: os.Stdout, steps: route.steps, gate: gate}
	}
	ctx, stop := notifyContext()
	defer stop()
	if code := runSetupGuideCommand(ctx, out, os.Stderr); code != identity.ExitFinding {
		t.Fatalf("interrupt exit %d", code)
	}
	if routeName == "handoff-secret" && os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "test-token" {
		t.Error("sign-in tail answered the token question")
	}
	if routeName == "child-systemd-run" || routeName == "child-dashboard-poll" {
		b, err := os.ReadFile(os.Getenv("TEGO_TEST_GUIDE_STOP_CALLS"))
		if err != nil || strings.Count(string(b), "stop\n") < 2 {
			t.Errorf("cancelled dashboard unit was not stopped: %q %v", b, err)
		}
	}
	if err := filepath.WalkDir(f.Home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".tego-save-") || strings.HasPrefix(entry.Name(), "sign-in-") {
			return fmt.Errorf("partial setup file: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if after := guidePTYFiles(t, f.Home); !strings.HasPrefix(routeName, "child-") && !reflect.DeepEqual(before, after) {
		t.Fatalf("interrupted guide changed files: before %v after %v", before, after)
	}
	if os.Getenv("TEGO_TEST_GUIDE_LATE") == "1" {
		// The guide has returned, the terminal is back, and the process has not ended: the gap a second signal can
		// fall into. Say so, then wait for the parent to have sent it (no sleep: the parent's byte follows its kill).
		returned := os.NewFile(4, "guide-test-returned")
		gate := os.NewFile(3, "guide-test-gate")
		if _, err := returned.Write([]byte("returned\n")); err != nil {
			t.Fatal(err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(gate, ack[:]); err != nil {
			t.Fatal(err)
		}
	}
}

func guidePTYFiles(t *testing.T, home string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[strings.TrimPrefix(path, home)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// guidePromptHangGuard ends a run in which a prompt never comes: the helper dying is its own case just above, so this
// is a hang. It is not a speed estimate: the helper is a second copy of this test binary, which a host with its disk
// busy took more than the 15 s this used to be to start and reach its first prompt (the gate's handoff-secret route).
const guidePromptHangGuard = 5 * time.Minute

func runGuidePTY(t *testing.T, route guidePTYRoute, target int, how string, ahead bool) {
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
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateRead.Close(); _ = gateWrite.Close() }()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childPID := filepath.Join(t.TempDir(), "pid")
	t.Cleanup(func() {
		b, _ := os.ReadFile(childPID)
		for _, value := range strings.Fields(string(b)) {
			pid, _ := strconv.Atoi(value)
			if pid > 1 {
				_ = unix.Kill(-pid, unix.SIGKILL)
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
	})
	c := exec.Command(self, "-test.run=^TestGuideInterruptRestoresTerminal$")
	c.Env = append(os.Environ(), "TEGO_TEST_GUIDE_INTERRUPT="+route.name, "TEGO_TEST_GUIDE_CHILD_PID="+childPID, "TEGO_TEST_GUIDE_STOP_CALLS="+childPID+".stops", "TERM=xterm-256color", "TEGO_TEST_GUIDE_AHEAD="+map[bool]string{true: "1", false: "0"}[ahead])
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	returnedRead, returnedWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = returnedRead.Close(); _ = returnedWrite.Close() }()
	late := strings.HasPrefix(how, "late-")
	if late {
		c.Env = append(c.Env, "TEGO_TEST_GUIDE_LATE=1")
	}
	c.ExtraFiles = []*os.File{gateRead, returnedWrite}
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = returnedWrite.Close()
	done := make(chan struct{})
	var childErr error
	go func() { childErr = c.Wait(); close(done) }()
	defer func() { _ = c.Process.Kill(); <-done }()
	var trace bytes.Buffer
	outputChanged := make(chan struct{}, 1)
	var mu sync.Mutex
	snapshot := func() string { mu.Lock(); defer mu.Unlock(); return trace.String() }
	ready := make(chan string, len(route.steps))
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		b := make([]byte, 4096)
		next := 0
		// xterm replies: synchronized output reset, Unicode core unsupported,
		// Kitty keyboard flags zero. Scan accumulated output for split queries.
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
				case outputChanged <- struct{}{}:
				default:
				}
				for i := range queries {
					q := &queries[i]
					count := strings.Count(current, q.q)
					for ; q.seen < count; q.seen++ {
						if _, err := master.Write([]byte(q.a)); err != nil {
							return
						}
					}
				}
				for next < len(route.steps) {
					prompt := route.steps[next].prompt
					want := prompt
					if ahead {
						want = "[before:" + prompt + "]"
					}
					if !strings.Contains(current, want) {
						break
					}
					ready <- prompt
					next++
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
		case <-readDone:
		case <-time.After(15 * time.Second):
			t.Error("PTY reader did not finish")
		}
	}()
	write := func(s string) {
		t.Helper()
		if _, err := master.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	for i, step := range route.steps[:target+1] {
		select {
		case got := <-ready:
			if got != step.prompt {
				t.Fatalf("prompt %q, wanted %q", got, step.prompt)
			}
		case <-done:
			t.Fatalf("helper ended before %s: %v\n%s", step.prompt, childErr, snapshot())
		case <-time.After(guidePromptHangGuard):
			t.Fatalf("no %s prompt within the %s hang guard:\n%s", step.prompt, guidePromptHangGuard, snapshot())
		}
		if i == target {
			if route.name == "dumb" && strings.HasPrefix(step.prompt, "Paste ") {
				write("partial-secret")
			}
			switch how {
			case "leave":
				// One key leaves the installer or the sign-in the guide started, and the guide asks the question that
				// started it again: the marker line, then that question drawn after it. A second key then ends the
				// guide at the question, which is what the checks below hold to the stopped ending.
				leave := guideLeaveSteps[route.name]
				write("\x03")
				waitFor := func(what string, found func(string) bool) {
					deadline := time.NewTimer(guidePromptHangGuard)
					defer deadline.Stop()
					for !found(snapshot()) {
						select {
						case <-outputChanged:
						case <-done:
							t.Fatalf("helper ended before %s:\n%s", what, snapshot())
						case <-deadline.C:
							t.Fatalf("no %s:\n%s", what, snapshot())
						}
					}
				}
				waitFor("marker "+leave.marker, func(out string) bool { return strings.Contains(out, leave.marker) })
				waitFor("the question again", func(out string) bool {
					_, after, _ := strings.Cut(out, leave.marker)
					return strings.Contains(after, leave.question)
				})
				write("\x03")
			case "key", "burst":
				write("\x03")
			default:
				if late {
					first, second := lateSignals(t, how)
					if err := c.Process.Signal(first); err != nil {
						t.Fatal(err)
					}
					// The helper says so once the guide has returned and only the process's end is left.
					returned := make(chan struct{})
					go func() { _, _ = bufio.NewReader(returnedRead).ReadString('\n'); close(returned) }()
					select {
					case <-returned:
					case <-done:
						t.Fatalf("helper ended on the first signal without waiting for the second: %v\n%s", childErr, snapshot())
					case <-time.After(15 * time.Second):
						t.Fatalf("guide did not return after %v:\n%s", first, snapshot())
					}
					if err := c.Process.Signal(second); err != nil {
						t.Fatal(err)
					}
					if _, err := gateWrite.Write([]byte{'x'}); err != nil {
						t.Fatal(err)
					}
				} else {
					sig := os.Signal(os.Interrupt)
					if how == "hup" {
						sig = syscall.SIGHUP
					}
					if how == "term" || how == "double" {
						sig = syscall.SIGTERM
					}
					if err := c.Process.Signal(sig); err != nil {
						t.Fatal(err)
					}
					if how == "double" {
						_ = c.Process.Signal(os.Interrupt)
					}
				}
			}
		} else if how == "burst" {
			if i == 0 {
				var keys strings.Builder
				for _, s := range route.steps[:target] {
					keys.WriteString(s.keys)
				}
				write(keys.String())
			}
		} else if route.name == "shell" && strings.Contains(step.prompt, "Which project") {
			write("\x1b[B")
			time.Sleep(20 * time.Millisecond)
			write("\r")
		} else {
			write(step.keys)
		}
		if ahead || step.prompt == "[handoff-ready]" {
			if _, err := gateWrite.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case <-done:
		// A second signal may arrive at any point up to the process's end, including after the guide has put the
		// terminal back: the helper's exit is still the guide's own, never the signal's.
		if childErr != nil {
			t.Fatalf("interrupted helper: %v\n%s", childErr, snapshot())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("guide ignored interrupt:\n%s", snapshot())
	}
	outputDeadline := time.NewTimer(15 * time.Second)
	defer outputDeadline.Stop()
	for !strings.Contains(snapshot(), "Stopped. Run tego start") {
		select {
		case <-outputChanged:
		case <-outputDeadline.C:
			t.Fatalf("no stopped ending:\n%s", snapshot())
		}
	}
	if strings.Contains(snapshot(), "Ready") {
		t.Fatalf("wrong interrupted ending:\n%s", snapshot())
	}
	if b, err := os.ReadFile(childPID); err == nil {
		for _, value := range strings.Fields(string(b)) {
			pid, _ := strconv.Atoi(value)
			for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil || strings.Contains(string(b), ") Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("guide child %d survived interruption", pid)
				}
			}
		}
	}
	if strings.Contains(snapshot(), "SECOND_SECRET") || strings.Contains(snapshot(), "partial-secret") {
		t.Fatalf("secret tail reached the screen:\n%s", snapshot())
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored: before %+v after %+v", before, after)
	}
}

// lateSignals reads "late-<first>-<second>", the two signals TestGuideSignalAfterRestore sends.
func lateSignals(t *testing.T, how string) (first, second os.Signal) {
	t.Helper()
	names := map[string]os.Signal{"int": os.Interrupt, "term": syscall.SIGTERM, "hup": syscall.SIGHUP}
	parts := strings.Split(how, "-")
	if len(parts) != 3 || names[parts[1]] == nil || names[parts[2]] == nil {
		t.Fatalf("unknown late signal pair %q", how)
	}
	return names[parts[1]], names[parts[2]]
}

// TestGuideSignalAfterRestore: a signal that comes after the guide has restored the terminal and returned, while its
// process has not yet ended, does not end the process with that signal. The helper holds that moment open, so each
// case fails every time the guide's subscription ends with the guide (the default action of TERM, INT or HUP ends the
// process with the signal) and does not depend on how loaded the machine is. The pairs cover each signal as the
// first, which the guide handles, and as the second, which arrives in the gap.
func TestGuideSignalAfterRestore(t *testing.T) {
	routes := map[string]guidePTYRoute{}
	for _, r := range append(append(append(guidePTYRoutes(), guideChildRoutes()...), guideDumbRoutes()...), guideHandoffRoutes()...) {
		routes[r.name] = r
	}
	cases := []struct {
		route  string
		target int
	}{{"shell", 0}, {"login", 2}, {"dumb", 0}, {"dumb", 2}, {"child-installer", 1}, {"child-systemd-run", 3}}
	for _, c := range cases {
		route := routes[c.route]
		for _, first := range []string{"int", "term", "hup"} {
			for _, second := range []string{"int", "term", "hup"} {
				t.Run(c.route+"/"+strconv.Itoa(c.target)+"/"+first+"-"+second, func(t *testing.T) {
					t.Parallel()
					runGuidePTY(t, route, c.target, "late-"+first+"-"+second, false)
				})
			}
		}
	}
}
