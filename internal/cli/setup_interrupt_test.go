// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
	shellAgent := agent
	shellAgent.keys = "\t/zzzz\r\x7f\x7f\x7f\x7fClaude\r"
	project := guidePTYStep{"Which project should Claude Code work in?", "\x1b[B\r"}
	rules := guidePTYStep{"Which rules should Claude Code follow?", "\r"}
	return []guidePTYRoute{
		{"shell", []guidePTYStep{shellAgent, project, rules}},
		{"login", []guidePTYStep{agent,
			{"How do you want to log in to Claude Code?", "\x1b[B\r"},
			{"Paste your Anthropic API key", "\r\x1b[200~test-token\x1b[201~\t\r"},
			{"Save the login for later sessions?", "\x1b[B\r"},
			{project.prompt, "\x1b[B\x1b[B\r"},
			{"Path to the project", "~/missing\r\x15~/bot\r"},
			{rules.prompt, "\x1b[B\x1b[B\r"},
			{"Which rules?", "\t\r"},
			{"Other hosts it may reach", "api.github.com\r"}}},
		{"command", []guidePTYStep{{agent.prompt, "\x1b[B\x1b[B\r"}, {"What command starts it?", "claude\r"},
			{"Which project should claude work in?", "\x1b[B\r"}, {"Which rules should claude follow?", "\r"}}},
		{"install", []guidePTYStep{agent, {"Install Claude Code now?", "\r"}}},
		{"saved", []guidePTYStep{agent, {"Use your saved Claude Code login?", "\r"}}},
		{"subscription", []guidePTYStep{agent, {"How do you want to log in to Claude Code?", "\r"},
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
			for _, how := range []string{"key", "signal"} {
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
		route := guidePTYRoutes()[1]
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

func guidePTYHelper(t *testing.T, routeName string) {
	t.Helper()
	var route guidePTYRoute
	for _, r := range guidePTYRoutes() {
		if r.name == routeName {
			route = r
		}
	}
	if len(route.steps) == 0 {
		t.Fatal("unknown route")
	}
	f := onFixture(t, "fresh")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	noLogins(t)
	fakeProgram(t, "claude")
	if routeName != "login" && routeName != "subscription" {
		t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-login")
	}
	previousLogin, previousDashboard, previousLook, previousInstall := guideSetupToken, guideDashboard, guideLookPath, guideInstall
	t.Cleanup(func() {
		guideSetupToken, guideDashboard, guideLookPath, guideInstall = previousLogin, previousDashboard, previousLook, previousInstall
	})
	guideSetupToken = func(context.Context, string, string) (string, error) { return "", nil }
	guideDashboard = func(string) string { t.Error("interrupted guide started dashboard"); return "" }
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
	before := guidePTYFiles(t, f.Home)
	var out io.Writer = os.Stdout
	if os.Getenv("TEGO_TEST_GUIDE_AHEAD") == "1" {
		gate := os.NewFile(3, "guide-test-gate")
		defer func() { _ = gate.Close() }()
		out = &guidePTYOutput{File: os.Stdout, steps: route.steps, gate: gate}
	}
	ctx, stop := notifyContext()
	defer stop()
	if code := runSetupGuide(ctx, os.Stdin, out, os.Stderr, true); code != identity.ExitFinding {
		t.Fatalf("interrupt exit %d", code)
	}
	if after := guidePTYFiles(t, f.Home); !reflect.DeepEqual(before, after) {
		t.Fatalf("interrupted guide changed files: before %v after %v", before, after)
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
	c := exec.Command(self, "-test.run=^TestGuideInterruptRestoresTerminal$")
	c.Env = append(os.Environ(), "TEGO_TEST_GUIDE_INTERRUPT="+route.name, "TERM=xterm-256color", "TEGO_TEST_GUIDE_AHEAD="+map[bool]string{true: "1", false: "0"}[ahead])
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	c.ExtraFiles = []*os.File{gateRead}
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var childErr error
	go func() { childErr = c.Wait(); close(done) }()
	defer func() { _ = c.Process.Kill(); <-done }()
	var trace bytes.Buffer
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
		case <-time.After(15 * time.Second):
			t.Fatalf("no %s prompt:\n%s", step.prompt, snapshot())
		}
		if i == target {
			if how != "signal" {
				write("\x03")
			} else if err := c.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
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
		if ahead {
			if _, err := gateWrite.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case <-done:
		if childErr != nil {
			t.Fatalf("interrupted helper: %v\n%s", childErr, snapshot())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("guide ignored interrupt:\n%s", snapshot())
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal not restored: before %+v after %+v", before, after)
	}
}
