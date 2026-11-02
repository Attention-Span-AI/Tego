// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

const testRun = identity.RunID("20261026T101500Z-ab12cd34-0011aa22")

// TestAskAnswerLine (G5): the line a run that can ask prints before its agent's first screen names the run and the
// exact commands that answer, and mentions the desktop notice only when one will be sent.
func TestAskAnswerLine(t *testing.T) {
	for _, desktop := range []bool{false, true} {
		line := askAnswerLine("tego run", testRun, desktop)
		for _, want := range []string{
			"tego ask " + string(testRun),
			"tego approve " + string(testRun) + " <ask_id>",
			"(or deny)",
			"Approvals",
		} {
			if !strings.Contains(line, want) {
				t.Errorf("desktop %v: line %q lacks %q", desktop, line, want)
			}
		}
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
			t.Errorf("desktop %v: %q is not one line", desktop, line)
		}
		if got := strings.Contains(line, "desktop"); got != desktop {
			t.Errorf("desktop %v: line %q mentions the desktop notice: %v", desktop, line, got)
		}
	}
}

// TestAskNoticesWanted: the line needs a contract that can ask and cli in ask.notify (the quiet start: a run that
// cannot ask prints nothing new); the desktop notice also needs desktop, tier landlock (the one tier whose launcher
// places no fanotify mark, so it may start a process during the run, ADR 0021 (3)) and a launcher that is not root.
func TestAskNoticesWanted(t *testing.T) {
	asks := &agent.RuleTable{AskConfig: &agent.AskConfig{}}
	cases := []struct {
		name          string
		rt            *agent.RuleTable
		notify        []string
		tier          backend.Tier
		euid          int
		line, desktop bool
	}{
		{"no ask rules", &agent.RuleTable{}, []string{"cli", "desktop"}, backend.TierLandlock, 1000, false, false},
		{"default", asks, config.DefaultAskNotify(), backend.TierLandlock, 1000, true, true},
		{"cli only", asks, []string{"cli"}, backend.TierLandlock, 1000, true, false},
		{"desktop only", asks, []string{"desktop"}, backend.TierLandlock, 1000, false, true},
		{"off", asks, []string{}, backend.TierLandlock, 1000, false, false},
		{"tier cgroup", asks, config.DefaultAskNotify(), backend.TierCgroup, 1000, true, false},
		{"root launcher", asks, config.DefaultAskNotify(), backend.TierLandlock, 0, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, desktop := askNotices(tc.rt, tc.notify, tc.tier, tc.euid)
			if line != tc.line || desktop != tc.desktop {
				t.Errorf("askNotices = line %v desktop %v, want %v %v", line, desktop, tc.line, tc.desktop)
			}
		})
	}
}

// TestNotifierMustBeRootOwned: the launcher runs the notifier outside the run, so a notify-send the agent could write
// (in a folder of the person's own, which a contract may let the agent write) is never run: only a file whose every
// directory up to / is root's and writable by root alone is.
func TestNotifierMustBeRootOwned(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "notify-send")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := trustedExecutable(mine); err == nil {
			t.Errorf("a notify-send of the invoking user's own, %s, was trusted", mine)
		}
		if got, err := findNotifier(dir); err == nil || got != "" {
			t.Errorf("findNotifier on a PATH of the user's own folder = %q, %v; want none", got, err)
		}
	}
	if _, err := findNotifier("relative/bin:"); err == nil {
		t.Error("a relative PATH entry was searched")
	}
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if st, err := os.Stat(sh); err == nil && ownedByRoot(st) {
		if err := trustedExecutable(sh); err != nil {
			t.Errorf("root's %s: %v", sh, err)
		}
	}
}

// stubNotifier writes a notify-send stand-in that appends its arguments, one per line, to <dir>/argv, then runs
// extra.
func stubNotifier(t *testing.T, extra string) (bin, argv string) {
	t.Helper()
	dir := t.TempDir()
	bin, argv = filepath.Join(dir, "notify-send"), filepath.Join(dir, "argv")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argv + "; done\necho --- >> " + argv + "\n" + extra
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argv
}

// TestDesktopNoticeRunsTheNotifier: one held request starts the notifier once, with argv only (no shell), after "--"
// so nothing in the text is an option, naming the agent (markup and control bytes made inert) and the command that
// answers; never the target or the rule.
func TestDesktopNoticeRunsTheNotifier(t *testing.T) {
	bin, argv := stubNotifier(t, "")
	n := newDesktopNotice(bin, nil, "evil<b>&\x1b]0;x\x07")
	defer n.stop()
	n.tell(tegoruntime.AskPending{Run: testRun, AskID: "q-0123456789abcdef0123456789abcdef", Op: "open"})
	var got string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(argv); err == nil && strings.Contains(string(b), "---") {
			got = string(b)
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(got, "---\n"), "\n")
	if len(lines) < 5 || lines[0] != "-a" || lines[1] != "tego" || lines[2] != "--" {
		t.Fatalf("notifier argv %q", lines)
	}
	body := strings.Join(lines[3:], "\n")
	for _, want := range []string{"tego ask " + string(testRun), "evil&lt;b&gt;&amp;", "open"} {
		if !strings.Contains(body, want) {
			t.Errorf("notice %q lacks %q", body, want)
		}
	}
	if strings.ContainsAny(body, "\x1b\x07<>") {
		t.Errorf("notice %q carries a control byte or raw markup", body)
	}
}

// TestDesktopNoticeNeverHoldsTheRequest: tell returns at once whatever the notifier does, a notifier that hangs is
// killed, and stop returns promptly: the broker calls tell on the goroutine that holds the agent's operation.
func TestDesktopNoticeNeverHoldsTheRequest(t *testing.T) {
	bin, argv := stubNotifier(t, "exec sleep 30\n")
	n := newDesktopNotice(bin, nil, "a")
	start := time.Now()
	for range 100 {
		n.tell(tegoruntime.AskPending{Run: testRun, AskID: "q-0123456789abcdef0123456789abcdef", Op: "connect"})
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("100 tells took %s", d)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(argv); err == nil {
			break
		}
	}
	start = time.Now()
	n.stop()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("stop took %s with a hanging notifier", d)
	}
	b, _ := os.ReadFile(argv)
	if c := strings.Count(string(b), "---"); c > 2 {
		t.Errorf("a burst of 100 asks started the notifier %d times; want the one running and at most one queued", c)
	}
}
