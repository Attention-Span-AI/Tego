// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

func TestAgentInstallerConsentAndRoot(t *testing.T) {
	oldLook, oldInstall, oldUID := guideLookPath, guideInstall, learnEUID
	t.Cleanup(func() { guideLookPath, guideInstall, learnEUID = oldLook, oldInstall, oldUID })
	guideLookPath = func(string) (string, error) { return "", errors.New("missing") }
	for _, a := range guideAgents[:2] {
		for _, answer := range []string{"1\n", "2\n"} {
			var out bytes.Buffer
			calls := 0
			learnEUID = func() int { return 1000 }
			guideInstall = func(_ context.Context, line string, _ io.Writer) error {
				calls++
				prompt := strings.Index(out.String(), "Install "+a.label+" now?")
				command := strings.Index(out.String(), a.install)
				if line != a.install || command < 0 || command > prompt {
					t.Errorf("installer not disclosed before yes: %s", &out)
				}
				return errors.New("stand-in stops here")
			}
			g := newWalk(strings.NewReader(answer), &out, false)
			_, _ = g.installed(context.Background(), a, a.label, a.command, t.TempDir())
			if answer == "2\n" && calls != 0 {
				t.Error("installer ran without yes")
			}
			if answer == "1\n" && calls != 1 {
				t.Errorf("yes made %d install calls", calls)
			}
		}
	}
	learnEUID = func() int { return 0 }
	calls := 0
	guideInstall = func(context.Context, string, io.Writer) error { calls++; return nil }
	var out bytes.Buffer
	g := newWalk(strings.NewReader("1\n"), &out, false)
	code, _ := g.installed(context.Background(), guideAgents[0], "Claude Code", "claude", t.TempDir())
	if code != identity.ExitFinding || calls != 0 || !strings.Contains(out.String(), "root") || !strings.Contains(out.String(), guideAgents[0].install) {
		t.Fatalf("root installer allowed: %d %d %s", code, calls, &out)
	}
}

func TestGuideWorksAsRoot(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	old := learnEUID
	learnEUID = func() int { return 0 }
	t.Cleanup(func() { learnEUID = old })
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, "2\n2\nsk-test-root\n1\n1\n1\n")
	if code != identity.ExitOK || !strings.Contains(out, "Ready") {
		t.Fatalf("root guide: %d\n%s\n%s", code, out, errs)
	}
}

// Ctrl-C reaches the guide as a key while it holds the terminal, so the guide must end the installer itself: the
// whole process group of the install line, and promptly.
func TestGuideInstallStopsWithTheGuide(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		result <- guideInstall(ctx, "sleep 300 & echo $$ $! > "+shellword.Quote(pidFile)+"; wait", io.Discard)
	}()
	var shell, pid int
	// Whatever the installer under test does, this test leaves no process behind.
	t.Cleanup(func() {
		for _, p := range []int{shell, pid} {
			if p > 1 {
				_ = unix.Kill(p, unix.SIGKILL)
			}
		}
	})
	for deadline := time.Now().Add(15 * time.Second); pid == 0; {
		if b, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(b), "\n") {
			if f := strings.Fields(string(b)); len(f) == 2 {
				shell, _ = strconv.Atoi(f[0])
				pid, _ = strconv.Atoi(f[1])
			}
		}
		if pid == 0 {
			if time.Now().After(deadline) {
				t.Fatal("the install line did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a stopped install returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the installer outlived the guide")
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("stopping took %s", took)
	}
	// The background member of the line's group is gone too (a zombie of a dead parent is reaped by init).
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
			break
		}
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err != nil || strings.Contains(string(b), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d of the install line is still running", pid)
		}
	}
}

func TestGuideStopsWhenTheInstallIsInterrupted(t *testing.T) {
	oldLook, oldInstall, oldUID := guideLookPath, guideInstall, learnEUID
	t.Cleanup(func() { guideLookPath, guideInstall, learnEUID = oldLook, oldInstall, oldUID })
	guideLookPath = func(string) (string, error) { return "", errors.New("missing") }
	learnEUID = func() int { return 1000 }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guideInstall = func(ctx context.Context, _ string, _ io.Writer) error { cancel(); return ctx.Err() }
	var out bytes.Buffer
	g := newWalk(strings.NewReader("1\n"), &out, false)
	_, err := g.installed(ctx, guideAgents[0], "Claude Code", "claude", t.TempDir())
	if !errors.Is(err, errStopped) {
		t.Fatalf("an interrupted install ended with %v, wanted the guide's stop: %s", err, &out)
	}
	if strings.Contains(out.String(), "didn't install") {
		t.Fatalf("an interrupted install was reported as a failed one: %s", &out)
	}
}
