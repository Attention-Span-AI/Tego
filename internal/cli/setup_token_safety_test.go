// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoginCaptureUnlinkedAndCanceled(t *testing.T) {
	home := t.TempDir()
	marker := filepath.Join(home, "capture-target")
	t.Setenv("CAPTURE_TARGET", marker)
	bin := t.TempDir()
	script := "#!/bin/sh\nfor last do :; done\nprintf '%s' \"$last\" > \"$CAPTURE_TARGET\"\nprintf '%s\\n' sk-ant-oat01-abcdefghijklmnopqrstuvwxyz > \"$last\"\nexec sleep 2\n"
	if err := os.WriteFile(filepath.Join(bin, "script"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := guideSetupToken(ctx, "claude", home); done <- err }()
	deadline := time.After(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("child did not start")
		case <-time.After(time.Millisecond * 5):
		}
	}
	target, _ := os.ReadFile(marker)
	if !strings.HasPrefix(string(target), "/proc/self/fd/") {
		t.Errorf("named transcript can survive termination: %s", target)
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".tego", "sign-in-*"))
	if len(matches) != 0 {
		t.Errorf("named transcripts while waiting: %v", matches)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("cancellation ignored")
		}
	case <-time.After(time.Millisecond * 700):
		t.Error("login kept waiting after cancellation")
		<-done
	}
}

func TestLoginCaptureWithSystemScript(t *testing.T) {
	if _, err := os.Stat("/usr/bin/script"); err != nil {
		t.Skip("system script unavailable")
	}
	bin := t.TempDir()
	program := filepath.Join(bin, "claude")
	token := "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz"
	if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf '%s\\n' "+token+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	old := guideLookPath
	t.Cleanup(func() { guideLookPath = old })
	guideLookPath = func(string) (string, error) { return "/usr/bin/script", nil }
	got, err := guideSetupToken(context.Background(), program, t.TempDir())
	if err != nil || got != token {
		t.Fatalf("script capture: %q %v", got, err)
	}
}

func TestLoginCancellationStopsSystemScriptChild(t *testing.T) {
	if _, err := os.Stat("/usr/bin/script"); err != nil {
		t.Skip("system script unavailable")
	}
	bin := t.TempDir()
	program := filepath.Join(bin, "claude")
	marker := filepath.Join(bin, "pid")
	t.Setenv("LOGIN_CHILD_PID", marker)
	if err := os.WriteFile(program, []byte("#!/bin/sh\ntrap '' TERM HUP\necho $$ > \"$LOGIN_CHILD_PID\"\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	old := guideLookPath
	t.Cleanup(func() { guideLookPath = old })
	guideLookPath = func(string) (string, error) { return "/usr/bin/script", nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := guideSetupToken(ctx, program, bin); done <- err }()
	var pid int
	deadline := time.After(3 * time.Second)
	for pid == 0 {
		if b, err := os.ReadFile(marker); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		select {
		case <-deadline:
			t.Fatal("login child did not start")
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer func() { _ = unix.Kill(pid, unix.SIGKILL) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("script did not stop")
	}
	// script sends SIGKILL before returning; the kernel can still be completing the child's exit.
	exitDeadline := time.Now().Add(time.Second)
	for {
		st, err := proc.New().Stat(pid)
		if errors.Is(err, proc.ErrGone) || (err == nil && st.State == 'Z') {
			break
		}
		if time.Now().After(exitDeadline) {
			t.Fatalf("login child %d survived cancellation (%c): %v", pid, st.State, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
