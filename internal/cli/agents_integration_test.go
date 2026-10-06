// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

// `tego agents --follow` end to end as root, on the real proc connector and the real /proc: a script named claude
// starts, is reported with a rule and its place against the governed runs, exits 7 and is reported again, and an
// interrupt ends the command with exit 0. Nothing is stubbed: the stubs of agents_test.go are the defaults here.
func TestIntegrationAgentsFollowSeesAFakeAgentOnTheRealKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the proc connector is a multicast netlink group that needs CAP_NET_ADMIN")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "go")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "claude")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nread _ < \"$AGENT_GO\"\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var out, errs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- mainWith(ctx, []string{"tego", "agents", "--follow", "--json"}, &out, &errs, []Command{cmdAgents()})
	}()
	waitFor(t, func() bool {
		return strings.Contains(errs.String(), "only observes") || strings.Contains(errs.String(), "[")
	})
	if strings.Contains(errs.String(), "[") {
		t.Skipf("the command did not start listening: %s", errs.String())
	}
	time.Sleep(300 * time.Millisecond) // it opens the socket right after the notice; an agent started earlier is found by the scan

	cmd := exec.Command(script)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "AGENT_GO=" + fifo}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := int32(cmd.Process.Pid)

	find := func(event string) (watcher.Sighting, bool) {
		for _, line := range strings.Split(out.String(), "\n") {
			var s watcher.Sighting
			if line != "" && json.Unmarshal([]byte(line), &s) == nil && s.Event == event && s.PID == pid {
				return s, true
			}
		}
		return watcher.Sighting{}, false
	}
	waitFor(t, func() bool { _, ok := find(watcher.EventAgentStarted); return ok })
	start, _ := find(watcher.EventAgentStarted)
	if start.Rule != "claude" || start.PPID != int32(os.Getpid()) || start.OutsideGovernedRun == nil || !*start.OutsideGovernedRun {
		t.Fatalf("agent_started = %+v", start)
	}
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("go\n")
	_ = f.Close()
	waitFor(t, func() bool { _, ok := find(watcher.EventAgentExited); return ok })
	if end, _ := find(watcher.EventAgentExited); end.ExitCode == nil || *end.ExitCode != 7 {
		t.Fatalf("agent_exited = %+v", end)
	}

	cancel()
	select {
	case code := <-done:
		if code != identity.ExitOK || !strings.Contains(errs.String(), "stopped; 1 agent(s) recognised") {
			t.Fatalf("code %d, stderr %q", code, errs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agents --follow did not stop when interrupted")
	}
}
