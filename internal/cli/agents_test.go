// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

const (
	agentsRunID = "r-0a1b2c3d-0123456789abc-xyz123"
	agentsRunCG = "/user.slice/tego.slice/tego-watch.slice/run-" + agentsRunID + ".scope"
)

// fakeProcRoot writes a directory tree shaped like /proc: one entry per process, with the files the watcher reads
// (stat, cmdline, cgroup, environ) and an exe link to a real file.
type fakeProcRoot struct {
	t    *testing.T
	root string
	bin  string
}

func newFakeProcRoot(t *testing.T) *fakeProcRoot {
	t.Helper()
	d := t.TempDir()
	f := &fakeProcRoot{t: t, root: filepath.Join(d, "proc"), bin: filepath.Join(d, "bin")}
	for _, p := range []string{f.root, f.bin} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// add makes a process: its program file (named program, created once), argv, comm, ppid, cgroup and environment.
func (f *fakeProcRoot) add(pid, ppid int, program, comm string, argv []string, cgroup, env string) {
	f.t.Helper()
	dir := filepath.Join(f.root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	exe := filepath.Join(f.bin, program)
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		f.t.Fatal(err)
	}
	// stat: pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime
	// cstime priority nice threads itrealvalue starttime
	stat := fmt.Sprintf("%d (%s) S %d 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0", pid, comm, ppid, 5000+pid)
	files := map[string]string{
		"stat":    stat,
		"cmdline": strings.Join(argv, "\x00") + "\x00",
		"cgroup":  "0::" + cgroup + "\n",
		"environ": env,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	// Its one task, as /proc/<pid>/task lists it: a scan's listing starts its events there (procconn.List).
	task := filepath.Join(dir, "task", strconv.Itoa(pid))
	if err := os.MkdirAll(task, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(task, "stat"), []byte(stat), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func sandboxAgents(t *testing.T, root string, privileged bool) {
	t.Helper()
	oldP, oldO, oldR := agentsPrivileged, agentsOpen, agentsProcRoot
	agentsPrivileged = func() bool { return privileged }
	agentsOpen = func() (watcher.Source, error) { return nil, fmt.Errorf("a test opened the real proc connector") }
	agentsProcRoot = root
	t.Cleanup(func() { agentsPrivileged, agentsOpen, agentsProcRoot = oldP, oldO, oldR })
}

func runAgentsCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = mainWith(t.Context(), append([]string{"tego", "agents"}, args...), &o, &e, []Command{cmdAgents()})
	return code, o.String(), e.String()
}

func TestAgentsUsageErrors(t *testing.T) {
	sandboxAgents(t, t.TempDir(), true)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"an argument":                  {[]string{"claude"}, "no arguments"},
		"children without follow":      {[]string{"--children"}, "--children needs --follow"},
		"an argv rule with no name":    {[]string{"--signature", "node .../cli.js"}, "needs a name"},
		"a relative path":              {[]string{"--signature", "bin/claude"}, "absolute"},
		"an empty rule":                {[]string{"--signature", ""}, "empty"},
		"nothing left to look for":     {[]string{"--no-default-signatures"}, "no signatures"},
		"every shipped rule removed":   {[]string{"--signature", "claude=", "--signature", "codex=", "--signature", "opencode=", "--signature", "gemini="}, "no signatures"},
		"an unknown flag":              {[]string{"--kill"}, "flag provided but not defined"},
		"a bad name has no usage hint": {[]string{"--signature", "web=node .../["}, "syntax error"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runAgentsCmd(t, tc.args...)
			if code != identity.ExitUsage || out != "" || !strings.Contains(errs, tc.want) {
				t.Fatalf("code %d, stdout %q, stderr %q; want usage error containing %q", code, out, errs, tc.want)
			}
		})
	}
}

// Without privilege it says so plainly and does nothing else, before it touches /proc or the kernel.
func TestAgentsNeedsRoot(t *testing.T) {
	for _, args := range [][]string{nil, {"--follow"}, {"--json"}} {
		sandboxAgents(t, filepath.Join(t.TempDir(), "no-proc-here"), false)
		code, out, errs := runAgentsCmd(t, args...)
		if code != identity.ExitLauncher || out != "" || !strings.Contains(errs, "needs root") || !strings.Contains(errs, "CAP_NET_ADMIN") || !strings.HasSuffix(strings.TrimSpace(errs), "[privilege]") {
			t.Fatalf("%v: code %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
}

// A process the kernel refuses the socket to is the same refusal, not a crash; and a kernel with no connector
// says so.
func TestAgentsFollowOpenFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("procconn: bind (needs CAP_NET_ADMIN): %w", unix.EPERM), "[privilege]"},
		{fmt.Errorf("procconn: socket: %w", unix.EPROTONOSUPPORT), "CONFIG_PROC_EVENTS"},
		{fmt.Errorf("procconn: bind: %w", unix.ENOMEM), "[io]"},
	} {
		sandboxAgents(t, t.TempDir(), true)
		agentsOpen = func() (watcher.Source, error) { return nil, tc.err }
		code, _, errs := runAgentsCmd(t, "--follow")
		if code != identity.ExitLauncher || !strings.Contains(errs, tc.want) {
			t.Fatalf("%v: code %d, stderr %q; want 125 containing %q", tc.err, code, errs, tc.want)
		}
	}
}

func TestAgentsListsWhatRuns(t *testing.T) {
	f := newFakeProcRoot(t)
	f.add(1, 0, "systemd", "systemd", []string{"/sbin/init"}, "/init.scope", "")
	f.add(300, 1, "bash", "bash", []string{"-bash"}, "/app.slice/term.scope", "")
	f.add(500, 300, "claude", "claude", []string{"claude", "--resume"}, "/app.slice/term.scope", "HOME=/home/u\x00")
	f.add(600, 1, "codex", "codex", []string{"codex"}, agentsRunCG, "TEGO_RUN_ID="+agentsRunID+"\x00")
	f.add(700, 300, "grep", "grep", []string{"grep", "claude", "x"}, "/app.slice/term.scope", "")
	sandboxAgents(t, f.root, true)

	code, out, errs := runAgentsCmd(t, "--json")
	if code != identity.ExitOK || !strings.Contains(errs, "only observes") || !strings.Contains(errs, "claude, codex, opencode, gemini") {
		t.Fatalf("code %d, stderr %q", code, errs)
	}
	got := map[int32]watcher.Sighting{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var s watcher.Sighting
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("line %q is not JSON: %v", line, err)
		}
		got[s.PID] = s
	}
	if len(got) != 2 || got[500].Rule != "claude" || got[600].Rule != "codex" {
		t.Fatalf("sightings %+v from %q", got, out)
	}
	if !*got[500].OutsideGovernedRun || got[500].Seen != watcher.SeenScan || got[500].PPID != 300 || got[500].Argv[1] != "--resume" {
		t.Fatalf("the agent in a terminal: %+v", got[500])
	}
	if *got[600].OutsideGovernedRun || got[600].RunCgroupID != agentsRunID || got[600].RunID != agentsRunID {
		t.Fatalf("the agent in a run: %+v", got[600])
	}

	// The same in text.
	code, out, _ = runAgentsCmd(t)
	if code != identity.ExitOK || !strings.Contains(out, "agent_started") || !strings.Contains(out, "OUTSIDE-GOVERNED-RUN") || !strings.Contains(out, "governed-by="+agentsRunID) {
		t.Fatalf("text: code %d, %q", code, out)
	}
}

func TestAgentsSignaturesAreEditable(t *testing.T) {
	f := newFakeProcRoot(t)
	f.add(500, 1, "claude", "claude", []string{"claude"}, "/t.scope", "")
	f.add(501, 1, "myagent", "myagent", []string{"myagent"}, "/t.scope", "")
	f.add(502, 1, "node", "node", []string{"node", "/srv/app/web/cli.js"}, "/t.scope", "")
	sandboxAgents(t, f.root, true)
	pids := func(args ...string) string {
		code, out, errs := runAgentsCmd(t, append(args, "--json")...)
		if code != identity.ExitOK {
			t.Fatalf("%v: code %d, stderr %q", args, code, errs)
		}
		var ids []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			var s watcher.Sighting
			if line != "" && json.Unmarshal([]byte(line), &s) == nil {
				ids = append(ids, fmt.Sprintf("%d:%s", s.PID, s.Rule))
			}
		}
		return strings.Join(sortStrings(ids), " ")
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "500:claude"},
		{[]string{"--signature", "myagent"}, "500:claude 501:myagent"},
		{[]string{"--signature", "claude="}, ""},
		{[]string{"--signature", "claude=/nowhere/claude"}, ""},
		{[]string{"--signature", "web=node .../web/cli.js"}, "500:claude 502:web"},
		{[]string{"--no-default-signatures", "--signature", "myagent"}, "501:myagent"},
	} {
		if got := pids(tc.args...); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.args, got, tc.want)
		}
	}
	// Nothing found, in text.
	code, out, _ := runAgentsCmd(t, "--signature", "claude=")
	if code != identity.ExitOK || !strings.Contains(out, "no agent process is running") {
		t.Fatalf("code %d, %q", code, out)
	}
}

func sortStrings(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

// chanSource is a Source whose events a test sends.
type chanSource struct {
	ch    chan []procconn.Event
	done  chan struct{}
	ready chan struct{} // closed at the first Recv: the watcher's start-up scan is over
	once  sync.Once
	first sync.Once
}

func (c *chanSource) Recv() ([]procconn.Event, error) {
	c.first.Do(func() { close(c.ready) })
	select {
	case evs := <-c.ch:
		return evs, nil
	case <-c.done:
		return nil, procconn.ErrClosed
	}
}

func (c *chanSource) Close() error { c.once.Do(func() { close(c.done) }); return nil }

// --follow reports an agent that starts and one that exits, then stops cleanly on interrupt with exit 0.
func TestAgentsFollow(t *testing.T) {
	f := newFakeProcRoot(t)
	sandboxAgents(t, f.root, true)
	src := &chanSource{ch: make(chan []procconn.Event), done: make(chan struct{}), ready: make(chan struct{})}
	agentsOpen = func() (watcher.Source, error) { return src, nil }

	var out, errs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- mainWith(ctx, []string{"tego", "agents", "--follow", "--json"}, &out, &errs, []Command{cmdAgents()})
	}()
	<-src.ready
	f.add(500, 300, "claude", "claude", []string{"claude"}, "/t.scope", "")
	src.ch <- []procconn.Event{{Kind: procconn.Exec, PID: 500, TGID: 500, TimestampNS: procconn.Monotonic()}}
	// By the time the kernel sends a process's exit, /proc no longer has it running.
	waitFor(t, func() bool { return strings.Count(out.String(), "\n") == 1 })
	if err := os.RemoveAll(filepath.Join(f.root, "500")); err != nil {
		t.Fatal(err)
	}
	src.ch <- []procconn.Event{{Kind: procconn.Exit, PID: 500, TGID: 500, ExitCode: 2 << 8, TimestampNS: procconn.Monotonic()}}
	waitFor(t, func() bool { return strings.Count(out.String(), "\n") == 2 })
	cancel()
	select {
	case code := <-done:
		if code != identity.ExitOK || !strings.Contains(errs.String(), "stopped; 1 agent(s) recognised") {
			t.Fatalf("code %d, stderr %q", code, errs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agents --follow did not stop when interrupted")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var start, end watcher.Sighting
	if json.Unmarshal([]byte(lines[0]), &start) != nil || json.Unmarshal([]byte(lines[1]), &end) != nil ||
		start.Event != watcher.EventAgentStarted || start.Seen != watcher.SeenExec || end.Event != watcher.EventAgentExited || *end.ExitCode != 2 {
		t.Fatalf("lines %q", lines)
	}
}

// The command's own summary and flags say what it is not: nothing it does touches a process.
func TestAgentsSaysItOnlyObserves(t *testing.T) {
	c := cmdAgents()
	if !strings.Contains(c.Summary, "observes only") {
		t.Fatalf("summary %q", c.Summary)
	}
	var usage bytes.Buffer
	code := mainWith(t.Context(), []string{"tego", "help"}, &usage, io.Discard, []Command{c})
	if code != identity.ExitOK || !strings.Contains(usage.String(), "agents") || !strings.Contains(usage.String(), "observes only") {
		t.Fatalf("help: %d %q", code, usage.String())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
