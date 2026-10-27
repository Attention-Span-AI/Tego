// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTheRunsOwnCodexHomeIsNotProposed is agent-contract.md R10a's learn half: writes the run's own CODEX_HOME grant
// allowed (fs.codex_home[...]) are granted by every run itself, under a path holding the run id, so they are neither
// proposed nor listed as writes outside the workspace; the header counts them.
func TestTheRunsOwnCodexHomeIsNotProposed(t *testing.T) {
	r := newRun(t, ws, "codex")
	home := "/run/user/1000/tego/r-12345678-0aaaaaaaaaaaa-abcdef/codex"
	e := r.add(record.KindFS, record.VerdictAllow, record.FSPayload{Op: record.FSOpen, Path: home + "/state_5.sqlite", Flags: wronly | creat})
	e.Rule = "fs.codex_home[" + home + "]"
	r.open(ws+"/out/a.txt", wronly|creat)
	p := r.propose(Options{})
	c := p.Contract()
	if strings.Contains(c, "/run/user/1000/tego") {
		t.Errorf("the run's own CODEX_HOME reached the proposal\n%s", c)
	}
	if p.RuntimeGranted != 1 || !strings.Contains(c, "1 file actions in the run's own CODEX_HOME") {
		t.Errorf("RuntimeGranted = %d\n%s", p.RuntimeGranted, c)
	}
}

// TestAPathSearchProposesTheProgramThatExists : a record taken before supervisor.md
// R23a held one bash search with attempts out of order, /usr/sbin/bash recorded after the /usr/bin/bash that ran,
// and learn took the last attempt, which tego compile refuses (path-missing). The attempt that started a program is
// the one that is a program on this machine.
func TestAPathSearchProposesTheProgramThatExists(t *testing.T) {
	r := newRun(t, ws, "python3", "agent.py")
	r.exec(10, "/usr/bin/python3", "python3", "agent.py")
	r.exec(11, "/home/u/.local/bin/bash", "bash", "-c", "ls")
	r.exec(11, "/usr/local/bin/bash", "bash", "-c", "ls")
	r.exec(11, "/usr/bin/bash", "bash", "-c", "ls")
	r.exec(11, "/usr/sbin/bash", "bash", "-c", "ls") // recorded after the one that ran
	p := r.propose(Options{})
	c := p.Contract()
	if got, want := entries(c, "exec"), []string{"/usr/bin/bash"}; !slices.Equal(got, want) {
		t.Errorf("exec.allow = %q, want %q\n%s", got, want, c)
	}
	if p.SearchMisses != 3 {
		t.Errorf("search misses = %d, want 3", p.SearchMisses)
	}
	load(t, c)
}

// TestLearnProposesNoProcPath : Codex starts itself through /proc/self/exe before every
// command, and learn listed it, which compiles (before R8a) to tego's own executable. It is left out, saying why.
func TestLearnProposesNoProcPath(t *testing.T) {
	r := newRun(t, ws, "codex")
	r.exec(10, "/usr/bin/codex", "codex")
	r.exec(11, "/proc/self/exe", "codex-linux-sandbox")
	r.exec(12, "/usr/bin/git", "git", "status")
	c := r.propose(Options{}).Contract()
	if got, want := entries(c, "exec"), []string{"/usr/bin/git"}; !slices.Equal(got, want) {
		t.Errorf("exec.allow = %q, want %q\n%s", got, want, c)
	}
	if !strings.Contains(c, "observed, not allowed: /proc/self/exe") || !strings.Contains(c, "exec-proc") {
		t.Errorf("the /proc path is not reported as left out\n%s", c)
	}
}

// TestLearnProposesNoMissingProgram: a program that is not on this machine now (a file the run removed, or a search
// whose every attempt missed) is reported, not proposed, since tego compile refuses it.
func TestLearnProposesNoMissingProgram(t *testing.T) {
	r := newRun(t, ws, "agent")
	r.exec(10, "/usr/bin/agent", "agent")
	r.exec(11, "/opt/missing/tool", "tool")
	r.exec(12, "/usr/sbin/lsb_release", "lsb_release", "-a")
	r.exec(12, "/usr/sbin/lsb_release", "lsb_release", "-a")
	c := r.propose(Options{}).Contract()
	if got := entries(c, "exec"); len(got) != 0 {
		t.Errorf("exec.allow = %q, want none\n%s", got, c)
	}
	for _, want := range []string{"/opt/missing/tool (seen once): not a program on this machine now", "/usr/sbin/lsb_release (seen once): not a program on this machine now"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q\n%s", want, c)
		}
	}
}

// TestLearnTestsTheRealFileSystemByDefault: with no Executable given, a path is a program when the file system has a
// regular file with an execute bit there, following links; a directory, a plain file and nothing are not.
func TestLearnTestsTheRealFileSystemByDefault(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prog, data, link := filepath.Join(dir, "prog"), filepath.Join(dir, "data"), filepath.Join(dir, "link")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(prog, link); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{prog: true, link: true, data: false, dir: false, filepath.Join(dir, "none"): false} {
		if got := executable(p); got != want {
			t.Errorf("executable(%s) = %v, want %v", p, got, want)
		}
	}
	l := New(Options{})
	if !l.executable(prog) || l.executable(data) {
		t.Error("a learner with no Executable does not ask the file system")
	}
}

// TestRouteProbesAreNotProposed : musl's getaddrinfo connects a UDP socket to port
// 65535 of each address a lookup returns and sends nothing; eight such destinations were proposed. They are reported,
// not allowed. A UDP connect to an address and port the run also connected to over TCP is kept, with a note that it
// may be glibc's probe.
func TestRouteProbesAreNotProposed(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "104.18.32.47:443")
	r.net("udp", "104.18.32.47:65535")
	r.net("udp", "[2606:4700:4408::ac40:9bd1]:65535")
	r.net("udp", "160.79.104.10:443")
	r.net("tcp", "160.79.104.10:443")
	r.net("udp", "10.0.0.9:3478")
	c := r.propose(Options{}).Contract()
	if got, want := entries(c, "net"), []string{"tcp://104.18.32.47:443", "tcp://160.79.104.10:443", "udp://10.0.0.9:3478", "udp://160.79.104.10:443"}; !slices.Equal(got, want) {
		t.Errorf("net.allow = %q, want %q\n%s", got, want, c)
	}
	if !strings.Contains(c, "observed, not allowed: udp port 65535 of 2 addresses (seen 2 times): a route probe") {
		t.Errorf("the route probe is not reported\n%s", c)
	}
	if !strings.Contains(c, `"udp://160.79.104.10:443"  # seen once; possibly the C library's address-sorting probe`) {
		t.Errorf("the UDP twin of a TCP destination carries no note\n%s", c)
	}
	if strings.Contains(c, `"udp://10.0.0.9:3478"  # seen once;`) {
		t.Errorf("a UDP destination with no TCP twin carries the note\n%s", c)
	}
	load(t, c)
}
