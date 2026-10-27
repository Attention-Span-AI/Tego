// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// wantReset is the sequence a run sends the terminal after a full-screen agent died (G1): kitty keyboard
// flags popped on the alternate screen, the alternate screen left, the flags popped on the main screen, the
// cursor shown, every mouse mode, bracketed paste and focus events off.
const wantReset = "\x1b[<u\x1b[?1049l\x1b[<u\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l"

// A full-screen agent that put the terminal in raw mode, on the alternate screen with the mouse reported, and
// was then SIGKILLed leaves it that way: nothing of the agent is left to undo it, and the shell sees only
// tego exit 137. The run puts back the modes it saved before the agent started and sends the reset.
func TestIntegrationKilledTUIGetsItsTerminalBack(t *testing.T) {
	stty, err := filepath.EvalSymlinks("/usr/bin/stty")
	if err != nil {
		t.Skipf("no stty: %v", err)
	}
	f := newFixture(t, contractFor("itty", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/stty", stty}))
	p := openPTY(t)
	saved := p.termios(t)
	if saved.Lflag&unix.ICANON == 0 {
		t.Fatal("a fresh pty is not in canonical mode")
	}
	deps := f.deps(t, nil)
	deps.Stdio = Stdio{In: p.slave, Out: p.slave, Err: p.slave}
	script := `stty raw -echo && printf '\033[?1049h\033[?1000h\033[?2004h\033[>1u' && kill -9 $$`
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", script}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndExit || res.ExitCode != 128+9 {
		t.Fatalf("result %+v, want reason exit and exit 137 (the agent's own SIGKILL)", res)
	}
	if !p.waitWritten([]byte("\x1b[?1049h"), 5*time.Second) {
		t.Fatalf("the agent never switched to the alternate screen; the terminal got %q", p.written())
	}
	if got := p.termios(t); got != saved {
		t.Fatalf("termios after the run: lflag %#x iflag %#x oflag %#x, want what it was before (lflag %#x iflag %#x oflag %#x)",
			got.Lflag, got.Iflag, got.Oflag, saved.Lflag, saved.Iflag, saved.Oflag)
	}
	if !p.waitWritten([]byte("\x1b[?1049h\x1b[?1000h\x1b[?2004h\x1b[>1u"+wantReset), 5*time.Second) {
		t.Fatalf("the terminal got %q, want the agent's modes followed by the reset %q", p.written(), wantReset)
	}
}

// An agent that ends on its own with the terminal as it found it gets nothing written after it: the reset is
// for an agent that died or left the terminal raw, and the run's terminal is the person's.
func TestIntegrationCleanAgentLeavesTheTerminalAlone(t *testing.T) {
	f := newFixture(t, contractFor("ittyclean", []string{"/bin/sh"}, []string{"/bin/sh"}))
	p := openPTY(t)
	saved := p.termios(t)
	deps := f.deps(t, nil)
	deps.Stdio = Stdio{In: p.slave, Out: p.slave, Err: p.slave}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "printf done"}, deps)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run: %+v %v", res, err)
	}
	if !p.waitWritten([]byte("done"), 5*time.Second) {
		t.Fatalf("the terminal got %q, want done", p.written())
	}
	time.Sleep(100 * time.Millisecond) // anything written after the agent would have reached the master by now
	if got := string(p.written()); got != "done" {
		t.Fatalf("the terminal got %q, want only the agent's own output", got)
	}
	if got := p.termios(t); got != saved {
		t.Fatal("termios changed under a clean run")
	}
}

// tego taking a stop signal from the terminal or the session (SIGINT, SIGTERM, SIGHUP) from an agent that
// ignores it ends in the stop_grace escalation, whose cgroup.kill leaves the agent no chance to tidy up: the
// run repairs the terminal on that path too.
func TestIntegrationStopGraceKillRestoresTheTerminal(t *testing.T) {
	stty, err := filepath.EvalSymlinks("/usr/bin/stty")
	if err != nil {
		t.Skipf("no stty: %v", err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newFixture(t, contractFor("ittygrace", []string{"/bin/sh"},
				[]string{"/bin/sh", "/bin/sleep", "/usr/bin/stty", stty}))
			f.machine.StopGrace = config.Setting[time.Duration]{Value: time.Second}
			p := openPTY(t)
			saved := p.termios(t)
			trapped := filepath.Join(f.out, "trapped")
			script := `trap '' INT TERM HUP; stty raw -echo && printf '\033[?1049h' && : > "$1"; while true; do sleep 1; done`
			signals := make(chan os.Signal, 1)
			deps := f.deps(t, signals)
			deps.Stdio = Stdio{In: p.slave, Out: p.slave, Err: p.slave}
			done := make(chan Result, 1)
			go func() {
				res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", script, "sh", trapped}, deps)
				if err != nil {
					t.Errorf("Run: %v", err)
				}
				done <- res
			}()
			waitForFile(t, trapped, 10*time.Second)
			signals <- sig
			select {
			case res := <-done:
				if res.Reason != record.RunEndSignal {
					t.Fatalf("result %+v, want reason signal", res)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the escalation never happened")
			}
			if got := p.termios(t); got != saved {
				t.Fatalf("termios lflag %#x after the run, want %#x", got.Lflag, saved.Lflag)
			}
			if !p.waitWritten([]byte("\x1b[?1049h"+wantReset), 5*time.Second) {
				t.Fatalf("the terminal got %q, want the reset after the agent's modes", p.written())
			}
		})
	}
}
