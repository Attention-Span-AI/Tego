// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"testing"
	"time"
)

// The terminal's access time moves when its input is read, and only then: the source reports 0 until it sees a
// change, the time of the tick that saw it after one, and keeps that time while the stamp stands still. The
// stamp is set back first because the kernel rewrites it only once per 8-second window.
func TestInputActivityFollowsTheTerminalsReadTime(t *testing.T) {
	p := openPTY(t)
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(p.slave.Name(), old, old); err != nil {
		t.Skipf("cannot set the pty's times: %v", err)
	}
	term := saveTerminal(Stdio{In: p.slave, Out: p.slave})
	if term == nil || term.in == nil {
		t.Fatal("a pty as stdin is not kept as the input terminal")
	}
	clock := uint64(1000)
	src := term.inputActivity(func() uint64 { return clock })
	if got := src(); got != 0 {
		t.Fatalf("first reading = %d, want 0 (a baseline is not activity)", got)
	}
	clock = 2000
	if got := src(); got != 0 {
		t.Fatalf("reading with no input = %d, want 0", got)
	}
	// The person types a line; the agent reads it.
	if _, err := p.master.WriteString("hello\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := p.slave.Read(buf); err != nil || n == 0 {
		t.Fatalf("agent read = %d, %v", n, err)
	}
	clock = 3000
	if got := src(); got != 3000 {
		t.Fatalf("reading after input = %d, want 3000", got)
	}
	clock = 4000
	if got := src(); got != 3000 {
		t.Fatalf("reading with no new input = %d, want it to stay 3000", got)
	}
}

// A stdin that is not a terminal has no input to count.
func TestInputActivityNeedsATerminalStdin(t *testing.T) {
	p := openPTY(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if term := saveTerminal(Stdio{In: r, Out: p.slave, Err: p.slave}); term == nil || term.in != nil {
		t.Fatalf("a pipe on stdin: terminal %+v, want a terminal with no input stream", term)
	}
}
