// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A terminal program on the pty: it sets raw mode and the alternate screen, says so, and is SIGKILLed.
// restore puts back the saved modes and writes the reset after the program's own bytes.
func TestRestoreAfterAKilledTUI(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skipf("no stty: %v", err)
	}
	p := openPTY(t)
	saved := p.termios(t)
	term := saveTerminal(Stdio{In: p.slave, Out: p.slave, Err: p.slave})
	if term == nil {
		t.Fatal("a pty is not saved as the shared terminal")
	}
	cmd := exec.Command("/bin/sh", "-c", `stty raw -echo && printf '\033[?1049h\033[?1003h' && exec sleep 60`)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.slave, p.slave, p.slave
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !p.waitWritten([]byte("\x1b[?1049h\x1b[?1003h"), 5*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatalf("the program never switched screens; the terminal got %q", p.written())
	}
	if p.termios(t).Lflag&unix.ICANON != 0 {
		t.Fatal("the program did not leave canonical mode")
	}
	_ = cmd.Process.Signal(unix.SIGKILL)
	_ = cmd.Wait()
	reset, err := term.restore(true)
	if err != nil || !reset {
		t.Fatalf("restore = %v, %v, want the reset written", reset, err)
	}
	if got := p.termios(t); got != saved {
		t.Fatalf("termios lflag %#x after restore, want %#x", got.Lflag, saved.Lflag)
	}
	if !p.waitWritten([]byte("\x1b[?1049h\x1b[?1003h"+terminalReset), 5*time.Second) {
		t.Fatalf("the terminal got %q, want the reset after the program's modes", p.written())
	}
}

// A program that exits on its own but leaves the terminal raw gets the reset as well; one that leaves it as
// it was gets nothing, not even a TCSETS.
func TestRestoreWritesOnlyWhenNeeded(t *testing.T) {
	p := openPTY(t)
	saved := p.termios(t)
	term := saveTerminal(Stdio{In: p.slave, Out: p.slave})
	if reset, err := term.restore(false); err != nil || reset {
		t.Fatalf("restore of an untouched terminal = %v, %v, want nothing written", reset, err)
	}
	raw := saved
	raw.Lflag &^= unix.ICANON | unix.ECHO
	if err := sys.FileDo(p.slave, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, &raw) }); err != nil {
		t.Fatal(err)
	}
	if reset, err := term.restore(false); err != nil || !reset {
		t.Fatalf("restore of a raw terminal = %v, %v, want the reset", reset, err)
	}
	if got := p.termios(t); got != saved {
		t.Fatalf("termios lflag %#x after restore, want %#x", got.Lflag, saved.Lflag)
	}
	if !p.waitWritten([]byte(terminalReset), 5*time.Second) {
		t.Fatalf("the terminal got %q, want the reset", p.written())
	}
}

// Streams that are no terminal have no modes to save, and the reset is never written into a pipe or file.
func TestNoTerminalNoRestore(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if term := saveTerminal(Stdio{In: r, Out: w, Err: w}); term != nil {
		t.Fatalf("pipes saved as a terminal: %+v", term)
	}
	var none *sharedTerminal
	if reset, err := none.restore(true); reset || err != nil {
		t.Fatalf("restore with no terminal = %v, %v", reset, err)
	}
	// A terminal on stdin alone is restored but gets no bytes when stdin is read-only.
	p := openPTY(t)
	in, err := os.OpenFile(p.slave.Name(), os.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	term := saveTerminal(Stdio{In: in, Out: w})
	if term == nil || term.out != nil {
		t.Fatalf("read-only terminal on stdin: %+v, want saved with no output stream", term)
	}
	if reset, err := term.restore(true); reset || err != nil {
		t.Fatalf("restore = %v, %v, want no reset written", reset, err)
	}
}
