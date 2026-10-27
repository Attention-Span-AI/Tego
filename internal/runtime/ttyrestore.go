// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// terminalReset turns off what a full-screen agent switches on and cannot turn off once it is dead (G1):
// kitty keyboard flags popped (CSI < u; kitty keeps one stack for each screen, so once on the alternate
// screen and once on the main one), the alternate screen left (?1049l), the cursor shown (?25h), the mouse
// modes off (?1000l ?1002l ?1003l ?1006l), bracketed paste off (?2004l) and focus events off (?1004l). A
// terminal ignores a sequence it does not know, and popping an empty stack leaves no flag set.
const terminalReset = "\x1b[<u\x1b[?1049l\x1b[<u\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l"

// errBackground is a terminal whose foreground process group is not this process's: the job at the front
// owns its modes, and this process setting them would take SIGTTOU.
var errBackground = errors.New("the terminal's foreground is another process group")

// sharedTerminal is the terminal the run shares with the agent, as it was before the agent ran. Without
// tego the shell restores the modes of a job that dies by a signal; under tego the shell's job is tego,
// which exits normally with 128+n, so the run does it (G1).
type sharedTerminal struct {
	modes *os.File // the first stream that is a terminal: its modes are read and set through it
	out   *os.File // the first of stdout, stderr and stdin that is a terminal open for writing; nil for none
	in    *os.File // the agent's stdin when it is a terminal: its last-read time is the person's input (inputActivity); nil for none
	saved unix.Termios
}

// saveTerminal reads the modes of the first of the agent's streams that is a terminal, or returns nil when
// none is one: a pipe or a file has no modes, and the reset is never written into one.
func saveTerminal(s Stdio) *sharedTerminal {
	streams := DescribeStdio(s)
	files := [3]*os.File{s.In, s.Out, s.Err}
	t := &sharedTerminal{}
	for i, st := range streams {
		if st.Kind == record.StdioTTY && t.modes == nil {
			t.modes = files[i]
		}
	}
	if streams[0].Kind == record.StdioTTY {
		t.in = files[0]
	}
	for _, i := range []int{1, 2, 0} {
		if streams[i].Kind == record.StdioTTY && streams[i].Writable && t.out == nil {
			t.out = files[i]
		}
	}
	if t.modes == nil {
		return nil
	}
	tio, err := termiosOf(t.modes)
	if err != nil {
		return nil
	}
	t.saved = *tio
	return t
}

// termiosOf reads f's terminal modes.
func termiosOf(f *os.File) (*unix.Termios, error) {
	var tio *unix.Termios
	err := sys.FileDo(f, func(fd int) error {
		var err error
		tio, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	})
	return tio, err
}

// restore is called once the agent's process group is gone. It writes terminalReset when the agent ended by
// a signal or left the terminal out of canonical mode, then puts back the saved modes if they changed, and
// reports whether it wrote the reset. A terminal that hung up (SIGHUP) or whose foreground is another
// process group (tego run in the background) is left alone. The modes are set at once (TCSETS), never after
// a drain, which a terminal whose output was stopped would never finish.
func (t *sharedTerminal) restore(signaled bool) (reset bool, err error) {
	if t == nil {
		return false, nil
	}
	var now *unix.Termios
	err = sys.FileDo(t.modes, func(fd int) error {
		if pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP); err == nil && pg != unix.Getpgrp() {
			return errBackground // ENOTTY: not this process's controlling terminal, which has no foreground to respect
		}
		var err error
		now, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	})
	if err != nil {
		return false, err
	}
	if (signaled || now.Lflag&unix.ICANON == 0) && t.out != nil {
		if _, err = t.out.WriteString(terminalReset); err != nil {
			return false, err
		}
		reset = true
	}
	if *now != t.saved {
		err = sys.FileDo(t.modes, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, &t.saved) })
	}
	return reset, err
}

// repairTerminal is restore for the run's agent, after awaitExit: the agent's main process died by a signal,
// or the stop_grace escalation killed the tree.
func (r *runner) repairTerminal(t *sharedTerminal) {
	signaled := r.wait.Status.Signaled() || r.signals != nil && r.signals.Outcome().Escalated
	reset, err := t.restore(signaled)
	if err != nil {
		r.log.Debug("run: terminal not restored", "err", err)
		return
	}
	if reset {
		r.log.Debug("run: terminal reset after the agent")
	}
}
