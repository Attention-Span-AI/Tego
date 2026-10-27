// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// stopPoll is the backstop of followStops: SIGCHLD is coalesced and can be taken by another subscriber, so the
// agent's state is also read on a timer (the reaper's interval).
const stopPoll = 250 * time.Millisecond

// stopSettle bounds the wait for this process's own SIGCONT after it raised its stop. A stop the kernel discards
// (an orphaned process group's SIGTSTP) is never followed by a SIGCONT; once it has passed, the agent is resumed
// as if tego had been continued. A stop that did happen freezes this timer with everything else, and a SIGCONT
// and the timer both ready on waking resume the agent the same way.
const stopSettle = time.Second

// startStopFollower starts followStops for a run whose agent shares a terminal with tego (term non-nil), as a member
// of the run's group. A run without one (a pipe, a file, a detached service) is left as it was.
func (r *runner) startStopFollower(ctx context.Context, term *sharedTerminal) {
	if term == nil || r.child == nil {
		return
	}
	r.group.Go("jobstop", func() error { r.followStops(ctx, term); return nil })
}

// followStops is the run's job control (G2), what sudo and script do for the command they run. An agent that
// stops itself (Claude Code's Ctrl-Z is kill(own pid, SIGTSTP)) stops alone: the shell waits for its job, which
// is tego, so without this it never gets the terminal back, and the next Ctrl-C there reaches the stopped run.
// When the agent's main process stops, answerStop stops tego the same way so the shell sees its job stopped, and
// resumes the agent once tego is continued (fg or bg).
//
// It is terminal plumbing and nothing else: it records nothing, starts no stop_grace and asks the supervisor
// nothing. A launcher that ignores SIGTSTP never follows: tier 2's, which must not stop because its fanotify
// listener answers for the host (HoldJobControl, E40), and one started with it ignored, which asked not to stop.
func (r *runner) followStops(ctx context.Context, term *sharedTerminal) {
	if signal.Ignored(syscall.SIGTSTP) {
		return
	}
	chld := make(chan os.Signal, 1)
	signal.Notify(chld, syscall.SIGCHLD)
	defer signal.Stop(chld)
	cont := make(chan os.Signal, 1)
	signal.Notify(cont, syscall.SIGCONT)
	defer signal.Stop(cont)
	tick := time.NewTicker(stopPoll)
	defer tick.Stop()
	for {
		sig, err := r.child.TakeStop()
		if err != nil {
			return // the agent has exited (or its pidfd is closed): nothing is left to follow
		}
		if sig != 0 {
			r.answerStop(ctx, term, sig, cont)
		}
		select {
		case <-ctx.Done():
			return
		case <-chld:
		case <-tick.C:
		}
	}
}

// answerStop follows one stop of the agent by sig. Only a run in the foreground of its terminal (tego's process
// group in front, or the agent's own) follows: a background run, and a terminal that is not tego's controlling
// one, are left as they were. It puts back the modes saved before the agent ran (the shell takes over a terminal
// in the state the stopped job leaves it), keeps the agent's for later, and stops this process with sig (SIGSTOP
// if it ignores sig). Continued, and in front again, it gives the terminal back to the agent's process group if
// that was in front at the stop, puts the agent's modes back, and continues the agent's group; continued in the
// background (bg) it only continues the agent's group, without touching the terminal.
func (r *runner) answerStop(ctx context.Context, term *sharedTerminal, sig syscall.Signal, cont <-chan os.Signal) {
	own := unix.Getpgrp()
	agent, err := unix.Getpgid(r.child.PID)
	if err != nil {
		return // gone between the stop and now
	}
	front, err := term.foreground()
	if err != nil || front != own && front != agent {
		r.log.Debug("run: the agent stopped in the background", "signal", sig)
		return
	}
	modes, err := termiosOf(term.modes)
	if err == nil && *modes != term.saved {
		_ = sys.FileDo(term.modes, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, &term.saved) })
	}
	raise := sig
	if signal.Ignored(sig) {
		raise = syscall.SIGSTOP
	}
	for len(cont) > 0 {
		<-cont
	}
	r.log.Debug("run: the agent stopped; tego stops with it", "signal", sig)
	if err := unix.Kill(os.Getpid(), raise); err != nil {
		r.log.Debug("run: could not stop with the agent", "err", err)
	}
	settle := time.NewTimer(stopSettle)
	select {
	case <-cont:
	case <-settle.C:
	case <-ctx.Done():
	}
	settle.Stop()
	if back, err := term.foreground(); err == nil && back == own {
		_ = sys.FileDo(term.modes, func(fd int) error {
			if front == agent && agent != own {
				_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, agent)
			}
			if modes != nil {
				return unix.IoctlSetTermios(fd, unix.TCSETS, modes)
			}
			return nil
		})
	}
	if err := unix.Kill(-agent, syscall.SIGCONT); err != nil {
		_ = r.child.Signal(syscall.SIGCONT)
	}
	r.log.Debug("run: continued; the agent resumes")
}

// foreground is the process group in front of the terminal, an error when it is not this process's controlling
// terminal (ENOTTY), which has no foreground to follow.
func (t *sharedTerminal) foreground() (int, error) {
	var pg int
	err := sys.FileDo(t.modes, func(fd int) error {
		var err error
		pg, err = unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		return err
	})
	return pg, err
}
