// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// Verb is the hidden tego verb cmd/tego dispatches to Run before the command line (`tego hook claude-code ...`):
// a harness-facing command, not a user's, so `tego -h` does not list it.
const Verb = "hook"

// Harness is the word after Verb that names this adapter.
const Harness = "claude-code"

// Run is `tego hook claude-code [--reason FILE] [--mode json|stderr]`, args being what follows Verb: one Claude
// Code hook event read from stdin, answered on stdout or stderr, its exit code returned (spec/reason/
// REASON-CHANNEL.md §3, ADR 0063).
//
// SessionStart prints the run's facts (reason.HookInstructions) and counts the session. PostToolUse,
// PostToolUseFailure, PostToolBatch and Stop each claim the refusals no hook of the run has shown yet, under the
// state lock, and print them once (reason.Render); with nothing new they print nothing, and neither does a Stop
// with stop_hook_active, which claims nothing, so a turn goes on at most once. Outside any tego run (no
// --reason, no TEGO_REASON) it is a silent no-op. Anything else it cannot use (its arguments, the payload, the
// reason file, hook-state, the lock) leaves one line on stderr, nothing on stdout and exit 0: the agent loses a
// note, the run loses nothing. Exit 2 comes only from --mode stderr, for the events where it shows Claude the text.
func Run(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	return run(stdin, stdout, stderr, args, os.Getenv, uint32(os.Getuid()), LockBudget) //nolint:gosec // a uid fits 32 bits
}

// run is Run with its environment, uid and lock budget given.
func run(stdin io.Reader, stdout, stderr io.Writer, args []string, getenv func(string) string, uid uint32, budget time.Duration) int {
	if len(args) == 0 || args[0] != Harness {
		warn(stderr, fmt.Sprintf("the first argument names the harness, and this tego has a hook for %s only", Harness))
		return exitOK
	}
	fs := flag.NewFlagSet(Verb+" "+Harness, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reasonFlag := fs.String("reason", "", "the run's reason file (default $"+envReason+")")
	mode := fs.String("mode", ModeJSON, "json or stderr")
	if err := fs.Parse(args[1:]); err != nil {
		warn(stderr, "usage: "+err.Error())
		return exitOK
	}
	if fs.NArg() > 0 || (*mode != ModeJSON && *mode != ModeStderr) {
		warn(stderr, fmt.Sprintf("usage: %s %s [--reason FILE] [--mode %s|%s]", Verb, Harness, ModeJSON, ModeStderr))
		return exitOK
	}
	reasonSet := false
	fs.Visit(func(f *flag.Flag) { reasonSet = reasonSet || f.Name == "reason" })
	t, found, err := discover(*reasonFlag, reasonSet, getenv, uid)
	if !found {
		return exitOK // outside any tego run: a hand install is a silent no-op
	}
	if err != nil {
		warn(stderr, err.Error())
		return exitOK
	}
	in, err := decodeInput(stdin)
	if err != nil {
		warn(stderr, err.Error())
		return exitOK
	}
	switch in.HookEventName {
	case EventSessionStart, EventPostToolBatch:
		if *mode == ModeStderr {
			return exitOK // exit 2 would reach only the user (SessionStart) or end the agent's loop (PostToolBatch)
		}
	case EventStop:
		if in.StopHookActive {
			// A Stop hook already kept this turn going once: say nothing and claim nothing, so the turn ends. Its
			// refusals stay for the next PostToolUse or the next turn's first Stop; a note here would keep a turn
			// going for as long as the run refuses, since a tool call resets Claude Code's continuation cap.
			return exitOK
		}
	case EventPostToolUse, EventPostToolUseFailure:
	default:
		warn(stderr, fmt.Sprintf("hook event %q is not one this hook answers", in.HookEventName))
		return exitOK
	}
	text, err := answer(t, in.HookEventName, budget)
	if err != nil {
		warn(stderr, err.Error())
		return exitOK
	}
	if text == "" {
		return exitOK
	}
	if *mode == ModeStderr {
		_, _ = io.WriteString(stderr, bounded(text)) // a failed write to Claude Code's pipe has nowhere to be reported
		return exitFeedback
	}
	if err := writeContext(stdout, in.HookEventName, text); err != nil {
		warn(stderr, "write: "+err.Error())
	}
	return exitOK
}

// answer is the text the hook prints for event, "" for nothing, with the state committed first: under the lock it
// reads the reason file and the state, claims (or, at SessionStart, counts the session), and writes the state, so
// that of hook processes started at once each refusal is printed by exactly one. A hook killed between the write
// and its print loses that note (at most once); the ledger still holds every refusal.
func answer(t target, event string, budget time.Duration) (string, error) {
	d, err := openStateDir(t.dir)
	if err != nil {
		return "", err
	}
	defer d.close()
	if err := d.lock(budget); err != nil {
		return "", err
	}
	f, err := readReason(t.reasonFile)
	if err != nil {
		return "", err
	}
	if f != nil && f.Run != t.run {
		return "", fmt.Errorf("reason file %s is run %q's, not %q's", t.reasonFile, f.Run, t.run)
	}
	s, err := d.read(t.run)
	if err != nil {
		return "", err
	}
	var text string
	if event == EventSessionStart {
		s.Sessions++
		text = reason.HookInstructions(t.reasonFile)
	} else {
		entries, notListed := claim(f, &s)
		if text = reason.Render(entries, notListed); text == "" {
			return "", nil // nothing new: the state is left as it was
		}
	}
	if err := d.write(s); err != nil {
		return "", err
	}
	return text, nil
}

// errReasonFile is a reason file the hook cannot read.
var errReasonFile = errors.New("unreadable reason file")

// readReason is the run's reason file, nil when the run has refused nothing yet (no file): opened without
// following a link or blocking on a FIFO, a regular file, decoded within its bound (reason.Decode).
func readReason(path string) (*reason.File, error) {
	fh, err := openRegular(path)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errReasonFile, err)
	}
	defer func() { _ = fh.Close() }() // read-only: nothing to flush
	f, err := reason.Decode(fh)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errReasonFile, path, err)
	}
	return f, nil
}
