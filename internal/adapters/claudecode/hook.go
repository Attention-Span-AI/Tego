// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
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
// SessionStart prints the run's facts and pending refusals, and counts the session. PostToolUse,
// PostToolUseFailure, PostToolBatch and Stop each claim the refusals that are theirs and not yet claimed, under the
// state lock, print them (reason.Render) and then, under the lock again, mark the claim printed; with nothing new
// they print nothing, and neither does a Stop with stop_hook_active, which claims nothing, so a turn goes on at most
// once. A refusal is theirs when the hook's harness is the nearest of the harnesses that have a hook among the refusal's owners, or when none is (it is shared). A claim
// whose hook was stopped before it marked it printed is told again by the next hook of that harness, so a refusal is
// printed at least once and may be printed twice; printed means the hook's output was written to the harness without
// error, and Tego cannot see whether the harness passed it to the model. Outside any tego run (no
// --reason, no TEGO_REASON) it is a silent no-op. Anything else it cannot use (its arguments, the payload, the
// reason file, hook-state, the lock) leaves one line on stderr, nothing on stdout and exit 0: the agent loses a
// note, the run loses nothing. Exit 2 comes only from --mode stderr, for the events where it shows Claude the text.
func Run(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	return run(stdin, stdout, stderr, args, os.Getenv, uint32(os.Getuid()), LockBudget) //nolint:gosec // a uid fits 32 bits
}

// run is Run with its environment, uid and lock budget given.
func run(stdin io.Reader, stdout, stderr io.Writer, args []string, getenv func(string) string, uid uint32, budget time.Duration) int {
	return runWith(stdin, stdout, stderr, args, getenv, uid, budget, systemProcs())
}

// runWith is run with the processes it asks about given (procs).
func runWith(stdin io.Reader, stdout, stderr io.Writer, args []string, getenv func(string) string, uid uint32, budget time.Duration, p procs) int {
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
	text, tok, err := answer(t, in.HookEventName, budget, p)
	if err != nil {
		warn(stderr, err.Error())
		return exitOK
	}
	if text == "" {
		return exitOK
	}
	if *mode == ModeStderr {
		// A failed write to Claude Code's pipe has nowhere to be reported, and leaves the claim for the next hook.
		if _, err := io.WriteString(stderr, bounded(text)); err == nil {
			markPrinted(t, tok, budget, stderr)
		}
		return exitFeedback
	}
	if err := writeContext(stdout, in.HookEventName, text); err != nil {
		warn(stderr, "write: "+err.Error())
		return exitOK // the claim stays pending: the next hook of this harness tells it again
	}
	markPrinted(t, tok, budget, stderr)
	return exitOK
}

// markPrinted removes the claim tok names from the state and counts the delivery, under the lock: the hook's output
// was written to the harness without error. A claim another hook already told again (it was older than claimStale)
// is not there, and nothing is counted.
func markPrinted(t target, tok claimToken, budget time.Duration, stderr io.Writer) {
	if !tok.made {
		return
	}
	if err := commit(t, tok, budget); err != nil {
		warn(stderr, err.Error())
	}
}

// claimToken names the claim answer made, for markPrinted.
type claimToken struct {
	made bool
	by   string
	at   int64
}

// answer is the text the hook prints for event, "" for nothing, with the claim committed first: under the lock it
// reads the reason file and state, tells again the claims of this hook's harness whose claimer is gone or too old,
// claims at delivery events and the first SessionStart what is this hook's (claim), records the claim as pending, and
// writes the state. Later starts preview pending refusals without claiming, so they cannot consume another session's
// tool note. Concurrent delivery hooks claim each refusal once. A hook killed between this write and its print leaves
// the claim pending, and the next hook of its harness tells it again (at least once; a note may print twice); the
// ledger still holds every refusal.
func answer(t target, event string, budget time.Duration, p procs) (string, claimToken, error) {
	d, err := openStateDir(t.dir)
	if err != nil {
		return "", claimToken{}, err
	}
	defer d.close()
	if err := d.lock(budget); err != nil {
		return "", claimToken{}, err
	}
	f, err := readReason(t.reasonFile)
	if err != nil {
		return "", claimToken{}, err
	}
	if f != nil && f.Run != t.run {
		return "", claimToken{}, fmt.Errorf("reason file %s is run %q's, not %q's", t.reasonFile, f.Run, t.run)
	}
	s, err := d.read(t.run)
	if err != nil {
		return "", claimToken{}, err
	}
	var text string
	owner := p.harness()
	next := s
	next.Owned = maps.Clone(s.Owned)
	next.Pending = slices.Clone(s.Pending)
	next.Harnesses = recordHarness(s.Harnesses, owner, p)
	redo, carry := reap(&next, owner, p)
	entries, notListed := claim(f, &next, owner, redo, carry)
	claims := len(entries) > 0 || notListed > 0
	tok := claimToken{}
	if claims && (event != EventSessionStart || s.Sessions == 0) {
		if len(next.Pending) >= maxPending {
			return "", claimToken{}, fmt.Errorf("%w: %d claims are waiting to be marked printed; refusals stay unclaimed", errState, len(next.Pending))
		}
		tok = claimToken{made: true, by: p.self(), at: p.now().Unix()}
		c := Claim{Owner: owner, By: tok.by, At: tok.at, NotListed: notListed}
		for _, e := range entries {
			c.Seqs = append(c.Seqs, e.Seq)
		}
		next.Pending = append(next.Pending, c)
		if !fit(&next, owner) {
			return "", claimToken{}, fmt.Errorf("%w: the state does not fit %d bytes; refusals stay unclaimed", errState, MaxStateBytes)
		}
		s = next
	}
	if event == EventSessionStart {
		s.Sessions++
		text = reason.RenderSessionStart(t.reasonFile, entries, notListed)
	} else {
		if text = reason.Render(entries, notListed); text == "" {
			return "", claimToken{}, nil // nothing new: the state is left as it was
		}
	}
	s.Harnesses = next.Harnesses
	if err := d.write(s); err != nil {
		return "", claimToken{}, err
	}
	return text, tok, nil
}

// commit marks the claim tok names printed: under the lock it removes it from the state's pending claims and counts
// the delivery.
func commit(t target, tok claimToken, budget time.Duration) error {
	d, err := openStateDir(t.dir)
	if err != nil {
		return err
	}
	defer d.close()
	if err := d.lock(budget); err != nil {
		return err
	}
	s, err := d.read(t.run)
	if err != nil {
		return err
	}
	for i, c := range s.Pending {
		if c.By == tok.by && c.At == tok.at {
			s.Pending = slices.Delete(slices.Clone(s.Pending), i, i+1)
			if len(s.Pending) == 0 {
				s.Pending = nil
			}
			s.Deliveries++
			return d.write(s)
		}
	}
	return nil
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
