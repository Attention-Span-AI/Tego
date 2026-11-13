// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Report is what a check found. internal/ledger names it VerifyReport.
type Report struct {
	// Run is the run being checked: the run directory's name when that is a run id, as it is for every directory a
	// ledger root holds, else the id the ledger's first line names.
	Run string
	// Lines is the number of complete lines the chain held through, whether or not the check failed: on a failure it
	// is the count before the line that broke it (a line that chains but fails validation, the run check or the shape
	// check is counted).
	Lines uint64
	// Head is the id of the last of those lines.
	Head string
	// Started and Ended report whether run_start opened and run_end closed the ledger.
	Started, Ended bool
	// TornBytes is the size of an ignored final chunk in which no top-level JSON value closed (CHAIN.md §2).
	TornBytes int
	// Anchored is true when an anchor was consulted and its head equals Head.
	Anchored bool
	// Newer is how many lines were of a newer record version: linked into the chain and counted in Lines, their
	// content not validated.
	Newer int
	// AtLine is set when the check failed on a line of its own, and BrokenLine is then that line's number (its seq;
	// run_start is line 0): a line that does not hash to its id, does not chain to the line before, fails validation,
	// belongs to another run, follows run_end or is longer than a line may be. A failure found once every line was
	// read (the anchor, bytes after run_end) or with no ledger to read leaves both unset.
	AtLine     bool
	BrokenLine uint64
}

// Walk is the check of one run's events.jsonl over its framed lines in order (ScanLines), as Verify takes it, and
// then of its anchor. It reads no file and no clock: its caller frames the lines, reads chain.log and, for an ended
// run with no anchor line, decides whether the run is still closing.
//
// Use: NewWalk; Step for each framed line until it says stop or fails; Finish; then, with an anchor, AnchorRun, the
// anchor's line for that run, and Anchor (and AnchorAfterWait when Anchor says AnchorAwait). Report says what it
// found at any point.
type Walk struct {
	check   LineCheck
	rep     Report
	dirName string
	offset  int64 // where the next line starts
}

// NewWalk starts the check of the run whose directory is named dirName (the last component of the path that names
// it, internal/ledger's RunDirPath): every line must carry that id when it is a run id, and the first line's id
// otherwise. validate also holds each line to its schema (LineCheck.Validate).
func NewWalk(dirName string, validate bool) *Walk {
	w := &Walk{check: LineCheck{Validate: validate}, dirName: dirName}
	if identity.RunID(dirName).Valid() {
		w.check.Run = dirName
	}
	return w
}

// Report is what the walk found so far: Lines and Head as far as the chain held, Run as the check had settled it.
func (w *Walk) Report() Report {
	rep := w.rep
	rep.Lines, rep.Head = w.check.Chain.Len(), w.check.Chain.Head()
	if rep.Run == "" {
		rep.Run = w.check.Run
	}
	return rep
}

// Step takes the next framed line and the error its framing gave (ScanLines). It returns stop at a torn tail, which
// ends the walk, and a finding (wrapping ErrUnverified) or the framing's read error otherwise.
func (w *Walk) Step(l Line, scanErr error) (stop bool, err error) {
	if scanErr != nil {
		if errors.Is(scanErr, ErrCorruptLedger) {
			// A line past the bound is the ledger's content, not a read failure.
			w.rep.AtLine, w.rep.BrokenLine = true, w.check.Chain.Len()
			return true, fmt.Errorf("%w: %w", ErrUnverified, scanErr)
		}
		return true, scanErr
	}
	if !l.Terminated && !WholeLine(l.Data) {
		w.rep.TornBytes = len(l.Data)
		return true, nil
	}
	if w.check.Ended {
		w.rep.AtLine, w.rep.BrokenLine = true, w.check.Chain.Len()
		return true, fmt.Errorf("%w: %w", ErrUnverified, AfterRunEnd(w.check.Chain.Len(), w.offset))
	}
	line := w.check.Chain.Len() // the number of the line in hand, which Add may count before it refuses it
	_, newer, err := w.check.Add(l.Data)
	if err != nil {
		w.rep.AtLine, w.rep.BrokenLine = true, line
		return true, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if newer {
		w.rep.Newer++
	}
	w.rep.Started, w.rep.Ended = w.check.Started, w.check.Ended
	w.offset += int64(len(l.Data)) + 1
	return false, nil
}

// Finish is the check once every line was read: bytes after run_end are a finding, since a torn tail is what a
// writer that died mid-write(2) leaves (E6) and a writer that wrote run_end is not that writer (Close appends
// run_end last and fsyncs). It settles Run: the check's, else the directory's name.
func (w *Walk) Finish() error {
	w.rep.Run = w.check.Run
	if w.rep.Ended && w.rep.TornBytes > 0 {
		return fmt.Errorf("%w: %w", ErrUnverified, coded(ErrAfterRunEnd,
			fmt.Errorf("%d bytes at byte offset %d after run_end", w.rep.TornBytes, w.offset)))
	}
	if w.rep.Run == "" {
		w.rep.Run = w.dirName
	}
	return nil
}

// AnchorRun is the run id to look up in the anchor, after Finish; a run that is no run id cannot be looked up, which
// is a finding (ErrRunIDInvalid).
func (w *Walk) AnchorRun() (string, error) {
	if !identity.RunID(w.rep.Run).Valid() {
		return "", fmt.Errorf("%w: %w", ErrUnverified,
			coded(ErrRunIDInvalid, fmt.Errorf("run id %q cannot be looked up in the anchor", w.rep.Run)))
	}
	return w.rep.Run, nil
}

// AnchorNext is what Anchor asks of its caller.
type AnchorNext int

const (
	// AnchorDone: the check is complete.
	AnchorDone AnchorNext = iota
	// AnchorRescan: the scan stopped short of run_end (or inside one) and the anchor already holds another head. A
	// launcher inside Close may have written run_end, fsynced and anchored between the scan and the anchor read;
	// Close fsyncs before it anchors, so the caller walks the ledger once more (a new Walk) and passes rescanned.
	AnchorRescan
	// AnchorAwait: an ended run has no anchor line. A launcher still inside Close (its lock held) anchors last; the
	// caller waits for it as it sees fit and passes what it found to AnchorAfterWait.
	AnchorAwait
)

// Anchor checks the anchor's line for the run (AnchorHeads; AnchorRun names it) against the walk's head. The anchor
// is consulted whenever it has a line for the run, not only when the ledger ends in run_end: an anchored head the
// ledger does not end with is a ledger that lost lines after it was closed, which only the anchor can tell from a
// launcher that died. rescanned says this walk is the one rescan AnchorRescan asked for.
func (w *Walk) Anchor(a AnchorHead, rescanned bool) (AnchorNext, error) {
	if a.Err != nil {
		return AnchorDone, anchorErr(a.Err)
	}
	switch {
	case a.OK && a.Head != w.Report().Head && !rescanned && (!w.rep.Ended || w.rep.TornBytes > 0):
		return AnchorRescan, nil
	case a.OK && a.Head != w.Report().Head:
		return AnchorDone, w.anchorMismatch(a.Head)
	case a.OK:
		w.rep.Anchored = true
	case w.rep.Ended:
		return AnchorAwait, nil
	}
	return AnchorDone, nil
}

// AnchorAfterWait finishes Anchor's AnchorAwait with the anchor's line as the caller last read it, once the run's
// lock was free (or there was none to probe): still no line is ErrAnchorMissing (E29). A caller that gave up while
// the lock was held returns ErrRunClosing itself and does not call this.
func (w *Walk) AnchorAfterWait(a AnchorHead) error {
	switch {
	case a.Err != nil:
		return anchorErr(a.Err)
	case a.OK && a.Head != w.Report().Head:
		return w.anchorMismatch(a.Head)
	case a.OK:
		w.rep.Anchored = true
		return nil
	}
	return fmt.Errorf("%w: %w: %s", ErrUnverified, ErrAnchorMissing, w.rep.Run)
}

func (w *Walk) anchorMismatch(head string) error {
	return fmt.Errorf("%w: %w", ErrUnverified, coded(ErrAnchorMismatch,
		fmt.Errorf("%w: anchored head %q, ledger head %q", record.ErrCorruptChain, head, w.Report().Head)))
}

// anchorErr is an anchor read's error as the check reports it: a malformed chain.log is a finding, any other error a
// read failure.
func anchorErr(err error) error {
	if errors.Is(err, ErrCorruptLedger) {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return err
}

// MissingLedger is the check of a run whose events.jsonl could not be opened: absent (missing) or not the regular
// file the writer made (replaced: a link, a FIFO, a directory), at eventsPath (which errors name), given the anchor's line for dirName and the open's
// error. With an anchor line for the run, that is a finding: chain.log says the run was recorded and closed. Without
// one, openErr is returned as it is: nothing vouches that the run was ever recorded. anchored is false when no
// anchor was given or dirName is no run id; the caller then passes the zero AnchorHead.
func MissingLedger(dirName, eventsPath string, a AnchorHead, anchored, replaced bool, openErr error) (Report, error) {
	if !anchored || !identity.RunID(dirName).Valid() {
		return Report{}, openErr
	}
	rep := Report{Run: dirName}
	switch {
	case a.Err != nil && errors.Is(a.Err, ErrCorruptLedger):
		return rep, fmt.Errorf("%w: %w", ErrUnverified, a.Err)
	case a.Err != nil:
		return rep, a.Err
	case !a.OK:
		return rep, openErr
	case replaced:
		return rep, fmt.Errorf("%w: %w", ErrUnverified, coded(ErrLedgerReplaced,
			fmt.Errorf("chain.log anchors %s at head %s, and %s is not the regular file the writer made: %w",
				dirName, a.Head, eventsPath, openErr)))
	}
	return rep, fmt.Errorf("%w: %w: chain.log anchors %s at head %s, and %s does not exist", ErrUnverified,
		ErrLedgerMissing, dirName, a.Head, eventsPath)
}
