// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"errors"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The check's sentinels. internal/ledger re-exports the ones it already had under their old names and messages, so
// errors.Is answers as before through every caller's wrapping. A finding about the record's content wraps
// ErrUnverified; an error without it says the record could not be read, never anything about its integrity.
var (
	// ErrCorruptLedger is a line that is not a record line and not a torn tail, or a chain.log line that is not an
	// anchor line (record-ledger.md §7).
	ErrCorruptLedger = errors.New("ledger: corrupt line")
	// ErrUnverified wraps every finding: the record is not what its writer wrote, or not anchored as it must be.
	ErrUnverified = errors.New("ledger: unverified")
	// ErrAnchorMissing is an ended run that chain.log has no line for (E29).
	ErrAnchorMissing = errors.New("ledger: no chain anchor for this run")
	// ErrLedgerMissing is a run chain.log anchors whose events.jsonl is gone.
	ErrLedgerMissing = errors.New("ledger: the anchored run's ledger is missing")
	// ErrRunMismatch is a line whose run id is not the run being checked.
	ErrRunMismatch = errors.New("ledger: a line belongs to another run")

	// The sentinels below name a finding that had none of its own. Each is attached with coded, which keeps the
	// finding's message as it was and adds the sentinel for errors.Is, so Reason can give every finding its code.

	// ErrRunShape is run_start anywhere but line 0, or line 0 not a run_start.
	ErrRunShape = errors.New("chaincheck: run_start is the first line and only the first")
	// ErrAfterRunEnd is a line, or bytes, after run_end.
	ErrAfterRunEnd = errors.New("chaincheck: bytes after run_end")
	// ErrLineTooLong is a line past MaxLineBytes.
	ErrLineTooLong = errors.New("chaincheck: line too long")
	// ErrRunIDInvalid is a run whose name is no run id, so its anchor line cannot be looked up.
	ErrRunIDInvalid = errors.New("chaincheck: run id cannot be looked up in the anchor")
	// ErrAnchorMismatch is an anchored head the ledger does not end with.
	ErrAnchorMismatch = errors.New("chaincheck: anchored head differs")
	// ErrAnchorMalformed is a chain.log that holds a line that is not an anchor line, or two heads for the run.
	ErrAnchorMalformed = errors.New("chaincheck: chain.log is malformed")
	// ErrLedgerReplaced is an anchored run whose events.jsonl is a link, a FIFO, a directory or any other
	// non-regular file.
	ErrLedgerReplaced = errors.New("chaincheck: the anchored run's ledger is not a regular file")
)

// codedError is err with a further sentinel for errors.Is; its message is err's alone.
type codedError struct {
	code, err error
}

func (e *codedError) Error() string   { return e.err.Error() }
func (e *codedError) Unwrap() []error { return []error{e.err, e.code} }

// coded returns err with code attached (codedError).
func coded(code, err error) error { return &codedError{code: code, err: err} }

// The verdicts of CHAIN.md §8.
const (
	VerdictMatch       = "match"
	VerdictMismatch    = "mismatch"
	VerdictCannotCheck = "cannot-check"
)

// Reason is the verdict and reason code (CHAIN.md §8) of a check's result: Check's, or internal/ledger's
// VerifyRunDir's and its integrity-only disk test bridge's. It reads err and the report alone, never a message's text, so a twin
// compares meaning. A finding with no code of its own reads "unverified" (a schema finding of a validating check);
// an error that is not a finding reads cannot-check "unreadable", or "no-ledger" when the error says the ledger
// does not exist (notExist, which the caller decides: this package does not import os).
func Reason(rep Report, err error, notExist func(error) bool) (verdict, reason string) {
	if err == nil {
		if !rep.Started {
			return VerdictCannotCheck, "no-run-start"
		}
		return VerdictMatch, "ok"
	}
	if !errors.Is(err, ErrUnverified) {
		switch {
		case errors.Is(err, ErrRunClosing):
			return VerdictCannotCheck, "run-closing"
		case errors.Is(err, ErrNoLedger), notExist != nil && notExist(err):
			return VerdictCannotCheck, "no-ledger"
		}
		return VerdictCannotCheck, "unreadable"
	}
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrLedgerMissing, "ledger-missing"},
		{ErrLedgerReplaced, "ledger-replaced"},
		{ErrAfterRunEnd, "after-run-end"},
		{ErrRunMismatch, "run-mismatch"},
		{ErrRunShape, "run-shape"},
		{ErrRunIDInvalid, "run-id-invalid"},
		{ErrAnchorMissing, "anchor-missing"},
		{ErrAnchorMismatch, "anchor-mismatch"},
		{ErrAnchorMalformed, "anchor-malformed"},
		{ErrLineTooLong, "line-too-long"},
		{record.ErrIDMismatch, "id-mismatch"},
		{record.ErrCorruptChain, "chain-broken"},
		{record.ErrMalformedLine, "line-malformed"},
		{record.ErrUnsupportedVersion, "line-malformed"},
	} {
		if errors.Is(err, c.err) {
			return VerdictMismatch, c.code
		}
	}
	return VerdictMismatch, "unverified"
}

// ErrRunClosing is an ended run with no anchor line whose lock is still held: the launcher is inside Close, which
// anchors last. It is not a finding; a retry a moment later checks. Only a caller that probes the lock (internal/ledger)
// returns it; this package names it so Reason can.
var ErrRunClosing = errors.New("ledger: run is closing, retry")
