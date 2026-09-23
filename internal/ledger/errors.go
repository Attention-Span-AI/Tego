// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Sentinel errors (I10). Every error this package returns wraps one of them or an *os.PathError, so callers
// test with errors.Is through the CLI's own wrapping.
var (
	// ErrRunLocked is returned by Open when another live process holds the run's lock (§7 row 1).
	ErrRunLocked = errors.New("ledger: run already active [run-locked]")
	// ErrRunEnded is returned by Open when the run directory already holds a run_end line.
	ErrRunEnded = errors.New("ledger: run already ended")
	// ErrBadRunRef is returned by Open when the run id or agent id has the wrong shape.
	ErrBadRunRef = errors.New("ledger: bad run reference")
	// ErrShortWrite is returned when write(2) accepted fewer bytes than the line without an error (E5).
	ErrShortWrite = errors.New("ledger: short write")
	// ErrTorn is returned by Append and Close after a write left a torn line on disk (E6, E7); the run is
	// terminal and only the reader's tolerance can recover it.
	ErrTorn = errors.New("ledger: a previous write left the ledger torn")
	// ErrClosed is returned by Append and Blob after Close (E26).
	ErrClosed = errors.New("ledger: writer closed")
	// ErrAlreadyClosed is returned by a second Close.
	ErrAlreadyClosed = errors.New("ledger: writer already closed")
	// ErrNotStarted is returned by Append when run_start has not been written yet, or a second time.
	ErrNotStarted = errors.New("ledger: run_start must be the first and only first event")
	// ErrAnchorWrite is returned by Close when events.jsonl is fsync'd and complete but the chain.log anchor
	// could not be written (E29): the run's own data is intact.
	ErrAnchorWrite = errors.New("ledger: chain anchor not written")
	// ErrCorruptLedger is returned by the reader for a malformed line that is not the torn tail (§7).
	ErrCorruptLedger = errors.New("ledger: corrupt line")
	// ErrBadSHA is returned for a blob name that is not 64 lowercase hex characters.
	ErrBadSHA = errors.New("ledger: blob name is not a sha256")
	// ErrUnsupportedVersion is record.ErrUnsupportedVersion, re-exported so callers of the reader need one
	// package.
	ErrUnsupportedVersion = record.ErrUnsupportedVersion
	// ErrCorruptChain is record.ErrCorruptChain: seq not gapless or prev not the previous id (I3, I4).
	ErrCorruptChain = record.ErrCorruptChain
	// ErrUnverified wraps every way Verify can find a ledger that is not what its writer wrote: a line
	// that does not hash to its id, a broken seq or prev link, an invalid event, an anchored head the
	// ledger does not end with, an anchor that is missing or malformed. An error without it is a read
	// failure, which says nothing about the ledger's integrity.
	ErrUnverified = errors.New("ledger: unverified")
	// ErrAnchorMissing is what Verify reports, beside ErrUnverified, for an ended run that chain.log has
	// no line for (E29). It is distinct from ErrCorruptChain: the run's own chain may be intact, but its
	// head has nothing outside the run directory to be checked against. The live-index sweep (SweepLive,
	// endListed) rebuilds the line only for an ended run the index still lists, under its lock and after the
	// chain verifies; a run whose Close failed its anchor write (E29) is cleared from the index, and nothing
	// rebuilds its line.
	ErrAnchorMissing = errors.New("ledger: no chain anchor for this run")
	// ErrRunClosing is what Verify reports for an ended run with no anchor line whose lock is still held after
	// closeWait: the launcher is inside Close, which anchors last. It is not a finding and does not wrap
	// ErrUnverified; a retry a moment later verifies.
	ErrRunClosing = errors.New("ledger: run is closing, retry")
	// ErrLedgerMissing is what VerifyRunDir reports, beside ErrUnverified, for a run chain.log anchors
	// whose events.jsonl is gone: the anchor says the run was recorded, so its absence is a finding
	// about the record, not a run that never existed.
	ErrLedgerMissing = errors.New("ledger: the anchored run's ledger is missing")
	// ErrRunMismatch is what Verify reports, beside ErrUnverified, for a line whose run id is not the
	// run being verified: a ledger copied in from another run keeps an intact chain of its own, and
	// only the id tells it from the run its directory names.
	ErrRunMismatch = errors.New("ledger: a line belongs to another run")
	// ErrLinkRefused is a symlink root would have had to follow in a directory that is not root's
	// alone (handover.go): the directory's owner could have aimed it anywhere, so root refuses it.
	ErrLinkRefused = errors.New("ledger: refusing to follow a symlink in a directory another user can change")
)
