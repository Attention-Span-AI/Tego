// SPDX-License-Identifier: Apache-2.0

package ledger

import "errors"

// Verdict is what one check of a run's record says about it: VerifyRunDir's result read the one way both `tego events
// <run> --verify` (R29) and the dashboard's chain check (internal/control/ledgerview) read it. The dashboard may not
// link the command line (TestControlLinksNoEngine), so the reading lives here, where both import it.
type Verdict int

// The verdicts. The zero Verdict is NoVerdict, so a verdict nobody set never reads as verified.
const (
	// NoVerdict is a check that could not judge the record: the ledger or the anchor could not be read, the run is
	// still inside Close, or the ledger verified but holds no run_start (a check of nothing, R25). `tego events
	// --verify` exits 125; the dashboard says "not checked".
	NoVerdict Verdict = iota
	// Verified is a record that is what its writer wrote: the chain holds and its head is anchored, or the run has not
	// ended and has no anchor line yet. Exit 0.
	Verified
	// Unverified is a record that is not what its writer wrote (ErrUnverified): a line that does not hash or chain,
	// an anchored head the ledger does not end with, an ended run with no anchor line, an anchored run whose ledger is
	// gone. Exit 1, [ledger-corrupt].
	Unverified
)

// VerdictOf is the verdict of a VerifyRunDir (or Reader.Verify) result: Unverified for an error that wraps
// ErrUnverified, whatever else the report says; NoVerdict for any other error, and for a ledger that verified with no
// run_start; Verified otherwise.
func VerdictOf(rep VerifyReport, err error) Verdict {
	switch {
	case errors.Is(err, ErrUnverified):
		return Unverified
	case err != nil, !rep.Started:
		return NoVerdict
	}
	return Verified
}
