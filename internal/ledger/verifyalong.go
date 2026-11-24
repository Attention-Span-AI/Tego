// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"

	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

// Verifier is the chain check (Verify) riding one pass of Lines, so a caller that reads the whole record anyway (the
// receipt behind tego run's end summary) does not read it a second time to verify it. It takes each scanned line as the
// pass reads it, before any view decodes or skips it, and steps the same walk Verify steps (chaincheck.Walk, every line
// validated); Finish then does what Verify does after its last line: the end rules and the anchor, and it gives
// what Verify gives. A pass that stopped before the end of the record (a view that returned early) leaves the walk
// short, and Finish then reads the record again, which is Verify.
type Verifier struct {
	r        *Reader
	w        *chaincheck.Walk
	err      error // the first line the walk refused
	done     bool  // the walk needs no more lines: it refused one, or stopped
	complete bool  // the pass read the record to its end
}

// VerifyAlong attaches a Verifier to the next pass of Lines over r, and only that pass.
func (r *Reader) VerifyAlong() *Verifier {
	v := &Verifier{r: r, w: chaincheck.NewWalk(runDirName(r.dir), true)}
	r.verifier = v
	return v
}

// takeVerifier hands the Verifier VerifyAlong attached to the pass starting now, and detaches it.
func (r *Reader) takeVerifier() *Verifier {
	v := r.verifier
	r.verifier = nil
	return v
}

// feed steps the walk over one scanned line, or over the error that ended the scan.
func (v *Verifier) feed(l rawLine, scanErr error) {
	if v == nil || v.done {
		return
	}
	stop, err := v.w.Step(chaincheck.Line{Data: l.data, Terminated: l.terminated}, scanErr)
	switch {
	case err != nil:
		v.err, v.done = err, true
	case stop:
		v.done = true
	}
}

// finished marks the pass as having read the record to its end.
func (v *Verifier) finished() {
	if v != nil {
		v.complete = true
	}
}

// Finish is Verify's answer for the record the pass read: the same report and the same error, against anchor (which may
// be nil, as in Verify).
func (v *Verifier) Finish(ctx context.Context, anchor ChainAnchor) (VerifyReport, error) {
	if !v.complete {
		return v.r.verify(ctx, anchor, false, true)
	}
	if v.err != nil {
		return v.w.Report(), v.err
	}
	return v.r.verifyEnd(ctx, v.w, anchor, false, true)
}
