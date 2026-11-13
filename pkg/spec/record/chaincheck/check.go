// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bytes"
	"errors"
)

// Input is one chain check's facts, all of them bytes a caller already holds.
type Input struct {
	// Dir is the name of the run directory: the last component of the path that names it (RunDirPath).
	Dir string
	// Events is events.jsonl; NoEvents says the run directory holds none.
	Events   []byte
	NoEvents bool
	// AnchorGiven says chain.log is consulted; Anchor is its bytes, and NoAnchorFile says the anchor path names no
	// file, which anchors nothing.
	AnchorGiven  bool
	Anchor       []byte
	NoAnchorFile bool
	// Validate also holds each line to its schema at the run's revision, as `tego events --verify` does; without it
	// the check is integrity alone, the scope the Rust twin implements.
	Validate bool
}

// ErrNoLedger is Check's error for a run directory with no events.jsonl that nothing anchors: it says nothing about
// the record (Reason: cannot-check, "no-ledger").
var ErrNoLedger = errors.New("chaincheck: no events.jsonl")

// Check applies the chain and anchor rules over bytes held in memory (CHAIN.md). With Validate it also
// checks the schema at the run's revision, as internal/ledger's VerifyRunDir does. Without Validate its
// scope is integrity alone. Reason interprets the report and error without reading error messages.
func Check(in Input) (Report, error) {
	heads := func(run string) AnchorHead {
		if in.NoAnchorFile {
			return AnchorHead{}
		}
		return AnchorHeads(bytes.NewReader(in.Anchor), []string{run})[run]
	}
	if in.NoEvents {
		var a AnchorHead
		if in.AnchorGiven {
			a = heads(in.Dir)
		}
		return MissingLedger(in.Dir, "events.jsonl", a, in.AnchorGiven, false, ErrNoLedger)
	}
	rescanned := false
	for {
		w := NewWalk(in.Dir, in.Validate)
		for l, err := range ScanLines(bytes.NewReader(in.Events)) {
			stop, err := w.Step(l, err)
			if err != nil {
				return w.Report(), err
			}
			if stop {
				break
			}
		}
		if err := w.Finish(); err != nil {
			return w.Report(), err
		}
		if !in.AnchorGiven {
			return w.Report(), nil
		}
		run, err := w.AnchorRun()
		if err != nil {
			return w.Report(), err
		}
		a := heads(run)
		next, err := w.Anchor(a, rescanned)
		switch {
		case err != nil:
			return w.Report(), err
		case next == AnchorRescan:
			rescanned = true
			continue
		case next == AnchorAwait:
			// No lock is held over bytes: the run is not closing, and the anchor reads as it did.
			err = w.AnchorAfterWait(a)
		}
		return w.Report(), err
	}
}
