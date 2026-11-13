// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// LineCheck is the check of one run's lines, one line at a time, that Walk, internal/ledger's Binder and its
// Follower share: each line's id is the digest of its bytes, seq is gapless and prev names the line before
// (record.Chain, I3, I4); every line carries the run's id (ErrRunMismatch); and run_start is line 0 and only line 0
// (runtime-launch.md §8, ErrRunShape). A line a newer record version wrote has its link checked, never its schema
// (limits-check-doctor-cli.md §6 case 20). None of its callers lets a line follow run_end; each says so in its own
// terms, from Ended.
//
// It holds no line: a chain's head and length, the run id, its revision and two flags, whatever the run's length.
type LineCheck struct {
	Chain record.Chain
	// Run is the id every line must carry; "" until the first line names it, for a caller that does not know it.
	Run string
	// Started: a run_start was read at seq 0. Ended: the last line read is a run_end.
	Started, Ended bool
	// Validate also holds each line of this binary's version to its schema at the run's revision
	// (record.Event.ValidateAt), as Verify does; the Follower decodes as the views do and leaves validation to Verify.
	Validate bool
	// minor is the run's revision, its run_start's record_minor, read when Validate is set: a field malformed or
	// below its revision is refused on any line.
	minor int
}

// Add checks data as the run's next line and returns its decoded event, or, for a line of a newer record version,
// nil and newer true. On a chain error the chain is unchanged; on a run or position error the line was linked, so
// Chain.Len counts it, as Verify has always reported it.
func (c *LineCheck) Add(data []byte) (e *record.Event, newer bool, err error) {
	var (
		run  string
		seq  uint64
		kind record.Kind
	)
	e, err = c.Chain.Add(data)
	switch {
	case errors.Is(err, record.ErrNewerVersion):
		link, lerr := c.Chain.AddNewer(data)
		if lerr != nil {
			return nil, false, lerr
		}
		newer, run, seq, kind = true, link.Run, link.Seq, record.Kind(link.Kind)
	case err != nil:
		return nil, false, err
	default:
		if c.Validate {
			if verr := c.validateAt(e); verr != nil {
				return nil, false, fmt.Errorf("line %d: %w", c.Chain.Len()-1, verr)
			}
		}
		run, seq, kind = e.Run, e.Seq, e.Kind
	}
	if c.Run == "" {
		c.Run = run
	}
	if run != c.Run {
		return nil, newer, fmt.Errorf("%w: line %d is run %q, verifying %q", ErrRunMismatch, c.Chain.Len()-1, run,
			c.Run)
	}
	if (seq == 0) != (kind == record.KindRunStart) {
		return nil, newer, coded(ErrRunShape,
			fmt.Errorf("line %d is %s: run_start is the first line and only the first", seq, kind))
	}
	// A newer line's kind and seq are chain fields, read as a v1 line's are: a newer run_start opens the ledger and a
	// newer run_end closes it.
	c.Started = c.Started || (seq == 0 && kind == record.KindRunStart)
	c.Ended = kind == record.KindRunEnd
	return e, newer, nil
}

// validateAt holds e to its schema at the run's revision: a run_start sets that revision from its own record_minor
// (record.Event.ValidateAt).
func (c *LineCheck) validateAt(e *record.Event) error {
	if e.Kind == record.KindRunStart {
		m, err := e.RunStartMinor()
		if err != nil {
			return err
		}
		c.minor = m
	}
	return e.ValidateAt(c.minor)
}

// AfterRunEnd is the finding for a line that follows run_end: line is its number, offset where it starts.
func AfterRunEnd(line uint64, offset int64) error {
	return coded(ErrAfterRunEnd, fmt.Errorf("line %d follows run_end at byte offset %d", line, offset))
}
