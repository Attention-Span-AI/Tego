// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// AnchorHead is what chain.log says of one run: the head it anchors (OK), no line for it (not OK, no Err), or Err,
// which wraps ErrCorruptLedger and ErrAnchorMalformed when the file is not an anchor (a line that is not
// "<run id> <event id>", or two heads for the run) and is a read error otherwise.
type AnchorHead struct {
	Head string
	OK   bool
	Err  error
}

// AnchorHeads reads chain.log (CHAIN.md §7) for each of runs: one line per anchored run, "<run> <head>\n", the run
// a run id and the head an event id, one space between. An unterminated last line is a torn append and is skipped
// (E28). A malformed line makes the file unreadable for every run, since the line that cannot be read could be any
// run's; two lines for one run that name different heads make that run's anchor corrupt, since a run is anchored
// once, at Close (the same line twice is the same anchor).
func AnchorHeads(f io.ReaderAt, runs []string) map[string]AnchorHead {
	out := make(map[string]AnchorHead, len(runs))
	for _, r := range runs {
		out[r] = AnchorHead{}
	}
	failAll := func(err error) {
		for r, h := range out {
			if h.Err == nil {
				out[r] = AnchorHead{Err: err}
			}
		}
	}
	for l, err := range ScanLines(f) {
		if err != nil {
			err = fmt.Errorf("ledger: read anchor: %w", err)
			if errors.Is(err, ErrCorruptLedger) {
				err = coded(ErrAnchorMalformed, err) // a line past the bound: the file is no anchor
			}
			failAll(err)
			break
		}
		if !l.Terminated {
			break
		}
		r, h, found := bytes.Cut(l.Data, []byte{' '})
		if !found || !identity.RunID(string(r)).Valid() || !record.IsID(string(h)) {
			failAll(coded(ErrAnchorMalformed,
				fmt.Errorf("%w: anchor line %q", ErrCorruptLedger, strings.TrimSpace(string(l.Data)))))
			break
		}
		cur, asked := out[string(r)]
		switch {
		case !asked || cur.Err != nil:
		case cur.OK && cur.Head != string(h):
			out[string(r)] = AnchorHead{Err: coded(ErrAnchorMalformed, fmt.Errorf("%w: chain.log holds two heads for %s, %s and %s",
				ErrCorruptLedger, r, cur.Head, h))}
		default:
			out[string(r)] = AnchorHead{Head: string(h), OK: true}
		}
	}
	return out
}
