// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strconv"
	"strings"
)

// Tail is an append cursor over the ledger: what a live page had read when it last asked. It is not a place in the
// Logs sort order. That order is (time, run, seq), and a line appended to a run whose recorder lags another's carries
// an earlier time than rows already shown, so a watermark in the sort key never saw it. A Tail names instead what
// was appended: the revision (Snapshot.Rev, which only grows and starts at the clock, so a restarted dashboard never
// repeats one) and, for each run that could still grow (no run_end read), the seq of its newest line then. A run that
// had ended is complete, and a run the Tail does not name is new: all its lines come after it.
type Tail struct {
	Rev uint64
	// Seq is the newest seq read of each run with no run_end.
	Seq map[string]uint64
	// Overflow is set when more runs than MaxTailRuns could still grow, so the Tail cannot name them all: nothing
	// can be said of what was appended, and the page loads its newest page again.
	Overflow bool
}

// MaxTailRuns bounds the open runs a Tail names, and so the length of the token a page carries.
const MaxTailRuns = 64

// TailOf is the append cursor of s.
func (s *Snapshot) TailOf() Tail {
	t := Tail{Rev: s.Rev, Seq: map[string]uint64{}}
	for _, r := range s.Runs {
		if r.Ended {
			continue
		}
		if len(t.Seq) == MaxTailRuns {
			t.Overflow = true
			break
		}
		t.Seq[r.ID] = r.LastSeq
	}
	return t
}

// String is t as a token a page carries: the revision, then ";" and each open run as run:seq, separated by commas;
// "!" after the revision says Overflow.
func (t Tail) String() string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(t.Rev, 10))
	if t.Overflow {
		b.WriteString("!")
	}
	b.WriteString(";")
	ids := make([]string, 0, len(t.Seq))
	for id := range t.Seq {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(id + ":" + strconv.FormatUint(t.Seq[id], 10))
	}
	return b.String()
}

// ParseTail reads a token String made.
func ParseTail(tok string) (Tail, bool) {
	head, rest, ok := strings.Cut(tok, ";")
	if !ok || len(tok) > 64*(MaxTailRuns+1)+32 {
		return Tail{}, false
	}
	t := Tail{Seq: map[string]uint64{}}
	if h, over := strings.CutSuffix(head, "!"); over {
		head, t.Overflow = h, true
	}
	rev, err := strconv.ParseUint(head, 10, 64)
	if err != nil {
		return Tail{}, false
	}
	t.Rev = rev
	if rest == "" {
		return t, true
	}
	for _, part := range strings.Split(rest, ",") {
		i := strings.LastIndexByte(part, ':')
		if i <= 0 || len(t.Seq) >= MaxTailRuns {
			return Tail{}, false
		}
		seq, err := strconv.ParseUint(part[i+1:], 10, 64)
		if err != nil {
			return Tail{}, false
		}
		t.Seq[part[:i]] = seq
	}
	return t, true
}

// keep is the rows of fr, a run's folded rows, with a line this Tail has not seen: those whose newest line is after
// the seq the Tail names for the run (every line of a run it does not name, and nothing of a run that has not changed
// since its revision). A new slice: fr's own is shared.
func (t *Tail) keep(r *Run, fr folded) []int32 {
	if r.Rev <= t.Rev {
		return nil
	}
	seen, named := t.Seq[r.ID]
	var out []int32
	for _, k := range fr.reps {
		if !named || fr.evs[k].Seq > seen {
			out = append(out, k)
		}
	}
	return out
}
