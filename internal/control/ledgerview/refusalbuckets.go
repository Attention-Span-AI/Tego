// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"sort"
	"time"
)

// RefusalCounts is a snapshot's refusals counted in consecutive time buckets (Snapshot.RefusalBuckets).
type RefusalCounts struct {
	// Counts[i] is the refusals timed in bucket i: from bounds[i] on, to bounds[i+1] exclusive.
	Counts []int
	// Lower says some refusal a bucket should hold may be missing: runs were omitted or one was still being read, a
	// record line could not be read, or an event window dropped events a bucket needs. Every count is then a lower
	// bound.
	Lower bool
	// Records are the runs whose complete record would settle a lower bound: one with unreadable lines or a read
	// failure, and one whose retained events leave out part of a bucket.
	Records []*Run
}

// Total is the refusals in every bucket.
func (c RefusalCounts) Total() int {
	n := 0
	for _, v := range c.Counts {
		n += v
	}
	return n
}

// bucketOf is the index of the bucket of bounds that holds t: -1 before the first edge, len(bounds)-1 at or after the
// last, which is no bucket.
func bucketOf(bounds []time.Time, t time.Time) int {
	n := len(bounds) - 1
	if t.Before(bounds[0]) {
		return -1
	}
	if !t.Before(bounds[n]) {
		return n
	}
	// The first edge after t, less one.
	return sort.Search(len(bounds), func(i int) bool { return bounds[i].After(t) }) - 1
}

// RefusalBuckets counts the snapshot's refusals (Event.Refusal, as the Overview and each run count them) into the
// buckets that bounds, ascending, cut: bucket i is [bounds[i], bounds[i+1]). A run whose every refusal falls in one
// bucket adds its whole counter; one that spans buckets, or the edge of the buckets, is counted from its events,
// where Run.RefusalFirst and RefusalLast bound each refusal's time even when the event window is cut or evicted. A
// run whose events leave out part of what a bucket needs makes the counts a lower bound (Lower) and is named in
// Records, as is a run with an unreadable line. With fewer than two bounds there is no bucket.
func (s *Snapshot) RefusalBuckets(bounds []time.Time) RefusalCounts {
	if len(bounds) < 2 {
		return RefusalCounts{}
	}
	n := len(bounds) - 1
	out := RefusalCounts{Counts: make([]int, n), Lower: s.RunsCut || s.Partial || s.ReadError != ""}
	for _, r := range s.Runs {
		// An unreadable line could be a refusal at any time, even when every decoded refusal falls in one bucket.
		// Invalid or absent timestamps are rejected by record.Decode and counted in Bad, never used as bounds.
		if r.Bad > 0 || r.ReadError != "" {
			out.Lower = true
			out.Records = append(out.Records, r)
		}
		if r.Refusals == 0 {
			continue
		}
		lo, hi := bucketOf(bounds, r.RefusalFirst), bucketOf(bounds, r.RefusalLast)
		switch {
		case lo == hi && lo >= 0 && lo < n:
			out.Counts[lo] += r.Refusals
			continue
		case lo == hi: // wholly before the first edge, or wholly after the last
			continue
		}
		for _, e := range r.AllEvents() {
			if !e.Refusal() {
				continue
			}
			if i := bucketOf(bounds, e.TS); i >= 0 && i < n {
				out.Counts[i]++
			}
		}
		if r.Cut {
			out.Lower = true
			if r.Bad == 0 {
				out.Records = append(out.Records, r)
			}
		}
	}
	return out
}
