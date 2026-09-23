// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAppendKeepsTheProducersMonotonicReading pins the one rule for mono_ns: it is the CLOCK_MONOTONIC
// reading at capture (§2's field doc, enforce-cgroup-observe.md E20), so a producer that took one keeps
// it, and only a zero — E20's "unknown" — gets the append time.
//
// The distinction is what an event's age in the queue does to the record. A kernel event read off the
// ring buffer a few milliseconds late, or a model request that began long before its response was
// parsed, would otherwise carry the moment the pipeline got round to it, and `measure`'s idle gaps and
// `status`'s stall would be measured against the pipeline's schedule instead of the agent's.
func TestAppendKeepsTheProducersMonotonicReading(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 0)

	// A reading older than every stamp the scripted clock hands out, so it cannot pass by accident.
	const captured = 1_234_567
	own := fsEvent("/home/u/proj/out/a.txt", nil)
	own.MonoNS = captured
	if err := w.Append(own); err != nil {
		t.Fatal(err)
	}
	blank := fsEvent("/home/u/proj/out/b.txt", nil)
	if err := w.Append(blank); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}

	lines := readAll(t, dir)
	if len(lines) != 4 {
		t.Fatalf("%d lines, want run_start, two fs events, run_end", len(lines))
	}
	if got := lines[1].MonoNS; got != captured {
		t.Fatalf("mono_ns %d on disk, want the producer's own %d", got, captured)
	}
	if own.MonoNS != captured {
		t.Fatalf("mono_ns %d left on the event, want %d", own.MonoNS, captured)
	}
	// run_start, the blank event and run_end carry the writer's own clock: all past 5s, where
	// openTestWriter's scripted clock starts.
	for _, i := range []int{0, 2, 3} {
		if got := lines[i].MonoNS; got <= 5_000_000_000 {
			t.Fatalf("line %d (%s) mono_ns %d, want the append-time reading", i, lines[i].Kind, got)
		}
	}
	// The chain still verifies: mono_ns is inside the hashed line, whoever set it.
	if rep := verify(t, dir, anchor); rep.Lines != 4 || !rep.Anchored {
		t.Fatalf("verify report %+v", rep)
	}
}
