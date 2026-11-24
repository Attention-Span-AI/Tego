// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/mirror"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// referenceMarkMirror is the dashboard's own copy of the mirror pairing as it was before the pairing had one
// implementation (internal/check/mirror): kept here, whole, so the shared fold is held to it over the same lines. It
// returns the index in evs of the action line ev took, or -1.
func referenceMarkMirror(evs []Event, paired *[]int, ev *Event) int {
	const window = 4
	if ev.Kind != string(record.KindRefused) {
		return -1
	}
	*paired = slices.DeleteFunc(*paired, func(i int) bool { return i < len(evs)-window })
	prev := -1
	for i, n := len(evs)-1, 0; i >= 0 && n < window; i, n = i-1, n+1 {
		a := &evs[i]
		if !record.Kind(a.Kind).IsAction() || a.Verdict != string(record.VerdictRefused) || slices.Contains(*paired, i) {
			continue
		}
		if a.Rule != ev.Rule || a.Reason != ev.Reason {
			continue
		}
		if ev.mono != 0 && a.mono == ev.mono && a.pid == ev.pid {
			*paired = append(*paired, i)
			return i
		}
		if n == 0 {
			prev = i
		}
	}
	if prev >= 0 {
		*paired = append(*paired, prev)
		return prev
	}
	return -1
}

// TestMirrorPairingMatchesItsReference: over every record v1 fixture and over hand-made orders (a line slipped between a
// refusal and its mirror, two refusals before either mirror, a mirror with no clock, a mirror with no action, a mirror
// further back than the window), the shared fold marks the same lines as mirrors, and each one took the same action,
// as the dashboard's own pairing did before there was one rule, and as the receipt's, measure's, drift's and learn's
// (mirror.Pairs.Take) say line by line.
func TestMirrorPairingMatchesItsReference(t *testing.T) {
	type run struct {
		name string
		evs  []record.Event
	}
	var runs []run
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(files) < 5 {
		t.Fatalf("fixtures: %d, %v", len(files), err)
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		var evs []record.Event
		sc := bufio.NewScanner(fh)
		sc.Buffer(nil, 1<<24)
		for sc.Scan() {
			if e, err := record.Decode(sc.Bytes()); err == nil {
				evs = append(evs, *e)
			}
		}
		_ = fh.Close()
		runs = append(runs, run{filepath.Base(f), evs})
	}
	refusedNet := func(pid int, mono uint64, rule string) record.Event {
		return record.Event{Kind: record.KindNet, Verdict: record.VerdictRefused, PID: pid, MonoNS: mono, Rule: rule, Reason: record.ReasonNetNotAllowed}
	}
	mirrorOf := func(pid int, mono uint64, rule string) record.Event {
		return record.Event{Kind: record.KindRefused, PID: pid, MonoNS: mono, Rule: rule, Reason: record.ReasonNetNotAllowed}
	}
	other := record.Event{Kind: record.KindFS, Verdict: record.VerdictAllow, PID: 7, MonoNS: 5}
	runs = append(runs,
		run{"adjacent", []record.Event{refusedNet(1, 10, "r"), mirrorOf(1, 10, "r")}},
		run{"another writer's line between", []record.Event{refusedNet(1, 10, "r"), other, mirrorOf(1, 10, "r")}},
		run{"two refusals before either mirror", []record.Event{refusedNet(1, 10, "r"), refusedNet(2, 11, "r"), mirrorOf(1, 10, "r"), mirrorOf(2, 11, "r")}},
		run{"the same refusal twice", []record.Event{refusedNet(1, 10, "r"), mirrorOf(1, 10, "r"), mirrorOf(1, 10, "r")}},
		run{"a mirror with no clock", []record.Event{refusedNet(1, 10, "r"), other, mirrorOf(1, 0, "r"), mirrorOf(1, 0, "r")}},
		run{"a mirror with a clock of its own", []record.Event{refusedNet(1, 10, "r"), mirrorOf(1, 99, "r")}},
		run{"another rule", []record.Event{refusedNet(1, 10, "r"), mirrorOf(1, 10, "s")}},
		run{"a mirror with no action", []record.Event{other, mirrorOf(1, 10, "r")}},
		run{"outside the window", []record.Event{refusedNet(1, 10, "r"), other, other, other, other, mirrorOf(1, 10, "r")}},
		run{"at the edge of the window", []record.Event{refusedNet(1, 10, "r"), other, other, other, mirrorOf(1, 10, "r")}},
	)
	for _, rn := range runs {
		t.Run(rn.name, func(t *testing.T) {
			var (
				pairs  mirror.Pairs
				paired []int
				st     = &runState{}
			)
			for i := range rn.evs {
				e := rn.evs[i]
				ev := fromRecord(&e)
				want := referenceMarkMirror(st.b.Events, &paired, &ev)
				takes := pairs.Take(&e)
				st.markMirror(&ev)
				if got := ev.Mirror; got != (want >= 0) || got != takes {
					t.Fatalf("line %d (%s): the dashboard marks mirror=%v, its reference %v, mirror.Pairs.Take %v", i, e.Kind, got, want >= 0, takes)
				}
				if want >= 0 {
					ref := st.b.Events[want]
					if wantWrite := ref.Kind == string(record.KindFS) && ref.Op != "read"; ev.write != wantWrite {
						t.Fatalf("line %d: the mirror takes write=%v from its action, want %v", i, ev.write, wantWrite)
					}
				}
				st.b.Events = append(st.b.Events, ev)
			}
		})
	}
}
