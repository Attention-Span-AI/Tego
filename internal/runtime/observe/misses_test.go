// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

type fakeMisses struct {
	n      uint64
	err    error
	closed int
}

func (m *fakeMisses) Lost() (uint64, error) { return m.n, m.err }
func (m *fakeMisses) Close() error          { m.closed++; return nil }

func TestTrampolineMissesCoverTheRunWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		end   uint64
		err   error
		why   string
		count int64
	}{
		{"no skips", 9, nil, "", 0},
		{"shared skips", 16, nil, GapTrampolineMiss, 7},
		{"counter reset", 8, nil, GapTrampolineCounterUnavailable, 1},
		{"counter unreadable", 9, errors.New("stats failed"), GapTrampolineCounterUnavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			r, err := New(Options{Rules: f.rules, Reader: newFakeRing()})
			if err != nil {
				t.Fatal(err)
			}
			m := &fakeMisses{n: 9}
			r.misses = m
			if err := r.Start(context.Background(), source.RunRef{ID: "r-misses"}, &fakeSink{}); err != nil {
				t.Fatal(err)
			}
			m.n, m.err = tc.end, tc.err
			if err := r.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := r.Stop(); err != nil {
				t.Fatal(err)
			}
			var got int64
			for _, g := range r.Gaps() {
				if g.Why == tc.why {
					got += g.Count
				}
			}
			if got != tc.count || m.closed != 1 {
				t.Fatalf("gap %s count %d; closed %d, want %d and 1", tc.why, got, m.closed, tc.count)
			}
		})
	}
}

func TestTrampolineCounterUnavailableAtStart(t *testing.T) {
	f := newFixture(t)
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing()})
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMisses{err: errors.New("stats unavailable")}
	r.misses = m
	if err := r.Start(context.Background(), source.RunRef{ID: "r-misses"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if gaps := r.Gaps(); len(gaps) != 1 || gaps[0].Why != GapTrampolineCounterUnavailable || m.closed != 1 {
		t.Fatalf("gaps %v, counter closed %d times; want one unavailable gap and one close", gaps, m.closed)
	}
}
