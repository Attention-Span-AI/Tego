// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A window makes the tokens and cost_usd budgets (R1, R2) a total over the last Span, across every run of one agent,
// not a count that starts at zero with each run (ADR 0165). This file is the watcher's half: it holds what the earlier
// runs spent, read by internal/runtime/budgetwindow from their verified ledgers, beside what this run spends, and
// compares the sum inside the window with the ceiling. It reads no file and no clock but the run's own.
//
// Spend is kept in one-minute buckets. A bucket counts until its whole minute has left the window, so a spend is
// counted up to a minute longer than the window and never shorter: the sliding edge errs toward the ceiling.

// CarryUse is spend an earlier run's ledger proves: the response's usage and the wall time its line was stamped.
type CarryUse struct {
	At    time.Time
	Usage ledger.TokenUsage
}

// Window is WithWindow's argument: the span, and the earlier runs' spend inside it.
type Window struct {
	Span  time.Duration
	Carry []CarryUse
}

// WithWindow makes tokens and cost_usd a total over w.Span across runs (ADR 0165). The carry is priced with this run's
// table, as the run's own responses are, so one price list reads the whole window. A span of 0 or less is none.
func WithWindow(w Window) Option {
	return func(wt *Watcher) {
		if w.Span > 0 {
			wt.win = &windowState{span: w.Span, carry: w.Carry}
		}
	}
}

// bucket is one minute of spend: its unix minute, tokens (input plus output, cache excluded), the priced cost and
// what unpriced responses would cost at the table's highest prices (UnpricedMaxUSD).
type bucket struct {
	minute      int64
	tokens      uint64
	cost        float64
	unpricedMax float64
}

type windowState struct {
	span  time.Duration
	carry []CarryUse
	// wall0 is the wall time when the watcher was made and mono0 the monotonic reading then: a run's own spend is
	// placed at wall0 plus the monotonic time since, so a wall clock stepped mid-run neither hides nor fabricates it
	// (the watcher's rule for every budget, Clock).
	wall0   time.Time
	mono0   uint64
	buckets []bucket // ascending by minute
}

// start places the carry in buckets once the watcher has its clock and prices.
func (s *windowState) start(w *Watcher) {
	s.wall0, s.mono0 = w.clock.Now(), w.clock.MonoNS()
	for _, c := range s.carry {
		// A line stamped after this run began (the wall clock was set back since) counts as spent now: it still counts
		// for a whole window from here, never longer, so a clock set days back cannot hold an agent down for days.
		at := c.At
		if at.After(s.wall0) {
			at = s.wall0
		}
		cost, unpricedMax := w.chargeOf(c.Usage)
		s.add(at.Unix()/60, ledger.SatAdd(c.Usage.In, c.Usage.Out), cost, unpricedMax)
	}
	s.carry = nil
}

// add puts spend into the bucket of minute, keeping the buckets in order.
func (s *windowState) add(minute int64, tokens uint64, cost, unpricedMax float64) {
	i, found := slices.BinarySearchFunc(s.buckets, minute, func(b bucket, m int64) int {
		switch {
		case b.minute < m:
			return -1
		case b.minute > m:
			return 1
		}
		return 0
	})
	if !found {
		s.buckets = slices.Insert(s.buckets, i, bucket{minute: minute})
	}
	b := &s.buckets[i]
	b.tokens = ledger.SatAdd(b.tokens, tokens)
	b.cost += cost
	b.unpricedMax += unpricedMax
}

// now is the run's wall time by its monotonic clock.
func (s *windowState) now(w *Watcher) time.Time {
	m := w.clock.MonoNS()
	if m < s.mono0 {
		return s.wall0
	}
	return s.wall0.Add(time.Duration(m - s.mono0))
}

// totals are the tokens and the cost (priced plus unpriced at the highest prices) of the buckets still inside the
// window at now; the ones that have left it are dropped.
func (s *windowState) totals(now time.Time) (tokens uint64, cost float64) {
	// A bucket is kept while its last second is inside the window.
	edge := now.Add(-s.span).Unix()
	drop := 0
	for drop < len(s.buckets) && (s.buckets[drop].minute+1)*60 <= edge {
		drop++
	}
	s.buckets = slices.Delete(s.buckets, 0, drop)
	for _, b := range s.buckets {
		tokens = ledger.SatAdd(tokens, b.tokens)
		cost += b.cost + b.unpricedMax
	}
	return tokens, cost
}

// chargeOf is what one response costs against a cost ceiling: its priced cost, or, for a response the table does not
// price, what it would cost at the table's highest prices (R2).
func (w *Watcher) chargeOf(u ledger.TokenUsage) (cost, unpricedMax float64) {
	if c, priced := w.prices.Cost(u); priced {
		return c, 0
	}
	if w.ceiling.Bounded(agent.BudgetCostUSD) {
		if c, ok := w.prices.MaxCost(u); ok {
			return 0, c
		}
	}
	return 0, 0
}
