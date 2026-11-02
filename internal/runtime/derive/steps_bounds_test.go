// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The tests here reach past the bounds of what Steps remembers for a late action (R42): the retired threads, the
// windows and the threads one epoch keeps rule (1)'s earlier answer for. Past each, a late action is answered as the
// state was at its time or left unattributed, never by a state it did not happen in or by another thread's reply.

// TestForgottenThreadKeepsItsLateAnswer: a retired thread is forgotten after MaxRetired later retirements, and with it
// rule (1)'s answer for its actions; the retirement that forgets it keeps that answer in its epoch, so an action of the
// thread from before then that arrives after it is still the thread's own, not the run's one window, another thread's.
func TestForgottenThreadKeepsItsLateAnswer(t *testing.T) {
	s := derive.NewSteps()
	first := at(turn(10, true, read...), 100)
	first.PID = 10
	s.Apply(first)
	end := at(answer(10, true), 110)
	end.PID = 10
	s.Apply(end)
	s.Exit(10)
	mono := uint64(200)
	for i := range derive.MaxRetired - 1 { // thread 10 is the oldest retirement and still remembered
		req := at(turn(0, false, read...), mono)
		req.PID = 100_000 + i
		s.Apply(req)
		s.Exit(req.PID)
		mono += 10
	}
	x := at(turn(0, false, read...), mono)
	x.PID = 9000
	s.Apply(x)
	xEnd := at(answer(0, false), mono+1)
	xEnd.PID = 9000
	s.Apply(xEnd)
	use := at(toolUse(0, false, "toolu_X"), mono+1)
	use.PID = 9000
	s.Apply(use)
	own := *record.AttributedByTID("t10", 1)
	wantAttr(t, "thread 10 in order", attributed(s, at(action(10), mono+5)), own)
	y := at(turn(0, false, read...), mono+10)
	y.PID = 9001
	s.Apply(y)
	s.Exit(9001) // one retirement more than the bound: thread 10 is forgotten
	wantAttr(t, "thread 10, late", attributed(s, at(action(10), mono+5)), own)
}

// TestLostWindowsKeepALateActionsOwnAnswer: past MaxToolWindows open windows the stage reads no window for the rest of
// the run, which changes the answer of every thread that held one; the loss keeps each such thread's earlier answer, so
// a late action of a thread whose one window was open at its time is still that reply's.
func TestLostWindowsKeepALateActionsOwnAnswer(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(at(turn(10, true, read...), 100))
	s.Apply(at(answer(10, true), 110))
	s.Apply(at(toolUse(10, true, "toolu_A"), 110))
	s.Apply(at(turn(20, true, read...), 200))
	s.Apply(at(answer(20, true), 210))
	for i := range derive.MaxToolWindows { // with toolu_A, one more than the bound
		s.Apply(at(toolUse(20, true, "toolu_"+strconv.Itoa(i)), 220))
	}
	wantAttr(t, "thread 10's tool, late", attributed(s, at(action(10), 150)), *record.AttributedByToolUse("t10", 1, "toolu_A"))
	wantAttr(t, "thread 10 in order", attributed(s, at(action(10), 230)), *record.AttributedByTID("t10", 1))
}

// manyWindows opens one window on each of n threads the uprobe source names (tids 1..n), all at mono 100: thread i's
// step i asks for toolu_i.
func manyWindows(s *derive.Steps, n int) {
	for i := 1; i <= n; i++ {
		s.Apply(at(turn(i, true, read...), 100))
		s.Apply(at(answer(i, true), 100))
		s.Apply(at(toolUse(i, true, "toolu_"+strconv.Itoa(i)), 100))
	}
}

// ids is toolu_first..toolu_last.
func ids(first, last int) []string {
	var out []string
	for i := first; i <= last; i++ {
		out = append(out, "toolu_"+strconv.Itoa(i))
	}
	return out
}

// TestTransitionPastTheTouchedBound: one transition that changes more than MaxTouched threads' answers (a request
// reporting that many threads' tools) keeps the earlier answer of the first MaxTouched; a late action of one of those is
// answered by it, and one of a thread past them is unattributed, never answered by the thread's state now.
func TestTransitionPastTheTouchedBound(t *testing.T) {
	n := derive.MaxTouched + 1
	s := derive.NewSteps()
	manyWindows(s, n)
	s.Apply(at(turn(999, true, ids(1, n)...), 200)) // touches thread 999, then threads 1..n
	wantAttr(t, "a kept thread, late", attributed(s, at(action(5), 150)), *record.AttributedByToolUse("t5", 5, "toolu_5"))
	wantAttr(t, "a thread past the bound, late", attributed(s, at(action(n), 150)),
		record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime})
	wantAttr(t, "the same thread in order", attributed(s, at(action(n), 250)), *record.AttributedByTID("t"+strconv.Itoa(n), n))
}

// TestMergedEpochPastTheTouchedBound: transitions at the same time fold into one epoch, which keeps at most MaxTouched
// earlier answers between them, and one that changed more than it kept, folded into another, still counts as such; a
// late action of a thread past the kept answers is unattributed.
func TestMergedEpochPastTheTouchedBound(t *testing.T) {
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	t.Run("two within the bound", func(t *testing.T) {
		n := derive.MaxTouched + derive.MaxTouched/4
		s := derive.NewSteps()
		manyWindows(s, n)
		half := n / 2
		s.Apply(at(turn(999, true, ids(1, half)...), 200))
		s.Apply(at(turn(998, true, ids(half+1, n)...), 200)) // folded into the same epoch
		wantAttr(t, "a kept thread, late", attributed(s, at(action(5), 150)), *record.AttributedByToolUse("t5", 5, "toolu_5"))
		wantAttr(t, "a thread past the bound, late", attributed(s, at(action(n), 150)), none)
	})
	t.Run("one past it", func(t *testing.T) {
		n := derive.MaxTouched + 1
		s := derive.NewSteps()
		manyWindows(s, n)
		s.Apply(at(turn(999, true, read...), 200))
		s.Apply(at(turn(999, true, ids(1, n)...), 200)) // touches thread 999 again, then threads 1..n
		wantAttr(t, "a kept thread, late", attributed(s, at(action(5), 150)), *record.AttributedByToolUse("t5", 5, "toolu_5"))
		wantAttr(t, "a thread past the bound, late", attributed(s, at(action(n), 150)), none)
	})
}

// TestWindowHoldersPastTheTouchedBound: an unread request, and the windows lost, change the answer of every thread that
// holds a window at once, and the holders are a map's keys. The epoch keeps the answers of the first of them by thread
// name, in a transition of its own or one folded into another at the same time, so which threads keep a late answer
// never depends on the order a map is walked in: every replay of one stream answers every late action alike.
func TestWindowHoldersPastTheTouchedBound(t *testing.T) {
	n := derive.MaxTouched + 36
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	byName := func(first, last int) []int { // tids first..last in the order of their threads' names
		var out []int
		for i := first; i <= last; i++ {
			out = append(out, i)
		}
		slices.SortFunc(out, func(a, b int) int { return strings.Compare("t"+strconv.Itoa(a), "t"+strconv.Itoa(b)) })
		return out
	}
	for _, c := range []struct {
		name string
		fold func(s *derive.Steps)
		kept []int // the holders whose answer the epoch keeps
	}{
		{"an unread request", func(s *derive.Steps) { s.Apply(at(turn(999, true), 200)) },
			byName(1, n)[:derive.MaxTouched-1]}, // thread 999's own first
		{"the windows lost", func(s *derive.Steps) {
			s.Apply(at(turn(999, true, read...), 200))
			s.Apply(at(answer(999, true), 200))
			for i := range derive.MaxToolWindows - n + 1 {
				s.Apply(at(toolUse(999, true, "toolu_more_"+strconv.Itoa(i)), 200))
			}
		}, byName(1, n)[:derive.MaxTouched-1]},
		{"an unread request folded into another transition", func(s *derive.Steps) {
			s.Apply(at(turn(998, true, ids(1, 40)...), 200)) // keeps thread 998's and threads 1..40's
			s.Apply(at(turn(999, true), 200))                // not read: thread 999's, then the other holders' by name
		}, append(byName(1, 40), byName(41, n)[:derive.MaxTouched-42]...)},
	} {
		t.Run(c.name, func(t *testing.T) {
			for range 4 {
				s := derive.NewSteps()
				manyWindows(s, n)
				c.fold(s)
				for i := 1; i <= n; i++ {
					want := none
					if slices.Contains(c.kept, i) {
						want = *record.AttributedByToolUse("t"+strconv.Itoa(i), i, "toolu_"+strconv.Itoa(i))
					}
					wantAttr(t, "thread "+strconv.Itoa(i)+", late", attributed(s, at(action(i), 150)), want)
				}
			}
		})
	}
}

// TestEpochPastTheBoundInATIDRun: an epoch that changed more threads' answers than it keeps is taken as having changed
// every other thread's once a model request has named a thread by its tid, whether that request made the epoch or was
// folded into it at the same time: a late action of a thread it did not keep is then unattributed, never answered by
// rules (2) and (3) as they stood at its time. In a run no request of which had named a tid by then, rules (2) and (3)
// answer it.
func TestEpochPastTheBoundInATIDRun(t *testing.T) {
	n := derive.MaxTouched + 1
	setup := func() *derive.Steps {
		s := derive.NewSteps()
		for i := 1; i <= n; i++ { // n forwarder lanes of one process, each with its reply's window open
			for _, e := range []*record.Event{at(turn(0, false, read...), 100), at(answer(0, false), 100),
				at(toolUse(0, false, "toolu_"+strconv.Itoa(i)), 100)} {
				e.Lane = uint64(i)
				s.Apply(e)
			}
		}
		z := at(turn(0, false, read...), 150) // another process's turn, alone in flight
		z.PID = 5000
		s.Apply(z)
		return s
	}
	reportAll := func(s *derive.Steps) { // another process's request, reporting every lane's tool: past the bound
		y := at(turn(0, false, ids(1, n)...), 200)
		y.PID = 6000
		s.Apply(y)
	}
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	t.Run("no tid named", func(t *testing.T) {
		s := setup()
		reportAll(s)
		wantAttr(t, "a late action", attributed(s, at(action(8), 175)), *record.AttributedByTime("t5000", n+1))
	})
	t.Run("the request that makes the epoch names one", func(t *testing.T) {
		s := setup()
		s.Apply(at(turn(77, true, ids(1, n)...), 200))
		wantAttr(t, "a late action", attributed(s, at(action(8), 175)), none)
	})
	t.Run("one folded into the epoch names one", func(t *testing.T) {
		s := setup()
		reportAll(s)
		s.Apply(at(turn(77, true, read...), 200))
		wantAttr(t, "a late action", attributed(s, at(action(8), 175)), none)
	})
}
