// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// skipReading is one answer of skipHandle's counter.
type skipReading struct {
	s   enforce.ProgramSkips
	err error
}

// skipHandle stands in for a root tier's handle: its skip counter answers readings in order, the last one for good,
// and it names a decision plane mode.
type skipHandle struct {
	fakeHandle
	mu       sync.Mutex
	readings []skipReading
	reads    int
	mode     string
}

func (h *skipHandle) ProgramSkips() (enforce.ProgramSkips, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.readings[min(h.reads, len(h.readings)-1)]
	h.reads++
	return r.s, r.err
}

func (h *skipHandle) DecisionPlane() (string, bool) { return h.mode, false }

func skips(deciding, tracking uint64) skipReading {
	return skipReading{s: enforce.ProgramSkips{Deciding: deciding, Tracking: tracking, Programs: 32}}
}

// skipRunner is a runner over h with a cgroup that counts kills and a pipeline that keeps the lines written past the
// drain.
func skipRunner(h *skipHandle) (*runner, *fakeCgroups, *[]*record.Event) {
	r := newTestRunner(Deps{})
	cg := &fakeCgroups{}
	r.cgm, r.cg = cg, cgroup.Cgroup{Path: "/run/test"}
	r.handle = h
	var events []*record.Event
	r.pipe = &pipeline{handle: func(ev *record.Event) { events = append(events, ev) }}
	return r, cg, &events
}

// gapsOf decodes the gap lines of events.
func gapsOf(t *testing.T, events []*record.Event) []record.GapPayload {
	t.Helper()
	var out []record.GapPayload
	for _, ev := range events {
		var p record.GapPayload
		if ev.Kind != record.KindGap || ev.DecodePayload(&p) != nil {
			t.Fatalf("not a gap line: %+v", ev)
		}
		out = append(out, p)
	}
	return out
}

// TestSkipDecide is the policy of a reading taken while the agent runs (ADR 0148): a run ends on a moved tracking or
// deciding counter and on an unreadable one; an adoption never ends; the waived fmod_ret plane's deciding skips only
// record, and do not shield a tracking skip.
func TestSkipDecide(t *testing.T) {
	base := enforce.ProgramSkips{Deciding: 7, Tracking: 3}
	for _, c := range []struct {
		name               string
		now                enforce.ProgramSkips
		err                error
		waived, recordOnly bool
		want               skipAction
		words              string
	}{
		{name: "no move", now: base, want: skipNone},
		{name: "deciding", now: enforce.ProgramSkips{Deciding: 9, Tracking: 3}, want: skipEnd, words: "decide the run's actions 2 times"},
		{name: "tracking", now: enforce.ProgramSkips{Deciding: 7, Tracking: 4}, want: skipEnd, words: "child cgroups"},
		{name: "unreadable", err: errors.New("EBADF"), want: skipEnd, words: "could not be read: EBADF"},
		{name: "waived deciding", now: enforce.ProgramSkips{Deciding: 8, Tracking: 3}, waived: true, want: skipLog},
		{name: "waived deciding and tracking", now: enforce.ProgramSkips{Deciding: 8, Tracking: 4}, waived: true, want: skipEnd},
		{name: "adoption deciding", now: enforce.ProgramSkips{Deciding: 8, Tracking: 3}, recordOnly: true, want: skipLog},
		{name: "adoption tracking", now: enforce.ProgramSkips{Deciding: 7, Tracking: 5}, recordOnly: true, want: skipLog},
		{name: "adoption unreadable", err: errors.New("EBADF"), recordOnly: true, want: skipLog},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, words := skipDecide(base, c.now, c.err, c.waived, c.recordOnly)
			if got != c.want || !strings.Contains(words, c.words) {
				t.Fatalf("skipDecide = %v, %q; want %v with %q", got, words, c.want, c.words)
			}
		})
	}
}

// TestSkipDeltaNeverHidesASkip: a counter below its base is not the counter the base read, and counts as one skip.
func TestSkipDeltaNeverHidesASkip(t *testing.T) {
	if skipDelta(5, 5) != 0 || skipDelta(9, 5) != 4 || skipDelta(4, 5) != 1 {
		t.Fatal("skipDelta")
	}
}

// TestSkipEndsTheRunAndRecordsTheCount: a deciding skip while the agent runs ends the run (reason error, its tree
// killed), and the final reading writes the count of every skip since the base, with the plane's mode.
func TestSkipEndsTheRunAndRecordsTheCount(t *testing.T) {
	for _, c := range []struct {
		name       string
		moved, end skipReading
		why        string
		count      int
		plane      string
	}{
		{name: "deciding", moved: skips(1, 0), end: skips(3, 0), why: record.GapDecidingSkip, count: 3, plane: "lsm"},
		{name: "tracking", moved: skips(0, 2), end: skips(0, 2), why: record.GapTrackingSkip, count: 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), c.moved, c.end}}
			r, cg, events := skipRunner(h)
			if err := r.readSkipBase(false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.watchSkips(ctx, r.skipState, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil || r.terminal != identity.ReasonError || cg.killed != 1 || !strings.Contains(r.detail, "kernel skips") {
				t.Fatalf("terminal=%v detail=%q killed=%d", r.terminal, r.detail, cg.killed)
			}
			r.finalSkipCheck()
			gs := gapsOf(t, *events)
			if len(gs) != 1 || gs[0].What != record.GapEnforce || gs[0].Why != c.why || gs[0].Count != c.count ||
				gs[0].DecisionPlane != c.plane {
				t.Fatalf("gaps %+v, want one %s count %d plane %q", gs, c.why, c.count, c.plane)
			}
		})
	}
}

// TestSkipCleanRunSaysWhatItSaidBefore: counters that hold still, at any value, end nothing and write no line.
func TestSkipCleanRunSaysWhatItSaidBefore(t *testing.T) {
	h := &skipHandle{mode: "lsm", readings: []skipReading{skips(41, 6)}}
	r, cg, events := skipRunner(h)
	ctx, cancel := context.WithCancel(context.Background())
	r.group, ctx = newGroup(ctx)
	if err := r.startSkipWatch(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if r.checkSkips(r.skipState) {
			t.Fatal("a reading with no move ended the watch")
		}
	}
	cancel()
	if err := r.group.Wait(); err != nil {
		t.Fatal(err)
	}
	r.finalSkipCheck()
	if r.terminal != "" || cg.killed != 0 || len(*events) != 0 {
		t.Fatalf("terminal=%v killed=%d events=%d: a run with no skip changed", r.terminal, cg.killed, len(*events))
	}
}

// TestSkipBaseUnreadableRefusesTheRun: a base that cannot be read refuses the run before the agent is released, so no
// run claims rules it could not check.
func TestSkipBaseUnreadableRefusesTheRun(t *testing.T) {
	h := &skipHandle{readings: []skipReading{{err: errors.New("no recursion_misses")}}}
	r, _, _ := skipRunner(h)
	err := r.startSkipWatch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no recursion_misses") || r.skipState != nil {
		t.Fatalf("err=%v state=%v", err, r.skipState)
	}
	r.finalSkipCheck() // nothing was watched, so nothing is written
}

// TestSkipUnreadableMidRunEndsAndRecords: a reading that fails while the agent runs ends the run, and the record says
// a reading failed even when the last one succeeds and shows no skip.
func TestSkipUnreadableMidRunEndsAndRecords(t *testing.T) {
	h := &skipHandle{readings: []skipReading{skips(0, 0), {err: errors.New("EBADF")}, skips(0, 0)}}
	r, cg, events := skipRunner(h)
	if err := r.readSkipBase(false); err != nil {
		t.Fatal(err)
	}
	if !r.checkSkips(r.skipState) || r.terminal != identity.ReasonError || cg.killed != 1 {
		t.Fatalf("terminal=%v killed=%d", r.terminal, cg.killed)
	}
	r.finalSkipCheck()
	gs := gapsOf(t, *events)
	if len(gs) != 1 || gs[0].Why != record.GapSkipCounterUnavailable || gs[0].Count != 0 {
		t.Fatalf("gaps %+v", gs)
	}
}

// TestSkipFinalReadingFailsClosed: a final reading that fails is a gap of its own, never a known zero.
func TestSkipFinalReadingFailsClosed(t *testing.T) {
	h := &skipHandle{readings: []skipReading{skips(0, 0), {err: errors.New("closed")}}}
	r, _, events := skipRunner(h)
	if err := r.readSkipBase(false); err != nil {
		t.Fatal(err)
	}
	r.finalSkipCheck()
	gs := gapsOf(t, *events)
	if len(gs) != 1 || gs[0].Why != record.GapSkipCounterUnavailable {
		t.Fatalf("gaps %+v", gs)
	}
}

// TestSkipTreeThatOutlivesTheKillIsNotCovered: a run whose cgroup did not empty after the kill has a task that can reach
// a hook after the final reading, so the record says the reading does not cover it, even with no skip seen.
func TestSkipTreeThatOutlivesTheKillIsNotCovered(t *testing.T) {
	h := &skipHandle{readings: []skipReading{skips(0, 0)}}
	r, _, events := skipRunner(h)
	if err := r.readSkipBase(false); err != nil {
		t.Fatal(err)
	}
	r.treeOutlived.Store(true)
	r.finalSkipCheck()
	gs := gapsOf(t, *events)
	if len(gs) != 1 || gs[0].Why != record.GapSkipCounterUnavailable {
		t.Fatalf("gaps %+v", gs)
	}
}

// adoptionLedger is an adoption's ledger in a fresh directory, with run_start written when started is true; dir is
// what eachLedgerEvent reads.
func adoptionLedger(t *testing.T, started bool) (*ledger.Writer, string) {
	t.Helper()
	const id = "r-00000000-000000000000a-skipad"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "adopted"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if started {
		if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Tier: "cgroup"}); err != nil {
			t.Fatal(err)
		}
	}
	return w, dir
}

// ledgerSkipGaps is the skip lines of the ledger in dir, as written so far.
func ledgerSkipGaps(t *testing.T, dir string) []record.GapPayload {
	t.Helper()
	var out []record.GapPayload
	eachLedgerEvent(t, dir, func(ev *record.Event) {
		var p record.GapPayload
		if ev.Kind == record.KindGap && ev.DecodePayload(&p) == nil {
			out = append(out, p)
		}
	})
	return out
}

// skipClock steps the live report's clock for a test.
func skipClock(t *testing.T) *time.Time {
	t.Helper()
	at := time.Date(2026, 11, 11, 23, 0, 0, 0, time.UTC)
	old := skipNow
	skipNow = func() time.Time { return at }
	t.Cleanup(func() { skipNow = old })
	return &at
}

// sumCounts is the counts of the lines of why.
func sumCounts(gs []record.GapPayload, why string) (n, lines int) {
	for _, g := range gs {
		if g.Why == why {
			n += g.Count
			lines++
		}
	}
	return n, lines
}

// TestSkipAdoptionReportsAtOnceThenAtABoundedRate: an adoption keeps every rule on after a skip (ending it would
// release the agent) and keeps polling; its first report is written at once, through the ledger writer, while the agent
// runs; later skips wait for the next report, at most one per skipReportInterval, each counting the skips since the
// last; the last reading writes the rest, and the counts add up to the skips since the base.
func TestSkipAdoptionReportsAtOnceThenAtABoundedRate(t *testing.T) {
	at := skipClock(t)
	w, dir := adoptionLedger(t, true)
	h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), skips(0, 0), skips(2, 0), skips(5, 0), skips(5, 1),
		skips(6, 1), skips(7, 1)}}
	r, cg, events := skipRunner(h)
	r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
	if err := r.readSkipBase(true); err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct {
		after time.Duration
		lines int
	}{{0, 0}, {time.Second, 1}, {10 * time.Second, 1}, {20 * time.Second, 1}, {skipReportInterval, 3}} {
		*at = at.Add(step.after)
		if r.checkSkips(r.skipState) {
			t.Fatalf("poll %d: an adoption's watch stopped", i)
		}
		if got := ledgerSkipGaps(t, dir); len(got) != step.lines {
			t.Fatalf("poll %d: %d skip lines in the ledger, want %d: %+v", i, len(got), step.lines, got)
		}
	}
	if r.terminal != "" || cg.killed != 0 {
		t.Fatalf("an adoption was ended: terminal=%v killed=%d", r.terminal, cg.killed)
	}
	live := ledgerSkipGaps(t, dir)
	if live[0].Count != 2 || live[0].DecisionPlane != "lsm" || live[1].Count != 4 || live[2].Why != record.GapTrackingSkip {
		t.Fatalf("live lines %+v, want deciding 2, then deciding 4 and tracking 1 a minute later", live)
	}
	r.finalSkipCheck()
	gs := gapsOf(t, *events)
	if len(gs) != 1 || gs[0].Why != record.GapDecidingSkip || gs[0].Count != 1 || r.terminal != "" {
		t.Fatalf("the last reading wrote %+v (terminal %q), want only the one skip since the last report", gs, r.terminal)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestSkipAdoptionWritesNothingBeforeRunStart is the start order: the poll precedes run_start on disk, where the
// writer would refuse ErrNotStarted. Watcher writes wait for startup and never invoke the release callback. The
// first report keeps what was seen before startup: a failed reading, then skips.
func TestSkipAdoptionWritesNothingBeforeRunStart(t *testing.T) {
	at := skipClock(t)
	w, dir := adoptionLedger(t, false)
	h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), {err: errors.New("EBADF")}, skips(3, 0), skips(3, 0)}}
	r, cg, _ := skipRunner(h)
	r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
	r.started = make(chan struct{})
	released := 0
	r.pipe.onLedgerFail = func(error) { released++ }
	if err := r.readSkipBase(true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		*at = at.Add(time.Second)
		if r.checkSkips(r.skipState) {
			t.Fatal("the watch stopped before run_start")
		}
	}
	if released != 0 || r.terminal != "" || cg.killed != 0 {
		t.Fatalf("before run_start: released %d, terminal %q, killed %d", released, r.terminal, cg.killed)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Tier: "cgroup"}); err != nil {
		t.Fatal(err)
	}
	if got := ledgerSkipGaps(t, dir); len(got) != 0 {
		t.Fatalf("lines written before run_start: %+v", got)
	}
	close(r.started)
	*at = at.Add(time.Second)
	r.checkSkips(r.skipState)
	got := ledgerSkipGaps(t, dir)
	if n, lines := sumCounts(got, record.GapDecidingSkip); n != 3 || lines != 1 {
		t.Fatalf("first report %+v, want the 3 skips seen before run_start", got)
	}
	if n, lines := sumCounts(got, record.GapSkipCounterRestored); n != 1 || lines != 1 {
		t.Fatalf("first report %+v, want the failed reading before run_start said", got)
	}
	if released != 0 {
		t.Fatalf("released %d", released)
	}
}

// TestSkipAdoptionOutageIsOneLineAndItsEndAnother: readings that fail for minutes write one unavailable line, not one a
// poll; recovery is written when the report is due, counting those failed readings.
func TestSkipAdoptionOutageIsOneLineAndItsEndAnother(t *testing.T) {
	at := skipClock(t)
	w, dir := adoptionLedger(t, true)
	readings := []skipReading{skips(0, 0)}
	for range 600 {
		readings = append(readings, skipReading{err: errors.New("EBADF")})
	}
	readings = append(readings, skips(0, 0))
	h := &skipHandle{mode: "lsm", readings: readings}
	r, _, _ := skipRunner(h)
	r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
	if err := r.readSkipBase(true); err != nil {
		t.Fatal(err)
	}
	for range 600 {
		*at = at.Add(skipPollInterval)
		r.checkSkips(r.skipState)
	}
	got := ledgerSkipGaps(t, dir)
	if _, lines := sumCounts(got, record.GapSkipCounterUnavailable); lines != 1 || len(got) != 1 {
		t.Fatalf("600 failed readings over 150 s wrote %+v, want one unavailable line", got)
	}
	*at = at.Add(skipReportInterval)
	r.checkSkips(r.skipState)
	got = ledgerSkipGaps(t, dir)
	if n, lines := sumCounts(got, record.GapSkipCounterRestored); lines != 1 || n != 600 || len(got) != 2 {
		t.Fatalf("the reading that worked again wrote %+v, want one restored line counting 600", got)
	}
}

// TestSkipAdoptionPartialReportCommitsEachLine reproduces a disk failure after the deciding line reached the
// ledger. Retrying must count only the unwritten tracking line; a successful prefix also starts the rate interval.
func TestSkipAdoptionPartialReportCommitsEachLine(t *testing.T) {
	at := skipClock(t)
	first := *at
	w, dir := adoptionLedger(t, true)
	h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), skips(4, 1)}}
	r, cg, _ := skipRunner(h)
	r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
	if err := r.readSkipBase(true); err != nil {
		t.Fatal(err)
	}
	write := r.skipState.writeGap
	fail := true
	r.skipState.writeGap = func(g source.Gap) error {
		if g.Why == record.GapTrackingSkip && fail {
			return errors.New("tracking line: disk full")
		}
		return write(g)
	}
	r.checkSkips(r.skipState)
	if got := ledgerSkipGaps(t, dir); len(got) != 1 || got[0].Count != 4 {
		t.Fatalf("partial report: %+v", got)
	}
	fail = false
	*at = at.Add(skipPollInterval)
	r.checkSkips(r.skipState)
	if got := ledgerSkipGaps(t, dir); len(got) != 1 {
		t.Fatalf("successful prefix did not start rate interval: %+v", got)
	}
	// The rate bound is the product's minute, independently of its implementation constant.
	*at = first.Add(time.Minute - time.Nanosecond)
	r.checkSkips(r.skipState)
	if got := ledgerSkipGaps(t, dir); len(got) != 1 {
		t.Fatalf("report before the minute: %+v", got)
	}
	*at = first.Add(time.Minute)
	r.checkSkips(r.skipState)
	got := ledgerSkipGaps(t, dir)
	if n, lines := sumCounts(got, record.GapDecidingSkip); n != 4 || lines != 1 {
		t.Fatalf("retry duplicated prefix: %+v", got)
	}
	if n, lines := sumCounts(got, record.GapTrackingSkip); n != 1 || lines != 1 {
		t.Fatalf("retry lost suffix: %+v", got)
	}
	if r.terminal != "" || cg.killed != 0 {
		t.Fatalf("adoption ended: %q killed %d", r.terminal, cg.killed)
	}
}

// TestSkipAdoptionRetainsOutageTransitions keeps a short outage, and distinct outages before the next report,
// as ordered opening/closing pairs. A failed closing write must not repeat its already written opening.
func TestSkipAdoptionRetainsOutageTransitions(t *testing.T) {
	for _, outages := range []int{1, 2} {
		t.Run(fmt.Sprint(outages), func(t *testing.T) {
			at := skipClock(t)
			w, dir := adoptionLedger(t, true)
			readings := []skipReading{skips(0, 0), skips(1, 0)}
			for range outages {
				readings = append(readings, skipReading{err: errors.New("EBADF")}, skips(1, 0))
			}
			readings = append(readings, skips(1, 0))
			h := &skipHandle{mode: "lsm", readings: readings}
			r, _, _ := skipRunner(h)
			r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
			if err := r.readSkipBase(true); err != nil {
				t.Fatal(err)
			}
			r.checkSkips(r.skipState) // first report, so the short outages wait
			for range 2 * outages {
				*at = at.Add(skipPollInterval)
				r.checkSkips(r.skipState)
			}
			if got := ledgerSkipGaps(t, dir); len(got) != 1 {
				t.Fatalf("report before the interval: %+v", got)
			}
			*at = at.Add(skipReportInterval)
			r.checkSkips(r.skipState)
			got := ledgerSkipGaps(t, dir)
			if len(got) != 1+2*outages {
				t.Fatalf("lost transitions: %+v", got)
			}
			for i := range outages {
				opening, closing := got[1+2*i], got[2+2*i]
				if opening.Why != record.GapSkipCounterUnavailable || closing.Why != record.GapSkipCounterRestored || closing.Count != 1 {
					t.Fatalf("outage %d: %+v then %+v", i, opening, closing)
				}
			}
		})
	}
	t.Run("failed closing write", func(t *testing.T) {
		at := skipClock(t)
		w, dir := adoptionLedger(t, true)
		h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), skips(1, 0), {err: errors.New("EBADF")}, skips(1, 0)}}
		r, _, events := skipRunner(h)
		r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
		if err := r.readSkipBase(true); err != nil {
			t.Fatal(err)
		}
		r.checkSkips(r.skipState)
		r.checkSkips(r.skipState)
		write := r.skipState.writeGap
		fail := true
		r.skipState.writeGap = func(g source.Gap) error {
			if fail && g.Why == record.GapSkipCounterRestored {
				return errors.New("closing line: disk full")
			}
			return write(g)
		}
		*at = at.Add(skipReportInterval)
		r.checkSkips(r.skipState)
		got := ledgerSkipGaps(t, dir)
		if len(got) != 2 || got[1].Why != record.GapSkipCounterUnavailable {
			t.Fatalf("partial outage: %+v", got)
		}
		// Even the final report must not duplicate the committed opening.
		r.finalSkipCheck()
		if gs := gapsOf(t, *events); len(gs) != 1 || gs[0].Why != record.GapSkipCounterRestored {
			t.Fatalf("final report: %+v", gs)
		}
		fail = false
		*at = at.Add(skipReportInterval)
		r.checkSkips(r.skipState)
		got = ledgerSkipGaps(t, dir)
		if len(got) != 3 || got[2].Why != record.GapSkipCounterRestored || got[2].Count != 1 {
			t.Fatalf("retry: %+v", got)
		}
	})
}

// TestSkipAdoptionWriteFailureReleasesNothing: a report the ledger refuses (a full disk) never ends the adoption or
// releases its agent; it is kept, and the last reading still counts every skip since the base.
func TestSkipAdoptionWriteFailureReleasesNothing(t *testing.T) {
	skipClock(t)
	w, _ := adoptionLedger(t, true)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), skips(4, 0), skips(4, 0)}}
	r, cg, events := skipRunner(h)
	r.writer, r.deps.Clock = w, fixedClock{at: time.Now()}
	released := 0
	r.pipe.onLedgerFail = func(error) { released++ }
	if err := r.readSkipBase(true); err != nil {
		t.Fatal(err)
	}
	r.checkSkips(r.skipState)
	if released != 0 || r.terminal != "" || cg.killed != 0 {
		t.Fatalf("a refused skip line released the agent: released %d, terminal %q, killed %d", released, r.terminal, cg.killed)
	}
	r.finalSkipCheck()
	if gs := gapsOf(t, *events); len(gs) != 1 || gs[0].Count != 4 {
		t.Fatalf("the last reading wrote %+v, want the 4 skips the refused report held", gs)
	}
}

// TestSkipFinalReadingEndsTheRun: a skip, or a failed reading, that only the last reading finds (the agent exited before
// the first poll) ends the run with reason error before run_end's ending is computed, so a successful exit cannot stand
// beside a line that says the rules may not have held. The waiver keeps its deciding exception and an adoption is not
// ended.
func TestSkipFinalReadingEndsTheRun(t *testing.T) {
	for _, c := range []struct {
		name               string
		final              skipReading
		waived, recordOnly bool
		ends               bool
		why                string
	}{
		{name: "deciding", final: skips(1, 0), ends: true, why: record.GapDecidingSkip},
		{name: "tracking", final: skips(0, 1), ends: true, why: record.GapTrackingSkip},
		{name: "unreadable", final: skipReading{err: errors.New("EBADF")}, ends: true, why: record.GapSkipCounterUnavailable},
		{name: "waived deciding", final: skips(1, 0), waived: true, why: record.GapDecidingSkip},
		{name: "waived tracking", final: skips(0, 1), waived: true, ends: true, why: record.GapTrackingSkip},
		{name: "adoption deciding", final: skips(1, 0), recordOnly: true, why: record.GapDecidingSkip},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.waived {
				old := skipWaiver
				skipWaiver = func() bool { return true }
				t.Cleanup(func() { skipWaiver = old })
			}
			h := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), c.final}}
			if c.waived {
				h.mode = "fmod_ret"
			}
			r, _, events := skipRunner(h)
			if err := r.readSkipBase(c.recordOnly); err != nil {
				t.Fatal(err)
			}
			r.finalSkipCheck()
			ended := r.terminal == identity.ReasonError && strings.HasPrefix(r.detail, "kernel skips: ")
			if ended != c.ends {
				t.Fatalf("terminal=%q detail=%q, want ended %v", r.terminal, r.detail, c.ends)
			}
			gs := gapsOf(t, *events)
			if len(gs) != 1 || gs[0].Why != c.why {
				t.Fatalf("gaps %+v, want one %s", gs, c.why)
			}
		})
	}
}

// TestSkipWaivedFmodRetRecordsAndKeepsWatching: under a test build's waiver a fmod_ret run's deciding skips only
// record, and a tracking skip after them still ends the run.
func TestSkipWaivedFmodRetRecordsAndKeepsWatching(t *testing.T) {
	old := skipWaiver
	skipWaiver = func() bool { return true }
	t.Cleanup(func() { skipWaiver = old })
	h := &skipHandle{mode: "fmod_ret", readings: []skipReading{skips(0, 0), skips(5, 0), skips(9, 0), skips(9, 1)}}
	r, cg, events := skipRunner(h)
	if err := r.readSkipBase(false); err != nil {
		t.Fatal(err)
	}
	if !r.skipState.waived {
		t.Fatal("a waived fmod_ret run was not marked waived")
	}
	first, second := r.checkSkips(r.skipState), r.checkSkips(r.skipState) // two readings, each with the skip
	if first || second || r.terminal != "" || cg.killed != 0 {
		t.Fatalf("a waived deciding skip ended the run: terminal=%v killed=%d", r.terminal, cg.killed)
	}
	if !r.checkSkips(r.skipState) || r.terminal != identity.ReasonError || cg.killed != 1 {
		t.Fatalf("a tracking skip under the waiver did not end the run: terminal=%v killed=%d", r.terminal, cg.killed)
	}
	r.finalSkipCheck()
	if gs := gapsOf(t, *events); len(gs) != 2 || gs[0].Count != 9 || gs[0].DecisionPlane != "fmod_ret" || gs[1].Count != 1 {
		t.Fatalf("gaps %+v", gs)
	}
	// The waiver covers fmod_ret mode only: an lsm run under the same test build ends on a deciding skip.
	h2 := &skipHandle{mode: "lsm", readings: []skipReading{skips(0, 0), skips(1, 0)}}
	r2, cg2, _ := skipRunner(h2)
	if err := r2.readSkipBase(false); err != nil {
		t.Fatal(err)
	}
	if !r2.checkSkips(r2.skipState) || cg2.killed != 1 {
		t.Fatal("the waiver spared an lsm run")
	}
}

// TestSkipTierWithoutCountersWatchesNothing: a handle with no skip counter (tier landlock) watches nothing and writes
// nothing.
func TestSkipTierWithoutCountersWatchesNothing(t *testing.T) {
	r := newTestRunner(Deps{})
	r.handle = &fakeHandle{}
	var events []*record.Event
	r.pipe = &pipeline{handle: func(ev *record.Event) { events = append(events, ev) }}
	if err := r.startSkipWatch(context.Background()); err != nil || r.skipState != nil {
		t.Fatalf("err=%v state=%v", err, r.skipState)
	}
	r.finalSkipCheck()
	if len(events) != 0 {
		t.Fatalf("events %v", events)
	}
}

// eachLedgerEvent hands fn each line of the run ledger in dir, as written so far.
func eachLedgerEvent(t *testing.T, dir string, fn func(*record.Event)) {
	t.Helper()
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	for e, err := range rd.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		fn(e)
	}
}
