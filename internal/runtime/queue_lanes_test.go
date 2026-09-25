// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAFloodedLaneLeavesTheOthersRoom: one shared channel let the agent choose which of the run's lines were lost, a
// flood of refused connects dropping every other producer's lines with its own. A full supervisor lane takes no room
// from the default or capture lanes.
func TestAFloodedLaneLeavesTheOthersRoom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(2)
		sup := q.Lane(LaneSupervisor)
		for range 2 {
			sup.Emit(&record.Event{Kind: record.KindRefused})
		}
		q.Emit(&record.Event{Kind: record.KindExec})
		q.Lane(LaneCapture).Emit(&record.Event{Kind: record.KindSSLResponse})
		if n := q.Dropped(); n != 0 {
			t.Fatalf("%d events dropped while only the supervisor lane was full", n)
		}
	})
}

// TestTheSupervisorLaneWaitsThenDrops: a producer of the supervisor lane waits for room, which slows the
// agent whose notification it is carrying, and drops only after supervisorBacklogWait.
func TestTheSupervisorLaneWaitsThenDrops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(1)
		sup := q.Lane(LaneSupervisor)
		sup.Emit(&record.Event{Seq: 1})
		start := time.Now()
		done := make(chan struct{})
		go func() { sup.Emit(&record.Event{Seq: 2}); close(done) }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("the second event did not wait for room")
		default:
		}
		<-q.lanes[LaneSupervisor] // room: the waiting event lands
		<-done
		if n := q.Dropped(); n != 0 {
			t.Fatalf("dropped %d, want the waiting event to land", n)
		}
		// The lane holds event 2 again; nobody reads, so the next one waits, then drops.
		sup.Emit(&record.Event{Seq: 3})
		if waited := time.Since(start); waited < supervisorBacklogWait {
			t.Fatalf("dropped after %v, want a wait of %v", waited, supervisorBacklogWait)
		}
		if n := q.Dropped(); n != 1 {
			t.Fatalf("dropped %d, want 1", n)
		}
	})
}

// TestStopWaitingReleasesAWaitingProducer: at shutdown no producer may hang on a pipeline that no longer reads.
func TestStopWaitingReleasesAWaitingProducer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(1)
		c := q.Lane(LaneCapture)
		c.Emit(&record.Event{Seq: 1})
		done := make(chan struct{})
		go func() { c.Emit(&record.Event{Seq: 2}); close(done) }()
		synctest.Wait()
		q.stopWaiting()
		<-done
		if n := q.droppedLanes()[LaneCapture]; n != 1 {
			t.Fatalf("capture dropped %d, want the released event counted", n)
		}
	})
}

// TestLostCaptureIsReported: a capture event the queue dropped reaches the runner, which ends a budgeted run.
func TestLostCaptureIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(1)
		sink := &collectSink{}
		p := testPipeline(t, q, sink)
		var lost int64
		p.onCaptureLost = func(n int64) { lost += n }
		c := q.Lane(LaneCapture)
		c.Emit(&record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder})
		c.Emit(&record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}) // waits, then drops
		p.drain()
		if lost != 1 {
			t.Fatalf("onCaptureLost saw %d, want 1", lost)
		}
	})
}

// TestNoCaptureDropEscapesTheBudgetReport: reportDrops swapped the capture lane's counter and then every lane's, so
// a capture drop landing between the two swaps reached the channel-full total but not onCaptureLost, and a
// token or cost budget went on with an ssl_response it never saw.
func TestNoCaptureDropEscapesTheBudgetReport(t *testing.T) {
	const drops = 20000
	q := NewQueue(1)
	q.stopWaiting() // a producer that finds the lane full drops at once
	p := testPipeline(t, q, &collectSink{})
	var lost atomic.Int64
	p.onCaptureLost = func(n int64) { lost.Add(n) }
	c := q.Lane(LaneCapture)
	c.Emit(&record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}) // fills the lane
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range drops {
			c.Emit(&record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder})
		}
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		p.reportDrops()
	}
	p.reportDrops()
	if got := lost.Load(); got != drops {
		t.Fatalf("onCaptureLost saw %d of %d capture drops", got, drops)
	}
}

// TestDropGapsAreRateLimited: reported after every handled event, a saturated queue wrote a gap line of count 1 for
// nearly every event. Within dropReportEvery one gap carries every drop.
func TestDropGapsAreRateLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue(1)
		sink := &collectSink{}
		p := testPipeline(t, q, sink)
		for range 50 {
			q.Emit(&record.Event{Kind: record.KindFS})
			p.maybeReportDrops()
		}
		gaps := 0
		for _, ev := range sink.all() {
			if ev.Kind == record.KindGap {
				gaps++
			}
		}
		if gaps != 1 {
			t.Fatalf("%d gap lines within one interval, want 1", gaps)
		}
		time.Sleep(dropReportEvery)
		q.Emit(&record.Event{Kind: record.KindFS})
		p.maybeReportDrops()
		if n := len(sink.all()); n != 2 {
			t.Fatalf("%d lines after the interval, want a second gap", n)
		}
	})
}

// TestTierTwoProducersHaveLanesOfTheirOwn: at tier 2 the kernel recorder and the fanotify listener shared the default
// lane with the run's own gaps, so a flood of one producer's lines (reads under record: full, refused opens) dropped
// the other's exec, connect and refusal lines. A full kernel lane now drops only kernel lines; the listener's and the
// default lane's still have room.
func TestTierTwoProducersHaveLanesOfTheirOwn(t *testing.T) {
	q := NewQueue(4)
	kernel, listener := q.Lane(LaneKernel), q.Lane(LaneListener)
	for range 10 {
		kernel.Emit(&record.Event{Kind: record.KindFS})
	}
	listener.Emit(&record.Event{Kind: record.KindFS, Verdict: record.VerdictRefused})
	q.Emit(&record.Event{Kind: record.KindGap})
	if got := q.Dropped(); got != 6 {
		t.Fatalf("dropped %d, want the kernel lane's 6 overflow alone", got)
	}
	if len(q.lanes[LaneListener]) != 1 || len(q.lanes[LaneDefault]) != 1 {
		t.Fatal("the listener's refusal or the run's gap was lost to the kernel lane's flood")
	}
}
