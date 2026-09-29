// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// emitQueueSize bounds what one listener holds for its sink: past it an event is dropped and counted
// (GapEmitQueueFull), never waited for. A variable so a test can make it small.
var emitQueueSize = 1024

// GapEmitQueueFull is gap what=capture: events the listener dropped because its emit queue was full, the run's
// pipeline having fallen that far behind. Each is counted in the run's gap report (Gaps); the first is reported
// unmetered, since what was dropped may be the one line that carried an exchange's spend
// (limits-check-doctor-cli.md R1 (s)).
const GapEmitQueueFull = derive.GapEmitQueueFull

// emitItem is one thing the queue hands the sink in order: an event, a report of unmetered spend, or word that
// a request will get no response, each of which goes through the queue so it follows the lines of the exchange
// it is about.
type emitItem struct {
	sink source.Sink
	ev   *record.Event
	// unmetered, when not empty, is a ReportUnmetered's why and ev is nil.
	unmetered string
	// abandon, when not zero, is the pair a ReportAbandoned names and ev is nil.
	abandon uint64
}

// emitQueue is the listener's hand-off to its sink (capture-derive.md I1). The run's capture lane waits for
// room up to its bound, and a handler that emitted into it directly held the agent's model request, or its
// next one on the connection, for as long as the ledger was behind. A handler now only appends here, under
// a lock no sink call is ever made under; one goroutine at a time, started when there is work and gone when
// there is none, hands the items to the sink in the order they were appended, so the lines of one exchange,
// and of exchanges one after another, keep their order. The goroutine may wait on the lane; nothing the
// client waits for does.
type emitQueue struct {
	mu       sync.Mutex
	idle     *sync.Cond // signalled when the drainer exits
	pending  []emitItem
	spare    []emitItem
	draining bool
	// abandoned is set when Close stopped waiting for the drainer: what is still pending is dropped and counted.
	abandoned bool
	// dropped counts items dropped since the listener started; lost is called at the first.
	dropped int64
	lost    func(source.Sink)
	note    func(int64)
}

func newEmitQueue(note func(int64), lost func(source.Sink)) *emitQueue {
	q := &emitQueue{note: note, lost: lost}
	q.idle = sync.NewCond(&q.mu)
	return q
}

// put appends one item without waiting. Past emitQueueSize the item is dropped and counted.
func (q *emitQueue) put(it emitItem) {
	q.mu.Lock()
	if len(q.pending) >= emitQueueSize || q.abandoned {
		if it.abandon != 0 {
			// Not a line of the record, so nothing is lost: the step tracker is told at once, which never
			// waits, and a pair whose ssl_request it has not seen yet is remembered there (derive.Steps.Abandon).
			q.mu.Unlock()
			source.ReportAbandoned(it.sink, it.abandon)
			return
		}
		first := q.dropped == 0
		q.dropped++
		q.mu.Unlock()
		q.drop(it, first)
		return
	}
	q.pending = append(q.pending, it)
	start := !q.draining
	q.draining = true
	q.mu.Unlock()
	if start {
		go q.drain()
	}
}

// drop counts one dropped item as a gap and, at the listener's first drop, reports unmetered spend. A dropped
// unmetered report is made directly: it never waits (ReportUnmetered).
func (q *emitQueue) drop(it emitItem, first bool) {
	q.note(1)
	if it.unmetered != "" {
		source.ReportUnmetered(it.sink, 1, it.unmetered)
		return
	}
	if first && q.lost != nil {
		q.lost(it.sink)
	}
}

// drain hands pending items to their sinks until none is left.
func (q *emitQueue) drain() {
	for {
		q.mu.Lock()
		if len(q.pending) == 0 {
			q.draining = false
			q.idle.Broadcast()
			q.mu.Unlock()
			return
		}
		batch := q.pending
		q.pending, q.spare = q.spare[:0], nil
		q.mu.Unlock()
		for i, it := range batch {
			if it.abandon != 0 {
				// Told even once Close stopped waiting: it is no line of the record and never waits.
				source.ReportAbandoned(it.sink, it.abandon)
				batch[i] = emitItem{}
				continue
			}
			q.mu.Lock()
			abandoned := q.abandoned
			first := abandoned && q.dropped == 0
			if abandoned {
				q.dropped++
			}
			q.mu.Unlock()
			switch {
			case abandoned:
				q.drop(it, first)
			case it.unmetered != "":
				source.ReportUnmetered(it.sink, 1, it.unmetered)
			default:
				it.sink.Emit(it.ev)
			}
			batch[i] = emitItem{}
		}
		q.mu.Lock()
		q.spare = batch[:0]
		q.mu.Unlock()
	}
}

// flush waits for every item appended so far to have been handed to its sink, up to wait. On timeout what is
// still pending is dropped and counted instead, so nothing reaches the sink long after the listener's Close.
func (q *emitQueue) flush(wait time.Duration) {
	done := make(chan struct{})
	go func() {
		q.mu.Lock()
		for q.draining {
			q.idle.Wait()
		}
		q.mu.Unlock()
		close(done)
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
		return
	case <-t.C:
	}
	q.mu.Lock()
	q.abandoned = true
	q.mu.Unlock()
	<-done
}
