// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestQueueEmitAllocatesNothing is BenchmarkQueueEmit's hand-off: every producer of the run (the supervisor's
// workers, the kernel recorder, the capture sources) calls Emit once per event, and it allocates nothing.
// The test holds it there; the benchmark would only report the change, and CI's bench gate only compare it
// with the parent commit.
func TestQueueEmitAllocatesNothing(t *testing.T) {
	q := NewQueue(QueueCapacity)
	ev := &record.Event{Kind: record.KindFS}
	n := testing.AllocsPerRun(100, func() {
		q.Emit(ev)
		select {
		case <-q.C():
		default:
		}
	})
	if n != 0 {
		t.Errorf("Queue.Emit makes %v allocations, want 0", n)
	}
}
