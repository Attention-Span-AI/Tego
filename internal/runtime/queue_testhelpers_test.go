// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/attention-span-ai/tego/pkg/spec/record"

// C is the default lane's receive side; tests read the run's own lines from it.
func (q *Queue) C() <-chan *record.Event { return q.lanes[LaneDefault] }

// Close closes every lane; producers must have stopped. Tests use it to drain the lanes.
func (q *Queue) Close() {
	q.stopWaiting()
	for _, ch := range q.lanes {
		close(ch)
	}
}
