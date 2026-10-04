// SPDX-License-Identifier: Apache-2.0

package runtime

// Dropped returns and resets the drop count of every lane together. Production reads droppedLanes.
func (q *Queue) Dropped() int64 {
	var n int64
	for _, c := range q.droppedLanes() {
		n += c
	}
	return n
}
