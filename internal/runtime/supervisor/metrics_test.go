// SPDX-License-Identifier: Apache-2.0

package supervisor

import "testing"

// TestMetricsCarryOrphanedAndStarved pins that the two counters the loop keeps for E35 and R21 leave it.
// Metrics is the only way out: run_end.supervisor is filled from it, and a counter it does not copy is one
// nothing ever reads, which is how a run's total of orphaned side effects and of starved backfills came to reach
// no reader at all.
func TestMetricsCarryOrphanedAndStarved(t *testing.T) {
	var l Loop
	l.metrics.notifications.Add(9)
	l.metrics.orphaned.Add(3)
	l.metrics.starved.Add(2)
	got := l.Metrics()
	if got.Orphaned != 3 || got.Starved != 2 {
		t.Fatalf("Metrics() = %+v, want orphaned 3 and starved 2", got)
	}
	if got.Notifications != 9 {
		t.Fatalf("Metrics() = %+v, want the notification count alongside them", got)
	}
}
