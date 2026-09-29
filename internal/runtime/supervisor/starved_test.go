// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import "testing"

// TestStarvedCountsARelayOnce: relay calls backfill on every 20 ms poll tick, and with maxStandby standbys
// running each call counted metrics.starved and logged a warning again, so one connect blackholed for the
// SYN schedule counted thousands of starved relays. It is counted once per relay, and a later tick that finds
// a slot still backfills.
func TestStarvedCountsARelayOnce(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	spawned := 0
	l.spawn = func() { spawned++ }
	l.standby.Store(maxStandby)
	n := notifFor(connectNR(), 4242)
	for range 10 {
		if l.backfill(n) {
			t.Fatal("backfill started a standby past maxStandby")
		}
	}
	if got := l.metrics.starved.Load(); got != 1 {
		t.Errorf("starved = %d after 10 ticks of one relay, want 1", got)
	}
	l.standby.Add(-1)
	if !l.backfill(n) || spawned != 1 {
		t.Errorf("backfill with a free slot: spawned %d, want 1", spawned)
	}
	if got := l.metrics.starved.Load(); got != 1 {
		t.Errorf("starved = %d, want 1", got)
	}
}
