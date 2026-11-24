// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"
	"time"
)

// TestShuffleOffset: a numeric seed names the subset (the same seed, the same cases), a seed of the testing package's
// own choosing (-shuffle=on) moves it with the clock so that every case is covered over a few runs, an ordered run starts at
// 0, and the environment's offset wins.
func TestShuffleOffset(t *testing.T) {
	now := time.Unix(1795551972, 722241000)
	for _, tc := range []struct {
		flag, override string
		want           int
	}{
		{"", "", 0}, {"off", "", 0}, {"1795540607547246751", "", 3}, {"1795540602790919918", "", 2}, {"-5", "", 3},
		{"1795540607547246751", "2", 2}, {"on", "1", 1}, {"1", "9", 1}, {"on", "x", int(now.UnixNano() / 1000 % 4)},
	} {
		if got := shuffleOffset(tc.flag, tc.override, 4, now); got != tc.want {
			t.Errorf("shuffleOffset(%q, %q) = %d, want %d", tc.flag, tc.override, got, tc.want)
		}
	}
	seen := map[int]bool{}
	for i := range 40 {
		seen[shuffleOffset("on", "", 4, now.Add(time.Duration(i)*1731*time.Microsecond))] = true
	}
	if len(seen) != 4 {
		t.Errorf("-shuffle=on reached offsets %v of 4 over 40 runs", seen)
	}
	if shuffleOffset("7", "", 0, now) != 0 {
		t.Error("every 0 gave a nonzero offset")
	}
}
