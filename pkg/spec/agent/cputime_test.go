// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"syscall"
	"testing"
	"time"
)

// processCPU is this process's CPU time, user and system, over all its threads. A test comparing samples of
// milliseconds, longer than a scheduler slice, reads it instead of the wall clock: on an oversubscribed machine
// every such sample waits for a CPU however many rounds run, so its fastest wall time carries the wait, where its
// CPU time carries only the work (the collector's included). Under 16 busy loops a 4,000-entry merge measured
// 23 to 94 ms by the wall clock, the best of three each time. pkg/spec imports nothing under internal/, so this
// is not testutil's.
func processCPU(t testing.TB) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// bestInterleaved runs rounds rounds of a and b, one sample of each a round, the one that goes first alternating, and
// returns each one's smallest sample. Each function times its own sample and returns it, so what it checks of its
// result stays out of the figure.
func bestInterleaved(rounds int, a, b func() time.Duration) (time.Duration, time.Duration) {
	fns := [2]func() time.Duration{a, b}
	best := [2]time.Duration{1 << 62, 1 << 62}
	for r := range rounds {
		for j := range 2 {
			i := (j + r) % 2
			best[i] = min(best[i], fns[i]())
		}
	}
	return best[0], best[1]
}
