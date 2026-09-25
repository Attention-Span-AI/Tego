// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestDecodeScalesLinearlyInKeys holds Decode to near-linear time in the number of keys on a line. A ledger
// line is bytes a tamperer can write (E16), and Decode runs on the last line of every retained run before
// each `tego run` (Reader.State) and on every line under Verify; a duplicate-key check that compared each
// key with every earlier one took 5 s for a 430 KB line and grows with the square of its length.
func TestDecodeScalesLinearlyInKeys(t *testing.T) {
	line := func(n int) []byte {
		var b bytes.Buffer
		b.WriteString(`{"v":1`)
		for i := range n {
			fmt.Fprintf(&b, `,"k%d":0`, i)
		}
		b.WriteString("}")
		return b.Bytes()
	}
	// The least CPU time of nine of each size, each after a collection, the two sizes interleaved and the one that
	// goes first alternating, so a change in the machine's load lands on both: with three, a loaded machine (load
	// average 45 while review agents ran, 2026-09-24) put a GC or a preemption into every sample of one size. CPU
	// time, not the wall clock: an 80k-key line takes tens of milliseconds, longer than a scheduler slice, so on an
	// oversubscribed machine every one of its samples waits for a CPU (under 16 busy loops and a load average of 45,
	// 2026-10-16, one run's best of nine was 192 ms, x80, where the others were 63 to 79 ms). pkg/spec imports
	// nothing under internal/, so testutil.MinOf's interleaving is written out here.
	cpu := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatal(err)
		}
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	lines := [2][]byte{line(5_000), line(80_000)}
	best := [2]time.Duration{1 << 62, 1 << 62}
	for r := range 9 {
		for j := range 2 {
			i := (j + r) % 2
			runtime.GC()
			st := cpu()
			_, _ = Decode(lines[i])
			best[i] = min(best[i], cpu()-st)
		}
	}
	small, large := best[0], best[1]
	// Sixteen times the keys: linear is ~16x (with sorting, ~20x); quadratic is ~256x. The wide gap keeps
	// the bound far from both, where 8x (linear ~8, bound 24) failed at x24-x31 on a loaded machine.
	ratio := float64(large) / float64(max(small, time.Microsecond))
	t.Logf("Decode: %v of CPU for 5k keys, %v for 80k (x%.1f, bound x80)", small, large, ratio)
	if ratio > 80 {
		t.Fatalf("Decode took %v for 5k keys and %v for 80k (x%.0f): superlinear in the number of keys",
			small, large, ratio)
	}
}
