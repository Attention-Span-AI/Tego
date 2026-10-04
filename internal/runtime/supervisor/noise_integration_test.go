// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// noiseFactor is how many scheduler round trips a notified syscall may cost before a timing test calls it
// slow on a loaded box. A notification is two wake-ups (target to listener, listener to target) plus the
// loop's work, so the path costs a small multiple of one pipe ping-pong; a per-op regression such as one more
// ioctl round trip adds a whole ping-pong and a listener stall of its own size, which the factor does not hide.
const noiseFactor = 12

// pingPongRTT is the median of several 500-exchange pipe ping-pongs between two OS threads: the price of
// waking a thread and being woken back, in this process, right now. It grows on a loaded box the way the
// seccomp round trip does, so a timing test compares against it and not against a wall-clock figure that
// only a quiet machine can hold.
func pingPongRTT() time.Duration {
	const exchanges, rounds = 500, 5
	var ab, ba [2]int
	if unix.Pipe2(ab[:], unix.O_CLOEXEC) != nil || unix.Pipe2(ba[:], unix.O_CLOEXEC) != nil {
		return 0
	}
	defer func() {
		for _, fd := range []int{ab[0], ab[1], ba[0], ba[1]} {
			_ = unix.Close(fd)
		}
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		buf := make([]byte, 1)
		for {
			if n, err := unix.Read(ab[0], buf); n != 1 || err != nil || buf[0] == 0 {
				return
			}
			_, _ = unix.Write(ba[1], buf)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	one, buf := []byte{1}, make([]byte, 1)
	var samples []time.Duration
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for i := 0; i < exchanges; i++ {
			_, _ = unix.Write(ab[1], one)
			_, _ = unix.Read(ba[0], buf)
		}
		samples = append(samples, time.Since(start)/exchanges)
	}
	_, _ = unix.Write(ab[1], []byte{0})
	wg.Wait()
	slices.Sort(samples)
	return samples[len(samples)/2]
}

// noiseGauge holds the ping-pongs measured during one timing test and turns their median into the test's
// ceiling: the soft ceiling on a quiet box, and noiseFactor times the median ping-pong when the box is loaded
// enough that scheduling alone costs more than the soft ceiling allows. The median, not the maximum, so one
// stalled measurement does not lift the ceiling over a real slowdown. A per-op slowdown still exceeds both.
type noiseGauge struct{ rtts []time.Duration }

// ceiling adds a fresh ping-pong to the gauge and returns the ceiling it now implies.
func (g *noiseGauge) ceiling(t testing.TB) time.Duration {
	g.rtts = append(g.rtts, pingPongRTT())
	sorted := slices.Sorted(slices.Values(g.rtts))
	rtt := sorted[len(sorted)/2]
	ceil := max(SoftCeiling, noiseFactor*rtt)
	t.Logf("scheduler noise: ping-pong %v (median of %d), ceiling %v (soft ceiling %v, factor %d)", rtt, len(sorted), ceil, SoftCeiling, noiseFactor)
	return ceil
}

// slowdownEnv is a test hook for proving the timing tests still catch a slowdown: a duration in it makes the
// target spin that long before every timed op. Unset, it costs nothing.
const slowdownEnv = "TEGO_TEST_TIMING_SLOWDOWN"

// injectedSlowdown reads slowdownEnv once in the target.
func injectedSlowdown() time.Duration {
	d, _ := time.ParseDuration(os.Getenv(slowdownEnv))
	return d
}

// spin busy-waits d, the artificial cost the hook adds (a sleep would round up to the timer's slack).
func spin(d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); {
	}
}
