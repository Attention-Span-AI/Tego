// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"syscall"
	"time"
	"unsafe"
)

// Clock supplies the two timestamps of every line (R7): a wall clock for ts, which may step, and a monotonic
// reading for mono_ns, which orders events within one boot. internal/runtime injects its own; tests and the
// fixture generator inject a scripted one.
type Clock interface {
	// Now is the wall clock; Append stores it in UTC.
	Now() time.Time
	// Mono is CLOCK_MONOTONIC in nanoseconds; 0 means unknown (E20).
	Mono() uint64
}

// SystemClock is the Clock a Writer uses when none is injected: time.Now and clock_gettime(CLOCK_MONOTONIC).
type SystemClock struct{}

// Now returns the wall clock.
func (SystemClock) Now() time.Time { return time.Now() }

// clockMonotonic is CLOCK_MONOTONIC on Linux (linux/time.h).
const clockMonotonic = 1

// Mono reads CLOCK_MONOTONIC. The raw syscall cannot fail for this clock id on Linux; 0 is returned if it does.
func (SystemClock) Mono() uint64 {
	var ts syscall.Timespec
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
