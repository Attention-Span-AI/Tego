// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package startphase

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestPhaseTiming turns the timing lines on in a binary built with -tags tegotesthooks: any non-empty value.
// A product build does not contain this file; a test build ignores it under AT_SECURE, like every TEGO_TEST_
// variable.
const EnvTestPhaseTiming = "TEGO_TEST_PHASE_TIMING"

// EnvTestLoadStats adds the cold start's load attribution to the timing lines (any non-empty value, and only with
// EnvTestPhaseTiming): each program's verifier statistics and the kernel stacks of a slow load (Attributing).
const EnvTestLoadStats = "TEGO_TEST_LOAD_STATS"

// EnvTestPhaseCPU adds the CPU time each phase used to the timing lines ("tego-phase-cpu <name> <microseconds>"; any
// non-empty value, and only with EnvTestPhaseTiming): the process's user plus system time between the phase's start
// and end, every thread, so a phase that overlaps another counts the other's CPU as well.
const EnvTestPhaseCPU = "TEGO_TEST_PHASE_CPU"

// processCPU is the process's user plus system CPU time so far.
func processCPU() time.Duration {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func init() {
	if os.Getenv(EnvTestPhaseTiming) == "" {
		return
	}
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	Default = func(name string, d time.Duration) {
		fmt.Fprintf(os.Stderr, "tego-phase %s %d\n", name, d.Microseconds())
	}
	if os.Getenv(EnvTestPhaseCPU) != "" {
		CPUNow = processCPU
		CPUSink = func(name string, cpu time.Duration) {
			fmt.Fprintf(os.Stderr, "tego-phase-cpu %s %d\n", name, cpu.Microseconds())
		}
	}
	if os.Getenv(EnvTestLoadStats) == "" {
		return
	}
	DefaultStat = func(name string, v int64) {
		fmt.Fprintf(os.Stderr, "tego-stat %s %d\n", name, v)
	}
	DefaultStack = func(name string, samples int, frames string) {
		fmt.Fprintf(os.Stderr, "tego-phase-stack %s %d %s\n", name, samples, frames)
	}
}
