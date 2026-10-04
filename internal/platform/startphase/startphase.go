// SPDX-License-Identifier: Apache-2.0

// Package startphase times the phases of `tego run`'s start (the mode probe, Prepare's steps, Arm) for the
// start-latency budget of docs/p0/enforce-plane.md §10 and a guest perf run. A product build
// times nothing: Default is nil, so Begin returns a no-op and costs one comparison. A binary built with
// -tags tegotesthooks prints one "tego-phase <name> <microseconds>" line per phase to stderr when
// TEGO_TEST_PHASE_TIMING is set (hooks.go), and with TEGO_TEST_LOAD_STATS beside it the cold start's per-program
// counts and kernel stacks (Stat, Stack).
package startphase

import "time"

// Sink receives one finished phase: its name and how long it took.
type Sink func(name string, d time.Duration)

// Default is the sink a caller uses when it was given none. It is set once, in an init function of a test build,
// and never after.
var Default Sink

// Begin starts phase name on sink (Default when sink is nil) and returns the function that ends it. With no sink
// the returned function does nothing.
func Begin(sink Sink, name string) func() {
	if sink == nil {
		sink = Default
	}
	if sink == nil {
		return func() {}
	}
	t := time.Now()
	return func() { sink(name, time.Since(t)) }
}

// Report sends an already measured phase to sink (Default when nil), for a phase whose name is known only at its end
// (an object that was adopted or loaded).
func Report(sink Sink, name string, d time.Duration) {
	if sink == nil {
		sink = Default
	}
	if sink != nil {
		sink(name, d)
	}
}

// DefaultStat and DefaultStack receive the cold start's attribution beside the phases (enforce-plane §10.1): a count
// (a program's verified instructions and states, printed "tego-stat <name> <n>"), and the kernel frames a slow load's
// thread was sampled in ("tego-phase-stack <name> <samples> <frames>"). A test build sets both in its init when
// TEGO_TEST_LOAD_STATS is set beside TEGO_TEST_PHASE_TIMING, and never after; a product build has neither.
var (
	DefaultStat  func(name string, v int64)
	DefaultStack func(name string, samples int, frames string)
)

// Attributing reports whether this process attributes its BPF loads: a test build whose phases are timed and that was
// asked for the attribution too (TEGO_TEST_LOAD_STATS). The attribution costs more than a clock read (the verifier's
// statistics log, a stack sampler, a bpf_prog_info read per program), so it is a knob of its own: a timed launch that
// did not ask for it loads exactly as it did before the attribution existed.
func Attributing() bool { return Default != nil && DefaultStat != nil }

// Stat sends count v of name to DefaultStat, when there is one.
func Stat(name string, v int64) {
	if DefaultStat != nil {
		DefaultStat(name, v)
	}
}

// Stack sends samples samples of frames, the kernel stack a slow phase name was found in, to DefaultStack, when there
// is one.
func Stack(name string, samples int, frames string) {
	if DefaultStack != nil {
		DefaultStack(name, samples, frames)
	}
}
