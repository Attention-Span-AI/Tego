// SPDX-License-Identifier: Apache-2.0

package startphase

import (
	"testing"
	"time"
)

func TestBeginReportsThePhaseToTheGivenSink(t *testing.T) {
	t.Parallel()
	var name string
	var d time.Duration
	end := Begin(func(n string, took time.Duration) { name, d = n, took }, "load")
	time.Sleep(2 * time.Millisecond)
	end()
	if name != "load" || d < 2*time.Millisecond {
		t.Fatalf("sink got %q, %v; want load, at least 2ms", name, d)
	}
}

func TestBeginWithNoSinkDoesNothing(t *testing.T) {
	t.Parallel()
	Begin(nil, "x")() // Default is nil in a plain build: nothing to call, nothing to panic on
}

// TestCountsAndStacksGoWhereTheTimingLinesGo: a count and a stack go to their own sinks, which a product build never
// sets, and Attributing is true only with both the phase sink and the count sink set.
func TestCountsAndStacksGoWhereTheTimingLinesGo(t *testing.T) {
	if Default != nil || DefaultStat != nil {
		t.Skip("phase timing is on in this test process (TEGO_TEST_PHASE_TIMING in a test build)")
	}
	Stat("load.prog.x.y.insns", 1)   // DefaultStat is nil in a plain build: nothing to call
	Stack("load.prog.x.y", 1, "a<b") // and so is DefaultStack
	var stats []string
	var stacks []string
	DefaultStat = func(name string, v int64) { stats = append(stats, name) }
	DefaultStack = func(name string, n int, frames string) { stacks = append(stacks, name+" "+frames) }
	t.Cleanup(func() { DefaultStat, DefaultStack = nil, nil })
	if Attributing() {
		t.Fatal("Attributing with counts but no phase sink: the attribution is part of the timed phases")
	}
	Default = func(string, time.Duration) {}
	t.Cleanup(func() { Default = nil })
	if !Attributing() {
		t.Fatal("not Attributing with both sinks set")
	}
	Stat("load.prog.x.y.insns", 3751)
	Stack("load.prog.x.y", 2, "__mutex_lock<bpf_trampoline_get")
	if len(stats) != 1 || len(stacks) != 1 || stacks[0] != "load.prog.x.y __mutex_lock<bpf_trampoline_get" {
		t.Fatalf("stats %v, stacks %v", stats, stacks)
	}
}
