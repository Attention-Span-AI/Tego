// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package doctor

import (
	"sync"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// PlaneRowForce says how often a test build makes one plane probe row fail on the outside leg.
type PlaneRowForce int

const (
	// PlaneRowForceNever only counts the probes that reach the row.
	PlaneRowForceNever PlaneRowForce = iota
	// PlaneRowForceFirst makes the first probe's row fail and lets every later one answer as the kernel does.
	PlaneRowForceFirst
	// PlaneRowForceAlways makes the row fail on every probe.
	PlaneRowForceAlways
)

// planeRowForce is the one row a test build makes fail: the hook (bpf.PlaneHook.Name) in forceMode, counted in every
// mode. It is set by a test only, through PlaneRowForceForTest, never from the environment, so a test build's binary
// run by hand cannot be made to fail a row; a product build has no copy of this file.
var planeRowForce struct {
	mu        sync.Mutex
	set       bool
	hook      string
	forceMode bpfobj.PlaneMode
	how       PlaneRowForce
	calls     map[bpfobj.PlaneMode]int
}

// PlaneRowForceForTest makes hook's row of mode m answer "refused" on its outside leg, where the real syscall passed,
// as how says: the row then fails its verdict on a real kernel, with the programs loaded, attached and run. Every
// probe of any mode that reaches hook's outside leg is counted, and calls(m) is the count for mode m: the number of
// times mode m was probed to the end. restore ends the forcing and clears the count. Only a syscall that passed is
// changed, so a real refusal or fault is never hidden, and only one row is forced at a time (a second call replaces
// the first).
func PlaneRowForceForTest(m bpfobj.PlaneMode, hook string, how PlaneRowForce) (calls func(bpfobj.PlaneMode) int, restore func()) {
	planeRowForce.mu.Lock()
	defer planeRowForce.mu.Unlock()
	planeRowForce.set, planeRowForce.hook, planeRowForce.forceMode, planeRowForce.how = true, hook, m, how
	planeRowForce.calls = map[bpfobj.PlaneMode]int{}
	calls = func(m bpfobj.PlaneMode) int {
		planeRowForce.mu.Lock()
		defer planeRowForce.mu.Unlock()
		return planeRowForce.calls[m]
	}
	restore = func() {
		planeRowForce.mu.Lock()
		defer planeRowForce.mu.Unlock()
		planeRowForce.set, planeRowForce.calls = false, nil
	}
	return calls, restore
}

// planeTestOutcome is the outcome of hook's outside leg in mode m, "refused" where a test forced it.
func planeTestOutcome(m bpfobj.PlaneMode, hook, outcome string) string {
	planeRowForce.mu.Lock()
	defer planeRowForce.mu.Unlock()
	if !planeRowForce.set || hook != planeRowForce.hook {
		return outcome
	}
	planeRowForce.calls[m]++
	if outcome != planePassed || m != planeRowForce.forceMode {
		return outcome
	}
	if planeRowForce.how == PlaneRowForceAlways || (planeRowForce.how == PlaneRowForceFirst && planeRowForce.calls[m] == 1) {
		return planeRefused
	}
	return outcome
}
