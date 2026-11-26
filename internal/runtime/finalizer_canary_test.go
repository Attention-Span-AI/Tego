// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"runtime"
	"testing"
	"unsafe"
)

// liveNeighbours keeps what TestFinalizerCanaryHasASlotOfItsOwn allocates reachable.
var liveNeighbours []*int

// TestFinalizerCanaryHasASlotOfItsOwn holds collectFinalizers to its one assumption: that the finalizer of its canary
// runs once the canary is unreachable, whatever else the process keeps alive. An object of under 16 bytes without
// pointers shares a 16-byte block with the objects allocated next to it, and the runtime runs its finalizer only when
// every object of the block is unreachable (runtime.SetFinalizer). The canary is allocated while a neighbour of that
// size is alive, and must never land beside one.
func TestFinalizerCanaryHasASlotOfItsOwn(t *testing.T) {
	const tries = 400
	liveNeighbours = liveNeighbours[:0]
	defer func() { liveNeighbours = nil }()
	for range tries {
		neighbour := new(int)
		liveNeighbours = append(liveNeighbours, neighbour)
		canary := newFinalizerCanary()
		if uintptr(unsafe.Pointer(canary))/16 == uintptr(unsafe.Pointer(neighbour))/16 {
			t.Fatalf("the canary lies in the 16-byte block of a live neighbour (%p, %p): its finalizer would not run while that neighbour lives", canary, neighbour)
		}
		runtime.KeepAlive(canary)
	}
}
