// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import "testing"

// TestLoopDispatchTableIsPrivateAndInMemory is supervisor.md E26 as far as it is testable without replacing the
// running binary: a Loop dispatches from a table it built once in New and holds in memory, so nothing on disk (a
// rename-installed upgrade included) can reach it, and a second Loop, which is what a new run is, builds its own
// table and is independent of the first.
func TestLoopDispatchTableIsPrivateAndInMemory(t *testing.T) {
	a, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	b, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	if len(a.dispatch) == 0 || len(a.dispatch) != len(b.dispatch) {
		t.Fatalf("dispatch tables have %d and %d entries, want equal and non-empty", len(a.dispatch), len(b.dispatch))
	}
	key := dispatchKey{arch: nativeAuditArch(), nr: nrFor(t, "mount")}
	if _, ok := a.dispatch[key]; !ok {
		t.Fatal("loop a has no mount handler")
	}
	delete(a.dispatch, key)
	if _, ok := b.dispatch[key]; !ok {
		t.Error("deleting an entry from one Loop's table changed another Loop's: the tables are shared, not private")
	}
	c, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
	if _, ok := c.dispatch[key]; !ok {
		t.Error("a Loop built after another's table was altered did not get a complete table of its own")
	}
}
