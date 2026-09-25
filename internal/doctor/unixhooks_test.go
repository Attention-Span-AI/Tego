// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// unixHooks are the two tier-2 hooks the backend leaves out below 6.7 (enforce-cgroup-observe.md §5 R7).
var unixHooks = []string{"cgroup/connect_unix", "cgroup/sendmsg_unix"}

// TestUnixHooksAreOptionalBelowTheirKernel pins the derivation to what the tier-2 backend does below 6.7: it
// leaves connect_unix and sendmsg_unix out of the load and runs, with unix sockets decided by the inherited
// tier-1 path (§5 R7, §6 E1). Doctor counted connect_unix among tier cgroup's required hooks, so on the 6.1
// floor (FEATURES E39) and RHEL 9's 5.14 it offered no tier cgroup, and `tego run`, which selects from the
// same derivation, refused one ("missing for cgroup: cgroup/connect_unix: needs kernel >= 6.7.0"). A kernel
// that has the attach points still needs both to load and attach, because the backend loads them there.
func TestUnixHooksAreOptionalBelowTheirKernel(t *testing.T) {
	old := Version{6, 1, 0}
	withUnixSupport(t, false)
	st := state(func(st *probeState) {
		st.kernel, st.release = old, "6.1.186"
		for i := range st.hooks {
			for _, name := range unixHooks {
				if st.hooks[i].Hook == name {
					st.hooks[i] = testHook(hookNamed(t, name), nil, nil, nil, old)
				}
			}
		}
	})
	for _, name := range unixHooks {
		var row HookResult
		for _, h := range st.hooks {
			if h.Hook == name {
				row = h
			}
		}
		if !row.Absent || row.BTF || row.Loaded || row.Attached {
			t.Fatalf("%s on %s: %+v, want an absent row that was not probed", name, old, row)
		}
		if !strings.Contains(row.Detail, "needs kernel >= 6.7.0") || !strings.Contains(row.Detail, "runs without it") {
			t.Errorf("%s detail %q does not say both what it needs and that the tier runs without it", name, row.Detail)
		}
	}
	if p := st.probe(); !p[backend.TierCgroup] {
		t.Fatalf("below 6.7 the derivation withholds tier cgroup: %v", st.missingFor(backend.TierCgroup))
	}
	for _, reason := range st.missingFor(backend.TierBPFLSM) {
		if strings.Contains(reason, "_unix") {
			t.Errorf("an absent unix hook is listed against a tier: %q", reason)
		}
	}
	d7 := programsVerdict(st.hooks)
	if !d7.OK {
		t.Errorf("D7 failed on two hooks the tier runs without: %s", d7.Detail)
	}
	if !strings.Contains(d7.Detail, "predates cgroup/connect_unix cgroup/sendmsg_unix") {
		t.Errorf("D7's line %q does not name the hooks this kernel predates", d7.Detail)
	}
	// The seccomp wording is the fanotify fallback's; a selected plane decides unix names itself (matrix_test.go).
	st.plane.Selected = PlaneFanotify
	matrix, notes := st.machineMatrix(backend.TierCgroup)
	if !matrix[backend.CapUnixSockets] || !strings.Contains(notes[backend.CapUnixSockets], "fall back to the seccomp supervisor") {
		t.Errorf("net.unix = %v, note %q: the row stays and the note says what decides unix sockets here",
			matrix[backend.CapUnixSockets], notes[backend.CapUnixSockets])
	}

	// On a kernel with the attach points, a unix hook that does not load is a real gap: Prepare loads it.
	broken := state(func(st *probeState) {
		for i := range st.hooks {
			if st.hooks[i].Hook == "cgroup/sendmsg_unix" {
				st.hooks[i].Loaded, st.hooks[i].Attached = false, false
				st.hooks[i].Detail = "load: permission denied"
			}
		}
	})
	if broken.probe()[backend.TierCgroup] {
		t.Fatal("a sendmsg_unix the verifier refuses on 6.17 was not listed against tier cgroup")
	}
	if !strings.Contains(strings.Join(broken.missingFor(backend.TierCgroup), "; "), "cgroup/sendmsg_unix: load") {
		t.Errorf("missingFor(cgroup) = %v, want the refused unix hook", broken.missingFor(backend.TierCgroup))
	}
}
