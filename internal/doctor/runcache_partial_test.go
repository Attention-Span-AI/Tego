// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"os"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestRunCacheFaultedPlaneReprobesThePlaneAlone: a run whose plane probe faulted keeps D7's tier-2 rows and D8's
// answer, so the next run re-probes the plane and nothing else; once the plane answers without a fault the entry is
// complete and the run after that probes nothing. DiscardCache still removes the entry the run was built from.
func TestRunCacheFaultedPlaneReprobesThePlaneAlone(t *testing.T) {
	var n calls
	c := passingChecks(&n)
	fault := true
	c.plane = func(_ bool, _ int, _, pin string, _ bool) (*PlaneState, []HookResult) {
		n.plane++
		st := passingPlane(pin)
		if fault {
			st.Modes[0] = PlaneModeResult{Mode: bpfobj.PlaneLSM, Tested: true, Faulted: true, Detail: "fixtures: no space"}
		}
		return st, passingPlaneRows()
	}
	cache, path := testCache(t)
	run := func() probeState {
		return scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	}
	reset := func() { n.n, n.plane = map[CheckID]int{}, 0 }

	run()
	reset()
	second := run()
	if n.n[CheckPrograms] != 0 || n.n[CheckFanotify] != 0 || n.plane != 1 || second.cached == nil {
		t.Errorf("after a faulted plane the next run probed %v and the plane %d times (cached %v); want the plane alone",
			n.n, n.plane, second.cached)
	}

	fault = false
	reset()
	third := run()
	if n.n[CheckPrograms] != 0 || n.n[CheckFanotify] != 0 || n.plane != 1 {
		t.Errorf("the run whose plane answered probed %v and the plane %d times", n.n, n.plane)
	}
	allBuilt(&third)
	if !third.probe()[backend.TierCgroup] {
		t.Errorf("a partial hit does not offer tier cgroup: %v", third.missingFor(backend.TierCgroup))
	}
	if e, ok := cache.load(testKey()); !ok || e.Plane == nil {
		t.Fatalf("the plane's answer did not complete the entry (read %v)", ok)
	}
	third.report(nil, "").DiscardCache()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("DiscardCache left the entry the run completed (%v)", err)
	}

	run()
	reset()
	run()
	if n.n[CheckPrograms] != 0 || n.n[CheckFanotify] != 0 || n.plane != 0 {
		t.Errorf("a complete entry still probed %v and the plane %d times", n.n, n.plane)
	}
}
