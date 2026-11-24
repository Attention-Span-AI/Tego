// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The descriptor fill and recorder use the kernel's PID identities. A different
// or unreadable namespace cannot be repaired by loading another plane mode.
func TestPIDNamespaceBlocksRootTiersBeforeAnyProgram(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inode   uint64
		err     error
		initial bool
	}{
		{"initial", 4026531836, nil, true},
		{"private", 4026532211, nil, false},
		{"unreadable", 0, os.ErrPermission, false},
		{"zero is not a proof", 0, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reach := range []backend.Tier{"", backend.TierCgroup, backend.TierBPFLSM} {
				var n calls
				checks := passingChecks(&n)
				reads := 0
				checks.pidNamespace = func() (uint64, error) { reads++; return tc.inode, tc.err }
				st := scope{root: true, reach: reach, checks: checks}.run(context.Background())
				allBuilt(&st)
				rep := st.report(nil, "")
				if rep.RootStateVisible() != tc.initial {
					t.Errorf("reach %s: root state visible %t, initial namespace %t", reach, rep.RootStateVisible(), tc.initial)
				}
				if reads != 1 {
					t.Errorf("reach %s: namespace reads %d, want 1", reach, reads)
				}
				if !rep.Tiers[backend.TierLandlock] {
					t.Errorf("reach %s: PID namespace changed tier landlock: %+v", reach, rep)
				}
				if tc.initial {
					if !rep.Tiers[backend.TierCgroup] || n.plane != 1 {
						t.Errorf("initial namespace changed: tiers=%v plane=%d", rep.Tiers, n.plane)
					}
					continue
				}
				for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
					if tier == backend.TierBPFLSM && reach == backend.TierCgroup {
						continue
					}
					why := rep.WhyNot(tier)
					if rep.Tiers[tier] || !strings.Contains(why, "process-id namespace") || strings.Contains(why, "tego bug") {
						t.Errorf("reach %s: tier %s offered=%t reason=%q", reach, tier, rep.Tiers[tier], why)
					}
					if b, _ := rep.Select(nil, nil, tier); b != nil {
						t.Errorf("pinned unavailable tier %s was selected", tier)
					}
				}
				if n.plane != 0 || n.n[CheckPrograms] != 0 {
					t.Errorf("private/unknown namespace loaded probes: programs=%d plane=%d", n.n[CheckPrograms], n.plane)
				}
				if rep.Tier != backend.TierLandlock {
					t.Errorf("auto got %s, want existing unavailable-tier fallback landlock", rep.Tier)
				}
			}
		})
	}
}

// A cached or pinned answer was measured by a process with usable PID
// identities. A private namespace must not consult either source of authority.
func TestPIDNamespacePrecedesCachedAndPinnedAnswers(t *testing.T) {
	var n calls
	checks := passingChecks(&n)
	checks.pidNamespace = func() (uint64, error) { return 4026532211, nil }
	keys, adopts := 0, 0
	cache := &runCache{key: func(string, int) (runCacheKey, bool) { keys++; return runCacheKey{}, false }}
	st := scope{root: true, reach: backend.TierCgroup, checks: checks, cache: cache,
		adopt: func(pin string) (*PlaneState, bool) { adopts++; return passingPlane(pin), true },
	}.run(context.Background())
	if keys != 0 || adopts != 0 || st.cached != nil || n.n[CheckPrograms] != 0 {
		t.Fatalf("namespace precondition bypassed: keys=%d adopts=%d cached=%v programs=%d", keys, adopts, st.cached, n.n[CheckPrograms])
	}
}

func TestAutoTiersExcludePrivatePIDNamespace(t *testing.T) {
	set := autoTiers(true, "private process-id namespace", func() bool {
		t.Error("private PID namespace consulted the LSM list")
		return true
	}, func(backend.Tier) error { return nil })
	if len(set.Tiers) != 1 || set.Tiers[0] != backend.TierLandlock || len(set.NeedPIDNamespace) != 2 {
		t.Fatalf("auto compilation admits unavailable root tiers: %+v", set)
	}
}

func TestPIDNamespaceMissingProbeIsUnknown(t *testing.T) {
	var n calls
	checks := passingChecks(&n)
	checks.pidNamespace = nil
	st := scope{root: true, checks: checks}.run(context.Background())
	allBuilt(&st)
	if st.probe()[backend.TierCgroup] || st.probe()[backend.TierBPFLSM] || n.plane != 0 || n.n[CheckPrograms] != 0 {
		t.Fatalf("missing namespace probe was treated as initial: tiers=%v programs=%d plane=%d", st.probe(), n.n[CheckPrograms], n.plane)
	}
}

func TestDecodedReportDoesNotAuthorizeRootState(t *testing.T) {
	rep := &Report{Root: true, rootStateVisible: true}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RootStateVisible() {
		t.Fatal("JSON conferred live namespace authority")
	}
}
