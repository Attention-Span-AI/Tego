// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestAliasRemedyRequiresHoldableContract(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{}, FS: []agent.FSRule{{Kind: agent.FSDenyRead, Path: a, Resolved: a}}}
	snapshot := cgroupenforce.ReadMounts()
	failure := cgroupenforce.ErrListenerAlias
	if err := listenerAliasRemedy(failure, rt, snapshot); !errors.Is(err, failure) || !strings.Contains(err.Error(), "tier bpflsm") {
		t.Fatalf("holdable contract remedy: %v", err)
	}
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: b, Resolved: b, Access: agent.AccessWriteSet})
	if err := listenerAliasRemedy(failure, rt, snapshot); strings.Contains(err.Error(), "tier bpflsm") {
		t.Fatalf("unholdable hard-link rows recommended another tier: %v", err)
	}
	rt.FS = rt.FS[:1]
	saved := planeFDCap
	t.Cleanup(func() { planeFDCap = saved })
	planeFDCap = func() int { return 0 }
	if err := listenerAliasRemedy(failure, rt, snapshot); strings.Contains(err.Error(), "tier bpflsm") {
		t.Fatalf("unholdable descriptor budget recommended another tier: %v", err)
	}
}

// planeRows is the table's plane rows as a root-tier run is filled from them: CompilePlane's, with a row for each
// mounted root below a deny_write target (enforce-plane R12), or why the plane cannot hold the table
// (decide.ErrPlaneCap, decide.ErrPlaneExecVerdict, cgroupenforce.ErrMountTable for a table with a deny_write target
// and a mount table that cannot be read).
func planeRows(rt *agent.RuleTable) (*decide.PlaneRows, error) { return planeRowsAt(rt, planeMounts) }
