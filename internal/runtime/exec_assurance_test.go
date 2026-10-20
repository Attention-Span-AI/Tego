// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// execClaimHandle is a networkHandle that answers ExecPinClaim (enforce.ExecPinClaimer) with claim and why.
type execClaimHandle struct {
	networkHandle
	claim bool
	why   string
}

func (h *execClaimHandle) ExecPinClaim() (bool, string) { return h.claim, h.why }

// TestExecAssuranceNeedsTheHandlesClaim is ADR 0048 (3) P2's exec.assurance: kernel at run start: a run whose handle
// does not claim exec pins (a tier with no ExecPinClaim, or one that says why not) is refused with the reason; a
// claiming handle starts; exec.assurance: best-effort never refuses.
func TestExecAssuranceNeedsTheHandlesClaim(t *testing.T) {
	kernel := &agent.RuleTable{ExecAssurance: agent.ExecAssuranceKernel}
	r := &runner{rt: kernel, handle: &fakeHandle{}, deps: Deps{Enforce: tierBackend{tier: backend.TierLandlock}}}
	if err := r.requireExecAssurance(); !errors.Is(err, ErrExecAssurance) {
		t.Fatalf("a tier that cannot pin execs: %v", err)
	}
	r.handle = &execClaimHandle{why: "doctor's exec pin cell has not passed"}
	if err := r.requireExecAssurance(); !errors.Is(err, ErrExecAssurance) || !strings.Contains(err.Error(), "exec pin cell") {
		t.Fatalf("a handle that does not claim: %v", err)
	}
	r.handle = &execClaimHandle{claim: true}
	if err := r.requireExecAssurance(); err != nil {
		t.Fatalf("a claiming handle: %v", err)
	}
	r = &runner{rt: &agent.RuleTable{}, handle: &fakeHandle{}, deps: r.deps}
	if err := r.requireExecAssurance(); err != nil {
		t.Fatalf("best effort: %v", err)
	}
	// The contract's kernel stands where the compiled value was lost (ExecutionAssurance).
	r = &runner{rt: &agent.RuleTable{Contract: &agent.Contract{Exec: &agent.ExecSection{Assurance: agent.ExecAssuranceKernel}}},
		handle: &fakeHandle{}, deps: r.deps}
	if err := r.requireExecAssurance(); !errors.Is(err, ErrExecAssurance) {
		t.Fatalf("the contract's kernel with the compiled value lost: %v", err)
	}
}

// TestExecAssuranceUnwindsBeforeChild: an exec.assurance: kernel run on a handle that does not claim pins exits 125
// before its child starts, and everything Prepare made is undone.
func TestExecAssuranceUnwindsBeforeChild(t *testing.T) {
	m, rt, root := startupFixture(t)
	rt.ExecAssurance = agent.ExecAssuranceKernel
	h := &networkHandle{}
	cg := &fakeCgroups{root: t.TempDir()}
	res, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: cg,
		Enforce: networkBackend{h: h}, Cwd: root,
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")}})
	if !errors.Is(err, ErrExecAssurance) || res.ExitCode != 125 {
		t.Fatalf("result %+v err %v", res, err)
	}
	if cg.created != 1 || cg.removed != 1 || h.closed != 1 {
		t.Fatalf("cleanup cg=%+v handle=%+v", cg, h)
	}
}
