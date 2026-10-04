// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// protectedWriteTable is a table whose write entry holds one built-in deny_write target, under root.
func protectedWriteTable(t *testing.T) *agent.RuleTable {
	t.Helper()
	root := tempDir(t)
	mkTree(t, root, "work/.git/config", "work/safe")
	return &agent.RuleTable{Contract: contractWith(true, true),
		FS:        []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "work"))},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: filepath.Join(root, "work/.git/config")}}}
}

// prepareAndClose prepares rt with run and closes the handle, failing the test on any error.
func prepareAndClose(t *testing.T, name string, rt *agent.RuleTable, run Run) {
	t.Helper()
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, run)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt is R5a under fs.assurance: kernel (ADR 0041 D1 (a)): with
// no plane rows, a table with built-in deny_write targets is refused before any rule is built, naming the target,
// the key and the fix. Plane rows prepare it; a table with no target is unaffected.
func TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt(t *testing.T) {
	rt := protectedWriteTable(t)
	rt.FSAssurance = agent.FSAssuranceKernel
	if h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{}); h != nil ||
		!errors.Is(err, ErrNegativeWriteNeedsPlane) || !strings.Contains(err.Error(), "fs.write") ||
		!strings.Contains(err.Error(), "fs.assurance") || !strings.Contains(err.Error(), "fs.deny_write[") {
		t.Fatalf("fs.assurance: kernel without a plane = %v, %v", h, err)
	}
	// The inherited Landlock plan remains usable when its caller supplies the rows of the kernel plane that will
	// enforce the exception before the child starts.
	prepareAndClose(t, "fs.assurance: kernel with plane rows", rt, Run{Plane: &decide.PlaneRows{}})
	rt.DenyWrite = nil
	prepareAndClose(t, "no target", rt, Run{})
}

// TestProtectedWritesBestEffortByDefault is R5a's default (fs.assurance best-effort, ADR 0041 D1 (a)): with no
// plane rows the same table is prepared, the supervisor refusing its targets best effort (supervisor R15c). From
// 82a723b3 to ADR 0041 D1 this Prepare failed with ErrNegativeWriteNeedsPlane.
func TestProtectedWritesBestEffortByDefault(t *testing.T) {
	prepareAndClose(t, "best effort without a plane", protectedWriteTable(t), Run{})
}
