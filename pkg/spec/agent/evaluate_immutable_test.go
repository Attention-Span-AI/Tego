// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestEvaluateDoesNotMutateRuleTable pins I4: "A *RuleTable is never mutated
// after Compile returns it... TTL refresh constructs a new *RuleTable
// (RCU-style swap)... Enforced by: no exported mutator method besides
// Evaluate (read-only); code review, since Go has no compiler-enforced
// immutability." That last clause is exactly why this needs a test: nothing
// but review catches a future Evaluate helper that takes a pointer into
// rt.FS/rt.Net/rt.Exec (several already do, for the "nearest" lookups) and
// writes through it instead of only reading.
//
// A production *RuleTable is read concurrently by every `compile --test`
// row and, in the running system, is the very value I9 says Load/Compile
// build exactly once per run — a stray write here would be a data race the
// next caller's read could observe.
// agent-contract.md I4 and E31 (Evaluate is stateless: no pid, no live process, no table mutation).
func TestEvaluateDoesNotMutateRuleTable(t *testing.T) {
	f, rt := evalFixture(t)
	p := func(rel string) string { return filepath.Join(f.project, rel) }

	snapshot := func() ([]FSRule, []NetRule, []ExecRule) {
		return append([]FSRule(nil), rt.FS...), append([]NetRule(nil), rt.Net...), append([]ExecRule(nil), rt.Exec...)
	}
	beforeFS, beforeNet, beforeExec := snapshot()

	// Exercise every action kind, in every tier, including the branches that
	// take a pointer into the table (evalFSLandlock's nearestGrant/nearestFS,
	// evalRename's accessAt union, evalExec's matchExec, evalNet's matchNet).
	actions := []struct {
		a    Action
		tier backend.Tier
	}{
		{Action{Kind: ActionFSRead, Path: p("secrets/key.pem")}, backend.TierLandlock},
		{Action{Kind: ActionFSWrite, Path: p("out/report.md")}, backend.TierLandlock},
		{Action{Kind: ActionFSRead, Path: p("out/keys/id_ed25519")}, backend.TierLandlock},
		{Action{Kind: ActionFSDelete, Path: p("config/app.toml")}, backend.TierCgroup},
		{Action{Kind: ActionFSMkdir, Path: p("out/sub")}, backend.TierLandlock},
		{Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("out/b")}, backend.TierCgroup},
		{Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("secrets/a")}, backend.TierCgroup},
		{Action{Kind: ActionExec, Path: filepath.Join(f.bin, "python")}, backend.TierLandlock},
		{Action{Kind: ActionExec, Path: filepath.Join(f.project, "script.sh"), Script: filepath.Join(f.bin, "python")}, backend.TierLandlock},
		{Action{Kind: ActionNetConnect, Host: "mcp.internal", Port: 8080}, backend.TierCgroup},
		{Action{Kind: ActionNetConnect, Host: "10.1.2.3", Port: 443}, backend.TierCgroup},
	}
	for _, tc := range actions {
		_ = rt.Evaluate(tc.a, tc.tier)
	}

	afterFS, afterNet, afterExec := snapshot()
	if !reflect.DeepEqual(beforeFS, afterFS) {
		t.Errorf("Evaluate mutated RuleTable.FS:\nbefore %+v\nafter  %+v", beforeFS, afterFS)
	}
	if !reflect.DeepEqual(beforeNet, afterNet) {
		t.Errorf("Evaluate mutated RuleTable.Net:\nbefore %+v\nafter  %+v", beforeNet, afterNet)
	}
	if !reflect.DeepEqual(beforeExec, afterExec) {
		t.Errorf("Evaluate mutated RuleTable.Exec:\nbefore %+v\nafter  %+v", beforeExec, afterExec)
	}
}
