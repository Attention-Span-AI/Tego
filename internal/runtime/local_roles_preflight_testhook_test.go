// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package runtime

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The root-only floor's conditions that need no backend are Preflight's: they are refused with no Enforce in
// Deps at all, so the CLI refuses before its kernel probe (ADR 0154; the cold-probe finding on row 16).
func TestPreflightRefusesTheLocalRolesFloorWithoutABackend(t *testing.T) {
	prev := localLauncher
	t.Cleanup(func() { localLauncher = prev })
	for _, tc := range []struct {
		name string
		euid int
		ns   uint64
		edit func(*agent.RuleTable)
		want string
	}{
		{"qualified", 0, record.InitialUserNamespace, func(*agent.RuleTable) {}, ""},
		{"setuid", 0, record.InitialUserNamespace, func(rt *agent.RuleTable) { rt.Contract.Setuid = true }, "setuid disabled"},
		{"record off", 0, record.InitialUserNamespace, func(rt *agent.RuleTable) { rt.Record = agent.RecordOff }, "local root-only approvals require"},
		{"unprivileged launcher", 1001, record.InitialUserNamespace, func(*agent.RuleTable) {}, "local root-only approvals require"},
		{"private namespace", 0, record.InitialUserNamespace + 1, func(*agent.RuleTable) {}, "local root-only approvals require"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localLauncher = func() (int, uint64, error) { return tc.euid, tc.ns, nil }
			m, rt, _ := startupFixture(t)
			config.SetOwnerOnlyForTest(m)
			tc.edit(rt)
			err := Preflight(rt, []string{"/bin/true"}, Deps{Config: m})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Preflight=%v, want %q", err, tc.want)
			}
			// The runtime repeats it for a caller that never ran Preflight, with the same words.
			if _, later := newRunner(rt, []string{"/bin/true"}, Deps{Config: m, Enforce: tierBackend{tier: backend.TierCgroup}}); later == nil || later.Error() != err.Error() {
				t.Fatalf("runtime backstop=%v; preflight=%v", later, err)
			}
		})
	}
}

// A machine without the floor is not asked anything of the launcher or the contract here.
func TestPreflightLeavesAPersonalMachineAloneByTheLocalRolesFloor(t *testing.T) {
	prev := localLauncher
	t.Cleanup(func() { localLauncher = prev })
	localLauncher = func() (int, uint64, error) { return 1001, record.InitialUserNamespace + 1, nil }
	m, rt, _ := startupFixture(t)
	rt.Contract.Setuid = true
	rt.Record = agent.RecordOff
	if err := Preflight(rt, []string{"/bin/true"}, Deps{Config: m}); err != nil && strings.Contains(err.Error(), "local root-only approvals") {
		t.Fatalf("a personal machine met the floor: %v", err)
	}
}
