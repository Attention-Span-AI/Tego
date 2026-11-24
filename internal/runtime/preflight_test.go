// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// These refusals require only a compiled contract and the caller, never a
// capability answer. The runtime still checks them for non-CLI callers.
func TestPreflightNeedsNoBackendAndRetainsCallerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*agent.RuleTable, *Deps)
		want string
	}{
		{"valid", func(*agent.RuleTable, *Deps) {}, ""},
		{"parent", func(_ *agent.RuleTable, d *Deps) { d.ParentRun = "invalid-parent" }, "is not a run id"},
		{"agent identity", func(rt *agent.RuleTable, _ *Deps) { rt.Contract.Name = "bad name" }, "agent"},
		{"kernel setuid", func(rt *agent.RuleTable, _ *Deps) {
			rt.NetAssurance = agent.NetAssuranceKernel
			rt.Contract.Net = &agent.NetSection{}
			rt.Contract.Setuid = true
		}, "setuid: true"},
		{"kernel io_uring", func(rt *agent.RuleTable, _ *Deps) {
			rt.NetAssurance = agent.NetAssuranceKernel
			rt.Contract.Net = &agent.NetSection{}
			rt.Contract.IOUring = true
		}, "io_uring: true"},
		{"ask bounds", func(rt *agent.RuleTable, _ *Deps) {
			rt.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 0}
		}, "invalid ask bounds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rt, _ := startupFixture(t)
			d := Deps{Config: m}
			tc.edit(rt, &d)
			err := Preflight(rt, []string{"/bin/true"}, d)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Preflight=%v, want %q", err, tc.want)
			}
			d.Enforce = tierBackend{tier: backend.TierCgroup}
			_, later := newRunner(rt, []string{"/bin/true"}, d)
			if later == nil || later.Error() != err.Error() {
				t.Fatalf("runtime backstop=%v; preflight=%v", later, err)
			}
		})
	}
}

// The machine still decides an otherwise valid kernel-network request. A
// preflight must not mistake a compiled tier hint for an actual capability proof.
func TestPreflightLeavesTierDecisionsToTheSelectedBackend(t *testing.T) {
	m, rt, _ := startupFixture(t)
	rt.NetAssurance = agent.NetAssuranceKernel
	rt.Contract.Net = &agent.NetSection{}
	d := Deps{Config: m}
	if err := Preflight(rt, []string{"/bin/true"}, d); err != nil {
		t.Fatal(err)
	}
	d.Enforce = tierBackend{tier: backend.TierLandlock}
	if _, err := newRunner(rt, []string{"/bin/true"}, d); err == nil || !strings.Contains(err.Error(), "requires cgroup or bpflsm") {
		t.Fatalf("tier refusal lost: %v", err)
	}
}

// Literal socket path and harness contradictions need no provisioned directory.
// A valid private request still waits for the actual provisioning backstop.
func TestPreflightChecksStaticSocketRequests(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		h           harness.Name
		want        string
	}{
		{"relative", "short", harness.ClaudeCode, "not absolute"},
		{"over budget", "/" + strings.Repeat("a", 81), harness.ClaudeCode, "maximum 103"},
		{"other harness", "%R", harness.Generic, "requires a provisioned claude-code harness"},
		{"private request", "%R", harness.ClaudeCode, ""},
		{"auto follows the provision", "short", harness.Auto, ""},
		{"explicit short", "/private", harness.ClaudeCode, ""},
		{"other harness literal", "short", harness.Generic, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rt, _ := startupFixture(t)
			rt.Contract.Harness = tc.h
			if tc.h == harness.Auto {
				rt.Harness = harness.ClaudeCode
			} // compiler hint before an adapter replaces argv
			rt.Set = map[string]string{"XDG_RUNTIME_DIR": tc.value}
			err := Preflight(rt, []string{"/bin/claude"}, Deps{Config: m})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Preflight=%v, want %q", err, tc.want)
			}
			if tc.h == harness.Auto {
				r := &runner{rt: rt, cmd: []string{"/bin/true"}}
				if err := r.configureClaudeSockets(); err != nil {
					t.Fatalf("final non-Claude argv: %v", err)
				}
			}
			if rt.Set["XDG_RUNTIME_DIR"] != tc.value {
				t.Fatal("mutated compiled environment")
			}
		})
	}
}
