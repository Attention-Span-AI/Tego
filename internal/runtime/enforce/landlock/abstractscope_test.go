// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestAbstractScopeRowFollowsTheABI is R7 on the capability line: the abstract-socket scope is created with
// every ruleset from ABI 6 on, so the backend and every handle it prepares report
// net.unix_abstract_scope exactly there, and a run below ABI 6, where nothing refuses an abstract name bound
// outside the run, records it absent (agent-contract R19). The static column claims it on no ABI.
func TestAbstractScopeRowFollowsTheABI(t *testing.T) {
	for abi := 1; abi <= 11; abi++ {
		want := abi >= 6
		b := New(Options{ABI: abi, syscalls: &fakeSyscalls{abi: abi}})
		if got := b.Capabilities().Has(backend.CapUnixAbstractScope); got != want {
			t.Errorf("ABI %d: backend reports the abstract scope %v, want %v", abi, got, want)
		}
		h, fake := prepare(t, abi, &agent.RuleTable{Record: agent.RecordSummary})
		if got := h.Capabilities().Has(backend.CapUnixAbstractScope); got != want {
			t.Errorf("ABI %d: the prepared handle reports the abstract scope %v, want %v", abi, got, want)
		}
		if len(fake.created) != 1 {
			t.Fatalf("ABI %d: %d rulesets created", abi, len(fake.created))
		}
		if scoped := fake.created[0].Scoped&uint64(scopeAbstractUnixSocket) != 0; scoped != want {
			t.Errorf("ABI %d: the ruleset handles the abstract scope %v while the row says %v", abi, scoped, want)
		}
	}
	if backend.Matrix(backend.TierLandlock).Has(backend.CapUnixAbstractScope) {
		t.Error("the static column claims an ABI-gated row")
	}
}
