// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/adapters/claudecode"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// TestForNamesEachBuiltProvisioner: claude-code has its provisioner; every other harness has
// none in this build, and auto and none never have one (the launcher resolves auto first and provisions nothing for
// none), so a run of them is the run harness: none would be, apart from run_start's harness record.
func TestForNamesEachBuiltProvisioner(t *testing.T) {
	for _, n := range append(harness.Names(), "") {
		p := For(n)
		if n == harness.ClaudeCode {
			if _, ok := p.(claudecode.Provisioner); !ok {
				t.Errorf("For(%q) = %T, want claudecode.Provisioner", n, p)
			}
		} else if p != nil {
			t.Errorf("For(%q) = %T, want nil", n, p)
		}
	}
}
