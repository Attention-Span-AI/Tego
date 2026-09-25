// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestCommandForFallsBackToTheContract is the point run decides what to exec: the command given on the command line
// when there is one, the contract's own command: otherwise.
func TestCommandForFallsBackToTheContract(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{Command: []string{"python3", "agent.py"}}}
	if got := commandFor(runOptions{}, rt); !slices.Equal(got, []string{"python3", "agent.py"}) {
		t.Errorf("no command given: runs %q, want the contract's", got)
	}
	if got := commandFor(runOptions{command: []string{}}, rt); !slices.Equal(got, []string{"python3", "agent.py"}) {
		t.Errorf("an empty command (a bare --): runs %q, want the contract's", got)
	}
	if got := commandFor(runOptions{command: []string{"/bin/echo", "x"}}, rt); !slices.Equal(got, []string{"/bin/echo", "x"}) {
		t.Errorf("a command given: runs %q, want it", got)
	}
	got := commandFor(runOptions{}, rt)
	got[0] = "changed"
	if rt.Contract.Command[0] != "python3" {
		t.Error("the command run is the contract's own slice, not a copy")
	}
}
