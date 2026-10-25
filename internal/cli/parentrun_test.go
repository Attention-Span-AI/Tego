// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestParentRunIsTheEnclosingRun is ADR 0073 D3: the run a `tego run` records as run_start.parent_run is the run it
// was started in. Inside a governed agent that is the enclosing run's TEGO_RUN_ID, since the agent's TEGO_PARENT_RUN
// names that run's own parent (the identity set, RUN-IDENTITY.md); with no TEGO_RUN_ID it is the TEGO_PARENT_RUN an
// orchestrator handed the launcher; with neither, none. The nested rows build the agent's environment with the
// launcher's own identity.Env.Apply, so they are what a tego run started by the agent reads.
func TestParentRunIsTheEnclosingRun(t *testing.T) {
	const outer, grand, handed identity.RunID = "r-00000000-000000000000a-outer0", "r-00000000-000000000000a-grand0",
		"r-00000000-000000000000a-hand00"
	base := []string{"PATH=/bin", "HOME=/home/u"}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"no run around it", base, ""},
		{"an orchestrator's TEGO_PARENT_RUN", append(append([]string{}, base...), identity.EnvParentRun+"="+string(handed)),
			string(handed)},
		{"nested in a run with no parent", identity.Env{RunID: outer, Agent: "a"}.Apply(base), string(outer)},
		{"nested in a run that has a parent", identity.Env{RunID: outer, Agent: "a", ParentRun: grand}.Apply(base),
			string(outer)},
		{"an empty TEGO_RUN_ID", append(append([]string{}, base...), identity.EnvRunID+"=",
			identity.EnvParentRun+"="+string(handed)), string(handed)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				v := ""
				for _, kv := range tc.env {
					if key, val, ok := strings.Cut(kv, "="); ok && key == k {
						v = val
					}
				}
				return v
			}
			if got := parentRunFrom(getenv); got != tc.want {
				t.Fatalf("parent run %q, want %q (environment %q)", got, tc.want, tc.env)
			}
		})
	}
}
