// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestEqualCompiledCommandIndexes(t *testing.T) {
	makeTable := func(entry string, unconstrained bool) *agent.RuleTable {
		p, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		grants := map[string]bool{}
		if unconstrained {
			grants["git"] = true
		}
		return &agent.RuleTable{ExecCommands: &agent.ExecCommands{Entries: []agent.ExecCommandEntry{{Pattern: p}}, Index: execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Unconstrained: grants})}}
	}
	for _, tc := range []struct {
		name  string
		other *agent.RuleTable
		want  Direction
	}{
		{"equal allocations", makeTable("git status", false), Unchanged},
		{"changed pattern", makeTable("git push", false), CannotClassify},
		{"changed private index", makeTable("git status", true), CannotClassify},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := rowResult(t, "program arguments", makeTable("git status", false), tc.other)
			if row.Direction != tc.want {
				t.Fatalf("%+v, want %s", row, tc.want)
			}
		})
	}
}
