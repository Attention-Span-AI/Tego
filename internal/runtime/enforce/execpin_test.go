// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestExecFactsDecided is ADR 0048 (3) P2's "When": a run asks for its execs to be pinned when its table has command
// rules, or an exec gate that can escalate; a table with neither, an exec gate that only scores other kinds, and
// no table ask for none, so their execs keep their copied facts and pay nothing.
func TestExecFactsDecided(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"no exec rules", "", false},
		{"deny list", "exec:\n  deny: [git push]\n", true},
		{"constrained allow", "exec:\n  allow: [git status]\n", true},
		{"bare allow", "exec:\n  allow: [git]\n", false},
		{"exec gate", "gate:\n  rules:\n    - 'exec matches \"rm -rf\"': 95\n", true},
		{"write gate", "fs:\n  write: [./work]\ngate:\n  rules:\n    - 'fs.write outside worktree': 90\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			f := contracttest.BuildAt(t, root, "version: 0\nname: pin\ncommand: [fixture]\ncapture: off\n"+c.body,
				contracttest.Tree{"work/": "", "bin/git": "#!/bin/sh\nexit 0\n"}, agent.WithCwd(filepath.Join(root, "work")))
			if got := f.Rules.ExecFactsDecided(); got != c.want {
				t.Fatalf("ExecFactsDecided %v, want %v (commands %v, gate %v)", got, c.want,
					f.Rules.ExecCommands.HasRules(), f.Rules.Gate != nil)
			}
		})
	}
	if (*agent.RuleTable)(nil).ExecFactsDecided() {
		t.Fatal("no table asked for pins")
	}
}
