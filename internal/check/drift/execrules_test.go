// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// execRulesTable is a contract with allow: [git, git status, git log] and deny: [git push, rm -r], compiled.
func execRulesTable(t *testing.T) *agent.RuleTable {
	t.Helper()
	rt := modelTable()
	rt.Contract.Exec = &agent.ExecSection{Allow: []string{"git status", "git log"}, Deny: []string{"git push", "rm -r"}}
	rt.Exec = []agent.ExecRule{{Raw: "git", Path: "/usr/bin/git", Basename: "git", Source: agent.ExecSourceAllow}}
	ec := &agent.ExecCommands{}
	var ps []*execmatch.Pattern
	for _, e := range []struct {
		list  execmatch.List
		entry string
	}{{execmatch.ListAllow, "git status"}, {execmatch.ListAllow, "git log"}, {execmatch.ListDeny, "git push"}, {execmatch.ListDeny, "rm -r"}} {
		p, err := execmatch.Parse(e.entry, e.list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
		ec.Entries = append(ec.Entries, agent.ExecCommandEntry{Pattern: p})
	}
	ec.Index = execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
	rt.ExecCommands = ec
	return rt
}

// cmdExecLine is an exec line whose decision a command rule made.
func cmdExecLine(verdict, rule, cmdRule, cmdList string, argv ...string) map[string]any {
	return map[string]any{"kind": "exec", "source": "seccomp", "rule": rule, "verdict": verdict, "authority": "rule",
		"attribution": map[string]string{"confidence": "unattributed", "method": "time"}, "path": "/usr/bin/" + argv[0],
		"argv": argv, "exec_id": "r/455/1", "command_rule": cmdRule, "command_list": cmdList, "argv_facts": "copied_syscall"}
}

// TestDriftExecCommandRules is ADR 0048 (8)'s drift half: a deny or ask entry is a guard, and one no line named is
// "guard not exercised", reported and never drift (a run where the agent behaved leaves every deny entry unfired);
// constrained allow entries are counted one by one through command_rule, so an unused one is undone.
func TestDriftExecCommandRules(t *testing.T) {
	rt := execRulesTable(t)
	rep, err := Compute(readerOver(t, modelLedger(runStartLine(),
		cmdExecLine("allow", "exec[git]", "git status", "allow", "git", "status"),
		runEndLine())), rt)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"exec.deny[git push]", "exec.deny[rm -r]"}; !slices.Equal(rep.GuardsNotExercised, want) {
		t.Errorf("guards not exercised %v, want %v", rep.GuardsNotExercised, want)
	}
	if !slices.Contains(rep.Undone, "exec.allow[git log]") || slices.Contains(rep.Undone, "exec.allow[git status]") {
		t.Errorf("undone %v: want git log unused and git status used", rep.Undone)
	}
	for _, u := range rep.Undone {
		if strings.HasPrefix(u, "exec.deny[") {
			t.Errorf("a deny entry is undone: %v", rep.Undone)
		}
	}
	rep, err = Compute(readerOver(t, modelLedger(runStartLine(),
		cmdExecLine("allow", "exec[git]", "git status", "allow", "git", "status"),
		cmdExecLine("allow", "exec[git]", "git log", "allow", "git", "log"),
		cmdExecLine("refused", "exec.deny[git push]", "git push", "deny", "git", "push"),
		runEndLine())), rt)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(rep.GuardsNotExercised, "exec.deny[git push]") || !rep.Drifted() {
		t.Errorf("a refused push is an exercised guard and drift: guards %v, drifted %v", rep.GuardsNotExercised, rep.Drifted())
	}
	if len(rep.Undone) != 0 {
		t.Errorf("every allow entry used: undone %v", rep.Undone)
	}
	agg, err := Aggregate([]*Report{rep, rep})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"exec.deny[rm -r]"}; !slices.Equal(agg.GuardsNotExercised, want) {
		t.Errorf("aggregate guards %v, want %v", agg.GuardsNotExercised, want)
	}
}
