// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mapTable is a write entry /w with an exec.allow directory /w/venv inside it and an exec file entry /w/bin/t1.
func mapTable(restricted bool) *agent.RuleTable {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Raw: "/w", Resolved: "/w", Access: agent.AccessWriteSet}},
		Exec: []agent.ExecRule{
			{Path: "/w/venv", Resolved: "/w/venv", Raw: "/w/venv", IsDir: true, Verdict: agent.VerdictAllow},
			{Path: "/w/bin/t1", Resolved: "/w/bin/t1", Raw: "/w/bin/t1", Basename: "t1", Verdict: agent.VerdictAllow},
		}}
	if restricted {
		rt.Contract.Exec = &agent.ExecSection{}
	}
	return rt
}

// TestEvaluateExecMapSplitsByTier is compile --test's exec.map row (ADR 0027, enforce-plane R26): only the decision
// plane decides a PROT_EXEC map, so tier landlock (no mmap hook, SEMANTICS §4) and tier cgroup as the fanotify listener allow
// what bpflsm refuses: a file under a write entry no exec entry covers, rule exec-map. A covered file, a file under
// no write entry and a contract with no exec: section map at every tier; the plane's column answers the same.
func TestEvaluateExecMapSplitsByTier(t *testing.T) {
	refused := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: ExecMapRule, Reason: record.ReasonExecNotAllowed}
	unmatched := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	rt := mapTable(true)
	for _, c := range []struct {
		path string
		want agent.EvalResult
	}{
		{"/w/drop.so", refused},
		{"/w/bin/t2", refused},
		{"/w/venv/lib/x.so", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.Exec[0].RuleName()}},
		{"/w/bin/t1", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.Exec[1].RuleName()}},
		{"/usr/lib/libc.so.6", unmatched},
	} {
		a := agent.Action{Kind: agent.ActionMapExec, Path: c.path}
		if got := Evaluate(rt, a, backend.TierBPFLSM); got != c.want {
			t.Errorf("bpflsm %s: %+v, want %+v", c.path, got, c.want)
		}
		if got := NewPlaneEvaluator(rt).Evaluate(a, Env{}); got != c.want {
			t.Errorf("plane column %s: %+v, want %+v", c.path, got, c.want)
		}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
			if got := Evaluate(rt, a, tier); got != unmatched {
				t.Errorf("%s %s: %+v; no mmap hook decides it there", tier, c.path, got)
			}
		}
	}
	open := mapTable(false)
	a := agent.Action{Kind: agent.ActionMapExec, Path: "/w/drop.so"}
	if got := Evaluate(open, a, backend.TierBPFLSM); got != unmatched {
		t.Errorf("no exec: section: %+v", got)
	}
	if got := NewPlaneEvaluator(open).Evaluate(a, Env{}); got != unmatched {
		t.Errorf("no exec: section, plane column: %+v", got)
	}
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionMapExec}, backend.TierBPFLSM); got.Rule != agent.InvalidActionRule {
		t.Errorf("a map with no path: %+v", got)
	}
}

// TestPlaneEvaluatorMapMatchesEvaluate is the parity property for exec.map: on every generated fs table, restricted,
// and on the exec tables of one or two entries, the plane column equals the root model at bpflsm.
func TestPlaneEvaluatorMapMatchesEvaluate(t *testing.T) {
	bad := 0
	check := func(desc string, rt *agent.RuleTable, probes []string) {
		pe := NewPlaneEvaluator(rt)
		if pe.Err() != nil {
			return
		}
		for _, p := range probes {
			a := agent.Action{Kind: agent.ActionMapExec, Path: p}
			if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want {
				if bad++; bad < 20 {
					t.Errorf("%s map %s: plane %+v, Evaluate %+v", desc, p, got, want)
				}
			}
		}
	}
	tables := genPlaneTables(func(desc string, rt *agent.RuleTable) {
		rt.Contract = &agent.Contract{Exec: &agent.ExecSection{}}
		check(desc, rt, planeProbes)
	})
	if tables < 1000 {
		t.Fatalf("only %d tables", tables)
	}
	fs := []agent.FSRule{{Kind: agent.FSWrite, Path: "/opt/x", Raw: "/opt/x", Resolved: "/opt/x", Access: agent.AccessWriteSet}}
	for i := range genExecPool {
		for j := i; j < len(genExecPool); j++ {
			ex := []agent.ExecRule{genExecPool[i]}
			if j != i {
				ex = append(ex, genExecPool[j])
			}
			rt := &agent.RuleTable{FS: fs, Exec: ex, Tier: backend.TierBPFLSM, Contract: &agent.Contract{Exec: &agent.ExecSection{}}}
			check("exec", rt, append([]string{"/opt/x/b", "/opt/x/c", "/opt/x/a"}, execProbes...))
		}
	}
}
