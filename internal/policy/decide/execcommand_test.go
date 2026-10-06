// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// commandTable is a hand-built deny-list table with the given entries ("deny: git push").
func commandTable(t *testing.T, entries ...string) *agent.RuleTable {
	t.Helper()
	sec := &agent.ExecSection{}
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, _ := strings.Cut(e, ": ")
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		switch l {
		case execmatch.ListAllow:
			sec.Allow = append(sec.Allow, body)
		case execmatch.ListDeny:
			sec.Deny = append(sec.Deny, body)
		case execmatch.ListAsk:
			sec.Ask = append(sec.Ask, body)
		}
		p, err := execmatch.Parse(body, l, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	if sec.Allow == nil && sec.Deny == nil {
		sec.Deny = []string{}
	}
	ec := &agent.ExecCommands{Index: execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})}
	for _, p := range ps {
		ec.Entries = append(ec.Entries, agent.ExecCommandEntry{Pattern: p})
	}
	return &agent.RuleTable{Contract: &agent.Contract{Exec: sec}, ExecCommands: ec, Tier: backend.TierLandlock,
		Reach: []backend.Tier{backend.TierLandlock}, Record: agent.RecordSummary}
}

// TestEvaluateExecCommand: compile --test's exec rows run through the image floor, then the command rules, then the
// gate (ADR 0048 (4)); a refusal names the entry, its list and how it matched, and an ask is completion_unsupported.
func TestEvaluateExecCommand(t *testing.T) {
	rt := commandTable(t, "deny: git push", "ask: npm install")
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Argv: []string{"git", "-C", ".", "push"}}, tier)
		if got.Verdict != agent.VerdictRefused || got.Rule != "exec.deny[git push]" || got.Reason != record.ReasonExecNotAllowed ||
			got.CommandRule != "git push" || got.CommandList != "deny" || got.CommandMatch != "definite" || got.ArgvFacts != "test_row" {
			t.Errorf("%s: git -C . push: %+v", tier, got)
		}
		got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Argv: []string{"npm", "i", "x"}}, tier)
		if got.Verdict != agent.VerdictRefused || got.Rule != "exec.ask[npm install]" || !got.CompletionUnsupported {
			t.Errorf("%s: npm i: %+v", tier, got)
		}
		got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Argv: []string{"git", "status"}}, tier)
		if got.Verdict != agent.VerdictAllow || got.CommandRule != "" {
			t.Errorf("%s: git status: %+v", tier, got)
		}
	}
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Argv: []string{"git", "push"}}, backend.TierObserve); got.Verdict != agent.VerdictAllow {
		t.Errorf("observe enforces nothing: %+v", got)
	}
	// A #! script through an interpreter row: python3 -m pip under deny pip install.
	rt = commandTable(t, "deny: pip install")
	got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/usr/local/bin/pipx-shim", Script: "/usr/bin/python3", ScriptArg: "",
		Argv: []string{"pipx-shim", "install", "x"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictAllow {
		t.Errorf("an unrelated script: %+v", got)
	}
	got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Argv: []string{"python3", "-m", "pip", "install", "x"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictRefused || got.CommandVia != "interpreter" {
		t.Errorf("python3 -m pip install: %+v", got)
	}
}

// TestEvaluateExecCommandFloorFirst: an image the floor refuses is never asked about, and an allow-list table's
// constrained tool refuses an unlisted invocation under exec.args[<tool>].
func TestEvaluateExecCommandFloorFirst(t *testing.T) {
	rt := commandTable(t, "allow: git status")
	rt.Exec = []agent.ExecRule{{Raw: "git", Path: "/usr/bin/git", Basename: "git", ByName: true, Verdict: agent.VerdictAllow, Source: agent.ExecSourceAllow}}
	got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/usr/bin/git", Argv: []string{"git", "push"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictRefused || got.Rule != "exec.args[git]" || got.CommandList != "unlisted" || got.CommandMatch != "" {
		t.Errorf("git push under allow git status: %+v (an unlisted refusal has no command_match)", got)
	}
	got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/usr/bin/git", Argv: []string{"git", "status", "-s"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictAllow || got.Rule != "exec[git]" || got.CommandRule != "git status" || got.CommandList != "allow" {
		t.Errorf("git status -s: %+v", got)
	}
	got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/usr/bin/curl", Argv: []string{"curl", "x"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictRefused || got.Rule != agent.UnmatchedRule || got.CommandRule != "" {
		t.Errorf("an unlisted image is refused by the floor alone: %+v", got)
	}
}

// TestEvaluateExecCommandLoader: compile --test reads the program a directly-invoked dynamic loader runs, as the
// supervisor does (ADR 0048 (3)): `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree` under deny: [rm -r]
// is refused via loader, behind loader options too, and as a #! line's interpreter with rm as its argument; rm -f
// through the loader is allowed. An image is a loader by its name only, as in the run: a
// static-pie program's words are its own operands, so `rg git push` and `backup /usr/bin/rm -rf old` run.
func TestEvaluateExecCommandLoader(t *testing.T) {
	rt := commandTable(t, "deny: rm -r", "deny: git push")
	const ld = "/lib64/ld-linux-x86-64.so.2"
	for _, c := range []struct {
		a    agent.Action
		want agent.Verdict
	}{
		{agent.Action{Kind: agent.ActionExec, Path: ld, Argv: []string{ld, "/usr/bin/rm", "-rf", "tree"}}, agent.VerdictRefused},
		{agent.Action{Kind: agent.ActionExec, Path: ld, Argv: []string{ld, "--preload", "x.so", "/usr/bin/rm", "-r", "t"}}, agent.VerdictRefused},
		{agent.Action{Kind: agent.ActionExec, Path: "/work/s", Script: ld, ScriptArg: "/usr/bin/rm", Argv: []string{"./s", "-r", "tree"}}, agent.VerdictRefused},
		{agent.Action{Kind: agent.ActionExec, Path: ld, Argv: []string{ld, "/usr/bin/rm", "-f", "x"}}, agent.VerdictAllow},
		{agent.Action{Kind: agent.ActionExec, Path: "/work/rg", Argv: []string{"rg", "git", "push"}}, agent.VerdictAllow},
		{agent.Action{Kind: agent.ActionExec, Path: "/work/backup", Argv: []string{"backup", "/usr/bin/rm", "-rf", "/old"}}, agent.VerdictAllow},
	} {
		got := Evaluate(rt, c.a, backend.TierLandlock)
		if got.Verdict != c.want || (c.want == agent.VerdictRefused && (got.Rule != "exec.deny[rm -r]" || got.CommandVia != "loader")) {
			t.Errorf("%v: %+v, want %s", c.a.Argv, got, c.want)
		}
	}
}

// TestCommandFactsDirEntry: a directory exec.allow entry grants any file under it, so compile reads the image as the
// requested file's basename, never the directory's last component. Under allow: ["/work/t/"]
// and deny: [git push], `/work/t/mytool push` is allowed (mytool is not git); a real git under the directory is still
// read as git and its push refused, so the fix does not open a hole.
func TestCommandFactsDirEntry(t *testing.T) {
	rt := commandTable(t, "deny: git push")
	// The directory's own last component is "git", a ruled tool: the bug read it as the image, so mytool's push was
	// refused as git push. The image is the requested file's basename.
	rt.Exec = []agent.ExecRule{
		{Raw: "/work/git/", Path: "/work/git/", IsDir: true, Verdict: agent.VerdictAllow, Source: agent.ExecSourceAllow},
		{Raw: "/bin/sh", Path: "/bin/sh", Basename: "sh", Verdict: agent.VerdictAllow, Source: agent.ExecSourceAllow},
	}
	got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/work/git/mytool", Argv: []string{"mytool", "push"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictAllow || got.CommandRule != "" {
		t.Errorf("/work/git/mytool push under a directory grant: %+v, want allow with no command rule (mytool is not git)", got)
	}
	got = Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/work/git/git", Argv: []string{"git", "push"}}, backend.TierLandlock)
	if got.Verdict != agent.VerdictRefused || got.Rule != "exec.deny[git push]" {
		t.Errorf("/work/git/git push under a directory grant: %+v, want refused exec.deny[git push] (its basename is git)", got)
	}
}
