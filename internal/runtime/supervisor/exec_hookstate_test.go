// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDenyListRefusesExecFromTheHookState is agent-contract.md R27's hook-state grant held as R10a holds the CODEX_HOME
// (ADR 0062): a deny-list run's hook-state directory is a write grant the run makes on its own authority, so a copy
// of a denied program there, run directly or through the dynamic loader, is refused harness-state-exec; a symlink there
// to a program elsewhere is that program, and the CODEX_HOME keeps its own rule.
func TestDenyListRefusesExecFromTheHookState(t *testing.T) {
	nr := nrFor(t, "execve")
	const (
		ld    = "/lib64/ld-linux-x86-64.so.2"
		state = "/run/user/1000/tego/r-1/hook-state"
		home  = "/run/user/1000/tego/r-1/codex"
	)
	grants := []agent.FSRule{
		{Path: state, Resolved: state, Kind: agent.FSWrite, Access: agent.AccessWriteSet, Runtime: agent.HarnessStateGrant},
		{Path: home, Resolved: home, Kind: agent.FSWrite, Access: agent.AccessWriteSet, Runtime: agent.CodexHomeGrant},
	}
	images := map[string]execImage{
		ld:                {id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1, 1)},
		state + "/notid":  {id: fakeID(state + "/notid"), linked: true, link: state + "/notid", here: true, head: []byte("\x7fELF")},
		state + "/tool":   {id: fakeID("/usr/bin/true"), linked: true, link: "/usr/bin/true", here: true, head: []byte("\x7fELF")},
		home + "/notid":   {id: fakeID(home + "/notid"), linked: true, link: home + "/notid", here: true, head: []byte("\x7fELF")},
		state + "x/notid": {id: fakeID(state + "x/notid"), linked: true, link: state + "x/notid", here: true, head: []byte("\x7fELF")},
		"/proc/42/fd/7":   {id: fakeID(state + "/sub/notid"), linked: true, link: state + "/sub/notid", head: []byte("\x7fELF")},
		"/usr/bin/id":     {id: fakeID("/usr/bin/id"), linked: true, link: "/usr/bin/id", here: true, head: []byte("\x7fELF")},
	}
	for _, c := range []struct {
		name    string
		path    string
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{"the copy", state + "/notid", []string{"notid", "-u"}, record.VerdictRefused, ruleHookStateExec},
		{"the copy through the loader", ld, []string{ld, state + "/notid", "-u"}, record.VerdictRefused, ruleHookStateExec},
		{"a linked copy not confirmed here", "/proc/42/fd/7", []string{"notid"}, record.VerdictRefused, ruleHookStateExec},
		{"a symlink to a program elsewhere", state + "/tool", []string{"tool"}, record.VerdictAllow, ruleUnmatched},
		{"a sibling directory is not hook-state", state + "x/notid", []string{"notid"}, record.VerdictAllow, ruleUnmatched},
		{"the CODEX_HOME keeps its rule", home + "/notid", []string{"notid"}, record.VerdictRefused, ruleCodexHomeExec},
		{"the denied program", "/usr/bin/id", []string{"id", "-u"}, record.VerdictRefused, "exec.deny[id]"},
	} {
		f := newFake()
		f.images = images
		pol := commandPolicy(t, "deny: id")
		pol.Rules.FS = append(pol.Rules.FS, grants...)
		l, sink := newTestLoop(t, f, pol)
		execAt(l, f, nr, 42, 0, c.path, c.argv...)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}
