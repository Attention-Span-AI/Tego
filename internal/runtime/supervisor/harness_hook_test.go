// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHarnessHookGrantIsPinnedOverTheWholeVector is ADR 0064 D3 (acceptance (5)) in the loop: in a run whose plane pins
// its execs, the harness hook's exact argv is allowed under exec.harness-hook[<binary>] and its pin covers the whole
// vector (k is its length), as any command rule's decision is pinned; every other vector of the binary is refused under
// the same rule, unlisted, and writes no pin.
func TestHarnessHookGrantIsPinnedOverTheWholeVector(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	const tego = "/opt/tego/bin/tego"
	hook := []string{tego, "hook", "claude-code", "--reason", "/run/user/1000/tego/R/last-refusal.json", "--mode", "json"}
	pol := contractPolicy(&agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/bin/sh"}}}, nil, nil)
	pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Path: tego, Resolved: tego, Basename: "tego",
		Source: agent.HarnessHookGrant, Runtime: agent.HarnessHookGrant, Verdict: agent.VerdictAllow})
	pol.Rules.ExecCommands = &agent.ExecCommands{Index: execmatch.NewIndex(rows.Builtin(),
		[]*execmatch.Pattern{execmatch.ExactPattern(agent.HarnessHookGrant, "tego", hook)}, execmatch.IndexOptions{})}
	l, sink, pinner := pinnedLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, tego, hook...)
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins written for the hook, want 1", len(pinner.writes))
	}
	if p := decodePin(pinner.writes[0].pin); int(p.K) != len(hook) || p.MACCov != covMAC(hook...) || p.Flags != execpin.FlagGuard {
		t.Fatalf("the hook's pin %+v: want k %d over the whole vector, guarded", p, len(hook))
	}
	execAt(l, f, nr, 42, 1, tego, tego, "run", "c.yaml")
	wantExecAnswer(t, f, record.VerdictRefused)
	if len(pinner.writes) != 1 {
		t.Fatal("the refused vector wrote a pin")
	}
	rule := "exec." + agent.HarnessHookGrant + "[" + tego + "]"
	refused := 0
	for _, ev := range sink.all() {
		if ev.Kind == record.KindExec && ev.Verdict == record.VerdictRefused {
			if p := execPayloadOf(t, ev); ev.Rule != rule || p.CommandList != "unlisted" {
				t.Errorf("the refused exec: rule %q list %q, want %s, unlisted", ev.Rule, p.CommandList, rule)
			}
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d refused exec lines, want 1", refused)
	}
}
