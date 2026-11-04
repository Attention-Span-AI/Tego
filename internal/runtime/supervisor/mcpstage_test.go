// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const stageTestExe = "/opt/tego/bin/tego"

func stagePolicy(t *testing.T, extra ...string) *Policy {
	t.Helper()
	pol := commandPolicy(t, append([]string{"allow: " + stageTestExe + " mcp relay *"}, extra...)...)
	pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Path: stageTestExe, Resolved: stageTestExe,
		Basename: "tego", Verdict: agent.VerdictAllow})
	return pol
}

// TestMCPStageGrantKeepsPolicyFloors: only the exact-child callback may lift an unlisted vector; an explicit
// deny or ask, a failed image floor or an unreadable image never acquires that runtime authority (ADR 0126).
func TestMCPStageGrantKeepsPolicyFloors(t *testing.T) {
	argv := []string{stageTestExe, "__mcp_server", "/usr/bin/python3", "python3", "/server.py"}
	for _, tc := range []struct {
		name, entry       string
		vouch, asked      bool
		headless, noImage bool
		live              bool
		verdict           record.Verdict
	}{
		{name: "no exact child", asked: true, verdict: record.VerdictRefused},
		{name: "exact child", vouch: true, asked: true, verdict: record.VerdictAllow},
		{name: "explicit deny", entry: "deny: tego __mcp_server *", vouch: true, verdict: record.VerdictRefused},
		{name: "explicit ask", entry: "ask: tego __mcp_server *", vouch: true, verdict: record.VerdictRefused},
		{name: "unreadable image", vouch: true, headless: true, verdict: record.VerdictRefused},
		{name: "ungranted image", vouch: true, noImage: true, verdict: record.VerdictRefused},
		{name: "live block", vouch: true, asked: true, live: true, verdict: record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []string
			if tc.entry != "" {
				entries = append(entries, tc.entry)
			}
			pol := stagePolicy(t, entries...)
			if tc.noImage {
				pol.Rules.Exec = pol.Rules.Exec[:len(pol.Rules.Exec)-1]
			}
			f := newFake()
			if tc.headless {
				f.headless = map[string]bool{stageTestExe: true}
			}
			asked := false
			rule := "exec.mcp-stage[" + stageTestExe + "]"
			opts := Options{MCPStage: func(pid int, dev, ino uint64, got []string) string {
				asked = true
				id := fakeID(stageTestExe)
				if pid != 42 || dev != id.dev || ino != id.ino || !slices.Equal(got, argv) {
					t.Fatalf("stage facts %d %d:%d %q", pid, dev, ino, got)
				}
				if tc.vouch {
					return rule
				}
				return ""
			}}
			if tc.live {
				set := liveSet(t, "exec", stageTestExe)
				opts.LiveBlocks = func() *liveblock.Set { return set }
			}
			l, sink := newTestLoopOpts(t, f, pol, opts)
			execAt(l, f, nrFor(t, "execve"), 42, 0, stageTestExe, argv...)
			wantExecAnswer(t, f, tc.verdict)
			if asked != tc.asked {
				t.Fatalf("runtime grant asked %v, want %v", asked, tc.asked)
			}
			if tc.verdict == record.VerdictAllow {
				ev := sink.one(t)
				p := execPayloadOf(t, ev)
				if ev.Rule != rule || p.CommandList != "" || p.ArgvRead != len(argv) || p.ArgvFacts != record.ArgvFactsCopied {
					t.Fatalf("stage line rule %q payload %+v", ev.Rule, p)
				}
			}
		})
	}
}

func TestMCPStageGrantPinsWholeVector(t *testing.T) {
	f := newFake()
	l, sink, pinner := pinnedLoop(t, f, stagePolicy(t))
	l.mono = func() uint64 { return 100 }
	argv := []string{stageTestExe, "__mcp_server", "/usr/bin/python3", "python3", "/server.py"}
	for range 40 {
		argv = append(argv, "argument-past-normal-prefix")
	}
	rule := "exec.mcp-stage[" + stageTestExe + "]"
	l.mcpStage = func(_ int, _, _ uint64, got []string) string {
		if !slices.Equal(got, argv) {
			t.Fatalf("stage allowance read an incomplete vector: %q", got)
		}
		return rule
	}
	execAt(l, f, nrFor(t, "execve"), 42, 0, stageTestExe, argv...)
	wantExecAnswer(t, f, record.VerdictAllow)
	if len(pinner.writes) != 1 {
		t.Fatalf("%d pins written, want one", len(pinner.writes))
	}
	if p := decodePin(pinner.writes[0].pin); int(p.K) != len(argv) || p.MACCov != covMAC(argv...) || p.Flags != execpin.FlagGuard {
		t.Fatalf("stage pin %+v, want guarded whole-vector pin (k=%d)", p, len(argv))
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("predicted stage allow hid the kernel outcome: %+v", got)
	}
	if n, ok := l.ContinuedExec(42, 42, 777*proc.NanosPerTick, 110); !ok || n.SupervisorOwned || n.RuntimeRule != rule || n.ArgvRead != len(argv) {
		t.Fatalf("stage naming %+v (%v), want kernel outcome with runtime provenance", n, ok)
	}
}
