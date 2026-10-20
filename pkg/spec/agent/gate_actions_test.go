// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateRowScoresTheConformanceActions: compile --test's gate scores fs.link, fs.attr and net.send rows as the
// run's gate scores the syscalls (supervisor gateFS, sendDecisionCtl): a hard link's two ends with the write
// predicates and its source with the read ones, as a rename's; an attribute change as a write on its path, a
// non-open mutation whose ask cannot complete; an unconnected send as the connect to its destination. A socket and
// an anonymous exec meet no gate predicate.
func TestGateRowScoresTheConformanceActions(t *testing.T) {
	p, e := CompileGateConfig(gateContract(t, "rules:\n - fs.write outside worktree: 100\n - fs.read matches \"/work/.env\": 100\n - net to undeclared host: 70\n"))
	if e != nil {
		t.Fatal(e)
	}
	rt := &RuleTable{Contract: &Contract{Name: "gate-actions"}, Gate: p, Workdir: "/work"}
	allow := EvalResult{Verdict: VerdictAllow, Rule: "fs.write[/]"}
	for _, tc := range []struct {
		name        string
		a           Action
		verdict     Verdict
		rule        string
		reason      record.Reason
		unsupported bool
	}{
		{"link inside the worktree", Action{Kind: ActionFSLink, Path: "/work/a", DestPath: "/work/b"}, VerdictAllow, "fs.write[/]", "", false},
		{"link out of the worktree", Action{Kind: ActionFSLink, Path: "/work/a", DestPath: "/tmp/b"}, VerdictRefused, "gate.rules[0]", record.ReasonFSGate, false},
		{"link of a .env file", Action{Kind: ActionFSLink, Path: "/work/.env", DestPath: "/work/b"}, VerdictRefused, "gate.rules[1]", record.ReasonFSGate, false},
		{"attr outside the worktree", Action{Kind: ActionFSAttr, Path: "/etc/x"}, VerdictRefused, "gate.rules[0]", record.ReasonFSGate, false},
		{"attr inside the worktree", Action{Kind: ActionFSAttr, Path: "/work/x"}, VerdictAllow, "fs.write[/]", "", false},
		{"unix send", Action{Kind: ActionNetSend, Path: "unix:/tmp/x.sock"}, VerdictRefused, "gate.rules[2]", record.ReasonNetGate, true},
		{"socket", Action{Kind: ActionNetSocket, Socket: SocketTriple{Family: 2, Type: 1}}, VerdictAllow, "fs.write[/]", "", false},
		{"anonymous exec", Action{Kind: ActionExecAnon}, VerdictAllow, "fs.write[/]", "", false},
	} {
		floor := allow
		if tc.a.Kind == ActionNetSend {
			floor = EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}
		}
		got := EvaluateGateRow(rt, tc.a, floor)
		if got.Verdict != tc.verdict || got.Rule != tc.rule && tc.verdict == VerdictRefused || got.Reason != tc.reason || got.CompletionUnsupported != tc.unsupported {
			t.Errorf("%s: %+v, want %s %s %s unsupported=%v", tc.name, got, tc.verdict, tc.rule, tc.reason, tc.unsupported)
		}
	}
	// An ask from the write gate on an attribute change cannot complete (a non-open mutation), as the run refuses it.
	ask, e := CompileGateConfig(gateContract(t, "rules:\n - fs.write outside worktree: 60\n"))
	if e != nil {
		t.Fatal(e)
	}
	rt.Gate = ask
	if got := EvaluateGateRow(rt, Action{Kind: ActionFSAttr, Path: "/etc/x"}, allow); got.Verdict != VerdictRefused || !got.CompletionUnsupported {
		t.Errorf("attr ask = %+v, want refused with completion_unsupported", got)
	}
}

// TestBestEffortCellsForTheConformanceActions: compile --test's column names the run's best-effort cells for the new
// rows as for the actions they mirror: a link is a move (its source under a read gate, both ends under a write gate),
// an attribute change a write mutation, a unix datagram send the gate's unix-datagram cell.
func TestBestEffortCellsForTheConformanceActions(t *testing.T) {
	p, e := CompileGateConfig(gateContract(t, "rules:\n - fs.write outside worktree: 100\n - fs.read matches \"/work/.env\": 100\n - net to undeclared host: 70\n"))
	if e != nil {
		t.Fatal(e)
	}
	rt := &RuleTable{Contract: &Contract{Name: "cells", Net: &NetSection{}}, Gate: p, Workdir: "/work"}
	allow := EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}
	for _, tc := range []struct {
		a    Action
		want []string
	}{
		{Action{Kind: ActionFSLink, Path: "/work/a", DestPath: "/work/b"}, []string{BestEffortGateFSReadMove, BestEffortGateFSWriteMutation}},
		{Action{Kind: ActionFSAttr, Path: "/work/a"}, []string{BestEffortGateFSWriteMutation}},
		{Action{Kind: ActionNetSend, Path: "unix:/tmp/x"}, []string{BestEffortGateNetUnixDatagram}},
		{Action{Kind: ActionNetSend, Host: "127.0.0.1", Port: 53, Proto: ProtoUDP}, nil},
		{Action{Kind: ActionNetSocket}, nil},
		{Action{Kind: ActionExecAnon}, nil},
	} {
		got := rt.BestEffortCellsFor(tc.a, allow, backend.TierBPFLSM)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: cells %v, want %v", tc.a.Kind, got, tc.want)
		}
	}
}
