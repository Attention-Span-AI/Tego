// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestBestEffortCellsAreDisclosedAtCompile is ADR 0041 D7's compile half: each (D) cell of D1 a contract's gate
// opens is one `unenforced` warning naming its stable id, and RuleTable.BestEffortCells, which run_start's
// best_effort carries, lists the same ids. A gate kind that cannot score to allow or above opens no cell; a net gate's
// IP actions are relayed (D6) and open none either, and its unix cells need `net to undeclared host`, with the
// unix connect cell only under a contract with no net: section.
func TestBestEffortCellsAreDisclosedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"no gate", "", nil},
		{"read gate", "gate:\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n",
			[]string{BestEffortGateFSReadOpen, BestEffortGateFSReadMove}},
		{"write gate below allow", "gate:\n  rules:\n    - fs.write outside worktree: 40\n", nil},
		{"write gate", "gate:\n  rules:\n    - fs.write outside worktree: 90\n",
			[]string{BestEffortGateFSWriteOpen, BestEffortGateFSWriteMutation}},
		{"exec gate", "gate:\n  rules:\n    - 'exec matches \"rm -rf\"': 95\n", []string{BestEffortGateExec}},
		{"literal net gate", "gate:\n  rules:\n    - 'net to 93.184.216.34:443': 90\n", nil},
		// With no net: section the run is in the unix-only state (ADR 0070): a unix connect is relayed as the agent on
		// the copy the gate scored, so it is no cell; host_sockets: true leaves it continued, as before.
		{"undeclared net gate, no net section", "gate:\n  rules:\n    - net to undeclared host: 90\n",
			[]string{BestEffortGateNetUnixDatagram}},
		{"undeclared net gate, no net section, host sockets opened", "host_sockets: true\ngate:\n  rules:\n    - net to undeclared host: 90\n",
			[]string{BestEffortGateNetUnixDatagram, BestEffortGateNetUnixConnect}},
		{"undeclared net gate, net section", "net:\n  allow: [\"93.184.216.34:443\"]\ngate:\n  rules:\n    - net to undeclared host: 90\n",
			[]string{BestEffortGateNetUnixDatagram}},
		// ADR 0041 Stage B: gate.completion: held completes the escalating fs opens through the open deputy, so their
		// open cells leave the list; an fs.read gate's O_PATH opens, which ADDFD cannot deliver, stay copied.
		{"held read and write gates", "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n    - fs.write outside worktree: 90\n",
			[]string{BestEffortGateFSReadOPath, BestEffortGateFSReadMove, BestEffortGateFSWriteMutation}},
		// A read-write open and a move's source are scored by both fs kinds, their scores summed (ADR 0007, 2026-10-20):
		// read 30 and write 30 escalate only together, so the cells of the actions
		// both kinds score open (a read-write open is a write-open), and no read-only open's.
		{"read and write gates that escalate only together", "gate:\n  rules:\n    - 'fs.read matches \"*.env\"': 30\n    - fs.write outside worktree: 30\n",
			[]string{BestEffortGateFSReadMove, BestEffortGateFSWriteOpen, BestEffortGateFSWriteMutation}},
		{"held read and write gates that escalate only together", "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 30\n    - fs.write outside worktree: 30\n",
			[]string{BestEffortGateFSReadMove, BestEffortGateFSWriteMutation}},
		{"copied completion spelled", "gate:\n  completion: copied\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n",
			[]string{BestEffortGateFSReadOpen, BestEffortGateFSReadMove}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n" + tc.src))
			if got := rt.BestEffortCells(); !slices.Equal(got, tc.want) {
				t.Fatalf("BestEffortCells = %v, want %v", got, tc.want)
			}
			var warned []string
			for _, d := range ds {
				if d.Code != CodeUnenforced || !strings.HasPrefix(d.Message, "best effort (") {
					continue
				}
				id, _, _ := strings.Cut(strings.TrimPrefix(d.Message, "best effort ("), ")")
				if id == BestEffortHostSocketsRoot {
					continue // a root tier's cell, not the table's (TestHostSocketsRootTierBestEffort)
				}
				warned = append(warned, id)
			}
			want := slices.Clone(tc.want) // diagnostics come sorted
			slices.Sort(want)
			slices.Sort(warned)
			if !slices.Equal(warned, want) {
				t.Fatalf("best-effort warnings %v, want one per cell %v:\n%s", warned, tc.want, render(ds))
			}
		})
	}
}

// TestBestEffortCellsForARow is compile --test's column half of D7: a row's answer names the (D) cells it rests on at
// its tier, and only those. A gate cell needs the row's action and an answer the floor did not refuse first; a rename
// of a secret out of its name under a read gate alone is refused by the source's read scoring, as the run's gateFS
// refuses it (Step 4), and that refusal rests on the read-move cell (EvaluateGateRow scored a rename with the write
// predicates only and, with none, answered allow where the run refused); a unix
// connect under `net to undeclared host` with no net: section rests on the unix-connect cell, an IP one on none (the
// relay completes it); observe enforces nothing.
func TestBestEffortCellsForARow(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  rules:\n" +
		"    - 'fs.read matches \"*.env\"': 90\n    - net to undeclared host: 90\n"))
	allow := EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}
	scored := 0
	gated := EvalResult{Verdict: VerdictRefused, Rule: "gate", Score: &scored}
	floor := EvalResult{Verdict: VerdictRefused, Rule: "fs.write[/x]"}
	rename := Action{Kind: ActionFSRename, Path: "/w/a.env", DestPath: "/w/b"}
	renamed := EvaluateGateRow(rt, rename, allow)
	if renamed.Verdict != VerdictRefused || renamed.Reason != record.ReasonFSGate || renamed.Score == nil || *renamed.Score != 90 {
		t.Fatalf("the rename of a secret out of its name under a read gate: %+v, want refused fs-gate at 90", renamed)
	}
	for _, tc := range []struct {
		name string
		a    Action
		got  EvalResult
		tier backend.Tier
		want []string
	}{
		{"a read the gate refuses", Action{Kind: ActionFSRead, Path: "/w/a.env"}, gated, backend.TierLandlock, []string{BestEffortGateFSReadOpen}},
		{"a read it allows, at bpflsm", Action{Kind: ActionFSRead, Path: "/w/a"}, allow, backend.TierBPFLSM, []string{BestEffortGateFSReadOpen}},
		{"a read the floor refuses", Action{Kind: ActionFSRead, Path: "/etc/shadow"}, floor, backend.TierCgroup, nil},
		{"a rename under a read gate", rename, renamed, backend.TierLandlock, []string{BestEffortGateFSReadMove}},
		{"a write with no write gate", Action{Kind: ActionFSWrite, Path: "/w/a"}, allow, backend.TierLandlock, nil},
		// No net: section and no host_sockets: true: the unix-only state's root-tier cell, and no gate cell, since the
		// connect is relayed on the copy the gate scored (ADR 0070).
		{"a unix connect", Action{Kind: ActionNetConnect, Path: "/run/x.sock", Proto: ProtoUnix}, allow, backend.TierCgroup,
			[]string{BestEffortHostSocketsRoot}},
		{"a unix connect at tier landlock", Action{Kind: ActionNetConnect, Path: "/run/x.sock", Proto: ProtoUnix}, allow, backend.TierLandlock, nil},
		{"an IP connect", Action{Kind: ActionNetConnect, Host: "192.0.2.1", Port: 443}, allow, backend.TierCgroup, nil},
		{"observe", Action{Kind: ActionFSRead, Path: "/w/a.env"}, allow, backend.TierObserve, nil},
	} {
		if got := rt.BestEffortCellsFor(tc.a, tc.got, tc.tier); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := (*RuleTable)(nil).BestEffortCellsFor(Action{Kind: ActionFSRead}, allow, backend.TierLandlock); got != nil {
		t.Errorf("a nil table: %v", got)
	}
	// Under gate.completion: held the open deputy completes the gate's reads (ADR 0041 Stage B): compile --test's read
	// row rests on no open cell, as compile's own warnings list none for it; a rename still rests on the move cell.
	held, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  completion: held\n  rules:\n" +
		"    - 'fs.read matches \"*.env\"': 90\n"))
	if got := held.BestEffortCellsFor(Action{Kind: ActionFSRead, Path: "/w/a.env"}, gated, backend.TierLandlock); got != nil {
		t.Errorf("a held read the gate refuses: %v, want no cell", got)
	}
	if got := held.BestEffortCellsFor(rename, renamed, backend.TierLandlock); !slices.Equal(got, []string{BestEffortGateFSReadMove}) {
		t.Errorf("a rename under a held read gate: %v, want %v", got, []string{BestEffortGateFSReadMove})
	}
}

// TestGateCompletionKey: gate.completion takes copied or held; held needs an fs gate rule that can score an open past
// allow to hold anything (NeedsOpenDeputy), and warns redundant-rule otherwise; a run whose deputy did not start lists
// the open cells again (BestEffortCellsRun), as the degrade says.
func TestGateCompletionKey(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"))
	if !rt.Gate.HeldCompletion() || !rt.NeedsOpenDeputy() {
		t.Fatalf("held completion %t, needs deputy %t:\n%s", rt.Gate.HeldCompletion(), rt.NeedsOpenDeputy(), render(ds))
	}
	if got := rt.BestEffortCellsRun("landlock", "", false, false); !slices.Contains(got, BestEffortGateFSReadOpen) {
		t.Fatalf("a run whose deputy did not start lists %v, want %s", got, BestEffortGateFSReadOpen)
	}
	if got := rt.BestEffortCellsRun("landlock", "", true, false); slices.Contains(got, BestEffortGateFSReadOpen) || !slices.Contains(got, BestEffortGateFSReadOPath) {
		t.Fatalf("a run whose deputy serves lists %v", got)
	}
	// The printed table names the held completion, and the deputy's runtime exec grant where the run restricts exec
	// (ADR 0041 D2: the grant is shown in the effective policy).
	var printed strings.Builder
	if err := PrintRuleTable(&printed, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed.String(), "fs opens held") || strings.Contains(printed.String(), "runtime exec grant") ||
		!strings.Contains(printed.String(), "make no Landlock domain of their own") {
		t.Fatalf("the table of a held gate with exec unrestricted:\n%s", printed.String())
	}
	execRT, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  allow: [\"/bin/sh\"]\ngate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"))
	printed.Reset()
	if err := PrintRuleTable(&printed, execRT); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed.String(), "runtime exec grant: tego's own binary, for the deputy") {
		t.Fatalf("the table of a held gate with an exec allow list names no runtime exec grant:\n%s\n%s", printed.String(), render(ds))
	}
	rt, ds = f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  completion: held\n  rules:\n    - 'exec matches \"rm -rf\"': 95\n"))
	if rt.NeedsOpenDeputy() {
		t.Fatal("an exec-only gate needs no deputy")
	}
	redundant := false
	for _, d := range ds {
		redundant = redundant || d.Code == CodeRedundantRule && strings.Contains(d.Message, "gate.completion: held holds nothing")
	}
	if !redundant {
		t.Fatalf("no redundant-rule warning for a completion: held that holds nothing:\n%s", render(ds))
	}
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: t\ncommand: [\"python\"]\ngate:\n  completion: kernel\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n", 0o644)
	if _, ds, err := Load(path, f.profiles()); err == nil || !strings.Contains(render(ds), "copied|held") {
		t.Fatalf("gate.completion: kernel loaded (%v):\n%s", err, render(ds))
	}
	// Held completion runs under no_new_privs only (ADR 0041 D2's credential change): a gate
	// needs setuid disabled, so no task of a held run can change its credentials through a setuid binary, and the
	// deputy, exec'd with the agent's, keeps the task's. setuid: true with a held gate does not load.
	f.file(path, "version: 0\nname: t\ncommand: [\"python\"]\nsetuid: true\ngate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n", 0o644)
	if _, ds, err := Load(path, f.profiles()); err == nil || !strings.Contains(render(ds), "setuid disabled") {
		t.Fatalf("gate.completion: held with setuid: true loaded (%v):\n%s", err, render(ds))
	}
}
