// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateDenyWrite is R20 (b) in compile --test: a modification that reaches a built-in deny_write
// target is refused, named after the target, in every enforcing tier — tiers 1 and 2 refuse it in the
// seccomp supervisor (supervisor R15c), which asks the same DenyWriteTarget — while an ordinary write in the
// same worktree, git's own writes beside the targets and a read of a target stay allowed, and an observe run
// allows everything. A target is matched at its resolved path too, and a rename of a directory above one is
// refused at either end.
func TestEvaluateDenyWrite(t *testing.T) {
	const work = "/work/proj"
	rt := &RuleTable{
		Contract: &Contract{},
		Tier:     backend.TierLandlock,
		FS:       []FSRule{{Path: work, Kind: FSWrite, Access: AccessWriteSet, Raw: "./proj"}},
		DenyWrite: []FSRule{
			{Path: work + "/.git/hooks", Kind: FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/.git/hooks"},
			{Path: "/home/u/.bashrc", Kind: FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: work + "/dotfiles/bashrc"},
		},
	}
	const hooks, bashrc = "fs.deny_write[" + work + "/.git/hooks]", "fs.deny_write[/home/u/.bashrc]"
	refused := func(rule string, r record.Reason) EvalResult {
		return EvalResult{Verdict: VerdictRefused, Rule: rule, Reason: r}
	}
	allowed := EvalResult{Verdict: VerdictAllow, Rule: "fs.write[./proj]"}
	for _, tc := range []struct {
		name string
		a    Action
		want EvalResult
	}{
		{"write a hook", Action{Kind: ActionFSWrite, Path: work + "/.git/hooks/pre-commit"}, refused(hooks, record.ReasonWriteOutsideContract)},
		{"delete a hook", Action{Kind: ActionFSDelete, Path: work + "/.git/hooks/pre-push"}, refused(hooks, record.ReasonDeleteOutsideContract)},
		{"mkdir in the hooks directory", Action{Kind: ActionFSMkdir, Path: work + "/.git/hooks/d"}, refused(hooks, record.ReasonMkdirOutsideContract)},
		{"write the dotfile where it resolves", Action{Kind: ActionFSWrite, Path: work + "/dotfiles/bashrc"}, refused(bashrc, record.ReasonWriteOutsideContract)},
		{"rename onto a hook", Action{Kind: ActionFSRename, Path: work + "/payload", DestPath: work + "/.git/hooks/pre-commit"}, refused(hooks, record.ReasonRenameOutsideContract)},
		{"rename the git directory away", Action{Kind: ActionFSRename, Path: work + "/.git", DestPath: work + "/g"}, refused(hooks, record.ReasonRenameOutsideContract)},
		{"rename a directory onto the git directory", Action{Kind: ActionFSRename, Path: work + "/evil", DestPath: work + "/.git"}, refused(hooks, record.ReasonRenameOutsideContract)},
		{"an ordinary write", Action{Kind: ActionFSWrite, Path: work + "/main.go"}, allowed},
		{"git's own index lock", Action{Kind: ActionFSWrite, Path: work + "/.git/index.lock"}, allowed},
		{"a rename beside the targets", Action{Kind: ActionFSRename, Path: work + "/.git/index.lock", DestPath: work + "/.git/index"}, allowed},
		{"a read of a hook", Action{Kind: ActionFSRead, Path: work + "/.git/hooks/pre-commit"}, allowed},
	} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			if got := rt.Evaluate(tc.a, tier); got != tc.want {
				t.Errorf("%s at %s: %+v, want %+v", tc.name, tier, got, tc.want)
			}
		}
		if got := rt.Evaluate(tc.a, backend.TierObserve); got.Verdict != VerdictAllow {
			t.Errorf("%s in an observe run: %+v, want allow: nothing is enforced there", tc.name, got)
		}
	}
}

// TestDenyTargetsAllocateNothing: DenyWriteTarget and DenyReadMoveTarget run on the supervisor's path for every
// notified modification, link and rename, over tables that can hold hundreds of deny_write targets and, at tier
// 2, up to envScanMaxEntries .env deny_read entries. A miss scans the whole table, so each step must compare in
// place (Covers) rather than build anc+"/" or a spelling slice per rule. The answers stay the same: a target at,
// above and (for a rename) beneath p is found, and a sibling that shares a prefix is not.
func TestDenyTargetsAllocateNothing(t *testing.T) {
	const work = "/home/someone/projects/a-rather-long-worktree-name"
	rt := &RuleTable{Contract: &Contract{}, Tier: backend.TierCgroup}
	for i := range 200 {
		d := work + "/sub" + string(rune('a'+i%26)) + "/repo" + string(rune('a'+i/26))
		rt.DenyWrite = append(rt.DenyWrite, FSRule{Path: d + "/.git/hooks", Resolved: d + "/.git/hooks", Kind: FSDenyWrite, BuiltIn: true, Unenforced: true})
		rt.FS = append(rt.FS, FSRule{Path: d + "/.env", Resolved: d + "/.env", Kind: FSDenyRead, BuiltIn: true, Unenforced: true})
	}
	miss := work + "/elsewhere/deeper/still/file.go"
	for _, tc := range []struct {
		name string
		f    func() bool
	}{
		{"deny_write miss", func() bool { _, ok := rt.DenyWriteTarget(miss, true); return ok }},
		{"deny_read move miss", func() bool { _, ok := rt.DenyReadMoveTarget(miss, true); return ok }},
	} {
		if tc.f() {
			t.Fatalf("%s: matched", tc.name)
		}
		if n := testing.AllocsPerRun(20, func() { tc.f() }); n != 0 {
			t.Errorf("%s: %v allocs per call, want 0", tc.name, n)
		}
	}
	last := work + "/subr/repoh"
	for _, tc := range []struct {
		p         string
		ancestors bool
		want      bool
	}{
		{last + "/.git/hooks", false, true},
		{last + "/.git/hooks/pre-commit", false, true},
		{last + "/.git/hooks/", false, true},
		{last + "//.git/hooks", false, true},
		{last + "/.git", false, false},
		{last + "/.git", true, true},
		{last + "/.git/hooksx", true, false},
		{last + "/.gi", true, false},
	} {
		if _, ok := rt.DenyWriteTarget(tc.p, tc.ancestors); ok != tc.want {
			t.Errorf("DenyWriteTarget(%q, %v) = %v, want %v", tc.p, tc.ancestors, ok, tc.want)
		}
	}
	for _, tc := range []struct {
		p         string
		ancestors bool
		want      bool
	}{
		{last + "/.env", false, true},
		{last + "/.envrc", false, false},
		{last, false, false},
		{last, true, true},
		{last + "x", true, false},
	} {
		if _, ok := rt.DenyReadMoveTarget(tc.p, tc.ancestors); ok != tc.want {
			t.Errorf("DenyReadMoveTarget(%q, %v) = %v, want %v", tc.p, tc.ancestors, ok, tc.want)
		}
	}
}
