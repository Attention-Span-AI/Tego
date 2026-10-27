// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// userDenyWriteTable is a write entry /h with an fs.deny_write entry /h/deploy (declared through the link /h/dl), a
// write entry /h/deploy/tmp that reopens part of it (declared through the link /h/tl), a built-in target /h/.git/hooks
// and a write entry inside it, /h/.git/hooks/sub, which reopens nothing.
func userDenyWriteTable() *agent.RuleTable {
	return &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/h/tl", Raw: "./tl/", Resolved: "/h/deploy/tmp", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/h/.git/hooks/sub", Raw: "./.git/hooks/sub", Resolved: "/h/.git/hooks/sub", Access: agent.AccessWriteSet},
		},
		DenyWrite: []agent.FSRule{
			{Kind: agent.FSDenyWrite, Path: "/h/.git/hooks", Resolved: "/h/.git/hooks", BuiltIn: true, Unenforced: true},
			{Kind: agent.FSDenyWrite, Path: "/h/dl", Raw: "./dl/", Resolved: "/h/deploy", Unenforced: true},
		},
	}
}

// TestUserDenyWriteIndexMatchesScan: the supervisor's index (FSIndex.DenyWriteTarget) and the plane rows' index
// (planeIndex.denyWriteIdx) give agent.RuleTable.DenyWriteTarget's answer for every path and both questions, nearest
// wins included: the nested write entry reopens the fs.deny_write entry at every spelling, never the built-in target.
func TestUserDenyWriteIndexMatchesScan(t *testing.T) {
	rt := userDenyWriteTable()
	ix, px := NewFSIndex(rt), newPlaneIndex(rt)
	paths := []string{"/", "/h", "/h/x", "/h/deploy", "/h/deploy/a", "/h/deploy/tmp", "/h/deploy/tmp/x", "/h/deploy/tmpx",
		"/h/dl", "/h/dl/a", "/h/dl/tmp", "/h/dl/tmp/x", "/h/tl", "/h/tl/x", "/h/.git", "/h/.git/hooks", "/h/.git/hooks/pre-commit",
		"/h/.git/hooks/sub", "/h/.git/hooks/sub/x", "/other"}
	want := map[string]bool{"/h/deploy/a": true, "/h/deploy": true, "/h/dl/a": true, "/h/dl": true, "/h/deploy/tmpx": true,
		"/h/.git/hooks": true, "/h/.git/hooks/pre-commit": true, "/h/.git/hooks/sub": true, "/h/.git/hooks/sub/x": true}
	for _, p := range paths {
		for _, ancestors := range []bool{false, true} {
			sr, sok := rt.DenyWriteTarget(p, ancestors)
			ir, iok := ix.DenyWriteTarget(p, ancestors)
			if sok != iok || sr.RuleName() != ir.RuleName() {
				t.Errorf("%s ancestors=%v: index %v %q, scan %v %q", p, ancestors, iok, ir.RuleName(), sok, sr.RuleName())
			}
			j, pok := px.denyWriteIdx(p, ancestors)
			if pok != sok || (pok && rt.DenyWrite[j].RuleName() != sr.RuleName()) {
				t.Errorf("%s ancestors=%v: plane index %v %d, scan %v %q", p, ancestors, pok, j, sok, sr.RuleName())
			}
			if !ancestors && sok != want[p] {
				t.Errorf("%s: reaches a target %v (%q), want %v", p, sok, sr.RuleName(), want[p])
			}
		}
	}
	// The indexed model compile --test asks (Evaluator) answers a write as the scan does.
	ev := NewEvaluator(rt)
	for _, p := range paths {
		if p == "/" || p == "/other" {
			continue // outside every write entry: refused unmatched, no target asked
		}
		sr, sok := rt.DenyWriteTarget(p, false)
		got := ev.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: p}, backend.TierLandlock)
		if (got.Verdict == agent.VerdictRefused) != sok || (sok && got.Rule != sr.RuleName()) {
			t.Errorf("Evaluator write %s: %+v, scan reaches %v %q", p, got, sok, sr.RuleName())
		}
	}
	// A rename of the reopening write entry's own name reaches the entry, at every spelling of it in the
	// entry; one beneath it does not, nor one of the link /h/tl, which lies beside the entry.
	for p, want := range map[string]bool{"/": true, "/h": true, "/h/deploy/tmp": true, "/h/dl/tmp": true, "/h/tl": false,
		"/h/deploy/tmp/x": false, "/h/tl/x": false} {
		if _, ok := rt.DenyWriteTarget(p, true); ok != want {
			t.Errorf("rename of %s: reaches a target %v, want %v", p, ok, want)
		}
	}
	// The name question: the same, as FSIndex and the scan answer it, for a made name.
	for p, want := range map[string]bool{"/h/deploy/tmp": true, "/h/dl/tmp": true, "/h/tl": false, "/h/deploy/tmp/x": false,
		"/h/deploy/new": true, "/h/x": false} {
		sr, sok := rt.DenyWriteNameTarget(p)
		ir, iok := ix.DenyWriteNameTarget(p)
		if sok != want || iok != sok || sr.RuleName() != ir.RuleName() {
			t.Errorf("made name %s: scan %v %q, index %v %q, want %v", p, sok, sr.RuleName(), iok, ir.RuleName(), want)
		}
	}
}

// TestPlaneRowsUserDenyWrite is ADR 0071 (3) in the plane rows: the fs.deny_write entry's row refuses a modification
// and an attribute change at and beneath it and a rename of it or of a directory above it, naming the entry; a rename or
// a hard link that would carry a file out of it is refused by REFER; the nested write entry's row reopens its subtree.
func TestPlaneRowsUserDenyWrite(t *testing.T) {
	rt := userDenyWriteTable()
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	const name = "fs.deny_write[./dl/]"
	for _, tc := range []struct {
		path  string
		q     PlaneQuestion
		allow bool
	}{
		{"/h/deploy/a", PlaneModify, false},
		{"/h/deploy/new", PlaneModify, false},
		{"/h/deploy/a", PlaneProtect, false},
		{"/h/deploy", PlaneRename, false},
		{"/h", PlaneRename, false},
		{"/h/deploy/a", PlaneRead, true},
		{"/h/deploy/tmp/x", PlaneModify, true},
		{"/h/deploy/tmp/x", PlaneProtect, true},
		{"/h/deploy/tmp/x", PlaneRename, true},
		{"/h/deploy/tmp", PlaneModify, true},
		{"/h/deploy/tmp", PlaneRename, false}, // the write entry's own name is the entry's
		{"/h/x", PlaneModify, true},
	} {
		v := s.Decide(tc.path, tc.q)
		if v.Allow != tc.allow {
			t.Errorf("%s q=%d: %+v, want allow=%v", tc.path, tc.q, v, tc.allow)
		}
		if !tc.allow && tc.path != "/h" && v.Rule.Name(rt) != name {
			t.Errorf("%s q=%d: names %q, want %q", tc.path, tc.q, v.Rule.Name(rt), name)
		}
	}
	if !PlaneReferRefused(s.KindAt("/h/deploy/a"), s.KindAt("/h/alias")) {
		t.Error("a hard link or rename carrying a file out of the entry must be refused by REFER")
	}
	if PlaneReferRefused(s.KindAt("/h/deploy/tmp/x"), s.KindAt("/h/y")) {
		t.Error("a move out of the reopened subtree is a move between two write grants")
	}
	// The built-in target is not reopened by the write entry inside it.
	if v := s.Decide("/h/.git/hooks/sub/x", PlaneModify); v.Allow {
		t.Errorf("beneath the built-in target's nested write entry: %+v, want refused", v)
	}
}

// TestUserDenyWriteBesideBuiltInTarget in the indexes: an fs.deny_write entry at a built-in target's
// place sits just before the target (compile's beforeBuiltInAt), and every index keeps the target's own semantics. A
// write entry inside the place reopens the declared entry but not the target, and the target's link spelling stays
// held (a link row at /h/.claude), while a refusal the declared entry reaches names it.
func TestUserDenyWriteBesideBuiltInTarget(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/h/dotclaude/projects", Raw: "./dotclaude/projects/", Resolved: "/h/dotclaude/projects", Access: agent.AccessWriteSet},
		},
		DenyWrite: []agent.FSRule{
			{Kind: agent.FSDenyWrite, Path: "/h/dotclaude", Raw: "./dotclaude/", Resolved: "/h/dotclaude", Unenforced: true},
			{Kind: agent.FSDenyWrite, Path: "/h/.claude", Resolved: "/h/dotclaude", BuiltIn: true, Unenforced: true},
		},
	}
	const user, builtIn = "fs.deny_write[./dotclaude/]", "fs.deny_write[/h/.claude]"
	ix, px := NewFSIndex(rt), newPlaneIndex(rt)
	for p, want := range map[string]string{
		"/h/dotclaude/a": user, "/h/dotclaude": user, "/h/dotclaude/projects/x": builtIn, "/h/dotclaude/projects": builtIn,
		"/h/.claude": builtIn, "/h/.claude/settings.json": builtIn, "/h/x": "",
	} {
		for _, ancestors := range []bool{false, true} {
			name := func(r agent.FSRule, ok bool) string {
				if !ok {
					return ""
				}
				return r.RuleName()
			}
			scan := name(rt.DenyWriteTarget(p, ancestors))
			index := name(ix.DenyWriteTarget(p, ancestors))
			plane := ""
			if j, ok := px.denyWriteIdx(p, ancestors); ok {
				plane = rt.DenyWrite[j].RuleName()
			}
			if index != scan || plane != scan {
				t.Errorf("%s ancestors=%v: scan %q, index %q, plane index %q", p, ancestors, scan, index, plane)
			}
			if !ancestors && scan != want {
				t.Errorf("%s: reaches %q, want %q", p, scan, want)
			}
		}
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/h/dotclaude/projects/x", "/h/dotclaude/a", "/h/.claude"} {
		if v := s.Decide(p, PlaneModify); v.Allow {
			t.Errorf("plane rows: modify %s: %+v, want refused", p, v)
		}
	}
	if !slices.Contains(s.NoFollow, "/h/.claude") {
		t.Errorf("the built-in target's link spelling must keep its own row: NoFollow %v", s.NoFollow)
	}
}

// TestUserDenyWriteQueryAllocations: the supervisor's per-notification question (FSIndex) and the
// Evaluator allocate nothing on a table with fs.deny_write entries and reopening write entries, in the reopened
// subtree (where nearest wins walks past reopen spellings), beside it and outside the entries.
func TestUserDenyWriteQueryAllocations(t *testing.T) {
	rt := userDenyWriteTable()
	ix, ev := NewFSIndex(rt), NewEvaluator(rt)
	paths := []string{"/h/deploy/tmp/x", "/h/deploy/tmp/sub/y", "/h/tl/x", "/h/dl/tmp/x", "/h/deploy/a", "/h/x", "/h/.git/hooks/sub/x"}
	for _, p := range paths {
		for _, ancestors := range []bool{false, true} {
			if n := testing.AllocsPerRun(100, func() { _, _ = ix.DenyWriteTarget(p, ancestors) }); n != 0 {
				t.Errorf("FSIndex.DenyWriteTarget(%s, %v): %g allocations, want 0", p, ancestors, n)
			}
		}
		if p == "/h/tl/x" {
			// The Evaluator's walk of a path spelled through a link-declared write entry allocates with no deny_write
			// rule in the table at all (3 allocations, measured): not this question's cost.
			continue
		}
		for _, kind := range []agent.ActionKind{agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir, agent.ActionFSRename} {
			a := agent.Action{Kind: kind, Path: p, DestPath: "/h/y"}
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierBPFLSM} {
				if n := testing.AllocsPerRun(100, func() { evaluatorSink = ev.Evaluate(a, tier) }); n != 0 {
					t.Errorf("Evaluator %s %s %s: %g allocations, want 0", tier, kind, p, n)
				}
			}
		}
	}
}

// TestPlaneRowsUserDenyWriteLinked in the plane rows: a file beneath the fs.deny_write directory entry
// with another hard link (RuleTable.DenyWriteLinked) has a row of its own, keyed at its inode, which refuses its
// modification under the entry, so a write through the other name meets it at the walk's first step.
func TestPlaneRowsUserDenyWriteLinked(t *testing.T) {
	rt := userDenyWriteTable()
	rt.DenyWriteLinked = []string{"/h/deploy/a"}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.Keyed, "/h/deploy/a") {
		t.Fatalf("the linked file must be keyed at its inode: Keyed %v", s.Keyed)
	}
	if v := s.Decide("/h/deploy/a", PlaneModify); v.Allow || v.Rule.Name(rt) != "fs.deny_write[./dl/]" {
		t.Errorf("the linked file's row: %+v, want refused under the entry", v)
	}
	base, err := CompilePlane(userDenyWriteTable())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(base.Keyed, "/h/deploy/a") {
		t.Error("with no linked file recorded, no row is keyed at /h/deploy/a")
	}
}

// TestUserDenyWriteLinkLeadingOut in the indexes and the plane rows: an fs.deny_write entry that is a
// symlink beneath the write entry /h leading out of every write entry (/h/ci -> /x/ci) is held at its own name. The
// supervisor's index and the Evaluator refuse removing, replacing or writing beneath the link, and the plane keys the
// link's own inode (a NoFollow row), whose modification and rename it refuses.
func TestUserDenyWriteLinkLeadingOut(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet}},
		DenyWrite: []agent.FSRule{
			{Kind: agent.FSDenyWrite, Path: "/h/ci", Raw: "./ci", Resolved: "/x/ci", Unenforced: true},
		},
	}
	const name = "fs.deny_write[./ci]"
	ix, ev := NewFSIndex(rt), NewEvaluator(rt)
	for _, a := range []agent.Action{
		{Kind: agent.ActionFSDelete, Path: "/h/ci"},
		{Kind: agent.ActionFSMkdir, Path: "/h/ci"},
		{Kind: agent.ActionFSWrite, Path: "/h/ci/pipeline.yml"},
		{Kind: agent.ActionFSRename, Path: "/h/ci", DestPath: "/h/moved"},
		{Kind: agent.ActionFSRename, Path: "/h/mine", DestPath: "/h/ci"},
	} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierBPFLSM} {
			if got := ev.Evaluate(a, tier); got.Verdict != agent.VerdictRefused || got.Rule != name {
				t.Errorf("Evaluator %s %s %s -> %s: %+v, want refused under %s", tier, a.Kind, a.Path, a.DestPath, got, name)
			}
		}
	}
	if r, ok := ix.DenyWriteTarget("/h/ci", false); !ok || r.RuleName() != name {
		t.Errorf("FSIndex at the link: %+v %v, want %s", r, ok, name)
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.NoFollow, "/h/ci") {
		t.Errorf("the link must be keyed at its own inode: NoFollow %v", s.NoFollow)
	}
	for _, q := range []PlaneQuestion{PlaneModify, PlaneRename} {
		if v := s.Decide("/h/ci", q); v.Allow || v.Rule.Name(rt) != name {
			t.Errorf("plane rows at the link q=%d: %+v, want refused under %s", q, v, name)
		}
	}
}
