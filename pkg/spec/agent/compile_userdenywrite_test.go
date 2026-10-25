// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// userDenyWriteProject lays out work/ with a deploy/ directory holding a file and a tmp/ directory beneath it.
func userDenyWriteProject(t *testing.T, f *fixture) (work, deploy string) {
	t.Helper()
	work = filepath.Join(f.project, "work")
	deploy = filepath.Join(work, "deploy")
	if err := os.MkdirAll(filepath.Join(deploy, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(deploy, "a"), "x", 0o644)
	f.file(filepath.Join(work, "ok.txt"), "x", 0o644)
	return work, deploy
}

// userDenyWriteRules is the table's fs.deny_write entries (not built in).
func userDenyWriteRules(rt *RuleTable) []FSRule {
	var out []FSRule
	for _, r := range rt.DenyWrite {
		if !r.BuiltIn {
			out = append(out, r)
		}
	}
	return out
}

// TestUserDenyWriteRefusesEveryModification is ADR 0071 (1) and (4): an fs.deny_write entry beneath a write entry
// compiles to a deny_write rule of its own, kept apart from the built-in set (BuiltIn false), named after the entry as
// declared, and every modification at or beneath it is refused in every enforcing tier's model, a rename at either end
// and a hard link out of it included, while the rest of the write entry stays writable. Compile warns once per entry,
// saying it is best effort at tier landlock and what that means.
func TestUserDenyWriteRefusesEveryModification(t *testing.T) {
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n  deny_write: [\"work/deploy/\"]\n"))
	user := userDenyWriteRules(rt)
	if len(user) != 1 || user[0].Kind != FSDenyWrite || !user[0].Unenforced || user[0].Raw != "work/deploy/" ||
		user[0].Resolved != deploy || user[0].Pos.Line == 0 || user[0].RuleName() != "fs.deny_write[work/deploy/]" {
		t.Fatalf("user entries %+v: want one positioned, unenforced deny_write rule named fs.deny_write[work/deploy/]", user)
	}
	for _, r := range rt.FS {
		if r.Kind == FSDenyWrite {
			t.Errorf("a deny_write entry must stay out of rt.FS: %+v", r)
		}
	}
	const rule = "fs.deny_write[work/deploy/]"
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, a := range []Action{
			{Kind: ActionFSWrite, Path: filepath.Join(deploy, "a")},
			{Kind: ActionFSWrite, Path: filepath.Join(deploy, "new")},
			{Kind: ActionFSDelete, Path: filepath.Join(deploy, "a")},
			{Kind: ActionFSDelete, Path: deploy},
			{Kind: ActionFSMkdir, Path: filepath.Join(deploy, "sub")},
			{Kind: ActionFSRename, Path: filepath.Join(work, "ok.txt"), DestPath: filepath.Join(deploy, "b")},
			{Kind: ActionFSRename, Path: filepath.Join(deploy, "a"), DestPath: filepath.Join(work, "a")},
			{Kind: ActionFSRename, Path: deploy, DestPath: filepath.Join(work, "deploy.old")},
			{Kind: ActionFSRename, Path: work, DestPath: filepath.Join(f.project, "work.old")},
			{Kind: ActionFSLink, Path: filepath.Join(deploy, "a"), DestPath: filepath.Join(work, "alias")},
		} {
			got := rt.Evaluate(a, tier)
			if got.Verdict != VerdictRefused {
				t.Errorf("%s %s %s -> %s: %+v, want refused", tier, a.Kind, a.Path, a.DestPath, got)
				continue
			}
			if a.Kind != ActionFSRename && a.Kind != ActionFSLink && got.Rule != rule {
				t.Errorf("%s %s %s: rule %q, want %q", tier, a.Kind, a.Path, got.Rule, rule)
			}
		}
		// A chmod, chown or xattr change is refused only where a decision plane decides (SEMANTICS §1), as beneath a
		// built-in target: the model's tier landlock and tier cgroup (its listener) allow it.
		attr := rt.Evaluate(Action{Kind: ActionFSAttr, Path: filepath.Join(deploy, "a")}, tier)
		if want := tier == backend.TierBPFLSM; (attr.Verdict == VerdictRefused) != want || (want && attr.Rule != rule) {
			t.Errorf("%s: chmod beneath the entry: %+v, want refused only where the plane decides", tier, attr)
		}
		if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(work, "ok.txt")}, tier); got.Verdict != VerdictAllow {
			t.Errorf("%s: a write beside the entry: %+v, want allowed", tier, got)
		}
		if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(deploy, "a")}, tier); got.Verdict != VerdictAllow {
			t.Errorf("%s: a read of the entry: %+v, want allowed", tier, got)
		}
	}
	var warned []Diagnostic
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, rule) {
			warned = append(warned, d)
		}
	}
	if len(warned) != 1 || warned[0].IsError() || warned[0].Line == 0 || !strings.Contains(warned[0].Message, "best effort at tier landlock") ||
		!strings.Contains(warned[0].Message, UserDenyWriteLabel) || !strings.Contains(warned[0].Fix, "fs.assurance: kernel") {
		t.Errorf("want one positioned best-effort warning naming the entry, the label and the fix:\n%s", render(ds))
	}
	var buf bytes.Buffer
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "best effort at tier landlock") {
		t.Errorf("compile's table must mark the entry:\n%s", buf.String())
	}
}

// TestUserDenyWriteNearestWins is ADR 0071 (1)'s nearest wins: a write entry strictly beneath an fs.deny_write entry
// reopens its own subtree, in every enforcing tier's model, and is no redundant entry (E10) though another write entry
// covers it; a modification beside it inside the deny_write entry stays refused, and so does a rename that carries a
// file out of the reopened subtree into the entry.
func TestUserDenyWriteNearestWins(t *testing.T) {
	f := newFixture(t)
	_, deploy := userDenyWriteProject(t, f)
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"work/deploy/tmp/\"]\n  deny_write: [\"work/deploy/\"]\n"))
	if hasCode(ds, CodeRedundantRule) {
		t.Errorf("a write entry that reopens a deny_write entry's subtree is not redundant:\n%s", render(ds))
	}
	tmp := filepath.Join(deploy, "tmp")
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, p := range []string{filepath.Join(tmp, "x"), filepath.Join(tmp, "sub", "y")} {
			if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: p}, tier); got.Verdict != VerdictAllow || got.Rule != "fs.write[work/deploy/tmp/]" {
				t.Errorf("%s: write %s: %+v, want allowed by the nested write entry", tier, p, got)
			}
		}
		if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(deploy, "a")}, tier); got.Verdict != VerdictRefused ||
			got.Rule != "fs.deny_write[work/deploy/]" {
			t.Errorf("%s: write beside the reopened subtree: %+v, want refused", tier, got)
		}
		if got := rt.Evaluate(Action{Kind: ActionFSRename, Path: filepath.Join(tmp, "x"), DestPath: filepath.Join(deploy, "x")}, tier); got.Verdict != VerdictRefused {
			t.Errorf("%s: a rename from the reopened subtree into the entry: %+v, want refused", tier, got)
		}
	}
	// The predicate itself: the reopened subtree, and its root, reach no target; a rename of a directory above the
	// entry does.
	for p, want := range map[string]bool{filepath.Join(tmp, "x"): false, tmp: false, filepath.Join(deploy, "a"): true, deploy: true} {
		if _, ok := rt.DenyWriteTarget(p, false); ok != want {
			t.Errorf("DenyWriteTarget(%s) = %v, want %v", p, ok, want)
		}
	}
	if _, ok := rt.DenyWriteTarget(filepath.Dir(deploy), true); !ok {
		t.Error("a rename of the directory above the entry must reach it")
	}
}

// TestUserDenyWriteReopenSpellings holds the nearest-wins predicate to every spelling the supervisor matches: the
// entry declared through a symlink, the nested write entry declared through another, and a path spelled through
// either reach the same answer as the resolved spelling.
func TestUserDenyWriteReopenSpellings(t *testing.T) {
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	if err := os.Symlink("deploy", filepath.Join(work, "dl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("deploy", "tmp"), filepath.Join(work, "tl")); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"work/tl/\"]\n  deny_write: [\"work/dl/\"]\n"))
	if len(userDenyWriteRules(rt)) != 1 {
		t.Fatalf("want the entry compiled: %+v", rt.DenyWrite)
	}
	for _, p := range []string{filepath.Join(deploy, "tmp", "x"), filepath.Join(work, "dl", "tmp", "x"), filepath.Join(work, "tl", "x")} {
		if r, ok := rt.DenyWriteTarget(p, false); ok {
			t.Errorf("%s: reached %s, want the nested write entry to reopen it at every spelling", p, r.RuleName())
		}
	}
	for _, p := range []string{filepath.Join(deploy, "a"), filepath.Join(work, "dl", "a")} {
		if _, ok := rt.DenyWriteTarget(p, false); !ok {
			t.Errorf("%s: want the entry to reach it", p)
		}
	}
}

// TestUserDenyWriteContradictionAndRedundancy is ADR 0071 (1)'s placement rules: an entry at a write entry's own path is
// a contradiction error from any file; an entry outside every write entry, or beneath another fs.deny_write entry with
// no write entry between, is redundant-rule from the top-level file and silent from a profile; a missing entry is
// path-missing from the top-level file and an unenforced warning from a profile.
func TestUserDenyWriteContradictionAndRedundancy(t *testing.T) {
	f := newFixture(t)
	userDenyWriteProject(t, f)
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	if _, ds, err := f.compileErr(f.load(head + "fs:\n  write: [\"work/\", \"work/deploy/\"]\n  deny_write: [\"work/deploy\"]\n")); err == nil ||
		!slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeContradiction && d.IsError() && strings.Contains(d.Message, "fs.deny_write") && d.Fix != ""
		}) {
		t.Errorf("an entry at a write entry's path: want a contradiction error with a fix (err %v):\n%s", err, render(ds))
	}
	rt, ds := f.compile(f.load(head + "fs:\n  write: [\"work/deploy/tmp/\"]\n  deny_write: [\"config/\"]\n"))
	if len(userDenyWriteRules(rt)) != 0 || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeRedundantRule && strings.Contains(d.Message, "fs.deny_write") && d.Line != 0
	}) {
		t.Errorf("an entry outside every write entry: want no rule and a redundant-rule warning:\n%s", render(ds))
	}
	rt, ds = f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n  deny_write: [\"work/deploy/\", \"work/deploy/tmp/\"]\n"))
	if len(userDenyWriteRules(rt)) != 1 || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeRedundantRule && strings.Contains(d.Message, "work/deploy/tmp/")
	}) {
		t.Errorf("an entry beneath another: want one rule and a redundant-rule warning:\n%s", render(ds))
	}
	if _, ds, err := f.compileErr(f.load(head + "fs:\n  write: [\"work/\"]\n  deny_write: [\"work/nothing\"]\n")); err == nil ||
		!slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodePathMissing && d.IsError() && d.Fix != "" }) {
		t.Errorf("a missing top-level entry: want path-missing (err %v):\n%s", err, render(ds))
	}
	writeProfile(t, f, "dw", "version: 0\nname: dw\nfs:\n  deny_write: [\"config/\", \"work/nothing\", \"work/deploy/\"]\n")
	rt, ds = f.compile(f.load(head + "extends: dw\nfs:\n  write: [\"work/\"]\n"))
	if got := userDenyWriteRules(rt); len(got) != 1 || got[0].Raw != "work/deploy/" {
		t.Errorf("profile entries %+v: want work/deploy/ alone", got)
	}
	if hasCode(ds, CodeRedundantRule) || hasCode(ds, CodePathMissing) {
		t.Errorf("a profile's entry outside every write entry is silent, and its missing one only warns:\n%s", render(ds))
	}
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && !d.IsError() && strings.Contains(d.Message, "work/nothing") && strings.Contains(d.Message, "does not exist")
	}) {
		t.Errorf("a profile's missing entry beneath a write entry: want an unenforced warning:\n%s", render(ds))
	}
}

// TestUserDenyWriteGlobRefused: a glob character is a schema error with a fix at Load, never a pattern.
func TestUserDenyWriteGlobRefused(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	for _, entry := range []string{"work/*.yml", "work/?", "work/[ab]"} {
		f.file(path, "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n  deny_write: [\""+entry+"\"]\n", 0o644)
		_, ds, err := Load(path, f.profiles())
		if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeSchema && strings.Contains(d.Message, "fs.deny_write") && d.Fix != "" && d.Line != 0
		}) {
			t.Errorf("%q: want a positioned schema error with a fix (err %v):\n%s", entry, err, render(ds))
		}
	}
}

// TestUserDenyWriteUnion is ADR 0071 (2): across extends the entries are a union that never loses one, a contract's
// `deny_write: []` contributes nothing and removes neither a profile's entries nor the built-in set, and a user entry at
// a built-in target's path is a rule of its own beside the target, which it never removes.
func TestUserDenyWriteUnion(t *testing.T) {
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	if err := os.MkdirAll(filepath.Join(work, "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRepo(t, f, work)
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	writeProfile(t, f, "dwa", "version: 0\nname: dwa\nfs:\n  deny_write: [\"work/deploy/\"]\n")
	rt, _ := f.compile(f.load(head + "extends: dwa\nfs:\n  write: [\"work/\"]\n  deny_write: [\"work/ci/\"]\n"))
	var raws []string
	for _, r := range userDenyWriteRules(rt) {
		raws = append(raws, r.Raw)
	}
	if !slices.Equal(raws, []string{"work/deploy/", "work/ci/"}) {
		t.Errorf("merged entries %v, want the profile's then the contract's", raws)
	}
	base, _ := f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n"))
	builtIn := denyWritePaths(base)
	if len(builtIn) == 0 {
		t.Fatal("the fixture's repository must give the built-in set targets")
	}
	rt, _ = f.compile(f.load(head + "extends: dwa\nfs:\n  write: [\"work/\"]\n  deny_write: []\n"))
	if got := userDenyWriteRules(rt); len(got) != 1 || got[0].Resolved != deploy {
		t.Errorf("deny_write: [] over a profile's entry: %+v, want the profile's entry kept", got)
	}
	rt, _ = f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n  deny_write: []\n"))
	if got := denyWritePaths(rt); !slices.Equal(got, builtIn) {
		t.Errorf("deny_write: [] alone: set %v, want the built-in set %v unchanged", got, builtIn)
	}
	hooks := filepath.Join(work, ".git", "hooks")
	rt, _ = f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n  deny_write: [\"work/.git/hooks\"]\n"))
	var at []FSRule
	for _, r := range rt.DenyWrite {
		if r.Resolved == hooks {
			at = append(at, r)
		}
	}
	// Two rules, the declared one first, so it names a refusal it reaches, and the built-in target kept.
	if len(at) != 2 || at[0].BuiltIn || at[0].RuleName() != "fs.deny_write[work/.git/hooks]" || !at[1].BuiltIn {
		t.Errorf("rules at %s: %+v, want the declared entry and then the built-in target", hooks, at)
	}
	if r, ok := rt.DenyWriteTarget(filepath.Join(hooks, "pre-commit"), false); !ok || r.RuleName() != "fs.deny_write[work/.git/hooks]" {
		t.Errorf("a hook's write: %+v %v, want refused under the declared entry", r, ok)
	}
}

// TestUserDenyWriteAssurance is ADR 0071 (3) at compile: fs.assurance: kernel makes each entry an error at a pinned tier
// landlock, as for the built-in set; a pin to tier bpflsm, where the plane always decides, warns nothing; and run_start's
// best_effort lists fs.deny_write exactly where no plane decides, apart from deny_write/default.
func TestUserDenyWriteAssurance(t *testing.T) {
	f := newFixture(t)
	userDenyWriteProject(t, f)
	const c = "version: 0\nname: t\ncommand: [\"python\"]\n%sfs:\n  write: [\"work/\"]\n  deny_write: [\"work/deploy/\"]\n%s"
	finding := func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && strings.Contains(d.Message, "fs.deny_write[work/deploy/]")
	}
	if _, ds, err := f.compileErr(f.load(fmt.Sprintf(c, "tier: landlock\n", "  assurance: kernel\n"))); err == nil ||
		countDiagnostics(ds, func(d Diagnostic) bool { return finding(d) && d.IsError() && strings.Contains(d.Fix, "decision plane") }) != 1 {
		t.Errorf("kernel assurance at a pinned landlock: want one error (err %v):\n%s", err, render(ds))
	}
	if _, ds := f.compile(f.load(fmt.Sprintf(c, "tier: bpflsm\n", ""))); countDiagnostics(ds, finding) != 0 {
		t.Errorf("pinned bpflsm: nothing to warn:\n%s", render(ds))
	}
	rt, _ := f.compile(f.load(fmt.Sprintf(c, "", "")))
	if cells := rt.BestEffortCellsAt(backend.TierLandlock, ""); !slices.Contains(cells, BestEffortUserDenyWrite) || slices.Contains(cells, BestEffortDenyWrite) {
		t.Errorf("tier landlock cells %v: want %s alone (no built-in target)", cells, BestEffortUserDenyWrite)
	}
	if cells := rt.BestEffortCellsAt(backend.TierCgroup, record.DecisionPlaneFanotify); !slices.Contains(cells, BestEffortUserDenyWrite) {
		t.Errorf("tier cgroup on the listener %v: want %s", cells, BestEffortUserDenyWrite)
	}
	for _, at := range []struct {
		tier  backend.Tier
		plane string
	}{{backend.TierCgroup, record.DecisionPlaneLSM}, {backend.TierCgroup, record.DecisionPlaneFmodRet}, {backend.TierBPFLSM, record.DecisionPlaneLSM}} {
		if cells := rt.BestEffortCellsAt(at.tier, at.plane); slices.Contains(cells, BestEffortUserDenyWrite) {
			t.Errorf("%s/%s cells %v: a plane decides the entry", at.tier, at.plane, cells)
		}
	}
	a := Action{Kind: ActionFSWrite, Path: filepath.Join(f.project, "work", "deploy", "a")}
	if got := rt.BestEffortCellsFor(a, rt.Evaluate(a, backend.TierLandlock), backend.TierLandlock); !slices.Equal(got, []string{BestEffortUserDenyWrite}) {
		t.Errorf("compile --test cells for the refused write %v, want [%s]", got, BestEffortUserDenyWrite)
	}
}

// TestUserDenyWritePrintGolden is the printed table of a hand-built table with an fs.deny_write entry beside a
// built-in target, under both values of fs.assurance (ADR 0071 (3)): the entry is marked best effort at tier landlock,
// or kernel-plane-required, and the built-in target keeps its own marks.
func TestUserDenyWritePrintGolden(t *testing.T) {
	var buf bytes.Buffer
	for _, a := range []FSAssurance{FSAssuranceBestEffort, FSAssuranceKernel} {
		rt := &RuleTable{FSAssurance: a,
			FS: []FSRule{{Path: "/w", Resolved: "/w", Kind: FSWrite, Access: AccessWriteSet, Raw: "/w"}},
			DenyWrite: []FSRule{
				{Path: "/w/.git/hooks", Resolved: "/w/.git/hooks", Kind: FSDenyWrite, BuiltIn: true, Unenforced: true},
				{Path: "/w/deploy", Resolved: "/w/deploy", Kind: FSDenyWrite, Raw: "./deploy/", Unenforced: true},
			}}
		var one bytes.Buffer
		if err := PrintRuleTable(&one, rt); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(one.String(), "\n") {
			if strings.HasPrefix(line, "fs ") || strings.HasPrefix(line, "  KIND") || strings.Contains(line, "/w") {
				buf.WriteString(strings.TrimRight(line, " ") + "\n")
			}
		}
	}
	golden := filepath.Join("testdata", "print-user-deny-write.golden")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("printed table differs from %s:\n%s", golden, buf.String())
	}
}
