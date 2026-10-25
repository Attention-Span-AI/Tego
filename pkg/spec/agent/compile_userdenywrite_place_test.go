// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// refusesAsControl compiles contract and control and asserts every action is refused by both at every enforcing tier:
// adding the contract's fs.deny_write entries never loosens what the control refuses.
func refusesAsControl(t *testing.T, f *fixture, contract, control string, actions []Action) *RuleTable {
	t.Helper()
	ctl, _ := f.compile(f.load(control))
	rt, _ := f.compile(f.load(contract))
	for _, tier := range enforcingTiers() {
		for _, a := range actions {
			if got := ctl.Evaluate(a, tier); got.Verdict != VerdictRefused {
				t.Fatalf("control %s %s %s -> %s: %s %s, want refused (the fixture is wrong)", tier, a.Kind, a.Path, a.DestPath, got.Verdict, got.Rule)
			}
			if got := rt.Evaluate(a, tier); got.Verdict != VerdictRefused {
				t.Errorf("%s %s %s -> %s: %s %s, want refused as without the fs.deny_write entry", tier, a.Kind, a.Path, a.DestPath, got.Verdict, got.Rule)
			}
		}
	}
	return rt
}

// TestUserDenyWriteKeepsBuiltInTarget and F1: an fs.deny_write entry at a built-in target's place never
// removes the target, so adding the entry loosens nothing R20 refuses. (a) a write entry strictly inside the place
// still grants nothing beneath the built-in target, which is never reopened; (b) the target's link spelling stays held
// when the entry names where the link leads; (c) a profile's entry at a dangling-symlink target, which compile drops,
// leaves the target in place. Where the entry reaches, the refusal names it, as declared.
func TestUserDenyWriteKeepsBuiltInTarget(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	t.Run("nested write entry", func(t *testing.T) {
		f := newFixture(t)
		out := filepath.Join(f.project, "out")
		claude := filepath.Join(out, ".claude")
		if err := os.MkdirAll(filepath.Join(claude, "projects"), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(claude, "settings.json"), "{}", 0o644)
		write := "fs:\n  write: [\"out/\", \"out/.claude/projects/\"]\n"
		rt := refusesAsControl(t, f, head+write+"  deny_write: [\"out/.claude/\"]\n", head+write, []Action{
			{Kind: ActionFSWrite, Path: filepath.Join(claude, "projects", "x")},
			{Kind: ActionFSWrite, Path: filepath.Join(claude, "settings.json")},
			{Kind: ActionFSDelete, Path: filepath.Join(claude, "projects")},
		})
		if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(claude, "settings.json")}, backend.TierLandlock); got.Rule != "fs.deny_write[out/.claude/]" {
			t.Errorf("where the declared entry reaches, it names the refusal: %+v", got)
		}
		builtIn := slices.ContainsFunc(rt.DenyWrite, func(r FSRule) bool { return r.BuiltIn && r.Resolved == claude })
		if !builtIn {
			t.Errorf("the built-in target at %s must stay in the table: %+v", claude, rt.DenyWrite)
		}
	})
	t.Run("git repository", func(t *testing.T) {
		f := newFixture(t)
		work := filepath.Join(f.project, "work")
		if err := os.MkdirAll(filepath.Join(work, ".claude", "commands"), 0o755); err != nil {
			t.Fatal(err)
		}
		gitRepo(t, f, work)
		write := "fs:\n  write: [\"work/\", \"work/.claude/commands\"]\n"
		refusesAsControl(t, f, head+write+"  deny_write: [\"work/.claude\"]\n", head+write, []Action{
			{Kind: ActionFSWrite, Path: filepath.Join(work, ".claude", "commands", "x.md")},
		})
		// Through extends too: a profile's entry at the place changes nothing the top-level nested write entry grants.
		writeProfile(t, f, "dwc", "version: 0\nname: dwc\nfs:\n  deny_write: [\"work/.claude\"]\n")
		refusesAsControl(t, f, head+"extends: dwc\n"+write, head+write, []Action{
			{Kind: ActionFSWrite, Path: filepath.Join(work, ".claude", "commands", "x.md")},
		})
	})
	t.Run("link spelling", func(t *testing.T) {
		f := newFixture(t)
		out := filepath.Join(f.project, "out")
		dot := filepath.Join(out, "dotclaude")
		if err := os.MkdirAll(dot, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(dot, "settings.json"), "{}", 0o644)
		if err := os.Symlink("dotclaude", filepath.Join(out, ".claude")); err != nil {
			t.Fatal(err)
		}
		write := "fs:\n  write: [\"out/\"]\n"
		link := filepath.Join(out, ".claude")
		rt := refusesAsControl(t, f, head+write+"  deny_write: [\"out/dotclaude/\"]\n", head+write, []Action{
			{Kind: ActionFSDelete, Path: link},
			{Kind: ActionFSMkdir, Path: link},
			{Kind: ActionFSWrite, Path: filepath.Join(link, "settings.json")},
			{Kind: ActionFSWrite, Path: filepath.Join(dot, "settings.json")},
		})
		if r, ok := rt.DenyWriteTarget(link, false); !ok || !r.BuiltIn {
			t.Errorf("the link %s: %+v %v, want the built-in target, which holds the link's own name", link, r, ok)
		}
	})
	t.Run("dangling symlink from a profile", func(t *testing.T) {
		f := newFixture(t)
		out := filepath.Join(f.project, "out")
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		mcp := filepath.Join(out, ".mcp.json")
		if err := os.Symlink("nowhere.json", mcp); err != nil {
			t.Fatal(err)
		}
		writeProfile(t, f, "dwm", "version: 0\nname: dwm\nfs:\n  deny_write: [\"out/.mcp.json\"]\n")
		write := "fs:\n  write: [\"out/\"]\n"
		refusesAsControl(t, f, head+"extends: dwm\n"+write, head+write, []Action{
			{Kind: ActionFSWrite, Path: mcp},
			{Kind: ActionFSDelete, Path: mcp},
		})
	})
}

// TestUserDenyWriteReopenName and F2: the reopening write entry's own name in the fs.deny_write
// directory is the entry's, as the plane keys it. A rename of it, away or into it, and a create of it (a mkdir, a hard
// link's new name) are refused, so the agent cannot plant an object of its own at deploy/tmp; what lies beneath it
// stays writable and movable, and the object it names stays writable and removable, as the write entry grants (the
// plane decides a removal on the object's own row, which the write entry's is).
func TestUserDenyWriteReopenName(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	tmp := filepath.Join(deploy, "tmp")
	rt, _ := f.compile(f.load(head + "fs:\n  write: [\"work/\", \"work/deploy/tmp/\", \"work/deploy/a\"]\n  deny_write: [\"work/deploy/\"]\n"))
	const rule = "fs.deny_write[work/deploy/]"
	a := filepath.Join(deploy, "a")
	for _, tier := range enforcingTiers() {
		for _, act := range []Action{
			{Kind: ActionFSRename, Path: tmp, DestPath: filepath.Join(work, "t2")},
			{Kind: ActionFSRename, Path: filepath.Join(work, "ok.txt"), DestPath: tmp},
			{Kind: ActionFSMkdir, Path: tmp},
			{Kind: ActionFSLink, Path: filepath.Join(work, "ok.txt"), DestPath: tmp},
			{Kind: ActionFSRename, Path: a, DestPath: filepath.Join(work, "a")},
			{Kind: ActionFSRename, Path: filepath.Join(work, "ok.txt"), DestPath: a},
		} {
			if got := rt.Evaluate(act, tier); got.Verdict != VerdictRefused || got.Rule != rule {
				t.Errorf("%s %s %s -> %s: %s %s, want refused under %s", tier, act.Kind, act.Path, act.DestPath, got.Verdict, got.Rule, rule)
			}
		}
		for _, act := range []Action{
			{Kind: ActionFSWrite, Path: filepath.Join(tmp, "x")},
			{Kind: ActionFSRename, Path: filepath.Join(tmp, "x"), DestPath: filepath.Join(tmp, "y")},
			{Kind: ActionFSMkdir, Path: filepath.Join(tmp, "sub")},
			{Kind: ActionFSDelete, Path: tmp},
			{Kind: ActionFSWrite, Path: a},
			{Kind: ActionFSDelete, Path: a},
		} {
			if got := rt.Evaluate(act, tier); got.Verdict != VerdictAllow {
				t.Errorf("%s %s %s -> %s: %s %s, want allowed by the write entry", tier, act.Kind, act.Path, act.DestPath, got.Verdict, got.Rule)
			}
		}
	}
	for p, want := range map[string][3]bool{ // DenyWriteTarget(p, false), DenyWriteTarget(p, true), DenyWriteNameTarget(p)
		tmp: {false, true, true}, filepath.Join(tmp, "x"): {false, false, false}, a: {false, true, true},
		filepath.Join(deploy, "b"): {true, true, true},
	} {
		_, w := rt.DenyWriteTarget(p, false)
		_, r := rt.DenyWriteTarget(p, true)
		_, n := rt.DenyWriteNameTarget(p)
		if got := [3]bool{w, r, n}; got != want {
			t.Errorf("%s: modification, rename, name %v, want %v", p, got, want)
		}
	}
}

// TestUserDenyWriteLinkedFiles at compile: a regular file beneath an fs.deny_write directory entry with
// another hard link made before the run (out/a-alias for out/deploy/a) is recorded for the plane to key at its inode
// (RuleTable.DenyWriteLinked), since a write through the other name walks from that name's directory and reaches only
// the write entry; a file with one link, one in a subtree a nested write entry reopens, and a symlink are not. A search
// its bound cuts says so, positioned at the entry, at every tier (a pinned bpflsm too).
func TestUserDenyWriteLinkedFiles(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	if err := os.MkdirAll(filepath.Join(deploy, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(deploy, "sub", "b"), "x", 0o644)
	f.file(filepath.Join(deploy, "tmp", "c"), "x", 0o644)
	for src, alias := range map[string]string{
		filepath.Join(deploy, "a"): "a-alias", filepath.Join(deploy, "sub", "b"): "b-alias", filepath.Join(deploy, "tmp", "c"): "c-alias",
	} {
		if err := os.Link(src, filepath.Join(work, alias)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "ok.txt"), filepath.Join(deploy, "ln")); err != nil {
		t.Fatal(err)
	}
	contract := head + "%sfs:\n  write: [\"work/\", \"work/deploy/tmp/\"]\n  deny_write: [\"work/deploy/\"]\n"
	rt, ds := f.compile(f.load(fmt.Sprintf(contract, "")))
	want := []string{filepath.Join(deploy, "a"), filepath.Join(deploy, "sub", "b")}
	if !slices.Equal(rt.DenyWriteLinked, want) {
		t.Errorf("DenyWriteLinked %v, want %v", rt.DenyWriteLinked, want)
	}
	if slices.ContainsFunc(ds, func(d Diagnostic) bool { return strings.Contains(d.Message, "another hard link") }) {
		t.Errorf("a search no bound cut warns nothing of it:\n%s", render(ds))
	}
	// Past the bound on the files the plane keys: the search says it is cut, at every tier.
	for i := 0; i <= maxDenyWriteLinked; i++ {
		p := filepath.Join(deploy, "many", strconv.Itoa(i))
		if i == 0 {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		f.file(p, "x", 0o644)
		if err := os.Link(p, filepath.Join(work, "many-"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	for _, pin := range []string{"", "tier: bpflsm\n"} {
		rt, ds = f.compile(f.load(fmt.Sprintf(contract, pin)))
		if len(rt.DenyWriteLinked) != maxDenyWriteLinked || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeUnenforced && strings.Contains(d.Message, "another hard link") && strings.Contains(d.Message, "work/deploy/") && d.Line != 0
		}) {
			t.Errorf("pin %q: %d linked files, want %d and a positioned unenforced warning:\n%s", pin, len(rt.DenyWriteLinked), maxDenyWriteLinked, render(ds))
		}
	}
	// A table held at tier landlock, where no plane decides, is not searched.
	if rt, _ = f.compile(f.load(fmt.Sprintf(contract, "tier: landlock\n"))); len(rt.DenyWriteLinked) != 0 {
		t.Errorf("held at tier landlock: %d linked files recorded, want none", len(rt.DenyWriteLinked))
	}
}

// TestBuiltInDenyWriteLinkedFiles in R20: a hook beneath a built-in directory target with
// another hard link in the write grant is recorded for the plane too, whatever write entry lies inside the target.
func TestBuiltInDenyWriteLinkedFiles(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	hook := filepath.Join(work, ".git", "hooks", "pre-commit")
	f.file(hook, "#!/bin/sh\n", 0o755)
	if err := os.Link(hook, filepath.Join(work, "hook-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, ".git", "hooks", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(work, ".git", "hooks", "sub", "h")
	f.file(nested, "#!/bin/sh\n", 0o755)
	if err := os.Link(nested, filepath.Join(work, "nested-alias")); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"work/.git/hooks/sub/\"]\n"))
	for _, p := range []string{hook, nested} {
		if !slices.Contains(rt.DenyWriteLinked, p) {
			t.Errorf("DenyWriteLinked %v, want the linked hook %s", rt.DenyWriteLinked, p)
		}
	}
}

// link makes each new name a hard link of its old one (new: old).
func link(t *testing.T, links map[string]string) {
	t.Helper()
	for alias, src := range links {
		if err := os.Link(src, alias); err != nil {
			t.Fatal(err)
		}
	}
}

// TestUserDenyWriteLinkedOneRowPerFile: the plane keys one fs row per inode, and a table
// two of whose rows name one file runs on the fanotify listener at tier cgroup and is refused at tier bpflsm, so the
// linked-file search records at most one name per file, and none for a file no name outside the entries reaches or
// that another row the plane keys already refuses modifying. (a) two names of one file beneath the entry and none
// elsewhere: nothing, since each name refuses by its path; a third name outside: one, the first the walk meets. (b) a
// file beneath the entry linked to an fs.deny_write file entry, to a built-in file target (.git/config) or to a
// deny_read file: nothing, since that row holds the inode with a refusal of its own. (c) two hooks linked to each other
// beneath .git/hooks in a contract with no fs.deny_write at all (R20 alone): nothing. (d) a file beneath the entry
// linked to an fs.write file entry is a contradiction: one row answers every name of the file, and the two say
// opposite things of it.
func TestUserDenyWriteLinkedOneRowPerFile(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	f := newFixture(t)
	work, deploy := userDenyWriteProject(t, f)
	gitRepo(t, f, work)
	hooks := filepath.Join(work, ".git", "hooks")
	for _, p := range []string{filepath.Join(deploy, "p1"), filepath.Join(deploy, "t1"), filepath.Join(work, "conf.yml"), filepath.Join(work, "secret")} {
		f.file(p, "x", 0o644)
	}
	f.file(filepath.Join(hooks, "pre-commit"), "#!/bin/sh\n", 0o755)
	link(t, map[string]string{
		filepath.Join(deploy, "p2"): filepath.Join(deploy, "p1"),
		filepath.Join(deploy, "t2"): filepath.Join(deploy, "t1"), filepath.Join(work, "t-alias"): filepath.Join(deploy, "t1"),
		filepath.Join(deploy, "c"):       filepath.Join(work, "conf.yml"),
		filepath.Join(deploy, "g"):       filepath.Join(work, ".git", "config"),
		filepath.Join(deploy, "s"):       filepath.Join(work, "secret"),
		filepath.Join(hooks, "pre-push"): filepath.Join(hooks, "pre-commit"),
	})
	contract := head + "fs:\n  write: [\"work/\", \"work/deploy/tmp/\"]\n  deny_write: [\"work/deploy/\", \"work/conf.yml\"]\n" +
		"  deny_read: [\"work/secret\"]\n"
	rt, ds := f.compile(f.load(contract))
	if want := []string{filepath.Join(deploy, "t1")}; !slices.Equal(rt.DenyWriteLinked, want) {
		t.Errorf("DenyWriteLinked %v, want %v", rt.DenyWriteLinked, want)
	}
	if slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return strings.Contains(d.Message, "another hard link") || strings.Contains(d.Message, "under another name")
	}) {
		t.Errorf("no finding of the linked files is due:\n%s", render(ds))
	}
	// (c) R20 alone: the hooks linked to each other.
	if rt, _ = f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n")); len(rt.DenyWriteLinked) != 0 {
		t.Errorf("R20 alone: DenyWriteLinked %v, want none: both names of the hook lie beneath .git/hooks", rt.DenyWriteLinked)
	}
	// (d) a file beneath the entry is the fs.write file entry other/w under another name.
	if err := os.MkdirAll(filepath.Join(f.project, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "other", "w"), "x", 0o644)
	link(t, map[string]string{filepath.Join(deploy, "w"): filepath.Join(f.project, "other", "w")})
	_, ds, err := Compile(f.load(head+"fs:\n  write: [\"work/\", \"other/w\"]\n  deny_write: [\"work/deploy/\"]\n"), f.machine, f.opts()...)
	if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Severity == SeverityError && d.Code == CodeContradiction && d.Line != 0 &&
			strings.Contains(d.Message, filepath.Join(deploy, "w")) && strings.Contains(d.Message, "fs.write[other/w]")
	}) {
		t.Errorf("a linked file the write entry other/w also names: %v, want a positioned contradiction naming both:\n%s", err, render(ds))
	}
}

// TestUserDenyWriteLinkedSearchCutUnderKernel: under fs.assurance: kernel a
// linked-file search a bound cuts is a compile error, at a plane tier the contract pins and by default alike, since a
// file it did not reach may be written through another name where the setting promises a kernel refusal; by default
// it stays a warning. Each bound that counts (the files the plane keys, the levels beneath the entry) is tested.
func TestUserDenyWriteLinkedSearchCutUnderKernel(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n%sfs:\n  write: [\"work/\"]\n  deny_write: [\"work/deploy/\"]\n%s"
	cut := func(d Diagnostic) bool {
		return d.Code == CodeUnenforced && d.Line != 0 && strings.Contains(d.Message, "another hard link") && strings.Contains(d.Message, "work/deploy/")
	}
	for name, plant := range map[string]func(work, deploy string){
		"files": func(work, deploy string) {
			if err := os.MkdirAll(filepath.Join(deploy, "many"), 0o755); err != nil {
				t.Fatal(err)
			}
			for i := 0; i <= maxDenyWriteLinked; i++ {
				p := filepath.Join(deploy, "many", strconv.Itoa(i))
				if err := os.WriteFile(p, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				link(t, map[string]string{filepath.Join(work, "many-"+strconv.Itoa(i)): p})
			}
		},
		"depth": func(_, deploy string) {
			deep := deploy
			for i := 0; i <= maxDenyWriteLinkDepth; i++ {
				deep = filepath.Join(deep, "d")
			}
			if err := os.MkdirAll(deep, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			work, deploy := userDenyWriteProject(t, f)
			plant(work, deploy)
			for _, pin := range []string{"", "tier: bpflsm\n"} {
				_, ds := f.compile(f.load(fmt.Sprintf(head, pin, "")))
				if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return cut(d) && d.Severity == SeverityWarning }) {
					t.Errorf("pin %q, default assurance: want the cut as a positioned warning:\n%s", pin, render(ds))
				}
				_, ds, err := Compile(f.load(fmt.Sprintf(head, pin, "  assurance: kernel\n")), f.machine, f.opts()...)
				if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
					return cut(d) && d.Severity == SeverityError && strings.Contains(d.Message, "fs.assurance: kernel")
				}) {
					t.Errorf("pin %q, fs.assurance: kernel: %v, want the cut as a positioned error naming the setting:\n%s", pin, err, render(ds))
				}
			}
		})
	}
}

// refusesEverywhere asserts every action is refused at every enforcing tier.
func refusesEverywhere(t *testing.T, rt *RuleTable, actions []Action) {
	t.Helper()
	for _, tier := range enforcingTiers() {
		for _, a := range actions {
			if got := rt.Evaluate(a, tier); got.Verdict != VerdictRefused {
				t.Errorf("%s %s %s -> %s: %s %s, want refused", tier, a.Kind, a.Path, a.DestPath, got.Verdict, got.Rule)
			}
		}
	}
}

// replaceLink is what an agent does to a symlink beneath its write entry: remove it, make a directory in its place,
// or move it away, and write beneath the name.
func replaceLink(link string) []Action {
	return []Action{
		{Kind: ActionFSDelete, Path: link},
		{Kind: ActionFSMkdir, Path: link},
		{Kind: ActionFSRename, Path: link, DestPath: filepath.Join(filepath.Dir(link), "moved")},
		{Kind: ActionFSWrite, Path: filepath.Join(link, "pipeline.yml")},
	}
}

// TestDenyWriteHoldsLinkName: an entry is placed at both of its spellings, the place it leads to and
// its own name, so a symlink beneath a write entry leading out of every one is held at its name (not dropped as
// lying outside, with a redundant-rule message that was false), from the top-level file and from a profile; and an
// entry whose name lies outside the entry covering where it leads is not covered by it. The class's instance in R20:
// a built-in target that is a link leading out of every write entry is held at its name too.
func TestDenyWriteHoldsLinkName(t *testing.T) {
	const head = "version: 0\nname: t\ncommand: [\"python\"]\n"
	project := func(t *testing.T) (*fixture, string, string) {
		f := newFixture(t)
		out, ext := filepath.Join(f.project, "out"), filepath.Join(f.project, "ext", "ci")
		for _, d := range []string{filepath.Join(out, "deploy", "ci"), ext} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		f.file(filepath.Join(ext, "pipeline.yml"), "x", 0o644)
		if err := os.Symlink(filepath.Join("..", "ext", "ci"), filepath.Join(out, "ci")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("deploy", "ci"), filepath.Join(out, "ci-link")); err != nil {
			t.Fatal(err)
		}
		return f, out, ext
	}
	t.Run("entry leading out of every write entry", func(t *testing.T) {
		f, out, ext := project(t)
		link := filepath.Join(out, "ci")
		rt, ds := f.compile(f.load(head + "fs:\n  write: [\"out/\"]\n  deny_write: [\"out/ci\"]\n"))
		if hasCode(ds, CodeRedundantRule) {
			t.Errorf("the link lies beneath the write entry; nothing about it is redundant:\n%s", render(ds))
		}
		if got := userDenyWriteRules(rt); len(got) != 1 || got[0].Path != link || got[0].Resolved != ext {
			t.Fatalf("user entries %+v: want one held at the link %s, resolved to %s", got, link, ext)
		}
		refusesEverywhere(t, rt, replaceLink(link))
		writeProfile(t, f, "dwl", "version: 0\nname: dwl\nfs:\n  deny_write: [\"out/ci\"]\n")
		rt, _ = f.compile(f.load(head + "extends: dwl\nfs:\n  write: [\"out/\"]\n"))
		if len(userDenyWriteRules(rt)) != 1 {
			t.Fatalf("a profile's entry at the link: %+v, want it kept", rt.DenyWrite)
		}
		refusesEverywhere(t, rt, replaceLink(link))
	})
	t.Run("both spellings outside every write entry", func(t *testing.T) {
		f, _, _ := project(t)
		rt, ds := f.compile(f.load(head + "fs:\n  write: [\"out/deploy/\"]\n  deny_write: [\"out/ci\"]\n"))
		if len(userDenyWriteRules(rt)) != 0 || !hasCode(ds, CodeRedundantRule) {
			t.Errorf("an entry whose name and landing both lie outside every write entry: %+v, want it redundant:\n%s",
				userDenyWriteRules(rt), render(ds))
		}
	})
	t.Run("inner entry whose name lies outside the covering entry", func(t *testing.T) {
		f, out, _ := project(t)
		link := filepath.Join(out, "ci-link")
		rt, ds := f.compile(f.load(head + "fs:\n  write: [\"out/\"]\n  deny_write: [\"out/deploy/\", \"out/ci-link\"]\n"))
		if hasCode(ds, CodeRedundantRule) {
			t.Errorf("out/ci-link's own name lies outside out/deploy/, which does not cover it:\n%s", render(ds))
		}
		if got := userDenyWriteRules(rt); len(got) != 2 {
			t.Fatalf("user entries %+v: want both", got)
		}
		refusesEverywhere(t, rt, replaceLink(link))
	})
	t.Run("built-in target leading out of every write entry", func(t *testing.T) {
		f := newFixture(t)
		work := filepath.Join(f.project, "work")
		shared := filepath.Join(f.project, "shared", "claude")
		for _, d := range []string{work, shared} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		f.file(filepath.Join(shared, "settings.json"), "{}", 0o644)
		link := filepath.Join(work, ".claude")
		if err := os.Symlink(filepath.Join("..", "shared", "claude"), link); err != nil {
			t.Fatal(err)
		}
		rt, _ := f.compile(f.load(head + "fs:\n  write: [\"work/\"]\n"))
		if r, ok := rt.DenyWriteTarget(link, false); !ok || !r.BuiltIn || r.Path != link || r.Resolved != shared {
			t.Fatalf("the link %s: %+v %v, want the built-in target held at its own name", link, r, ok)
		}
		refusesEverywhere(t, rt, replaceLink(link))
	})
}
