// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// gitRepo lays out a non-bare repository's .git directory under dir.
func gitRepo(t *testing.T, f *fixture, dir string) {
	t.Helper()
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(dir, ".git", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", 0o644)
	f.file(filepath.Join(dir, ".git", "config"), "[core]\n", 0o644)
}

func denyWritePaths(rt *RuleTable) []string {
	var out []string
	for _, r := range rt.DenyWrite {
		out = append(out, r.Path)
	}
	slices.Sort(out)
	return out
}

// TestBuiltInDenyWriteSet: a write entry that is a repository's root reaches its git hooks and
// config, the harness settings and a shell startup file at its root, and a home dotfile that links into it;
// each is in the built-in deny_write set, unenforced and built in, kept out of rt.FS, and named in an
// unenforced warning of its own at the write entry (ADR 0041 D1 (a), as deny_read names each entry Landlock
// cannot hold). Evaluate answers refused, under the target's rule, for a write to one in each enforcing tier's
// model. By default (fs.assurance best-effort) a tier with no kernel decision plane runs the table with the
// supervisor's best-effort refusal, which the warning and the printed table say.
func TestBuiltInDenyWriteSet(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	if err := os.MkdirAll(filepath.Join(work, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(work, ".claude", "settings.json"), "{}", 0o644)
	f.file(filepath.Join(work, ".mcp.json"), "{}", 0o644)
	f.file(filepath.Join(work, ".bashrc"), "", 0o644)
	f.file(filepath.Join(work, "gitconfig"), "[user]\n", 0o644)
	if err := os.Symlink(filepath.Join(work, "gitconfig"), filepath.Join(f.home, ".gitconfig")); err != nil {
		t.Fatal(err)
	}

	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"))
	want := []string{
		filepath.Join(f.home, ".gitconfig"),
		filepath.Join(work, ".bashrc"), filepath.Join(work, ".claude"),
		filepath.Join(work, ".git", "config"), filepath.Join(work, ".git", "hooks"), filepath.Join(work, ".mcp.json"),
	}
	slices.Sort(want)
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v\nwant %v", got, want)
	}
	for _, r := range rt.DenyWrite {
		if r.Kind != FSDenyWrite || !r.BuiltIn || !r.Unenforced || r.RuleName() != "fs.deny_write["+r.Path+"]" {
			t.Errorf("%+v: want a built-in, unenforced deny_write rule named after its path", r)
		}
	}
	if r := rt.DenyWrite[slices.IndexFunc(rt.DenyWrite, func(r FSRule) bool { return strings.HasSuffix(r.Path, ".gitconfig") })]; r.Resolved != filepath.Join(work, "gitconfig") {
		t.Errorf("a home dotfile is governed where it resolves: %+v", r)
	}
	for _, r := range rt.FS {
		if r.Kind == FSDenyWrite {
			t.Errorf("the set must stay out of rt.FS, which every enforcing component walks: %+v", r)
		}
	}
	var warned []Diagnostic
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, "deny_write") {
			warned = append(warned, d)
		}
	}
	if len(warned) != len(rt.DenyWrite) {
		t.Fatalf("want one warning per target (%d), have %d:\n%s", len(rt.DenyWrite), len(warned), render(ds))
	}
	for _, r := range rt.DenyWrite {
		i := slices.IndexFunc(warned, func(d Diagnostic) bool { return strings.Contains(d.Message, r.RuleName()) })
		if i < 0 || warned[i].Line == 0 || warned[i].IsError() || !strings.Contains(warned[i].Message, "best effort") ||
			!strings.Contains(warned[i].Message, BestEffortDenyWrite) || !strings.Contains(warned[i].Fix, "fs.assurance: kernel") {
			t.Errorf("%s: want a positioned best-effort warning of its own naming %s and the fs.assurance fix:\n%s",
				r.RuleName(), BestEffortDenyWrite, render(ds))
		}
	}
	if !strings.Contains(render(ds), filepath.Join(work, ".git", "hooks")+" (git hooks)") {
		t.Errorf("the warnings must say what each target is:\n%s", render(ds))
	}
	if rt.FilesystemAssurance() != FSAssuranceBestEffort {
		t.Errorf("fs assurance %q, want the default %q", rt.FilesystemAssurance(), FSAssuranceBestEffort)
	}
	hook := filepath.Join(work, ".git", "hooks", "pre-commit")
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: hook}, tier)
		if got.Verdict != VerdictRefused || got.Rule != "fs.deny_write["+filepath.Join(work, ".git", "hooks")+"]" {
			t.Errorf("%s: %+v: the enforcing policy refuses a hook write beneath a write entry; unsupported launch must refuse preparation", tier, got)
		}
	}
	var buf bytes.Buffer
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "deny_write") || !strings.Contains(buf.String(), "best-effort(supervisor; landlock: parent writable)") ||
		strings.Contains(buf.String(), "kernel-plane-required") || strings.Contains(buf.String(), "assurance kernel") {
		t.Errorf("compile's table must show the set:\n%s", buf.String())
	}
}

// TestBuiltInDenyWriteNames: the names are the set compile holds, each where the set looks for it. A repository that
// is the write entry and holds every name (a git directory's beneath its .git), with the home directory's names
// linking into it as a dotfiles repository's do, has each of them held and nothing else; and a caller that changes
// the list it was given changes no one else's.
func TestBuiltInDenyWriteNames(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	for _, n := range BuiltInDenyWriteNames() {
		p := filepath.Join(work, n)
		if _, err := os.Lstat(p); err == nil {
			continue // .git/hooks and .git/config, which gitRepo made
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(p, "", 0o644)
	}
	for _, n := range denyWriteInHome {
		link := filepath.Join(f.home, n.name)
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(work, n.name), link); err != nil {
			t.Fatal(err)
		}
	}
	BuiltInDenyWriteNames()[0] = "changed by a caller"

	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"))
	held := map[string]bool{}
	for _, r := range rt.DenyWrite {
		rel, err := filepath.Rel(work, r.Path)
		if err != nil || !filepath.IsLocal(rel) {
			rel, _ = filepath.Rel(f.home, r.Path)
		}
		held[filepath.ToSlash(rel)] = true
	}
	names := BuiltInDenyWriteNames()
	for _, n := range names {
		if !held[n] {
			t.Errorf("BuiltInDenyWriteNames has %s, which compile does not hold: %v", n, denyWritePaths(rt))
		}
	}
	for n := range held {
		if !slices.Contains(names, n) {
			t.Errorf("compile holds %s, which BuiltInDenyWriteNames %v lacks", n, names)
		}
	}
}

// TestDenyWriteOptOut is R20's opt-out: naming a target in fs.write drops it from the set, and an entry
// inside a target keeps the target in the set; neither is reported as a redundant entry, which would tell
// the author to take the grant back.
func TestDenyWriteOptOut(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	if err := os.MkdirAll(filepath.Join(work, ".claude", "commands"), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"work/.git/hooks\", \"work/.claude/commands\"]\n"))
	want := []string{filepath.Join(work, ".claude"), filepath.Join(work, ".git", "config")}
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v, want %v", got, want)
	}
	if hasCode(ds, CodeRedundantRule) {
		t.Errorf("an entry that grants inside the set is not redundant:\n%s", render(ds))
	}
}

// TestDenyWriteGitLayouts covers the other places a write entry reaches git's hooks and config: a bare
// repository named directly, and a .git file (a submodule or linked worktree) whose gitdir lies under
// another write entry. A gitdir outside every write entry is left out, since nothing there is writable,
// and a write entry with no repository and no dotfile at its root adds nothing and warns nothing.
func TestDenyWriteGitLayouts(t *testing.T) {
	f := newFixture(t)
	bare := filepath.Join(f.project, "bare.git")
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(bare, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(bare, "HEAD"), "ref: refs/heads/main\n", 0o644)
	f.file(filepath.Join(bare, "config"), "[core]\n\tbare = true\n", 0o644)

	sub := filepath.Join(f.project, "sub")
	modules := filepath.Join(f.project, "modules")
	gitdir := filepath.Join(modules, "sub")
	for _, d := range []string{sub, filepath.Join(gitdir, "hooks")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(gitdir, "config"), "[core]\n", 0o644)
	f.file(filepath.Join(sub, ".git"), "gitdir: ../modules/sub\n", 0o644)

	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"bare.git/\", \"sub/\", \"modules/\"]\n"))
	want := []string{filepath.Join(bare, "config"), filepath.Join(bare, "hooks"), filepath.Join(gitdir, "config"), filepath.Join(gitdir, "hooks")}
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v, want %v", got, want)
	}

	rt, _ = f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"sub/\"]\n"))
	if len(rt.DenyWrite) != 0 {
		t.Errorf("a gitdir outside every write entry is not writable, so it is not in the set: %v", denyWritePaths(rt))
	}
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"out/\"]\n"))
	if len(rt.DenyWrite) != 0 || strings.Contains(render(ds), "deny_write") {
		t.Errorf("out/ reaches nothing in the set:\n%v\n%s", denyWritePaths(rt), render(ds))
	}
}

// compileWithin compiles c in a goroutine and fails the test when Compile has not returned after limit: the
// planted-file cases below hung or exhausted memory before the reads were bounded, and a hung test binary
// says nothing about which case did it.
func compileWithin(t *testing.T, f *fixture, c *Contract, limit time.Duration) *RuleTable {
	t.Helper()
	rt, _ := compileWithinDiags(t, f, c, limit)
	return rt
}

// compileWithinDiags is compileWithin that also returns the compile's diagnostics.
func compileWithinDiags(t *testing.T, f *fixture, c *Contract, limit time.Duration) (*RuleTable, []Diagnostic) {
	t.Helper()
	type result struct {
		rt  *RuleTable
		ds  []Diagnostic
		err error
	}
	done := make(chan result, 1)
	go func() {
		rt, ds, err := Compile(c, f.machine, f.opts()...)
		done <- result{rt, ds, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("compile: %v\n%s", r.err, render(r.ds))
		}
		return r.rt, r.ds
	case <-time.After(limit):
		t.Fatalf("compile did not return within %s", limit)
		return nil, nil
	}
}

// TestDenyWritePlantedPointers is I6 for the files R20 reads from where the agent can write: a .git file
// naming a gitdir the agent also controls, whose commondir is a FIFO or a link to /dev/zero, and a .git file
// that is a sparse file of several gigabytes with no newline. Read line by line, the FIFO blocked the
// operator's next compile for ever and the other two grew one string until the process ran out of memory.
// Each must now compile promptly, the planted pointer read as no pointer at all, and the gitdir the .git
// file names still found where it is an ordinary one.
func TestDenyWritePlantedPointers(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, f *fixture, work, gd string)
		// wantGitdir says the .git file is still read as a pointer, so the gitdir's hooks are in the set.
		wantGitdir bool
	}{
		{"commondir is a FIFO", func(t *testing.T, f *fixture, work, gd string) {
			if err := syscall.Mkfifo(filepath.Join(gd, "commondir"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"commondir links to /dev/zero", func(t *testing.T, f *fixture, work, gd string) {
			if err := os.Symlink("/dev/zero", filepath.Join(gd, "commondir")); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a sparse multi-gigabyte .git file", func(t *testing.T, f *fixture, work, gd string) {
			if err := os.Truncate(filepath.Join(work, ".git"), 8<<30); err != nil {
				t.Skipf("the filesystem under the test's temp dir holds no sparse file this large: %v", err)
			}
		}, false},
		{"a .git file over the bound", func(t *testing.T, f *fixture, work, gd string) {
			f.file(filepath.Join(work, ".git"), "gitdir: x"+strings.Repeat("y", maxGitFile), 0o644)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			work := filepath.Join(f.project, "work")
			gd := filepath.Join(work, "x")
			if err := os.MkdirAll(filepath.Join(gd, "hooks"), 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(work, ".git"), "gitdir: x", 0o644)
			tc.plant(t, f, work, gd)
			rt := compileWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"), 10*time.Second)
			hooks := filepath.Join(gd, "hooks")
			if got := slices.Contains(denyWritePaths(rt), hooks); got != tc.wantGitdir {
				t.Errorf("gitdir hooks in the set = %v, want %v: %v", got, tc.wantGitdir, denyWritePaths(rt))
			}
		})
	}
}

// TestReadSmall pins the bounded read R20's pointers and configs go through: a regular file within the bound
// is read, and a file over it, a FIFO, a device, a directory and (unless asked) a final symlink are not; nor
// is a file on a file system not known to store data, or one its owner holds a write lease on.
func TestReadSmall(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("gitdir: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 65), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(small, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		follow bool
		ok     bool
	}{
		{small, false, true},
		{big, false, false},
		{fifo, false, false},
		{"/dev/zero", true, false},
		{dir, false, false},
		{link, false, false},
		{link, true, true},
	} {
		data, ok := readSmall(tc.path, 64, tc.follow)
		if ok != tc.ok || (ok && string(data) != "gitdir: x\n") {
			t.Errorf("readSmall(%s, follow %v) = %q, %v; want ok %v", tc.path, tc.follow, data, ok, tc.ok)
		}
	}
	// Regular files of the kernel's own interfaces are refused by their file system before one is opened for
	// reading, as root too, where /proc/kmsg is one whose read waits for the next kernel message. Under a
	// config's bound fstat passes each (procfs reports size 0, sysfs a page), and ostype and uevent_seqnum are
	// readable by every user, so only the file-system check refuses them.
	for _, p := range []string{"/proc/sys/kernel/ostype", "/sys/kernel/uevent_seqnum", "/proc/kmsg"} {
		if data, ok := readSmall(p, maxGitConfig, true); ok {
			t.Errorf("readSmall(%s) = %q: a kernel interface file was read", p, data)
		}
	}
	// The file systems read are a list of those that store data, not a list of those to skip: a message
	// queue's file on mqueue, which no list of kernel interface file systems named, reads as its statistics.
	if mq := mqueueFile(t); mq != "" {
		if data, ok := readSmall(mq, maxGitConfig, true); ok {
			t.Errorf("readSmall(a message queue) = %q: a file system not known to store data was read", data)
		}
	}
	// A file under a write lease: the reopen for reading is O_NONBLOCK, so the lease answers EWOULDBLOCK at
	// once; without it, the open waited for the lease-break time, 45 s by default, on every such file.
	if lease := leased(t, []byte("gitdir: x\n")); lease != "" {
		within(t, "readSmall(a file under a write lease)", func() {
			if data, ok := readSmall(lease, 64, false); ok {
				t.Errorf("readSmall(a file under a write lease) = %q: read without breaking the lease", data)
			}
		})
	}
}

// TestDenyWriteHooksPath is R20's core.hooksPath: git runs a repository's hooks from the directory it names
// instead of the git directory's hooks/, so that directory is in the set when it lies beneath a write entry.
// Husky 9 sets .husky/_, whose scripts run the hook of the same name in .husky, where the hooks a user edits
// are, so .husky is the target; Husky 5 to 8 set .husky itself, and a .githooks directory is the other common
// layout. A hooksPath in the user's global git config applies to every repository, relative to its root.
func TestDenyWriteHooksPath(t *testing.T) {
	const repoConfig, worktreeConfig, globalConfig = ".git/config", ".git/config.worktree", "~/.gitconfig"
	cases := []struct {
		name, config, dir, want string
		file                    string
	}{
		{"Husky 9", "[core]\n\thooksPath = .husky/_\n", ".husky/_", ".husky", repoConfig},
		{"Husky 8", "[core]\n\thooksPath = .husky\n", ".husky", ".husky", repoConfig},
		{".githooks, quoted and commented", "[Core]\n\tHooksPath = \".githooks\" # team hooks\n", ".githooks", ".githooks", repoConfig},
		{"one-line section", "[core] hooksPath=.githooks\n", ".githooks", ".githooks", repoConfig},
		{"in the global config", "[core]\n\thooksPath = .githooks\n", ".githooks", ".githooks", globalConfig},
		// A linked worktree with extensions.worktreeConfig reads config.worktree after config.
		{"in config.worktree", "[core]\n\thooksPath = .githooks\n", ".githooks", ".githooks", worktreeConfig},
		// Git uses the last assignment; many earlier ones must not push it out of what is read.
		{"the last of many", decoys(3*maxHooksValues) + "[core]\n\thooksPath = .githooks\n", ".githooks", ".githooks", repoConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			work := filepath.Join(f.project, "work")
			gitRepo(t, f, work)
			if err := os.MkdirAll(filepath.Join(work, tc.dir), 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(work, tc.want, "pre-commit"), "#!/bin/sh\n", 0o755)
			switch tc.file {
			case globalConfig:
				f.file(filepath.Join(f.home, ".gitconfig"), tc.config, 0o644)
			default:
				f.file(filepath.Join(work, tc.file), tc.config, 0o644)
			}
			rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"))
			target := filepath.Join(work, tc.want)
			if !slices.Contains(denyWritePaths(rt), target) {
				t.Fatalf("deny_write set %v lacks the core.hooksPath directory %s", denyWritePaths(rt), target)
			}
			if tc.want != tc.dir && slices.Contains(denyWritePaths(rt), filepath.Join(work, tc.dir)) {
				t.Errorf("%s is beneath %s, which covers it", tc.dir, tc.want)
			}
			if !strings.Contains(render(ds), target+" (git hooks (core.hooksPath))") {
				t.Errorf("the warning must name the hooks directory:\n%s", render(ds))
			}
		})
	}
	// An absolute core.hooksPath in the global config is in the set wherever it lies beneath a write entry,
	// whether or not a repository is found there.
	f := newFixture(t)
	shared := filepath.Join(f.project, "tools", "hooks")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.home, ".gitconfig"), "[core]\n\thooksPath = "+shared+"\n", 0o644)
	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"tools/\"]\n"))
	if !slices.Contains(denyWritePaths(rt), shared) {
		t.Errorf("deny_write set %v lacks the global hooks directory %s", denyWritePaths(rt), shared)
	}
}

// decoys is n distinct core.hooksPath assignments, each in its own [core] section.
func decoys(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("[core]\n\thooksPath = decoy" + strconv.Itoa(i) + "\n")
	}
	return b.String()
}

// TestHooksPathsParse pins the part of git's config syntax hooksPaths reads.
func TestHooksPathsParse(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   []string
	}{
		{"[core]\n\thooksPath = a\n", []string{"a"}},
		{"[core]\nhookspath=\"b c\"\n", []string{"b c"}},
		{"[core]\n\thooksPath = d ; comment\n", []string{"d"}},
		{"[core]\n\thooksPath = \"e;f\"\n", []string{"e;f"}},
		{"[core]\n\thooksPath = g\\\\h\n", []string{"g\\h"}},
		{"[core \"x\"]\n\thooksPath = no\n", nil},
		{"[user]\n\thooksPath = no\n[core]\n\teditor = vi\n", nil},
		{"[core]\n\thooksPath = one\n[core]\n\thooksPath = two\n", []string{"one", "two"}},
		{"# [core]\n\thooksPath = no\n", nil},
		// A value the kernel refuses as a path name runs no hook, and is not a candidate.
		{"[core]\n\thooksPath = " + strings.Repeat("l/", pathMax/2-1) + "xy\n", nil},
		{"[core]\n\thooksPath = " + strings.Repeat("l/", pathMax/2-1) + "x\n", []string{strings.Repeat("l/", pathMax/2-1) + "x"}},
	} {
		if got := hooksPaths([]byte(tc.config)); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.config, got, tc.want)
		}
	}
}

// TestDenyWriteOtherHarnessSettings is R20 for the project settings of the other harnesses and of an
// editor: Cursor's .cursor/mcp.json (CVE-2025-54135/54136), Codex's .codex, Gemini's .gemini and VS Code's
// .vscode/tasks.json each name commands the user's next session runs, at a write entry's root and at a
// repository's found beneath one. .idea and .gitmodules are R20's accepted residuals and stay writable.
func TestDenyWriteOtherHarnessSettings(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.project, "src")
	repo := filepath.Join(src, "a")
	gitRepo(t, f, repo)
	names := []string{".cursor", ".codex", ".gemini", ".vscode"}
	for _, dir := range []string{src, repo} {
		for _, n := range append(names, ".idea") {
			if err := os.MkdirAll(filepath.Join(dir, n), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		f.file(filepath.Join(dir, ".gitmodules"), "", 0o644)
	}

	rt, _ := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"))
	want := []string{filepath.Join(repo, ".git", "config"), filepath.Join(repo, ".git", "hooks")}
	for _, dir := range []string{src, repo} {
		for _, n := range names {
			want = append(want, filepath.Join(dir, n))
		}
	}
	slices.Sort(want)
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v\nwant %v", got, want)
	}
}

// TestDenyWriteNestedRepositories is R20 for a write entry above repositories rather than at one (fs.write:
// ["~/src"]): each repository found beneath it, to maxRepoDepth levels, contributes its git hooks and config
// and the harness settings at its root, and a submodule's git directory under a repository's .git/modules
// contributes its own. The search stops at its bounds and the warning says so.
func TestDenyWriteNestedRepositories(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.project, "src")
	a := filepath.Join(src, "a")
	deep := filepath.Join(src, "org", "team", "b")
	gitRepo(t, f, a)
	gitRepo(t, f, deep)
	if err := os.MkdirAll(filepath.Join(a, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(a, ".git", "modules", "lib", "x")
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(mod, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(mod, "HEAD"), "ref: refs/heads/main\n", 0o644)
	f.file(filepath.Join(mod, "config"), "[core]\n", 0o644)
	tooDeep := filepath.Join(src, "1", "2", "3", "4", "c")
	gitRepo(t, f, tooDeep)
	// A package manager's tree is not searched: node_modules holds thousands of directories, and a package
	// checked out with its .git is the package's, not the author's.
	gitRepo(t, f, filepath.Join(src, "node_modules", "pkg"))

	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"src/\"]\n"))
	want := []string{
		filepath.Join(a, ".claude"),
		filepath.Join(a, ".git", "config"), filepath.Join(a, ".git", "hooks"),
		filepath.Join(mod, "config"), filepath.Join(mod, "hooks"),
		filepath.Join(deep, ".git", "config"), filepath.Join(deep, ".git", "hooks"),
	}
	slices.Sort(want)
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v\nwant %v", got, want)
	}
	if !strings.Contains(render(ds), "stops at 4 levels") {
		t.Errorf("a search that left a directory unsearched must say so:\n%s", render(ds))
	}
}

// TestReadDirBounded pins the listing R20 uses beneath directories the agent can write: at most max
// entries, more reported, and nothing from a FIFO or through a link standing where a directory was expected.
func TestReadDirBounded(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if es, more := readDirBounded(dir, 3); len(es) != 3 || !more {
		t.Errorf("max 3 of 5: %d entries, more %v", len(es), more)
	}
	if es, more := readDirBounded(dir, 5); len(es) != 5 || more || es[0].Name() != "a" || es[4].Name() != "e" {
		t.Errorf("all 5, sorted: %v, more %v", es, more)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, link, "/dev/zero"} {
		if es, _ := readDirBounded(p, 3); es != nil {
			t.Errorf("%s: listed %v", p, es)
		}
	}
}

// TestReadBoundedRefusesEAGAIN pins readSmall's read loop: a descriptor with nothing to read yet answers
// EAGAIN, which must refuse the file at once. Read through an *os.File, Go's poller parks the goroutine on
// EAGAIN until the descriptor is readable, which for /proc/kmsg as root is the next kernel message; a
// non-blocking pipe whose writer stays open and silent is the same wait without root.
func TestReadBoundedRefusesEAGAIN(t *testing.T) {
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(p[0]) })
	done := make(chan bool, 1)
	go func() {
		_, err := readBounded(p[0], 0, 64)
		done <- err == nil
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("a read that answered EAGAIN was taken as the file's content")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readBounded waited on EAGAIN instead of refusing")
	}
	// Within the bound, content is read to its end and nothing more; one byte past it, refused.
	if _, err := syscall.Write(p[1], []byte("gitdir: x\n")); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(p[1])
	if data, err := readBounded(p[0], 0, 64); err != nil || string(data) != "gitdir: x\n" {
		t.Errorf("readBounded = %q, %v; want the pipe's content", data, err)
	}
	var q [2]int
	if err := syscall.Pipe2(q[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(q[0]) })
	if _, err := syscall.Write(q[1], bytes.Repeat([]byte("a"), 65)); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(q[1])
	if data, err := readBounded(q[0], 0, 64); !errors.Is(err, errOverBound) {
		t.Errorf("65 bytes read under a bound of 64: %q, %v; want errOverBound", data, err)
	}
}

// TestDenyWriteKernelFileLinks is the case that hung the operator's next compile as root: a git config, a
// commondir and a global git config linked to /proc/kmsg, which the agent can plant in any write entry (and
// in the home directory when it is one). /proc/kmsg is a regular file of size 0, so the O_PATH and fstat
// checks passed it, and Go's poller parked the read on its EAGAIN. Compile must return promptly for every
// user; the case itself needs root, since only root opens /proc/kmsg for reading, and runs in the KVM guest
// (test/vm/kvm-run.sh, as docs/p0/agent-contract.md §10 says).
func TestDenyWriteKernelFileLinks(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	if err := os.Remove(filepath.Join(work, ".git", "config")); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{filepath.Join(work, ".git", "config"), filepath.Join(f.home, ".gitconfig")} {
		if err := os.Symlink("/proc/kmsg", link); err != nil {
			t.Fatal(err)
		}
	}
	linked := filepath.Join(f.project, "linked")
	gd := filepath.Join(linked, "gd")
	if err := os.MkdirAll(filepath.Join(gd, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(linked, ".git"), "gitdir: gd\n", 0o644)
	if err := os.Symlink("/proc/kmsg", filepath.Join(gd, "commondir")); err != nil {
		t.Fatal(err)
	}
	rt := compileWithin(t, f, f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"linked/\"]\n"), 10*time.Second)
	for _, want := range []string{filepath.Join(work, ".git", "hooks"), filepath.Join(gd, "hooks")} {
		if !slices.Contains(denyWritePaths(rt), want) {
			t.Errorf("deny_write set %v lacks %s", denyWritePaths(rt), want)
		}
	}
}

// TestDenyWriteCandidateLeadingNowhereIsDisclosed: a candidate that is a symlink leading nowhere yet (.git/hooks ->
// ../hk, hk not made) keeps the link in the set, but no tier holds the place it leads to, which the run may make
// beneath its write entry and fill with hooks git then runs: compile names that place and the fix. It said only that
// the entry reached .git/hooks, as for a hooks directory it held. A link whose target is there is held
// where it leads, with no such warning, and one leading nowhere outside every write entry gets none either, since the
// run cannot make its target.
func TestDenyWriteCandidateLeadingNowhereIsDisclosed(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	gitRepo(t, f, work)
	hooks := filepath.Join(work, ".git", "hooks")
	if err := os.RemoveAll(hooks); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../hk", hooks); err != nil {
		t.Fatal(err)
	}
	hk := filepath.Join(work, "hk")
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n")
	disclosed := func(ds []Diagnostic, place string) bool {
		return countDiagnostics(ds, func(d Diagnostic) bool {
			return d.Code == CodeUnenforced && strings.Contains(d.Message, "a symlink to "+place) &&
				strings.Contains(d.Message, "not there yet") && strings.Contains(d.Fix, place)
		}) == 1
	}
	rt, ds := compileWithinDiags(t, f, c, 10*time.Second)
	if !disclosed(ds, hk) {
		t.Errorf("a hooks link leading nowhere beneath the write entry is not disclosed once:\n%s", render(ds))
	}
	if !slices.Contains(denyWritePaths(rt), hooks) {
		t.Errorf("deny_write set %v no longer holds the link %s", denyWritePaths(rt), hooks)
	}
	if err := os.Mkdir(hk, 0o755); err != nil {
		t.Fatal(err)
	}
	rt, ds = compileWithinDiags(t, f, c, 10*time.Second)
	if disclosed(ds, hk) {
		t.Errorf("a hooks link whose target is there is disclosed as leading nowhere:\n%s", render(ds))
	}
	if !slices.ContainsFunc(rt.DenyWrite, func(r FSRule) bool { return r.Resolved == hk }) {
		t.Errorf("deny_write set %v does not hold %s, where the link leads", rt.DenyWrite, hk)
	}
	outside := filepath.Join(f.root, "outside", "hk")
	if err := os.Remove(hooks); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, hooks); err != nil {
		t.Fatal(err)
	}
	if _, ds := compileWithinDiags(t, f, c, 10*time.Second); disclosed(ds, outside) {
		t.Errorf("a hooks link leading nowhere outside every write entry is disclosed:\n%s", render(ds))
	}
}

// plantSharedGitDir lays out, beneath work, what an agent plants to multiply the search's work: a git
// directory work/shared whose modules/ holds modules empty directories, and repos directories each holding
// a .git file that names it, every other one through a link of its own (work/l<i>), so neither the path
// nor the text of the pointer says two of them are the same git directory.
func plantSharedGitDir(t *testing.T, f *fixture, work string, repos, modules int) string {
	t.Helper()
	shared := filepath.Join(work, "shared")
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(shared, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(shared, "HEAD"), "ref: refs/heads/main\n", 0o644)
	f.file(filepath.Join(shared, "config"), "[core]\n", 0o644)
	for i := 0; i < modules; i++ {
		if err := os.MkdirAll(filepath.Join(shared, "modules", "m"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < repos; i++ {
		name := "d" + strconv.Itoa(i)
		if err := os.Mkdir(filepath.Join(work, name), 0o755); err != nil {
			t.Fatal(err)
		}
		target := "../shared"
		if i%2 == 1 {
			if err := os.Symlink("shared", filepath.Join(work, "l"+strconv.Itoa(i))); err != nil {
				t.Fatal(err)
			}
			target = "../l" + strconv.Itoa(i)
		}
		f.file(filepath.Join(work, name, ".git"), "gitdir: "+target+"\n", 0o644)
	}
	return shared
}

// TestDenyWriteSharedGitDirPlant is the search's budget and its identity dedupe: thousands of directories
// beneath a write entry, each holding a .git file that names one git directory, half of them through a link
// of their own, whose modules/ is as wide. Each .git file made the search read that git directory's configs
// and walk its modules/ again, so compile's cost grew with the square of what the agent planted (minutes at
// a few thousand, a second's work to plant). It must now compile within seconds, name the shared git
// directory's hooks, and say the budget cut the search: the directories the search for repositories
// examines (2501) and those the walk of modules/ examines (2500) are each under 4096, and together over
// the one budget the write entry has. A second write entry has a budget of its own, so the plant does not
// hide the repository beneath it.
func TestDenyWriteSharedGitDirPlant(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	shared := plantSharedGitDir(t, f, work, 2500, 2500)
	other := filepath.Join(f.project, "other", "r")
	gitRepo(t, f, other)
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\", \"other/\"]\n")
	start := time.Now()
	rt := compileWithin(t, f, c, 10*time.Second)
	t.Logf("compiled in %s", time.Since(start))
	for _, want := range []string{filepath.Join(shared, "hooks"), filepath.Join(other, ".git", "hooks")} {
		if !slices.Contains(denyWritePaths(rt), want) {
			t.Errorf("deny_write set %v lacks %s", denyWritePaths(rt), want)
		}
	}
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(render(ds), "ran out of its budget") {
		t.Errorf("the warning must say the budget cut the search:\n%s", render(ds))
	}

	// Within the budget, the git directory is walked once, however many paths name it: 300 .git files, half
	// through links, over a modules/ of 50 cost about 350 directories examined, where walking it again for
	// each path, or for each distinct path, cost thousands and ran out of the budget.
	g := newFixture(t)
	work = filepath.Join(g.project, "work")
	shared = plantSharedGitDir(t, g, work, 300, 50)
	rt, ds = g.compile(g.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"))
	if !slices.Contains(denyWritePaths(rt), filepath.Join(shared, "hooks")) || strings.Contains(render(ds), "budget") {
		t.Errorf("one git directory named by 300 paths is walked once, within the budget: %v\n%s", denyWritePaths(rt), render(ds))
	}
}

// TestDenyWriteSearchBudgets pins the rest of the write entry's one budget, each spent by a layout that stays
// under every per-call bound: directory entries read across listings, bytes read across git configs, and
// candidate paths probed across repositories. Each ends the search with the warning saying so.
func TestDenyWriteSearchBudgets(t *testing.T) {
	const contract = "version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"work/\"]\n"
	cases := []struct {
		name  string
		plant func(t *testing.T, f *fixture, work string)
	}{
		{"entries: 17 directories of 4000 names", func(t *testing.T, f *fixture, work string) {
			gitRepo(t, f, filepath.Join(work, "repo"))
			for i := 0; i < 17; i++ {
				dir := filepath.Join(work, "wide"+strconv.Itoa(i))
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				one := filepath.Join(dir, "0")
				f.file(one, "", 0o644)
				for j := 1; j < 4000; j++ {
					if err := os.Link(one, filepath.Join(dir, strconv.Itoa(j))); err != nil {
						t.Fatal(err)
					}
				}
			}
		}},
		{"bytes: 70 repositories with a 256 KiB config", func(t *testing.T, f *fixture, work string) {
			for i := 0; i < 70; i++ {
				repo := filepath.Join(work, "r"+strconv.Itoa(i))
				gitRepo(t, f, repo)
				if err := os.Truncate(filepath.Join(repo, ".git", "config"), maxGitConfig); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"paths: 2000 repositories under 8 global hooks paths", func(t *testing.T, f *fixture, work string) {
			f.file(filepath.Join(f.home, ".gitconfig"), decoys(maxHooksValues), 0o644)
			gd := filepath.Join(work, "g")
			for _, d := range []string{"objects", "refs"} {
				if err := os.MkdirAll(filepath.Join(gd, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f.file(filepath.Join(gd, "HEAD"), "ref: refs/heads/main\n", 0o644)
			for i := 0; i < 2000; i++ {
				repo := filepath.Join(work, "r"+strconv.Itoa(i))
				if err := os.Mkdir(repo, 0o755); err != nil {
					t.Fatal(err)
				}
				f.file(filepath.Join(repo, ".git"), "gitdir: ../g\n", 0o644)
			}
			if err := os.MkdirAll(filepath.Join(work, "r0", ".claude"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			work := filepath.Join(f.project, "work")
			if err := os.Mkdir(work, 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(work, ".bashrc"), "", 0o644) // a target, so the entry has a warning to say it in
			tc.plant(t, f, work)
			if _, ds := f.compile(f.load(contract)); !strings.Contains(render(ds), "ran out of its budget") {
				t.Errorf("the search must spend the write entry's budget and say so:\n%s", render(ds))
			}
		})
	}
}

// TestDenyWriteEnclosingRepository is R20 for a write entry inside a repository rather than at or above one:
// git, run in the entry, uses the enclosing repository, whose core.hooksPath can name a directory beneath the
// entry. Husky's documented monorepo setup (`cd .. && husky frontend/.husky`) sets frontend/.husky/_ in the
// repository's config, and fs.write: ["./"] run from frontend/ left frontend/.husky writable and unnamed. A
// relative core.hooksPath in the global config is taken from the enclosing repository's root as well.
func TestDenyWriteEnclosingRepository(t *testing.T) {
	f := newFixture(t)
	mono := filepath.Join(f.project, "mono")
	gitRepo(t, f, mono)
	f.file(filepath.Join(mono, ".git", "config"), "[core]\n\thooksPath = frontend/.husky/_\n", 0o644)
	if err := os.MkdirAll(filepath.Join(mono, "frontend", ".husky", "_"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mono, "backend", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.home, ".gitconfig"), "[core]\n\thooksPath = backend/hooks\n", 0o644)

	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nfs:\n  write: [\"mono/frontend/\", \"mono/backend/\"]\n"))
	want := []string{filepath.Join(mono, "backend", "hooks"), filepath.Join(mono, "frontend", ".husky")}
	if got := denyWritePaths(rt); !slices.Equal(got, want) {
		t.Fatalf("deny_write set %v\nwant %v", got, want)
	}
	if !strings.Contains(render(ds), filepath.Join(mono, "frontend", ".husky")+" (git hooks (core.hooksPath))") {
		t.Errorf("the warning must name the enclosing repository's hooks directory:\n%s", render(ds))
	}
}

// denyWriteCompile is the contract the deny_write compile tests vary: a pin (or none) and an fs.assurance line (or
// none) over a write entry that is a repository, two targets (.git/hooks, .git/config).
const denyWriteCompile = "version: 0\nname: t\ncommand: [\"python\"]\n%sfs:\n  write: [\"work/\"]\n%s"

// denyWriteFinding is a deny_write target's compile finding.
func denyWriteFinding(d Diagnostic) bool {
	return d.Code == CodeUnenforced && strings.Contains(d.Message, "fs.deny_write[")
}

// countDiagnostics is how many of ds match.
func countDiagnostics(ds []Diagnostic, match func(Diagnostic) bool) int {
	n := 0
	for _, d := range ds {
		if match(d) {
			n++
		}
	}
	return n
}

// TestCompileDenyWriteErrorsAtPinnedLandlock is ADR 0041 D8's "compile and run agree" under
// fs.assurance: kernel, the one value D1 (a) leaves the launch refusal to: a run no decision plane decides is
// refused, so at a tier landlock the contract pins or the machine config holds each target is a compile error with
// the fix, as setuid: true is there; an auto contract, one a landlock-only build caps there, and a pin to tier
// cgroup keep a warning per target, since the machine decides whether a plane loads (the auto case names the tiers
// its build holds, as tego compile does). Before D8, compile only warned while every run exited 125.
func TestCompileDenyWriteErrorsAtPinnedLandlock(t *testing.T) {
	f := newFixture(t)
	gitRepo(t, f, filepath.Join(f.project, "work"))
	const kernel = "  assurance: kernel\n"
	held := *f.machine
	held.Tier = tierCeil(backend.TierLandlock)
	for _, tc := range []struct {
		name, tier string
		m          *config.Machine
	}{{"pinned landlock", "tier: landlock\n", f.machine}, {"machine-held landlock", "", &held}} {
		_, ds, err := Compile(f.load(fmt.Sprintf(denyWriteCompile, tc.tier, kernel)), tc.m, f.opts()...)
		isError := func(d Diagnostic) bool {
			return denyWriteFinding(d) && d.IsError() && d.Line != 0 && strings.Contains(d.Message, "fs.assurance: kernel") &&
				strings.Contains(d.Fix, "decision plane") && strings.Contains(d.Fix, "fs.assurance: kernel")
		}
		if err == nil || countDiagnostics(ds, isError) != 2 {
			t.Errorf("%s: want one error per target with the fix (err %v):\n%s", tc.name, err, render(ds))
		}
	}
	for _, tc := range []struct {
		name  string
		tier  string
		extra []CompileOption
	}{
		{"auto", "", []CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)}},
		{"landlock-only build", "", []CompileOption{WithTiers(backend.TierLandlock)}},
		{"pinned cgroup", "tier: cgroup\n", nil},
	} {
		rt, ds := f.compile(f.load(fmt.Sprintf(denyWriteCompile, tc.tier, kernel)), tc.extra...)
		if !rt.DenyWriteNeedsPlane() || countDiagnostics(ds, func(d Diagnostic) bool {
			return denyWriteFinding(d) && !d.IsError() && strings.Contains(d.Message, "fs.assurance: kernel")
		}) != 2 {
			t.Errorf("%s: want a warning per target, not an error:\n%s", tc.name, render(ds))
		}
	}
}

// TestCompileDenyWriteBestEffortByDefault is ADR 0041 D1 (a) at compile: by default (fs.assurance best-effort) a
// non-empty built-in deny_write set runs at every tier, below a decision plane on the supervisor's best-effort
// refusal, so even a contract pinned to, or held at, tier landlock compiles with one unenforced warning per
// target and no error (from D8 until D1 it was an error there; from 82a723b3 every such run exited 125). An auto
// contract and a pin to tier cgroup warn the same; a pin to tier bpflsm, where the plane always decides, warns
// nothing under either value.
func TestCompileDenyWriteBestEffortByDefault(t *testing.T) {
	f := newFixture(t)
	gitRepo(t, f, filepath.Join(f.project, "work"))
	held := *f.machine
	held.Tier = tierCeil(backend.TierLandlock)
	for _, tc := range []struct {
		name, tier string
		m          *config.Machine
	}{{"pinned landlock", "tier: landlock\n", f.machine}, {"machine-held landlock", "", &held}, {"auto", "", f.machine},
		{"pinned cgroup", "tier: cgroup\n", f.machine}} {
		rt, ds, err := Compile(f.load(fmt.Sprintf(denyWriteCompile, tc.tier, "")), tc.m, f.opts()...)
		if err != nil || len(rt.DenyWrite) != 2 || countDiagnostics(ds, func(d Diagnostic) bool {
			return denyWriteFinding(d) && !d.IsError() && strings.Contains(d.Message, "best effort")
		}) != 2 || countDiagnostics(ds, func(d Diagnostic) bool { return denyWriteFinding(d) && d.IsError() }) != 0 {
			t.Errorf("%s: want it to compile with one best-effort warning per target (err %v):\n%s", tc.name, err, render(ds))
			continue
		}
		if rt.FilesystemAssurance() != FSAssuranceBestEffort || rt.DenyWriteNeedsPlane() {
			t.Errorf("%s: assurance %q, needs a plane %v", tc.name, rt.FilesystemAssurance(), rt.DenyWriteNeedsPlane())
		}
	}
	for _, a := range []string{"", "  assurance: kernel\n"} {
		if _, ds := f.compile(f.load(fmt.Sprintf(denyWriteCompile, "tier: bpflsm\n", a))); countDiagnostics(ds, denyWriteFinding) != 0 {
			t.Errorf("pinned bpflsm (%q): the plane decides every target there, so nothing is to warn:\n%s", a, render(ds))
		}
	}
}
