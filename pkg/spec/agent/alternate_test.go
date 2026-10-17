// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// ADR 0057 D2: the table carries what the alternate guard refuses beyond its rows, whether it existed at compile or
// not: a declared deny_read glob, by its spelling and its base's resolved one, and every path of the built-in list,
// absent ones included and whatever deny_read says.
func TestDenyReadPatternsNameWhatDidNotExistAtCompile(t *testing.T) {
	f := newFixture(t)
	keys := filepath.Join(f.root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(keys, "old.pem"), "k", 0o600)
	link := filepath.Join(f.root, "keylink")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	rt, ds := f.compile(f.load(askReadContract(`  write: ["out/"]`, `  deny_read: ["`+link+`/*.pem"]`)))
	for _, p := range []string{
		filepath.Join(keys, "new.pem"),          // created after compile, by its resolved spelling
		filepath.Join(link, "new.pem"),          // and as declared
		filepath.Join(keys, "NEW.PEM"),          // another case of the name
		filepath.Join(f.home, ".netrc"),         // a built-in path that did not exist at compile
		filepath.Join(f.home, ".ssh", "id_new"), // beneath one
		filepath.Join(f.home, ".config", "gh", "hosts.yml"),
	} {
		if _, ok := rt.DenyReadPatternOf(p); !ok {
			t.Errorf("%s is not refused by a pattern; patterns %+v\n%s", p, rt.DenyReadPatterns, render(ds))
		}
	}
	if d, ok := rt.DenyReadPatternOf(filepath.Join(keys, "new.pem")); !ok || d.Rule != "fs.deny_read["+link+"/*.pem]" {
		t.Errorf("the glob's pattern names %+v", d)
	}
	for _, p := range []string{filepath.Join(keys, "new.txt"), filepath.Join(f.home, ".netrc-notes"), filepath.Join(f.project, "out", "x")} {
		if d, ok := rt.DenyReadPatternOf(p); ok {
			t.Errorf("%s is refused by %+v", p, d)
		}
	}
	// deny_read: [] turns the built-in rows off, not the guard: an alternate is never a credential path.
	rt2, _ := f.compile(f.load(askReadContract(`  write: ["out/"]`, `  deny_read: []`)))
	if _, ok := rt2.DenyReadPatternOf(filepath.Join(f.home, ".aws", "credentials")); !ok {
		t.Error("deny_read: [] left ~/.aws/credentials to the alternate guard")
	}
}

// A write alternate's built-in deny_write class is read off its names alone, wherever it lies.
func TestWriteAlternateClassByName(t *testing.T) {
	for p, want := range map[string]string{
		"/w/otherrepo/.git/hooks/pre-commit":        "git hooks",
		"/w/repo/.git/modules/sub/hooks/post-merge": "git hooks",
		"/w/repo/.git/config":                       "git config",
		"/w/repo/.git/worktrees/x/config.worktree":  "git config",
		"/w/repo/.git":                              "git config",
		"/w/repo/.husky/pre-commit":                 "git hooks",
		"/w/elsewhere/.claude/settings.json":        "harness settings",
		"/w/x/.mcp.json":                            "harness settings",
		"/w/x/.vscode/tasks.json":                   "editor settings",
		"/home/u/.bashrc":                           "shell startup",
		"/home/u/dotfiles/.zshenv":                  "shell startup",
		"/home/u/.config/fish/config.fish":          "shell startup",
		"/home/u/.gitconfig":                        "git config",
		"/home/u/.config/git/config":                "git config",
	} {
		if got, ok := WriteAlternateClass(p); !ok || got != want {
			t.Errorf("WriteAlternateClass(%s) = %q %v, want %q", p, got, ok, want)
		}
	}
	for _, p := range []string{"/w/repo/.git/objects/ab/cd", "/w/repo/hooks/pre-commit", "/w/out/config", "/w/out/stand-in", "/w/.gitignore"} {
		if got, ok := WriteAlternateClass(p); ok {
			t.Errorf("WriteAlternateClass(%s) = %q", p, got)
		}
	}
}
