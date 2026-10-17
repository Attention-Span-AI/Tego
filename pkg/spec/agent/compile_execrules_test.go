// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompileExecPatternGrantsItsImage: an exec.allow command pattern grants its command word's image as a bare
// entry of that word would, under the rule exec[<command word>] (ADR 0048 (1)); deny and ask entries grant nothing.
func TestCompileExecPatternGrantsItsImage(t *testing.T) {
	f := newFixture(t)
	f.file(filepath.Join(f.bin, "git"), string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git status, git diff]\n  deny: [git push, rm -r]\n")
	rt, _ := f.compile(c)
	var names []string
	for _, r := range rt.Exec {
		names = append(names, r.RuleName())
	}
	if got := strings.Join(names, ","); got != "exec[static-tool],exec[git]" {
		t.Errorf("rules %s, want exec[static-tool],exec[git]", got)
	}
	for _, r := range rt.Exec {
		if r.Basename == "git" && !r.ByName {
			t.Error("a pattern's bare command word grants by name, as a bare entry does")
		}
	}
	if rt.ExecUnrestricted() {
		t.Error("an allow key restricts images")
	}
}

// TestCompileExecPatternFilesystemErrors: the filesystem only improves an error. An unquoted path with spaces that
// names a file is refused with "quote the path"; quoted, it is a path entry. A directory takes no words.
func TestCompileExecPatternFilesystemErrors(t *testing.T) {
	f := newFixture(t)
	spaced := filepath.Join(f.bin, "My Tool")
	f.file(spaced, string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [\"" + spaced + "\"]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasFinding(ds, CodeExecRule, SeverityError) || !strings.Contains(render(ds), "quote the path") {
		t.Errorf("an unquoted path with spaces: %v\n%s", err, render(ds))
	}
	c = f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [\"'" + spaced + "'\"]\n")
	rt, _ := f.compile(c)
	found := false
	for _, r := range rt.Exec {
		found = found || r.Path == spaced
	}
	if !found {
		t.Errorf("a quoted path with spaces is a path entry: %+v", rt.Exec)
	}
	c = f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [\"" + f.bin + " run\"]\n")
	_, ds, err = Compile(c, f.machine, f.opts()...)
	if err == nil || !strings.Contains(render(ds), "a directory entry takes no words") {
		t.Errorf("a directory with words: %v\n%s", err, render(ds))
	}
}

// TestCompileExecPathWithQuoteCharacters: an exec.allow path with no space or tab is the path as written, quote
// characters included, as before ADR 0048. An unbalanced quote was refused as `unterminated ' quote`, and a balanced
// pair was removed, so `/opt/a'b'c/tool` granted /opt/abc/tool, another file.
func TestCompileExecPathWithQuoteCharacters(t *testing.T) {
	f := newFixture(t)
	brien := filepath.Join(f.bin, "O'Brien", "tool")
	abc := filepath.Join(f.bin, "a'b'c", "tool")
	other := filepath.Join(f.bin, "abc", "tool")
	for _, p := range []string{brien, abc, other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(p, string(elf64("", 2)), 0o755)
	}
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [\"" + brien + "\", \"" + abc + "\"]\n  deny: [rm -r]\n")
	rt, _ := f.compile(c)
	paths := map[string]bool{}
	for _, r := range rt.Exec {
		paths[r.Path] = true
	}
	if !paths[brien] || !paths[abc] || paths[other] {
		t.Errorf("rules %v: want %s and %s, never %s", paths, brien, abc, other)
	}
}
