// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// saveOf is a Save of the contract named name into l's user registry, looked up from l's working directory.
func (l *layout) saveOf(name string) Save {
	return Save{Places: l.places, From: []string{l.dir}, Name: name, Text: []byte(strings.ReplaceAll(l.contractFmt, "%s", name))}
}

func step(err error) SaveStep {
	var se *SaveError
	if errors.As(err, &se) {
		return se.Step
	}
	return 0
}

// Write makes agents/ 0700 and the entry 0600 in the user registry, and the entry is what Resolve then reads for the
// name from the folder it was saved for.
func TestSaveWritesTheEntryTegoRunFinds(t *testing.T) {
	l := newLayout(t)
	if err := os.Remove(l.user); err != nil {
		t.Fatal(err)
	}
	sv := l.saveOf("bot")
	compiled := ""
	sv.Compile = func(path string, text []byte) error { compiled = path; return nil }
	path, err := sv.Write()
	want := filepath.Join(l.user, AgentsDir, "bot.yaml")
	if err != nil || path != want || compiled != want {
		t.Fatalf("Write = %q, %v (compiled %q), want %q", path, err, compiled, want)
	}
	for p, mode := range map[string]fs.FileMode{l.user: 0o700, filepath.Dir(want): 0o700, want: 0o600} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v, want mode %o", p, err, mode)
		}
	}
	e, err := l.places.Resolve("bot")
	if err != nil || e.Path != want || e.Registry != User || string(e.Data) != string(sv.Text) {
		t.Fatalf("Resolve: %+v, %v", e, err)
	}
}

// A name that is no agent name, one that starts with -, and a registry that is no absolute path are refused before
// anything is looked at or written.
func TestSaveRefusesANameOrRegistryItCannotUse(t *testing.T) {
	l := newLayout(t)
	for _, name := range []string{"", "../x", "a/b", ".bot", "bot.yaml", "Bot", strings.Repeat("a", 41)} {
		if _, err := l.saveOf(name).Write(); step(err) != SaveName {
			t.Errorf("%q: %v, want SaveName", name, err)
		}
	}
	if _, err := l.saveOf("-bot").Write(); step(err) != SaveName || !strings.Contains(err.Error(), "reads as a flag") {
		t.Errorf("-bot: %v", err)
	}
	for _, user := range []string{"", "relative/tego"} {
		sv := l.saveOf("bot")
		sv.Places.User = user
		if _, err := sv.Write(); step(err) != SaveNoRegistry {
			t.Errorf("registry %q: %v", user, err)
		}
	}
	if ents, _ := os.ReadDir(l.user); len(ents) != 0 {
		t.Errorf("written: %v", ents)
	}
}

// A name a registry resolves already, or one tego run would find ambiguous from the folder (a file of the name
// there), is taken; Check says so without writing, and Write writes nothing.
func TestSaveRefusesATakenName(t *testing.T) {
	l := newLayout(t)
	have := l.write(l.user, filepath.Join(AgentsDir, "bot.yaml"), "bot")
	_, err := l.saveOf("bot").Check()
	var se *SaveError
	if !errors.As(err, &se) || se.Step != SaveTaken || se.Entry == nil || se.Entry.Path != have || se.Dir != l.dir {
		t.Fatalf("an entry of the name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(l.dir, "tool"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = l.saveOf("tool").Write()
	if step(err) != SaveTaken || !strings.Contains(err.Error(), "taken") || code(errors.Unwrap(err)) != CodeAmbiguous {
		t.Fatalf("a file of the name in the folder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(l.user, AgentsDir, "tool.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a taken name was written: %v", err)
	}
}

// agents/ a link out of the registry: the name cannot be shown free, and nothing is written there. With no folder to
// look the name up from, the write itself refuses to follow the link.
func TestSaveNeverFollowsALinkOutOfAgents(t *testing.T) {
	l := newLayout(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(l.user, AgentsDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.saveOf("bot").Write(); step(err) != SaveTaken || !strings.Contains(err.Error(), "cannot say whether") {
		t.Errorf("looked up: %v", err)
	}
	sv := l.saveOf("bot")
	sv.From = nil
	if _, err := sv.Write(); step(err) != SaveIO {
		t.Errorf("not looked up: %v", err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Errorf("written through the link: %v", ents)
	}
}

// A link, or a file, at the entry's name is never written over or through.
func TestSaveNeverWritesOverAFileOrALink(t *testing.T) {
	l := newLayout(t)
	agents := filepath.Join(l.user, AgentsDir)
	if err := os.Mkdir(agents, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "victim.yaml")
	if err := os.Symlink(outside, filepath.Join(agents, "bot.yaml")); err != nil {
		t.Fatal(err)
	}
	sv := l.saveOf("bot")
	sv.From = nil
	if _, err := sv.Write(); step(err) != SaveExists {
		t.Errorf("a dangling link at the name: %v", err)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link was followed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(agents, "old.yaml"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	sv = l.saveOf("old")
	sv.From = nil
	if _, err := sv.Write(); step(err) != SaveExists {
		t.Errorf("a file at the name: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(agents, "old.yaml")); string(b) != "keep" {
		t.Errorf("the file was written over: %q", b)
	}
}

// The entry inside one of the contract's own fs.write entries, and a contract that does not compile, are refused
// with nothing written.
func TestSaveRefusesItsOwnWriteEntryAndACompileError(t *testing.T) {
	l := newLayout(t)
	sv := l.saveOf("bot")
	sv.Writes = []string{filepath.Dir(l.user) + "/"}
	if _, err := sv.Write(); step(err) != SaveInsideWrite || !strings.Contains(err.Error(), "fs.write") {
		t.Errorf("own write entry: %v", err)
	}
	sv = l.saveOf("bot")
	sv.Writes = []string{l.user + "-other"}
	sv.Compile = func(string, []byte) error { return errors.New("bad field") }
	if _, err := sv.Write(); step(err) != SaveNoCompile || !strings.Contains(err.Error(), "bad field") {
		t.Errorf("compile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(l.user, AgentsDir, "bot.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("written: %v", err)
	}
}

// A registry inside one of tego's own directories: the entry written would be refused by tego run, so it is removed
// and the save refused.
func TestSaveRemovesAnEntryTegoRunWouldRefuse(t *testing.T) {
	l := newLayout(t)
	sv := l.saveOf("bot")
	sv.Places.Own = []string{filepath.Dir(l.user)}
	_, err := sv.Write()
	var se *SaveError
	if !errors.As(err, &se) || se.Step != SaveUnusable || se.Dir != l.dir || !strings.Contains(err.Error(), "R6a") {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(l.user, AgentsDir, "bot.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the refused entry is still there: %v", err)
	}
}
