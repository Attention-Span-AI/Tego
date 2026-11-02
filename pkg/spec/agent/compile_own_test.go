// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ownInstall makes an install directory under the fixture holding tego and tego-control, and returns it. A target
// under fixture bin would refuse nothing of use: the contract's own tools live there.
func ownInstall(f *fixture) string {
	dir := filepath.Join(f.root, "opt", "tego", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.file(filepath.Join(dir, "tego"), "tego", 0o755)
	f.file(filepath.Join(dir, "tego-control"), "control", 0o755)
	return dir
}

func writeSection(entries ...string) string {
	return "version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + strings.Join(entries, "\", \"") + "\"]\n"
}

// wantRefused compiles c and wants R10's contradiction, naming want.
func wantRefused(t *testing.T, f *fixture, c *Contract, want string, opts ...CompileOption) {
	t.Helper()
	_, ds, err := Compile(c, f.machine, f.opts(opts...)...)
	if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return d.Code == CodeContradiction && d.Severity == SeverityError && strings.Contains(d.Message, want)
	}) {
		t.Fatalf("no contradiction naming %q (err=%v):\n%s", want, err, render(ds))
	}
}

// shadowWarnings is the path-shadow diagnostics of a compile that must pass.
func shadowWarnings(t *testing.T, f *fixture, c *Contract, opts ...CompileOption) []Diagnostic {
	t.Helper()
	_, ds := f.compile(c, opts...)
	return slices.DeleteFunc(slices.Clone(ds), func(d Diagnostic) bool { return d.Code != CodePathShadow })
}

// TestCompileRefusesWritesOverTegosBinaries: an entry over the install directory compiled, and the agent replaced the
// tego binary, so the next run ran its code outside any contract. R10 refuses an entry at or over tego or tego-control,
// found as the running file or on the launcher's PATH, and one holding a name a walk to them reads.
func TestCompileRefusesWritesOverTegosBinaries(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	exe := filepath.Join(dir, "tego")
	if err := os.Symlink(dir, filepath.Join(f.project, "tools")); err != nil {
		t.Fatal(err)
	}
	onPATH := WithPATH(f.bin + ":" + dir)
	for name, c := range map[string]struct {
		entry string
		opts  []CompileOption
		want  string
	}{
		"the file":                   {exe, []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"its directory":              {dir, []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"a directory above":          {filepath.Join(f.root, "opt"), []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"a link to its directory":    {"./tools", []CompileOption{WithOwnBinaries(exe)}, "the tego binary"},
		"tego-control beside it":     {filepath.Join(dir, "tego-control"), []CompileOption{WithOwnBinaries(exe)}, "the tego-control binary"},
		"found on PATH":              {dir, []CompileOption{WithOwnBinaries(""), onPATH}, "the tego binary on PATH"},
		"tego-control found on PATH": {filepath.Join(dir, "tego-control"), []CompileOption{WithOwnBinaries(""), onPATH}, "the tego-control binary"},
	} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, f, f.load(writeSection(c.entry)), c.want, c.opts...)
		})
	}
	t.Run("tego-control not there yet", func(t *testing.T) {
		// The agent would fill the name beside a running tego that has none.
		other := filepath.Join(f.root, "other")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(other, "tego"), "tego", 0o755)
		wantRefused(t, f, f.load(writeSection(filepath.Join(other, "tego-control"))), "tego-control",
			WithOwnBinaries(filepath.Join(other, "tego")))
	})
	t.Run("tego-control alone on PATH", func(t *testing.T) {
		other := filepath.Join(f.root, "other2")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(other, "tego-control"), "control", 0o755)
		wantRefused(t, f, f.load(writeSection(other)), "the tego-control binary on PATH", WithOwnBinaries(""), WithPATH(other+":"+f.bin))
	})
	t.Run("an ask scope over it", func(t *testing.T) {
		wantRefused(t, f, f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  ask: [\""+dir+"\"]\n"), "the tego binary",
			WithOwnBinaries(exe))
	})
}

// TestCompileRefusesWritesOverALinkToTego: tego is found by what a person types, so where PATH holds a link to the real
// file (ln -s /opt/tego/bin/tego ~/.local/bin/), an entry over the link's directory lets the agent point it elsewhere,
// and the os.Executable name alone never sees that. The tego-control the real file hands off to lies beside it.
func TestCompileRefusesWritesOverALinkToTego(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	links := filepath.Join(f.home, ".local", "bin")
	if err := os.MkdirAll(links, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "tego"), filepath.Join(links, "tego")); err != nil {
		t.Fatal(err)
	}
	opts := []CompileOption{WithOwnBinaries(filepath.Join(dir, "tego")), WithPATH(links + ":" + f.bin)}
	wantRefused(t, f, f.load(writeSection(links)), "holds the symlink "+filepath.Join(links, "tego"), opts...)
	wantRefused(t, f, f.load(writeSection(filepath.Join(f.home, ".local"))), "the tego binary", opts...)
	opts = []CompileOption{WithOwnBinaries(""), WithPATH(links + ":" + f.bin)}
	wantRefused(t, f, f.load(writeSection(filepath.Join(dir, "tego-control"))), "the tego-control binary", opts...)
}

// TestCompileKeepsWritesBesideTegosBinaries: only what reaches a binary is refused. An entry beside the install
// directory, or one inside it that holds no name on the way, leaves tego where it is, and a compile not told of any
// binary, a library's, refuses nothing.
func TestCompileKeepsWritesBesideTegosBinaries(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	exe := filepath.Join(dir, "tego")
	opts := []CompileOption{WithOwnBinaries(exe), WithPATH(f.bin + ":" + dir)}
	for _, d := range []string{filepath.Join(f.root, "opt", "data"), filepath.Join(dir, "cache")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		f.compile(f.load(writeSection(d)), opts...)
	}
	f.compile(f.load(writeSection(filepath.Join(f.project, "out"))), opts...)
	f.compile(f.load(writeSection(dir)), WithPATH(f.bin+":"+dir))
	t.Run("a running file that is not there", func(t *testing.T) {
		f.compile(f.load(writeSection(dir)), WithOwnBinaries(filepath.Join(f.root, "gone", "tego")), WithPATH(f.bin))
	})
}

// TestCompileWarnsAboutPATHBeforeTego is the shell's other way to tego: a write entry over a directory PATH searches
// first lets the agent plant a tego that a person's next `tego` runs. The directory holds nothing of tego's, and an
// activated .venv/bin is the common case, so the contract compiles, and the warning says what to change.
func TestCompileWarnsAboutPATHBeforeTego(t *testing.T) {
	f := newFixture(t)
	dir := ownInstall(f)
	out := filepath.Join(f.project, "out")
	venv := filepath.Join(out, ".venv", "bin")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.load(writeSection(out))
	got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(venv+":"+dir+":"+f.bin))
	if len(got) != 1 || got[0].Severity != SeverityWarning || !strings.Contains(got[0].Message, venv) ||
		!strings.Contains(got[0].Message, filepath.Join(dir, "tego")) || !strings.Contains(got[0].Message, "outside the contract") ||
		!strings.Contains(got[0].Fix, dir) {
		t.Fatalf("path-shadow warnings: %+v", got)
	}
	t.Run("an empty PATH element is the working directory", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(":"+dir+":"+f.bin), WithCwd(out)); len(got) != 1 {
			t.Fatalf("path-shadow warnings: %+v", got)
		}
	})
	t.Run("a directory after tego", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(""), WithPATH(dir+":"+venv+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned about a directory searched after tego: %+v", got)
		}
	})
	t.Run("tego not on PATH", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithOwnBinaries(filepath.Join(dir, "tego")), WithPATH(venv+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned with no tego for the name to shadow: %+v", got)
		}
	})
	t.Run("not asked", func(t *testing.T) {
		if got := shadowWarnings(t, f, c, WithPATH(venv+":"+dir+":"+f.bin)); len(got) != 0 {
			t.Fatalf("warned with no WithOwnBinaries: %+v", got)
		}
	})
}
