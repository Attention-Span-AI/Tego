// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// multicallFixture lays out a multi-call host in the fixture, the two shapes measured on Ubuntu 25.10 and 26.04.1
// (uutils: symlinks on PATH to hard links of one file) and read for busybox (symlinks to one file named busybox), with
// a fake static ELF for each file, so the test holds on a host whose own coreutils are GNU's.
//
//	bin/ls -> ../lib/mc/ls, bin/cat -> ../lib/mc/cat   lib/mc/{ls,cat,sleep}: one file, 3 links
//	bb/whoami -> ../lib/bb/busybox, bb/id -> same      lib/bb/busybox: one file, 1 link
func multicallFixture(t *testing.T) (f *fixture, mc, bb string) {
	t.Helper()
	f = newFixture(t)
	mcDir, bbDir := filepath.Join(f.root, "lib", "mc"), filepath.Join(f.root, "lib", "bb")
	for _, d := range []string{mcDir, bbDir, filepath.Join(f.root, "bb")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mc, bb = filepath.Join(mcDir, "ls"), filepath.Join(bbDir, "busybox")
	f.file(mc, string(elf64("", 2)), 0o755)
	f.file(bb, string(elf64("", 2)), 0o755)
	for _, n := range []string{"cat", "sleep"} {
		if err := os.Link(mc, filepath.Join(mcDir, n)); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(f.bin, "ls"): "../lib/mc/ls", filepath.Join(f.bin, "cat"): "../lib/mc/cat",
		filepath.Join(f.root, "bb", "whoami"): "../lib/bb/busybox", filepath.Join(f.root, "bb", "id"): "../lib/bb/busybox",
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	return f, mc, bb
}

// multicallFindings is the exec-multicall diagnostics among ds.
func multicallFindings(ds []Diagnostic) []Diagnostic {
	return slices.DeleteFunc(slices.Clone(ds), func(d Diagnostic) bool { return d.Code != CodeExecMulticall })
}

// TestCompileWarnsExecMulticall: an allowed exec entry whose file has more than one hard link, or whose file is named
// busybox, toybox or coreutils, gets one exec-multicall warning per file, not per entry. It names every entry that
// leads to the file and the file's link count, sits at the first such entry's line, and is a note (Informational):
// `tego run` leaves it out unless -v, and `tego compile` and the dashboard's check print it. A file with one link and
// another name, and an entry naming a directory, get none.
func TestCompileWarnsExecMulticall(t *testing.T) {
	f, mc, bb := multicallFixture(t)
	c := f.load("version: 0\nname: mc\ncommand: [static-tool]\nexec:\n  allow:\n    - ls\n    - cat\n    - " +
		filepath.Join(f.root, "bb", "whoami") + "\n    - " + filepath.Join(f.root, "bb", "id") + "\n    - static-tool\n    - " +
		filepath.Join(f.root, "lib") + "/\n")
	_, ds := f.compile(c)
	got := multicallFindings(ds)
	if len(got) != 2 {
		t.Fatalf("exec-multicall findings = %d, want 2 (one per file):\n%s", len(got), render(ds))
	}
	want := []Diagnostic{
		{
			Line: 6, Code: CodeExecMulticall, Severity: SeverityWarning,
			Message: `the exec entries "ls" and "cat" lead to one program file, ` + mc + `, with 3 names (hard links). ` +
				"Tiers cgroup and bpflsm admit only the names listed; tier landlock admits the file by any of its names " +
				"to an agent that wins the exec race, and a multi-call build that reads argv[0] (busybox, uutils without " +
				"Ubuntu's patch) runs any program it holds through a listed name",
			Fix: multicallFix,
		},
		{
			Line: 8, Code: CodeExecMulticall, Severity: SeverityWarning,
			Message: `the exec entries "` + filepath.Join(f.root, "bb", "whoami") + `" and "` + filepath.Join(f.root, "bb", "id") +
				`" lead to ` + bb + ", a multi-call program, which runs the program argv[0] or argv[1] names. " +
				"A listed name admits every program it holds, at every tier",
			Fix: multicallFix,
		},
	}
	for i, d := range got {
		if d.Line != want[i].Line || d.Code != want[i].Code || d.Severity != want[i].Severity || d.Message != want[i].Message || d.Fix != want[i].Fix {
			t.Errorf("finding %d:\n got %d %s %s %q\n fix %q\nwant %d %s %s %q\n fix %q", i, d.Line, d.Code, d.Severity, d.Message, d.Fix,
				want[i].Line, want[i].Code, want[i].Severity, want[i].Message, want[i].Fix)
		}
		if !d.Informational() {
			t.Errorf("finding %d is not a note: a run would repeat it at every start", i)
		}
		if d.Tier != "" {
			t.Errorf("finding %d holds at tier %s only, want every tier", i, d.Tier)
		}
	}
}

// TestCompileExecMulticallCountsEveryAllowedEntry: the command and an MCP server's command are allowed exec entries as
// exec.allow's are, and one file named coreutils with a single link (GNU's coreutils-single, where the names are
// symlinks) is a dispatcher by its name; the finding names the entries in the order the table holds them. Where one of
// a file's entries is its dispatcher's name, the finding is the dispatcher's in either order.
func TestCompileExecMulticallCountsEveryAllowedEntry(t *testing.T) {
	f, mc, _ := multicallFixture(t)
	core := filepath.Join(f.root, "lib", "coreutils")
	f.file(core, string(elf64("", 2)), 0o755)
	if err := os.Symlink("../lib/coreutils", filepath.Join(f.bin, "uname")); err != nil {
		t.Fatal(err)
	}
	c := f.load("version: 0\nname: mc\ncommand: [ls]\nmcp:\n  - name: m\n    command: [cat]\nexec:\n  allow: [uname]\n")
	_, ds := f.compile(c)
	got := multicallFindings(ds)
	if len(got) != 2 {
		t.Fatalf("exec-multicall findings = %d, want 2:\n%s", len(got), render(ds))
	}
	if !strings.HasPrefix(got[0].Message, `the exec entries "ls" and "cat" lead to one program file, `+mc+", with 3 names") {
		t.Errorf("command and mcp: %q", got[0].Message)
	}
	if !strings.HasPrefix(got[1].Message, `the exec entry "uname" leads to `+core+", a multi-call program") {
		t.Errorf("coreutils by name: %q", got[1].Message)
	}

	// Ubuntu 25.10's layout: the dispatcher /usr/bin/coreutils is one more hard link of the file ls leads to. Listed
	// with ls, in either order, the one finding is the dispatcher's, under the dispatcher's own name: the listed
	// coreutils runs any utility its argv[1] names at every tier, which the hard-link wording would deny.
	disp := filepath.Join(f.root, "lib", "mc", "coreutils")
	if err := os.Link(mc, disp); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ allow, names string }{
		{"[ls, " + disp + "]", `the exec entries "ls" and "` + disp + `" lead to `},
		{"[" + disp + ", ls]", `the exec entries "` + disp + `" and "ls" lead to `},
	} {
		_, ds := f.compile(f.load("version: 0\nname: mc\ncommand: [static-tool]\nexec:\n  allow: " + tc.allow + "\n"))
		got := multicallFindings(ds)
		if len(got) != 1 {
			t.Fatalf("allow %s: exec-multicall findings = %d, want 1:\n%s", tc.allow, len(got), render(ds))
		}
		want := tc.names + disp + " (4 names, hard links), a multi-call program, " +
			"which runs the program argv[0] or argv[1] names. A listed name admits every program it holds, at every tier"
		if got[0].Message != want {
			t.Errorf("allow %s:\n got %q\nwant %q", tc.allow, got[0].Message, want)
		}
	}
}

// TestCompileExecMulticallOnlyWhereImagesAreRestricted: with no exec: section every image runs, and a deny-list
// restricts none (ADR 0048 (1)): no entry admits a file there, so a multi-call file is no finding.
func TestCompileExecMulticallOnlyWhereImagesAreRestricted(t *testing.T) {
	f, _, _ := multicallFixture(t)
	for _, body := range []string{
		"version: 0\nname: mc\ncommand: [ls]\n",
		"version: 0\nname: mc\ncommand: [ls]\nexec:\n  deny: [rm -r]\n",
	} {
		_, ds := f.compile(f.load(body))
		if got := multicallFindings(ds); len(got) != 0 {
			t.Errorf("%q gave %s", body, render(got))
		}
	}
}

// TestExecMulticallChangesNoRule: the warning is a statement only. The same contract compiled where ls and cat are two
// files and where they are hard links of one file gives the same rule table, printed and as the exec rules, the same
// error (none) and the same diagnostics but the one exec-multicall finding, so `tego compile`'s exit and its --json
// table do not move.
func TestExecMulticallChangesNoRule(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.root, "lib", "mc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ls, cat := filepath.Join(dir, "ls"), filepath.Join(dir, "cat")
	f.file(ls, string(elf64("", 2)), 0o755)
	f.file(cat, string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: mc\ncommand: [static-tool]\nexec:\n  allow:\n    - " + ls + "\n    - " + cat + "\n")
	compile := func() (*RuleTable, []Diagnostic, string) {
		t.Helper()
		rt, ds, err := Compile(c, f.machine, f.opts()...)
		if err != nil {
			t.Fatalf("compile: %v\n%s", err, render(ds))
		}
		var out bytes.Buffer
		if err := PrintRuleTable(&out, rt); err != nil {
			t.Fatal(err)
		}
		return rt, ds, out.String()
	}
	twoFiles, twoDs, twoText := compile()
	if got := multicallFindings(twoDs); len(got) != 0 {
		t.Fatalf("two files of one link each gave %s", render(got))
	}
	if err := os.Remove(cat); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ls, cat); err != nil {
		t.Fatal(err)
	}
	oneFile, oneDs, oneText := compile()
	if got := multicallFindings(oneDs); len(got) != 1 {
		t.Fatalf("one file of two links gave %d exec-multicall findings, want 1:\n%s", len(got), render(oneDs))
	}
	if !reflect.DeepEqual(twoFiles.Exec, oneFile.Exec) {
		t.Errorf("exec rules moved:\n two files %+v\n one file  %+v", twoFiles.Exec, oneFile.Exec)
	}
	if twoText != oneText {
		t.Errorf("printed table moved:\n two files\n%s\n one file\n%s", twoText, oneText)
	}
	if twoFiles.Hash != oneFile.Hash || twoFiles.Tier != oneFile.Tier || HasErrors(oneDs) {
		t.Errorf("hash, tier or errors moved: %x %x, %s %s, errors %v", twoFiles.Hash, oneFile.Hash, twoFiles.Tier, oneFile.Tier, HasErrors(oneDs))
	}
	rest := slices.DeleteFunc(slices.Clone(oneDs), func(d Diagnostic) bool { return d.Code == CodeExecMulticall })
	if !reflect.DeepEqual(rest, twoDs) {
		t.Errorf("other diagnostics moved:\n two files\n%s\n one file\n%s", render(twoDs), render(rest))
	}
}

// TestMulticallOf is the one reading of a file doctor and compile share: the file an exec name leads to, its link
// count and whether its name is a dispatcher's. It stats and never opens or runs the file.
func TestMulticallOf(t *testing.T) {
	f, mc, bb := multicallFixture(t)
	for _, tc := range []struct {
		path string
		want MulticallFile
		ok   bool
	}{
		{filepath.Join(f.bin, "ls"), MulticallFile{Resolved: mc, Links: 3}, true},
		{filepath.Join(f.root, "bb", "whoami"), MulticallFile{Resolved: bb, Links: 1, Dispatcher: true}, true},
		{filepath.Join(f.bin, "static-tool"), MulticallFile{Resolved: filepath.Join(f.bin, "static-tool"), Links: 1}, false},
		{filepath.Join(f.root, "lib"), MulticallFile{}, false},
		{filepath.Join(f.root, "nothing-here"), MulticallFile{}, false},
	} {
		got, ok := MulticallOf(tc.path)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("MulticallOf(%s) = %+v %v, want %+v %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
	for _, name := range []string{"busybox", "busybox.static", "toybox", "coreutils"} {
		if !multicallDispatcher(name) {
			t.Errorf("%s is not read as a dispatcher", name)
		}
	}
	for _, name := range []string{"ls", "xbusybox", "coreutils2", "gnucoreutils"} {
		if multicallDispatcher(name) {
			t.Errorf("%s is read as a dispatcher", name)
		}
	}
}
