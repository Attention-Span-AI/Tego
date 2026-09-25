// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Contract hardening: each test below pins one finding of the 2026-09-24 review, and failed before its fix.

// A YAML null list element (`~`, or a bare `-`) is dropped by yaml.v3's typed decode, so
// `deny_read: [~]` became the explicit `deny_read: []` and switched the built-in credential list off.
func TestContractNullListElementIsAnError(t *testing.T) {
	for _, body := range []string{
		"fs:\n  deny_read: [~]\n",
		"fs:\n  deny_read:\n    -\n",
		"fs:\n  write: [~]\n",
		"exec:\n  allow: [~]\n",
		"net:\n  allow: [~]\n",
		"env:\n  pass: [~]\n",
		"command: [~, /bin/true]\n",
	} {
		src := "version: 0\nname: a\ncommand: [/bin/true]\n" + body
		if strings.HasPrefix(body, "command:") {
			src = "version: 0\nname: a\n" + body
		}
		_, ds, err := LoadBytes("agent.yaml", []byte(src), nil)
		if err == nil {
			t.Errorf("%q loaded without an error (a null element was silently dropped): %v", body, codes(ds))
		}
	}
}

// The schema walk validates a scalar's raw text while the typed decode applies the tag: a `!!binary`
// value is base64-decoded after the walk accepted the encoded text.
func TestContractBinaryTagCannotBypassTheSchema(t *testing.T) {
	for _, body := range []string{
		"name: !!binary ai9v\ncommand: [/bin/true]\n",                         // name "j/o"
		"name: a\ncommand: [/bin/true]\ntier: !!binary auto\n",                // tier "j\xebh"
		"name: a\ncommand: [/bin/true]\nrecord: !!binary full\n",              // record "~\xe9e"
		"name: a\ncommand: [/bin/true]\nenv:\n  set:\n    X: !!binary YQpi\n", // "a\nb"
	} {
		_, _, err := LoadBytes("agent.yaml", []byte("version: 0\n"+body), nil)
		if err == nil {
			t.Errorf("%q loaded: a !!binary scalar passed the walk as its encoded text", body)
		}
	}
}

// A contract is one YAML document; a second document was ignored without a word.
func TestContractSecondDocumentIsAnError(t *testing.T) {
	src := "version: 0\nname: a\ncommand: [/bin/true]\nnet: {}\n---\nversion: 0\nname: b\ncommand: [/bin/sh]\nfs: {write: [/]}\n"
	if _, _, err := LoadBytes("agent.yaml", []byte(src), nil); err == nil {
		t.Fatal("a two-document contract loaded; the second document was silently ignored")
	}
}

// `env.pass: []` (pass nothing) and no env: (inherit everything) compile to different environments and
// must not share a contract_hash (R13: nothing Compile reads may live outside Canonical).
func TestContractEmptyEnvPassChangesTheHash(t *testing.T) {
	a, _, err := LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [/bin/true]\nenv:\n  pass: []\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := LoadBytes("b.yaml", []byte("version: 0\nname: a\ncommand: [/bin/true]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if ha == hb {
		t.Fatal("env.pass: [] and no env: have the same contract_hash but compile to pass=none and pass=inherit all")
	}
}

// `**` is not recursive in filepath.Glob: `deny_read: [g/**/s.json]` covered one level only, silently, and a
// file two levels down stayed readable. It is refused, naming why; a file whose own name holds a glob
// character is that file, not a pattern.
func TestContractDoubleStarGlobIsRefused(t *testing.T) {
	f := newFixture(t)
	deep := filepath.Join(f.project, "g", "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(deep, "s.json"), "x", 0o600)
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  deny_read: [\"g/**/s.json\"]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !strings.Contains(render(ds), "**") {
		t.Fatalf("g/**/s.json compiled (err %v); want a refusal that names **:\n%s", err, render(ds))
	}

	lit := filepath.Join(f.project, "lit[1].txt")
	f.file(lit, "x", 0o600)
	c = f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  deny_read: [\"lit[1].txt\"]\n")
	if rt, _ := f.compile(c); findFS(rt, FSDenyRead, lit) == nil {
		t.Fatal("a file named lit[1].txt was read as a glob and not denied")
	}
}

// R10 asks containment of resolved paths (E8), but the contract's own file was compared as the link's
// directory: agent.yaml -> out/real.yaml with fs.write [out/] let the agent rewrite its next contract.
func TestContractSymlinkedContractInsideWriteEntryIsAContradiction(t *testing.T) {
	f := newFixture(t)
	real := filepath.Join(f.project, "out", "real.yaml")
	f.file(real, "version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [out/]\n", 0o644)
	link := filepath.Join(f.project, "agent-link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	c, ds, err := Load(link, f.profiles())
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	_, ds, err = Compile(c, f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodeContradiction) {
		t.Fatalf("the contract's target lies inside fs.write out/ and compiled without [contradiction]: %v", codes(ds))
	}
}

// The same path in fs.write and fs.deny_read: Evaluate lets the write entry win the tie in the root
// tiers while tier 2's decideOpen refuses (equal length: deny wins), and compile says nothing.
func TestContractWriteAndDenyReadOnOnePathIsDiagnosed(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [out/]\n  deny_read: [out/]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodeContradiction) {
		t.Fatalf("write and deny_read on one path compiled (err %v): %v", err, codes(ds))
	}
}

// compile --test: a row path is never home-expanded, so `~/x` names <cwd>/~/x; a duplicated key keeps the
// last value silently; an alias value is the anchor's name, not the anchored value.
func TestContractTestTableRowsReadAsWritten(t *testing.T) {
	tbl, _, err := LoadTestTableBytes("t.yaml", []byte(`version: 0
tests:
  - {name: dup, action: fs.read, path: /a, expect: refused, expect: allow}
`))
	if err == nil && tbl.Rows[0].Expect == VerdictAllow {
		t.Error("a row with expect: refused then expect: allow loaded as allow, silently")
	}
	tbl, _, err = LoadTestTableBytes("t.yaml", []byte(`version: 0
tests:
  - {name: one, action: fs.read, path: &p /home/u/.ssh/id_rsa, expect: refused}
  - {name: two, action: fs.read, path: *p, expect: refused}
`))
	if err == nil && tbl.Rows[1].Path != "/home/u/.ssh/id_rsa" {
		t.Errorf("an aliased path loaded as %q, not the anchored value", tbl.Rows[1].Path)
	}
	tbl, _, err = LoadTestTableBytes("t.yaml", []byte("version: 0\ntests:\n  - {action: fs.read, path: ~/.ssh/id_rsa, expect: refused}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a := tbl.Rows[0].action("/work", "/home/u"); a.Path != "/home/u/.ssh/id_rsa" {
		t.Errorf("row path ~/.ssh/id_rsa evaluated as %s, want /home/u/.ssh/id_rsa", a.Path)
	}
	// An exec row's ~/ expands as Compile expands exec.allow's: it named <cwd>/~/bin/tool, so a row asserting
	// a refusal of an allowed ~/ binary passed.
	tbl, _, err = LoadTestTableBytes("t.yaml", []byte("version: 0\ntests:\n"+
		"  - {action: exec, path: ~/bin/tool, script: ~/bin/s.sh, expect: refused}\n"+
		"  - {action: exec, argv: [~/bin/tool, -x], expect: refused}\n"+
		"  - {action: exec, argv: [rg], expect: refused}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a := tbl.Rows[0].action("/work", "/home/u"); a.Path != "/home/u/bin/tool" || a.Script != "/home/u/bin/s.sh" {
		t.Errorf("exec row ~/bin/tool, ~/bin/s.sh evaluated as %s, %s; want both under /home/u", a.Path, a.Script)
	}
	if a := tbl.Rows[1].action("/work", "/home/u"); a.Path != "/home/u/bin/tool" {
		t.Errorf("exec row argv[0] ~/bin/tool evaluated as %s, want /home/u/bin/tool", a.Path)
	}
	if a := tbl.Rows[2].action("/work", "/home/u"); a.Path != "" || len(a.Argv) == 0 || a.Argv[0] != "rg" {
		t.Errorf("bare-name exec row became path %q argv %q, want the name left alone", a.Path, a.Argv)
	}
	// A net.connect row's unix socket path expands ~/ as Compile expands a `unix:~/...` entry: left as
	// written it never equalled the entry's absolute path, so an `expect: refused` row passed for the
	// wrong reason. An abstract name (@...) is a name, not a path, and stays as written. A row's own "unix:" prefix is
	// kept (the expansion dropped it, and the gate reads a prefixed path as a unix destination).
	tbl, _, err = LoadTestTableBytes("t.yaml", []byte("version: 0\ntests:\n"+
		"  - {action: net.connect, path: ~/run/s.sock, expect: refused}\n"+
		"  - {action: net.connect, path: \"unix:~/run/s.sock\", expect: refused}\n"+
		"  - {action: net.connect, path: \"@~/abs\", expect: refused}\n"+
		"  - {action: net.connect, path: \"unix:@~/abs\", expect: refused}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"/home/u/run/s.sock", "unix:/home/u/run/s.sock", "@~/abs", "unix:@~/abs"} {
		if a := tbl.Rows[i].action("/work", "/home/u"); a.Path != want {
			t.Errorf("net.connect row %q evaluated as %q, want %q", tbl.Rows[i].Path, a.Path, want)
		}
	}
}

// An alias fan-out made the schema walk visit an aliased subtree once per alias before yaml.v3's own limit
// applied: a 20 KB contract took 12 s and 2.5 GB. The expansion is bounded, and refused quickly.
func TestContractAliasFanOutIsRefusedQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 0\nname: a\ncommand: [/bin/true]\nmcp:\n  - &m {name: m, command: [")
	for i := range 4000 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("x")
	}
	b.WriteString("]}\n")
	for range 4000 {
		b.WriteString("  - *m\n")
	}
	start := time.Now()
	_, _, err := LoadBytes("agent.yaml", []byte(b.String()), nil)
	if err == nil {
		t.Fatal("a contract expanding to 16M nodes through aliases loaded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refusing it took %v", d)
	}
}

// A write entry inside tego's own directory (the one holding the chain anchor: config, prices, profiles)
// or inside a run directory under the ledger root lets the agent rewrite what later runs load, or another
// run's record, though it contains none of R10's targets. Both are contradictions.
func TestContractWriteInsideTegosOwnTreesIsAContradiction(t *testing.T) {
	f := newFixture(t)
	tego := filepath.Join(f.home, ".tego")
	profiles := filepath.Join(tego, "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(f.ledger, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{profiles, other} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + entry + "\"]\n")
		_, ds, err := Compile(c, f.machine, f.opts(WithChainAnchor(filepath.Join(tego, "chain.log")))...)
		if err == nil || !hasCode(ds, CodeContradiction) {
			t.Errorf("fs.write %s compiled (err %v): %v", entry, err, codes(ds))
		}
	}
}

// A contract, profile or test table is read from a regular file or a pipe only: opening a FIFO with no
// writer blocked Load in open(2) forever, and a device (a tty, /dev/zero) was read as if it were one.
// agent-contract.md E25: only a regular file, a pipe or a socket is read, so a FIFO with no writer cannot hold Load.
func TestLoadReadsOnlyAFileOrAPipe(t *testing.T) {
	if _, _, err := Load("/dev/zero", nil); !errors.Is(err, ErrNotAFile) {
		t.Errorf("Load(/dev/zero) = %v, want ErrNotAFile", err)
	}
	fifo := filepath.Join(t.TempDir(), "agent.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := Load(fifo, nil); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("an empty FIFO loaded as a contract")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load of a FIFO with no writer blocked")
	}
}

// A contract file with a second name (a hard link) is refused (ADR 0059): R10 keeps every write entry off the names
// the next run reads the contract by, and none is compared with the other name, so a run whose write entry holds it
// rewrote the contract its next run loads. With its one name back it loads.
func TestLoadRefusesAContractWithASecondName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: a\ncommand: [python]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "kept.yaml")
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path, nil); !errors.Is(err, config.ErrUntrusted) || !strings.Contains(err.Error(), "2 names") {
		t.Fatalf("Load of a contract with 2 names = %v, want config.ErrUntrusted naming them", err)
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path, nil); err != nil {
		t.Fatalf("Load with one name: %v", err)
	}
}
