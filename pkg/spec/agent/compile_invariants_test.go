// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompileIgnoresAmbientPATH pins I8: "Load/Compile read no environment
// variable except $PATH, and that is the run's effective PATH, never
// os.Getenv("PATH") read ambiently." Compile takes PATH only through
// WithPATH; nothing in this package may fall back to the process's own
// environment.
//
// The regression this guards: a real $PATH almost always contains a usable
// "python", so a silent ambient read would make exec resolution succeed by
// accident and every other PATH test in this package (which all pass PATH
// explicitly) would stay green while a caller that forgets WithPATH quietly
// gets the compiling process's PATH instead of the run's.
func TestCompileIgnoresAmbientPATH(t *testing.T) {
	f := newFixture(t)

	// A binary named "python" that exists only on the process's real PATH,
	// never handed to Compile via WithPATH.
	decoyDir := t.TempDir()
	f.file(filepath.Join(decoyDir, "python"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	t.Setenv("PATH", decoyDir)

	c := f.load("version: 0\nname: a\ncommand: [python]\n")
	// Every other option except WithPATH: omitting it must not fall back to
	// os.Getenv("PATH"), which t.Setenv just pointed at the decoy binary.
	opts := []CompileOption{WithResolver(f.resolver), WithCwd(f.project), WithHome(f.home)}
	rt, ds, err := Compile(c, f.machine, opts...)
	if err == nil || rt != nil {
		t.Fatalf("command resolved via the ambient PATH: rt=%+v err=%v", rt, err)
	}
	if !hasCode(ds, CodeExecNotOnPath) {
		t.Fatalf("want exec-not-on-path (no PATH given to Compile), got %v\n%s", codes(ds), render(ds))
	}
}

// TestCompileNeverCreatesTheWriteLeaf pins R7 and I6 together: "Compile does
// not check that the parent is writable... Creating the directory... is
// run's job, not compile's" (R7), and Compile performs no write-flagged
// syscall at all (I6). A write entry whose parent exists but whose leaf does
// not must compile to Missing:true with no attempt to create it.
//
// The parent directory is made read-only so that if Compile regressed into
// pre-creating the leaf (a plausible "helpful" mistake — see the PROVE step
// in the test's sibling commit), the create would fail loudly with EACCES
// instead of silently succeeding and hiding the violation.
func TestCompileNeverCreatesTheWriteLeaf(t *testing.T) {
	f := newFixture(t)
	parent := filepath.Join(f.project, "out")
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out/newleaf]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile must not need to create the leaf: %v\n%s", err, render(ds))
	}
	r := findFS(rt, FSWrite, filepath.Join(parent, "newleaf"))
	if r == nil || !r.Missing {
		t.Fatalf("write leaf rule: %+v", r)
	}
}

// TestCompileSurvivesContractFileDeletedAfterLoad pins E21: "Contract file
// deleted/replaced between Load and Compile... no effect on an already-
// returned *Contract." Compile never re-reads the contract's bytes (Hash
// comes from the in-memory Canonical() form), so a file that vanished
// between the two calls — the two-CLI-invocation race the edge case names —
// must not turn into a Compile failure; the implicit contract-file FSRule
// simply carries Missing:true like any other absent implicit path.
func TestCompileSurvivesContractFileDeletedAfterLoad(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\n")
	path := filepath.Join(f.project, "agent.yaml")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile must tolerate a vanished contract file: %v\n%s", err, render(ds))
	}
	r := findFS(rt, FSImplicit, path)
	if r == nil || !r.Missing {
		t.Fatalf("implicit contract-file entry: %+v", r)
	}
}

// TestCompileExecNotOnPathNamesMCPServer pins E37: an unresolvable
// mcp[].command[0] gets "the same code and Fix shape as any other PATH
// exhaustion, with the message additionally naming the offending
// mcp[].name so a contract with several MCP servers doesn't need
// per-entry guessing." A bare exec-not-on-path code is not enough on its
// own to prove the message actually names the server.
// agent-contract.md E37.
func TestCompileExecNotOnPathNamesMCPServer(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nmcp:\n  - name: ghost\n    command: [mcp-ghost]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodeExecNotOnPath) {
		t.Fatalf("want exec-not-on-path, got err=%v codes=%v", err, codes(ds))
	}
	if !strings.Contains(render(ds), `mcp "ghost" command "mcp-ghost"`) {
		t.Fatalf("message does not name the mcp server (E37):\n%s", render(ds))
	}
}

// TestCompileWriteSymlinkKeepsDeclaredPath pins the two halves of E8. FSRule.Path
// stays the entry as declared, because that string is the rule name the ledger
// carries and the one `tego drift` compares against; rewriting it to a realpath
// would name something no contract declared. FSRule.Resolved carries the target,
// because the run opens the entry O_PATH *without* O_NOFOLLOW — which follows the
// link and pins the target — so the target, not the link, is the subtree the rule
// governs and the one every containment check must ask about.
func TestCompileWriteSymlinkKeepsDeclaredPath(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "realtarget")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "linkdir")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [linkdir]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if r := findFS(rt, FSWrite, link); r == nil {
		t.Fatalf("write rule must be keyed on the declared symlink path %s, not its target; rules: %+v", link, rt.FS)
	}
	if r := findFS(rt, FSWrite, target); r != nil {
		t.Fatalf("write rule resolved to the symlink's target instead of the declared path: %+v", r)
	}
	if r := findFS(rt, FSWrite, link); r.Resolved != target {
		t.Fatalf("write rule Resolved = %q, want the symlink's target %q", r.Resolved, target)
	}
}
