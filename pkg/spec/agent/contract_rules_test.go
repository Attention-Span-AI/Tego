// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestRedundantWriteEntryWarnsAndKeepsBoth is agent-contract.md E10: two fs.write entries, one an ancestor of
// the other, are not an error: the subsumed one draws a redundant-rule warning and both stay in the table.
func TestRedundantWriteEntryWarnsAndKeepsBoth(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out, out/sub]\n")
	rt, ds := f.compile(c)
	if HasErrors(ds) {
		t.Fatalf("nested write entries are not an error:\n%s", render(ds))
	}
	var got *Diagnostic
	for i := range ds {
		if ds[i].Code == CodeRedundantRule && strings.Contains(ds[i].Message, "out/sub") {
			got = &ds[i]
		}
	}
	if got == nil {
		t.Fatalf("no redundant-rule warning on the subsumed out/sub:\n%s", render(ds))
	}
	if findFS(rt, FSWrite, filepath.Join(f.project, "out")) == nil || findFS(rt, FSWrite, filepath.Join(f.project, "out", "sub")) == nil {
		t.Errorf("both write entries must stay in the table")
	}
}

// TestUnicodePathsAreComparedByRawBytes is agent-contract.md E4: a path stored NFC on disk and written NFD in
// the contract is not normalised into a match, so it reports path-missing. A documented limitation.
func TestUnicodePathsAreComparedByRawBytes(t *testing.T) {
	f := newFixture(t)
	nfc, nfd := "café", "café"
	if err := os.MkdirAll(filepath.Join(f.project, nfc), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.project, nfd)); err == nil {
		t.Skip("this filesystem normalises Unicode names itself, so the two spellings are one path")
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [" + filepath.Join(f.project, nfd, "out") + "]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasCode(ds, CodePathMissing) {
		t.Fatalf("an NFD spelling of an NFC directory must be path-missing, got err=%v\n%s", err, render(ds))
	}
}

// snapshot is every entry under root with its mode, time and content, to compare a tree before and after.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		body := ""
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			body = string(b)
		}
		out[p] = info.Mode().String() + "|" + info.ModTime().String() + "|" + body
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCompileChangesNoFileOfTheAgents is agent-contract.md R24 for this package: compiling a
// contract and answering rows against the table touch no file of the agent's, its project or its binaries:
// same names, modes, times and bytes afterwards.
func TestCompileChangesNoFileOfTheAgents(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out]\nexec:\n  allow: [python, tool.sh]\nnet:\n  allow: [mcp.internal:8080]\n")
	before := snapshot(t, f.root)
	rt, _ := f.compile(c)
	_ = rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(f.project, "out", "x")}, backend.TierLandlock)
	after := snapshot(t, f.root)
	for p, v := range before {
		if after[p] != v {
			t.Errorf("%s changed:\nbefore %q\nafter  %q", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s was created", p)
		}
	}
}

// TestExecEntryIsAdvisoryAtCompile is agent-contract.md E13: a binary replaced after Compile (a pyenv shim
// rewrite) is accepted. The table keeps what Compile read (the path and the loader it recorded) and nothing
// re-reads the file, so only the next Compile sees the new one.
func TestExecEntryIsAdvisoryAtCompile(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n")
	rt, _ := f.compile(c)
	r := findExec(rt, "python")
	if r == nil || r.Interp != "/lib64/ld-fake.so.2" {
		t.Fatalf("compiled python = %+v, want the fixture's fake loader", r)
	}
	f.file(filepath.Join(f.bin, "python"), string(elf64("/lib64/ld-other.so.2", 3)), 0o755)
	if again := findExec(rt, "python"); again.Interp != "/lib64/ld-fake.so.2" || again.Path != r.Path {
		t.Errorf("the compiled table changed under a replaced binary: %+v", again)
	}
	rt2, _ := f.compile(c)
	if r2 := findExec(rt2, "python"); r2 == nil || r2.Interp != "/lib64/ld-other.so.2" {
		t.Errorf("the next Compile must see the replaced binary, got %+v", r2)
	}
}

// TestResolvedAtIsMonotonicAndOutsideTheHash is agent-contract.md E23: NetRule.ResolvedAt is stamped from
// time.Now, so it carries a monotonic reading that survives a wall-clock step, and it is kept in memory only:
// two Compiles at different clocks hash alike.
func TestResolvedAtIsMonotonicAndOutsideTheHash(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [mcp.internal:8080]\n")
	early, _, err := Compile(c, f.machine, f.opts(WithClock(func() time.Time { return time.Unix(1_000, 0) }))...)
	if err != nil {
		t.Fatal(err)
	}
	late, _, err := Compile(c, f.machine, f.opts(WithClock(time.Now))...)
	if err != nil {
		t.Fatal(err)
	}
	if early.Hash != late.Hash {
		t.Errorf("contract_hash depends on the resolution time")
	}
	at := late.Net[0].ResolvedAt
	if !strings.Contains(at.String(), "m=+") {
		t.Errorf("ResolvedAt = %s carries no monotonic reading, so a clock step would skew TTL arithmetic", at)
	}
}
