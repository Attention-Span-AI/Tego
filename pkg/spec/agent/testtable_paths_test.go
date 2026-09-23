// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTestRowBareRelativeFSPathResolves pins E28 for the one path shape that used to slip through:
// a single-component relative path in a filesystem row. TestRow.action must hand Evaluate the
// absolute form Compile resolved the contract's entries to, because cleanPath deliberately resolves
// nothing (I6) and CoverSteps compares whole components against absolute entries.
//
// The regression this guards is silent and bidirectional: `- action: fs.write, path: report.md,
// expect: refused` used to PASS under `fs: {write: ["./"]}` while the run writes the file happily,
// and `- action: fs.read, path: .env, expect: refused` used to FAIL against the built-in deny_read
// entry that every tier enforces. Both rows landed in the `unmatched` bucket whatever the contract
// said, which is the one outcome a test table must never produce.
func TestTestRowBareRelativeFSPathResolves(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The contract lives outside the project so that `write: ["./"]` — the shape that makes a
	// bare row path meaningful — is not itself an R10 contradiction.
	path := filepath.Join(f.root, "agent.yaml")
	f.file(path, "version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"./\"]\n", 0o644)
	c, ds, err := Load(path, f.profiles())
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	rt, _ := f.compile(c)

	const src = `version: 0
tests:
  - name: bare name under the write entry
    action: fs.write
    path: report.md
    expect: allow
    rule: fs.write[./]
  - name: nested name under the write entry
    action: fs.write
    path: work/report.md
    expect: allow
    rule: fs.write[./]
  - name: bare name under the built-in deny_read list
    action: fs.read
    path: .env
    expect: refused
  - name: bare name as a rename destination
    action: fs.rename
    path: work/a
    dest: b
    expect: allow
`
	table, tds, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load table: %v\n%s", err, render(tds))
	}
	for _, res := range table.Run(rt, f.project) {
		if !res.Pass {
			t.Errorf("row %q: got %+v, want %s (rule %q)", res.Row.Label(), res.Got, res.Row.Expect, res.Row.Rule)
		}
	}
}

// TestTestRowBareExecNameStaysACommand is the other side of the same split: an exec row written as
// `argv: [rg]` names a command, not a file in cwd, and must keep doing so.
func TestTestRowBareExecNameStaysACommand(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [static-tool]\nexec:\n  allow: [python]\n"))

	const src = `version: 0
tests:
  - action: exec
    argv: [python, agent.py]
    expect: allow
    rule: exec[python]
`
	table, ds, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	for _, res := range table.Run(rt, f.project) {
		if !res.Pass {
			t.Errorf("row %q: got %+v, want %s (rule %q)", res.Row.Label(), res.Got, res.Row.Expect, res.Row.Rule)
		}
	}
}
