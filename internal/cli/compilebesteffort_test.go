// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileTestShowsBestEffortCells is ADR 0041 D7's "compile --test columns show the same": a row whose answer in a
// tier rests on a best-effort cell, a decision a run takes on copied syscall facts, names that cell's id, in the text
// line and as each column's best_effort in --json, as run_start.best_effort lists it for a run of the contract there.
// A gate decides every tier alike, so its cells hold in every column, refusals included (a sibling thread can race a
// benign spelling, continued, to the refused one); the built-in deny_write target is best effort where no decision
// plane decides it, which compile, probing no machine, takes to be tier landlock and tier cgroup, and the bpflsm
// column's plane refuses it by inode. A refusal the floor makes before the gate rests on no cell, and so does an exec
// a command rule refuses, which never runs (exec.rules/argv is an allow's cell, ADR 0048). A
// rename of a secret out of its name is refused by the source's read scoring, as a run refuses it (ADR 0041 Step 4).
// Before, every one of these rows printed a bare PASS and the columns said nothing of how the
// answer would be decided.
func TestCompileTestShowsBestEffortCells(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("the exec row names git, not on PATH")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work", ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := `version: 0
name: besteffort
command: [true]
fs:
  write: ["./work"]
exec:
  allow: [git status]
gate:
  rules:
    - 'fs.read matches "*.env"': 90
    - fs.write outside worktree: 90
`
	table := `tests:
  - name: a secret the read gate refuses
    action: fs.read
    path: work/app.env
    expect: refused
  - name: an ordinary read the read gate scores
    action: fs.read
    path: work/main.go
    expect: allow
  - name: the protected target
    action: fs.write
    path: work/.mcp.json
    expect: refused
  - name: an ordinary write the write gate scores
    action: fs.write
    path: work/main.go
    expect: allow
  - name: a write the floor refuses
    action: fs.write
    path: /etc/passwd
    expect: refused
  - name: a delete in the worktree
    action: fs.delete
    path: work/main.go
    expect: allow
  - name: a command the exec rules allow
    action: exec
    argv: [git, status]
    expect: allow
  - name: a git subcommand the rules leave out
    action: exec
    argv: [git, push]
    expect: refused
  - name: rename a secret out of its name
    action: fs.rename
    path: work/app.env
    dest: work/notes.txt
    expect: refused
`
	for name, body := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	args := []string{"compile", "agent.yaml", "--offline", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm"}
	code, out, errs := run(t, args...)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	want := []string{
		"PASS a secret the read gate refuses [best effort: gate.fs.read/open]\n",
		"PASS an ordinary read the read gate scores [best effort: gate.fs.read/open]\n",
		"PASS the protected target [best effort: deny_write/default at landlock, cgroup]\n",
		"PASS an ordinary write the write gate scores [best effort: gate.fs.write/open]\n",
		"PASS a write the floor refuses\n",
		"PASS a delete in the worktree [best effort: gate.fs.write/mutation]\n",
		"PASS a command the exec rules allow [best effort: exec.rules/argv]\n",
		"PASS a git subcommand the rules leave out\n",
		"PASS rename a secret out of its name [best effort: gate.fs.read/move; gate.fs.write/mutation]\n",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("stdout lacks %q:\n%s", w, out)
		}
	}

	code, out, errs = run(t, append(args, "--json")...)
	if code != identity.ExitOK {
		t.Fatalf("--json: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var rep TestReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, out)
	}
	cells := map[string][][]string{}
	for _, r := range rep.Rows {
		for _, c := range r.Columns {
			cells[r.Name] = append(cells[r.Name], c.BestEffort)
		}
	}
	for row, wantCols := range map[string][][]string{
		"a secret the read gate refuses": {{"gate.fs.read/open"}, {"gate.fs.read/open"}, {"gate.fs.read/open"}},
		"the protected target":           {{"deny_write/default"}, {"deny_write/default"}, nil},
		"a write the floor refuses":      {nil, nil, nil},
	} {
		got := cells[row]
		if len(got) != len(wantCols) {
			t.Errorf("%q: %d columns, want %d", row, len(got), len(wantCols))
			continue
		}
		for i := range wantCols {
			if !slices.Equal(got[i], wantCols[i]) {
				t.Errorf("%q column %d: best_effort %v, want %v", row, i, got[i], wantCols[i])
			}
		}
	}
	if strings.Contains(out, `"best_effort":[]`) || strings.Contains(out, `"best_effort":null`) {
		t.Errorf("a column with no cell carries an empty best_effort:\n%s", out)
	}
}
