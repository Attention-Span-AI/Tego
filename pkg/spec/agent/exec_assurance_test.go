// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestExecAssuranceKey is ADR 0048 (3) P2's exec.assurance in the contract: it takes best-effort or kernel and
// defaults to best effort; kernel with no command rules and no escalating exec gate warns redundant-rule, since it
// holds nothing there; kernel beside command rules compiles quietly.
func TestExecAssuranceKey(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\n"))
	if rt.ExecutionAssurance() != ExecAssuranceBestEffort || rt.ExecAssurance != ExecAssuranceBestEffort {
		t.Fatalf("default %q / %q:\n%s", rt.ExecutionAssurance(), rt.ExecAssurance, render(ds))
	}
	rt, ds = f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  deny: [git push]\n  assurance: kernel\n"))
	if rt.ExecutionAssurance() != ExecAssuranceKernel || hasCode(ds, CodeRedundantRule) || !rt.ExecFactsDecided() {
		t.Fatalf("kernel beside a deny entry: %q, decided %t:\n%s", rt.ExecutionAssurance(), rt.ExecFactsDecided(), render(ds))
	}
	rt, ds = f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  allow: [python]\n  assurance: kernel\n"))
	if rt.ExecutionAssurance() != ExecAssuranceKernel || !hasCode(ds, CodeRedundantRule) || rt.ExecFactsDecided() {
		t.Fatalf("kernel with nothing to hold: %q:\n%s", rt.ExecutionAssurance(), render(ds))
	}
	if _, ds, err := LoadBytes("a.yaml", []byte("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  deny: [git push]\n"+
		"  assurance: strict\n"), nil); err == nil || !strings.Contains(render(ds), "exec.assurance") || !strings.Contains(render(ds), `"strict"`) {
		t.Fatalf("an unknown value: %v\n%s", err, render(ds))
	}
}

// TestExecAssuranceSurvivesCanonical: a deny-list section with exec.assurance keeps both through the run's contract
// copy (MarshalYAML), so the copy recompiles to the same mode and the same requirement.
func TestExecAssuranceSurvivesCanonical(t *testing.T) {
	b, err := yaml.Marshal(ExecSection{Deny: []string{}, Assurance: ExecAssuranceKernel})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, "deny: []") || !strings.Contains(s, "assurance: kernel") {
		t.Fatalf("encoded %q", s)
	}
}

// TestBestEffortDropsPinnedExecCells is ADR 0048 (6): exec.rules/argv and gate.exec are listed for a table with command
// rules and an escalating exec gate, and leave run_start.best_effort exactly when the kernel holds the run's execs.
func TestBestEffortDropsPinnedExecCells(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  deny: [git push]\n" +
		"gate:\n  rules:\n    - 'exec matches \"rm -rf\"': 95\n"))
	for _, pinned := range []bool{false, true} {
		got := rt.BestEffortCellsRun("cgroup", "lsm", false, pinned)
		has := slices.Contains(got, BestEffortExecRules) && slices.Contains(got, BestEffortGateExec)
		none := !slices.Contains(got, BestEffortExecRules) && !slices.Contains(got, BestEffortGateExec)
		if pinned && !none || !pinned && !has {
			t.Fatalf("pinned %t: %v\n%s", pinned, got, render(ds))
		}
	}
	if got := rt.BestEffortCellsAt("cgroup", "lsm"); !slices.Contains(got, BestEffortExecRules) {
		t.Fatalf("BestEffortCellsAt claims no pins: %v", got)
	}
}

// TestExecAssuranceMergeKeepsKernel: across extends the stricter exec.assurance wins, as fs.assurance's does, so a
// contract cannot lower a profile's kernel silently; Load says so at the contract's own line. A contract may raise a
// profile's best-effort to kernel.
func TestExecAssuranceMergeKeepsKernel(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "strict-exec", "exec:\n  deny: [git push]\n  assurance: kernel\n")
	writeProfile(t, f, "loose-exec", "exec:\n  deny: [git push]\n  assurance: best-effort\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: strict-exec\ncommand: [python]\nexec:\n  deny: [rm]\n  assurance: best-effort\n", 0o644)
	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if c.Exec.Assurance != ExecAssuranceKernel {
		t.Errorf("merged exec.assurance %q, want the profile's kernel kept", c.Exec.Assurance)
	}
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return !d.IsError() && d.File == path && d.Line == 7 && strings.Contains(d.Message, "exec.assurance")
	}) {
		t.Errorf("want a warning at the contract's exec.assurance line that the profile's kernel stands:\n%s", render(ds))
	}
	f.file(path, "version: 0\nname: a\nextends: loose-exec\ncommand: [python]\nexec:\n  deny: [rm]\n  assurance: kernel\n", 0o644)
	if c, ds, err = Load(path, src); err != nil || c.Exec.Assurance != ExecAssuranceKernel {
		t.Errorf("a contract raising a profile's best-effort: %v, %v\n%s", c, err, render(ds))
	}
}
