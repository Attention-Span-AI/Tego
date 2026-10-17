// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestFSAssuranceKey is the fs.assurance key (agent-contract R20, ADR 0041 D1 (a)): best-effort or kernel, the
// default best-effort; any other value is a schema error; the value is part of contract_hash, so a ledger can
// tell which one a run held; and RuleTable.FilesystemAssurance reads the stricter of the compiled value and the
// contract's, so a hand-built table cannot lose an explicit kernel requirement.
func TestFSAssuranceKey(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: t\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  assurance: strict\n", 0o644)
	if _, ds, err := Load(path, f.profiles()); err == nil || !strings.Contains(render(ds), "assurance") {
		t.Fatalf("fs.assurance: strict loaded (err %v):\n%s", err, render(ds))
	}
	const body = "version: 0\nname: t\ncommand: [python]\nfs:\n  write: [\"out/\"]\n"
	plain, _ := f.compile(f.load(body))
	if plain.FSAssurance != FSAssuranceBestEffort || plain.FilesystemAssurance() != FSAssuranceBestEffort {
		t.Errorf("default fs assurance %q/%q, want %q", plain.FSAssurance, plain.FilesystemAssurance(), FSAssuranceBestEffort)
	}
	strict, _ := f.compile(f.load(body + "  assurance: kernel\n"))
	if strict.FSAssurance != FSAssuranceKernel || strict.FilesystemAssurance() != FSAssuranceKernel {
		t.Errorf("fs.assurance: kernel compiled to %q/%q", strict.FSAssurance, strict.FilesystemAssurance())
	}
	if strict.Hash == plain.Hash {
		t.Error("fs.assurance: kernel and the default hash the same: contract_hash cannot tell them apart")
	}
	same, _ := f.compile(f.load(body + "  assurance: best-effort\n"))
	if same.FSAssurance != FSAssuranceBestEffort {
		t.Errorf("fs.assurance: best-effort compiled to %q", same.FSAssurance)
	}
	hand := &RuleTable{Contract: &Contract{FS: &FSSection{Assurance: FSAssuranceKernel}}}
	if hand.FilesystemAssurance() != FSAssuranceKernel {
		t.Error("a table whose contract says kernel read as best effort")
	}
	hand.FSAssurance = FSAssuranceBestEffort
	if hand.FilesystemAssurance() != FSAssuranceKernel {
		t.Error("a compiled best-effort outvoted the contract's kernel requirement")
	}
	if (&RuleTable{}).FilesystemAssurance() != FSAssuranceBestEffort {
		t.Error("an empty table's fs assurance is not the default")
	}
}

// TestFSAssuranceMergeKeepsKernel: across extends the stricter value wins, so a contract cannot lower a profile's
// fs.assurance: kernel silently; Load says so at the contract's own line. A contract may raise a profile's
// best-effort to kernel.
func TestFSAssuranceMergeKeepsKernel(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "strict-fs", "fs:\n  assurance: kernel\n")
	writeProfile(t, f, "loose-fs", "fs:\n  assurance: best-effort\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: strict-fs\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  assurance: best-effort\n", 0o644)
	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if c.FS.Assurance != FSAssuranceKernel {
		t.Errorf("merged fs.assurance %q, want the profile's kernel kept", c.FS.Assurance)
	}
	if !slices.ContainsFunc(ds, func(d Diagnostic) bool {
		return !d.IsError() && d.File == path && d.Line == 7 && strings.Contains(d.Message, "fs.assurance")
	}) {
		t.Errorf("want a warning at the contract's fs.assurance line that the profile's kernel stands:\n%s", render(ds))
	}
	f.file(path, "version: 0\nname: a\nextends: loose-fs\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  assurance: kernel\n", 0o644)
	if c, ds, err = Load(path, src); err != nil || c.FS.Assurance != FSAssuranceKernel {
		t.Errorf("a contract raising a profile's best-effort: %v, %v\n%s", c, err, render(ds))
	}
}

// TestBestEffortCellsDenyWrite is ADR 0041 D7 for D1 (a): a run whose built-in deny_write set no kernel decision
// plane decides (tier landlock, tier cgroup on the fanotify listener) lists deny_write/default in run_start's
// best_effort, after the gate cells; one a plane decides (an lsm or fmod_ret mode, tier bpflsm), one with no
// target, one under fs.assurance: kernel (which never starts without a plane) and an observe run, which enforces
// nothing, do not.
func TestBestEffortCellsDenyWrite(t *testing.T) {
	rt := &RuleTable{DenyWrite: []FSRule{{Kind: FSDenyWrite, Path: "/w/.git/hooks"}}}
	for _, tc := range []struct {
		tier  backend.Tier
		plane string
		want  bool
	}{
		{backend.TierLandlock, "", true},
		{backend.TierCgroup, "", true},
		{backend.TierCgroup, "fanotify", true},
		{backend.TierCgroup, "lsm", false},
		{backend.TierCgroup, "fmod_ret", false},
		{backend.TierBPFLSM, "lsm", false},
		{backend.TierObserve, "", false},
	} {
		if got := slices.Contains(rt.BestEffortCellsAt(tc.tier, tc.plane), BestEffortDenyWrite); got != tc.want {
			t.Errorf("tier %s plane %q: deny_write cell listed %v, want %v", tc.tier, tc.plane, got, tc.want)
		}
	}
	if got := (&RuleTable{}).BestEffortCellsAt(backend.TierLandlock, ""); len(got) != 0 {
		t.Errorf("a table with no target lists %v", got)
	}
	strict := &RuleTable{DenyWrite: rt.DenyWrite, FSAssurance: FSAssuranceKernel}
	if got := strict.BestEffortCellsAt(backend.TierLandlock, ""); len(got) != 0 {
		t.Errorf("fs.assurance: kernel lists %v: such a run is refused, never best effort", got)
	}
}
