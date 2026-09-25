// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// launcherPick is internal/runtime resolveCommand's choice for a bare name: the first non-directory exec rule
// with that basename in the final table (copied, since that package imports this one).
func launcherPick(rt *RuleTable, name string) string {
	for _, e := range rt.Exec {
		if !e.IsDir && e.Path != "" && e.Basename == name {
			return e.Path
		}
	}
	return ""
}

// TestRunCommandBareNameKeepsPinnedExecAllow: addRunCommand says "a bare name
// another entry already names by basename runs that entry's binary and adds nothing", but it ran before
// exec.allow and mcp[] were added, so a bare CLI name that exec.allow pins to another path was granted again
// from PATH, and resolveCommand then ran the PATH binary, not the pinned one it ran before eb673e6.
func TestRunCommandBareNameKeepsPinnedExecAllow(t *testing.T) {
	f := newFixture(t)
	pinned := filepath.Join(f.root, "opt", "python")
	if err := os.MkdirAll(filepath.Dir(pinned), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(pinned, string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: a\ncommand: [static-tool]\nexec:\n  allow: [\"" + pinned + "\"]\n")
	base, _ := f.compile(c)
	rt, _ := f.compile(c, WithRunCommand("python"))
	if got := launcherPick(base, "python"); got != pinned {
		t.Fatalf("without the grant the launcher runs %s, want the pinned %s", got, pinned)
	}
	if len(rt.Exec) != len(base.Exec) {
		t.Errorf("run command python added %d rule(s) though exec.allow already names python: %+v", len(rt.Exec)-len(base.Exec), rt.Exec)
	}
	if got := launcherPick(rt, "python"); got != pinned {
		t.Errorf("tego run -- python now runs %s, not the exec.allow-pinned %s", got, pinned)
	}
}

// TestRunCommandBareNameIsGrantedByPath: a bare CLI command was compiled ByName,
// so tier 3 admitted any file of that basename, one the agent writes under its write entry included, for the
// whole run. It is granted as the absolute path PATH resolved it to, which RunCommandGrant names, at a
// position on the command line rather than line 1 of the contract.
func TestRunCommandBareNameIsGrantedByPath(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out]\nexec: {}\n")
	rt, _ := f.compile(c, WithRunCommand("static-tool"))
	planted := filepath.Join(f.project, "out", "static-tool")
	r := rt.Evaluate(Action{Kind: ActionExec, Path: planted}, backend.TierBPFLSM)
	if r.Verdict == VerdictAllow {
		t.Errorf("tier 3: a static-tool the agent wrote at %s is admitted under %s (run command given as a bare name)", planted, r.Rule)
	}
	want := filepath.Join(f.bin, "static-tool")
	if rt.RunCommandGrant != want {
		t.Errorf("RunCommandGrant = %q, want %q", rt.RunCommandGrant, want)
	}
	for _, e := range rt.Exec {
		if e.Path == want && (e.ByName || e.Pos.File != CommandLineFile) {
			t.Errorf("the run command's rule: %+v, want by path at %s", e, CommandLineFile)
		}
	}
	if r := rt.Evaluate(Action{Kind: ActionExec, Path: want}, backend.TierBPFLSM); r.Verdict != VerdictAllow {
		t.Errorf("tier 3: the run command %s itself is refused: %+v", want, r)
	}
}
