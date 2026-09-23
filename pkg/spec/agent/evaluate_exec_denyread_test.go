// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// rootTiers are the two tiers whose nearest-ancestor walk runs at file_open (SEMANTICS §2).
func rootTiers() []backend.Tier { return []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} }

// TestExecUnrestrictedStopsAtAnEnforceableDenyRead is the boundary of SEMANTICS §1's "no `exec:` —
// deny nothing". That default is about exec rules; the kernel still opens the program
// O_RDONLY|__FMODE_EXEC (SEMANTICS §4), and that open is a read every enforcing tier refuses under a
// deny_read.
//
// Tier 1: the Landlock builder implements the default by adding EXECUTE to the sibling read sets,
// the enumerated ancestors and the write masks, but the exec open needs READ_FILE too, and nothing
// carries READ_FILE inside a deny_read target with no write entry nested in it: its entry carries
// Access 0, an ancestor carries no READ_FILE, and no level within it is enumerated (I11,
// enforce-landlock R3). Root tiers: SEMANTICS §2's nearest-ancestor walk runs at file_open and the
// deny_read entry decides it; in tier 2 the fanotify listener sees the exec open as a FAN_OPEN_PERM
// and refuses it under the deny_read (cgroup policy.go decideOpen), and the inherited tier-1 ruleset
// refuses this undeclared binary as well.
//
// Reporting allow in any of them is a false assurance in the permissive direction: a
// `compile --test` row that passes and a run that dies.
func TestExecUnrestrictedStopsAtAnEnforceableDenyRead(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.home, ".ssh", "tool")
	if err := os.WriteFile(tool, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	wantRule := "fs.deny_read[" + filepath.Join(f.home, ".ssh") + "]"

	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied {
			t.Errorf("tier %s: exec of %s = %+v, want refused/%s: the exec open is a read under a deny_read", tier, tool, got, record.ReasonReadDenied)
		}
		if got.Rule != wantRule {
			t.Errorf("tier %s: rule = %q, want the deny_read entry that decided (%s)", tier, got.Rule, wantRule)
		}
	}

	for _, tier := range enforcingTiers() {
		// A binary outside every deny_read entry is untouched.
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: "/usr/bin/curl"}, tier); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
			t.Errorf("tier %s: exec of an ordinary undeclared binary = %+v, want allow/%s", tier, got, UnmatchedRule)
		}
		// So is the agent's own command.
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "python")}, tier); got.Verdict != VerdictAllow {
			t.Errorf("tier %s: exec of the declared command = %+v, want allow", tier, got)
		}
	}
	// Observe mode enforces nothing, so it records the exec and allows it.
	if got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, backend.TierObserve); got.Verdict != VerdictAllow {
		t.Errorf("observe: exec of %s = %+v, want allow", tool, got)
	}
}

// TestExecUnrestrictedIgnoresAnUnenforceableDenyRead is the tier-1 half of the other side: when a
// write entry sits at or above the deny_read entry, tier 1 cannot enforce it (SEMANTICS §2, the
// unenforced marker) and Landlock leaves the subtree readable and executable, so no refusal may be
// invented there. The root tiers enforce every deny_read whatever the marker says, so they refuse.
func TestExecUnrestrictedIgnoresAnUnenforceableDenyRead(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.project, "out", "keys", "tool")
	if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\n  deny_read: [\"out/keys/\"]\n"))

	if got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, backend.TierLandlock); got.Verdict != VerdictAllow {
		t.Errorf("landlock: exec under an unenforceable deny_read = %+v, want allow", got)
	}
	for _, tier := range rootTiers() {
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, tier); got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied {
			t.Errorf("tier %s: exec under a deny_read the root tiers enforce = %+v, want refused/%s", tier, got, record.ReasonReadDenied)
		}
	}
}

// TestExecOfADeclaredBinaryUnderADenyRead separates the tiers on a binary the contract names. In
// Landlock the entry holds an fd of its own with READ_FILE|EXECUTE (execGrants), and Landlock unions
// that with the deny_read target's Access 0, so it runs. The root tiers' file_open walk stops only at
// fs entries, never at an exec.allow entry, so the deny_read decides the open and the exec is refused
// whether the contract has an exec: section or not.
func TestExecOfADeclaredBinaryUnderADenyRead(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.home, ".ssh", "tool")
	if err := os.WriteFile(tool, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	wantRule := "fs.deny_read[" + filepath.Join(f.home, ".ssh") + "]"
	for _, src := range []string{
		"version: 0\nname: a\ncommand: [\"" + tool + "\"]\n",                           // no exec: section
		"version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + tool + "\"]\n", // exec.allow names it
	} {
		rt, _ := f.compile(f.load(src))
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, backend.TierLandlock); got.Verdict != VerdictAllow || got.Rule != "exec["+tool+"]" {
			t.Errorf("%q: landlock exec of a declared binary = %+v, want allow/exec[%s]", src, got, tool)
		}
		for _, tier := range rootTiers() {
			got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, tier)
			if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied || got.Rule != wantRule {
				t.Errorf("%q: tier %s: exec of a declared binary under %s = %+v, want refused/%s/%s", src, tier, wantRule, got, record.ReasonReadDenied, wantRule)
			}
		}
	}
}

// TestExecInterpreterUnderADenyRead: a #! script's interpreter is opened O_RDONLY|__FMODE_EXEC as
// well (SEMANTICS §4, binfmt_script), so an interpreter under a deny_read refuses the script's exec
// in every enforcing tier even when the script itself is outside every deny_read entry.
func TestExecInterpreterUnderADenyRead(t *testing.T) {
	f := newFixture(t)
	interp := filepath.Join(f.home, ".ssh", "interp")
	if err := os.WriteFile(interp, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(f.project, "run.sh")
	f.file(script, "#!"+interp+"\n", 0o755)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))

	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionExec, Path: script, Script: interp}, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied {
			t.Errorf("tier %s: script whose interpreter is under a deny_read = %+v, want refused/%s", tier, got, record.ReasonReadDenied)
		}
	}
	// The control: an interpreter outside every deny_read runs the same script.
	for _, tier := range enforcingTiers() {
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: script, Script: filepath.Join(f.bin, "python")}, tier); got.Verdict != VerdictAllow {
			t.Errorf("tier %s: script with an ordinary interpreter = %+v, want allow", tier, got)
		}
	}
}

// TestExecRootTierCheckIsTheWalkNotAPrefix keeps the root-tier refusal the nearest-ancestor walk it
// is (SEMANTICS §2 "Nearest wins"), not a prefix test on the deny_read path: a write entry nested
// inside the deny_read target is the nearer entry for a binary beneath it, and the open is allowed.
func TestExecRootTierCheckIsTheWalkNotAPrefix(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.project, "secrets", "build", "tool")
	if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"secrets/build/\"]\n  deny_read: [\"secrets/\"]\n"))
	for _, tier := range rootTiers() {
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, tier); got.Verdict != VerdictAllow {
			t.Errorf("tier %s: exec under a write entry nested in a deny_read = %+v, want allow (nearest wins)", tier, got)
		}
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.project, "secrets", "key.pem")}, tier); got.Verdict != VerdictRefused {
			t.Errorf("tier %s: exec beside the nested write entry = %+v, want refused", tier, got)
		}
	}
}

// wantReadDenied checks one exec row in the root tiers: refused as the read the exec open is, named
// by the deny_read entry that decided it.
func wantReadDenied(t *testing.T, rt *RuleTable, a Action, rule, why string) {
	t.Helper()
	for _, tier := range rootTiers() {
		got := rt.Evaluate(a, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied || got.Rule != rule {
			t.Errorf("%s: tier %s: %+v = %+v, want refused/%s/%s", why, tier, a, got, record.ReasonReadDenied, rule)
		}
	}
}

// wantLandlockAllow checks the same row in tier 1, where a declared file keeps an fd of its own with
// READ_FILE|EXECUTE (enforce-landlock R5) that the deny_read target's Access 0 does not withdraw.
func wantLandlockAllow(t *testing.T, rt *RuleTable, a Action, rule, why string) {
	t.Helper()
	got := rt.Evaluate(a, backend.TierLandlock)
	if got.Verdict != VerdictAllow || (rule != "" && got.Rule != rule) {
		t.Errorf("%s: landlock: %+v = %+v, want allow %s", why, a, got, rule)
	}
}

// TestExecBareNameIsTheEntryItMatches: a bare command name in a row (`argv: [tool]`, the shape
// examples/tests/verdicts.yaml uses) names no file, and this package makes no PATH lookup (I6). It
// means the resolved path of the entry it matches, so the read the exec open is must be asked of
// that path. Taking the bare string as a path of its own, or skipping it, answers the read for no
// file at all and certifies in the root tiers an exec the file_open walk refuses.
func TestExecBareNameIsTheEntryItMatches(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.home, ".ssh", "tool")
	if err := os.WriteFile(tool, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	deny := "fs.deny_read[" + filepath.Join(f.home, ".ssh") + "]"
	row := Action{Kind: ActionExec, Argv: []string{"tool"}}
	for _, c := range []struct{ name, src string }{
		{"exec.allow names it (restricted)", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + tool + "\"]\n"},
		{"command names it (no exec: section)", "version: 0\nname: a\ncommand: [\"" + tool + "\"]\n"},
	} {
		rt, _ := f.compile(f.load(c.src))
		wantLandlockAllow(t, rt, row, "exec["+tool+"]", c.name)
		wantReadDenied(t, rt, row, deny, c.name)
	}
}

// TestExecRestrictedScriptFilesAreReads covers the restricted branch's read check on the two files
// of a #! exec that the row itself names, the script and its interpreter, both opened
// O_RDONLY|__FMODE_EXEC (SEMANTICS §4; the loader has its own test below). The root tiers' hook
// passes the script stage and decides the exec rules on the interpreter, but the file_open walk
// still sees both opens, so either one under a deny_read refuses the exec there. In tier 1 both are
// declared and hold their own fds, so the exec runs.
func TestExecRestrictedScriptFilesAreReads(t *testing.T) {
	f := newFixture(t)
	deny := "fs.deny_read[" + filepath.Join(f.home, ".ssh") + "]"
	python := filepath.Join(f.bin, "python")

	t.Run("script under the deny_read", func(t *testing.T) {
		script := filepath.Join(f.home, ".ssh", "run.sh")
		f.file(script, "#!"+python+"\n", 0o755)
		rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, \"" + script + "\"]\n"))
		row := Action{Kind: ActionExec, Path: script, Script: python}
		wantReadDenied(t, rt, row, deny, "script under ~/.ssh")
		wantLandlockAllow(t, rt, row, "", "script under ~/.ssh")
	})

	interp := filepath.Join(f.home, ".ssh", "interp")
	if err := os.WriteFile(interp, []byte(elf64("", 2)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(f.project, "run.sh")
	f.file(script, "#!"+interp+"\n", 0o755)
	src := "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + interp + "\", \"" + script + "\"]\n"

	t.Run("interpreter under the deny_read", func(t *testing.T) {
		rt, _ := f.compile(f.load(src))
		row := Action{Kind: ActionExec, Path: script, Script: interp}
		wantReadDenied(t, rt, row, deny, "interpreter under ~/.ssh")
		wantLandlockAllow(t, rt, row, "exec["+interp+"]", "interpreter under ~/.ssh")
	})

	// A bare interpreter name means the entry it matches, exactly as a bare program name does.
	t.Run("bare interpreter name", func(t *testing.T) {
		rt, _ := f.compile(f.load(src))
		row := Action{Kind: ActionExec, Path: script, Script: "interp"}
		wantReadDenied(t, rt, row, deny, "bare interpreter matching an entry under ~/.ssh")
		wantLandlockAllow(t, rt, row, "exec["+interp+"]", "bare interpreter matching an entry under ~/.ssh")
	})
}

// TestExecLoaderUnderADenyRead: binfmt_elf opens the PT_INTERP loader of the ELF an exec ends in
// O_RDONLY|__FMODE_EXEC too (SEMANTICS §4), so a loader under a deny_read refuses the exec in the root
// tiers' file_open walk. In tier 1 Prepare refuses to grant a loader at or below any deny_read target
// and the run never starts (enforce-landlock E29), and tier 2 inherits that Prepare. Compile records
// the loader of every declared ELF entry (ExecRule.Interp), which is the only loader this package can
// name, and warns about it (loader-refused): no other row of such a contract can pass honestly in
// those two tiers, because the run exits 125 before any action.
func TestExecLoaderUnderADenyRead(t *testing.T) {
	f := newFixture(t)
	ld := filepath.Join(f.home, ".ssh", "ld.so")
	f.file(ld, string(elf64("", 1)), 0o755)
	tool := filepath.Join(f.bin, "ldtool")
	f.file(tool, string(elf64(ld, 2)), 0o755)
	script := filepath.Join(f.project, "run.sh")
	f.file(script, "#!"+tool+"\n", 0o755)
	deny := "fs.deny_read[" + filepath.Join(f.home, ".ssh") + "]"

	for _, c := range []struct{ name, src string }{
		{"no exec: section", "version: 0\nname: a\ncommand: [ldtool]\n"},
		{"exec.allow", "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [ldtool, \"" + script + "\"]\n"},
	} {
		rt, ds := f.compile(f.load(c.src))
		if !hasCode(ds, CodeLoaderRefused) {
			t.Errorf("%s: ldtool's loader under %s produced no %s warning:\n%s", c.name, deny, CodeLoaderRefused, render(ds))
		}
		for _, row := range []Action{
			{Kind: ActionExec, Path: tool},
			{Kind: ActionExec, Argv: []string{"ldtool"}},
			{Kind: ActionExec, Path: script, Script: tool}, // the loader is the interpreter's
		} {
			for _, tier := range enforcingTiers() {
				got := rt.Evaluate(row, tier)
				if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied || got.Rule != deny {
					t.Errorf("%s: tier %s: %+v whose loader is under %s = %+v, want refused/%s", c.name, tier, row, deny, got, record.ReasonReadDenied)
				}
			}
		}
	}
	// The control lives in a contract whose every loader is clean: in the one above, Prepare fails in
	// the landlock and cgroup tiers, so no row of it runs there, python's included.
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + script + "\"]\n"))
	if hasCode(ds, CodeLoaderRefused) {
		t.Errorf("control contract warned about a loader:\n%s", render(ds))
	}
	for _, tier := range enforcingTiers() {
		if got := rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "python")}, tier); got.Verdict != VerdictAllow {
			t.Errorf("control: tier %s: exec of python = %+v, want allow", tier, got)
		}
	}
}
