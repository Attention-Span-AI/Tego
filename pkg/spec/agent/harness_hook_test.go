// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// hookFixture is an allow-list contract's table and a tego binary (a static ELF) beside its own binaries, with the
// hook's exact argv.
func hookFixture(t *testing.T, contract string) (*fixture, *RuleTable, []string) {
	t.Helper()
	f := newFixture(t)
	tego := filepath.Join(f.bin, "tego")
	f.file(tego, string(elf64("", 2)), 0o755)
	rt, ds := f.compile(f.load(contract))
	if HasErrors(ds) {
		t.Fatalf("compile: %s", render(ds))
	}
	return f, rt, []string{tego, "hook", "claude-code", "--reason", "/run/user/1000/tego/R/last-refusal.json", "--mode", "json"}
}

// hookExec is the supervisor's facts of a direct exec of argv[0] with argv, read whole, with the file's identity.
func hookExec(t *testing.T, argv []string) *execmatch.Facts {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(argv[0], &st); err != nil {
		t.Fatal(err)
	}
	return &execmatch.Facts{Requested: filepath.Base(argv[0]), Path: argv[0], Image: filepath.Base(argv[0]), Argv0: argv[0],
		Argv: argv, ArgvComplete: true, ID: execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}, HasID: true}
}

// TestWithHarnessHookGrantsTheExactArgv is ADR 0064's grant on the compiled table (acceptance (1) and (5)): an image rule
// for the tego binary, runtime harness-hook, and a command rule that admits the hook's whole vector and refuses every
// other under the same rule, exec.harness-hook[<binary>], reading the whole vector (the K a plane tier's exec pin
// covers). The grant makes the table decide execs on copied facts, so a plane tier asks for the run's execs to be
// pinned, and run_start's best_effort lists exec.rules/argv where no pin holds them. The compiled table is untouched.
func TestWithHarnessHookGrantsTheExactArgv(t *testing.T) {
	_, rt, argv := hookFixture(t, "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n")
	n := len(rt.Exec)
	got, err := rt.WithHarnessHook(argv)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Exec) != n || rt.ExecCommands != nil || rt.HarnessHook != nil || rt.ExecFactsDecided() {
		t.Fatalf("the compiled table was changed: %d exec rules, commands %v, hook %q", len(rt.Exec), rt.ExecCommands, rt.HarnessHook)
	}
	rule := "exec." + HarnessHookGrant + "[" + argv[0] + "]"
	if len(got.Exec) != n+1 {
		t.Fatalf("%d exec rules, want %d", len(got.Exec), n+1)
	}
	if r := got.Exec[n]; r.Path != argv[0] || r.Runtime != HarnessHookGrant || r.RuleName() != rule || r.ByName || r.IsDir || r.Verdict != VerdictAllow {
		t.Fatalf("the image rule %+v (%s)", r, r.RuleName())
	}
	if got.HarnessHookRule() != rule || !IsRuntimeRule(rule) || !slices.Equal(got.HarnessHook, argv) {
		t.Fatalf("HarnessHookRule %q, runtime %v, hook %q", got.HarnessHookRule(), IsRuntimeRule(rule), got.HarnessHook)
	}
	if !got.ExecCommands.HasRules() || !got.ExecFactsDecided() || !got.ExecCommands.Index.Constrained("tego") {
		t.Fatal("the grant decides no exec on copied facts: a plane tier would not pin the run")
	}
	res := got.ExecCommands.Index.Decide(hookExec(t, argv))
	if res.Outcome != execmatch.OutcomeAllowed || res.Rule() != rule || res.K != len(argv) || !res.Final {
		t.Fatalf("the hook: %+v (rule %q)", res, res.Rule())
	}
	for _, other := range [][]string{{argv[0], "run", "c.yaml"}, {argv[0], "approve", "01J0000000000000000000000A", "a1"}, {argv[0], "__probe"},
		{argv[0], "hook", "other"}, append(slices.Clone(argv[:4]), "/tmp/other.json", "--mode", "json"), {argv[0]}, append(slices.Clone(argv), "x")} {
		res := got.ExecCommands.Index.Decide(hookExec(t, other))
		if res.Outcome != execmatch.OutcomeRefused || res.Rule() != rule || res.K != len(other) {
			t.Errorf("%q: %+v (rule %q), want refused under %s", other, res, res.Rule(), rule)
		}
	}
	if !slices.Contains(got.BestEffortCellsRun(backend.TierLandlock, "", false, false), BestEffortExecRules) {
		t.Error("tier landlock: the grant's argv is a copied fact, and best_effort does not say so")
	}
	if slices.Contains(got.BestEffortCellsRun(backend.TierBPFLSM, record.DecisionPlaneLSM, false, true), BestEffortExecRules) {
		t.Error("a pinned run lists exec.rules/argv for the grant")
	}
}

// TestWithHarnessHookKeepsTheContractsRules: beside a contract's own command rules the grant adds its pattern and
// identity and keeps theirs, and an exec rule that already names the binary is not granted a second time.
func TestWithHarnessHookKeepsTheContractsRules(t *testing.T) {
	f, rt, argv := hookFixture(t, "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, \"static-tool -v\"]\n")
	got, err := rt.WithHarnessHook(argv)
	if err != nil {
		t.Fatal(err)
	}
	tool := []string{filepath.Join(f.bin, "static-tool"), "-v"}
	for _, a := range [][]string{argv, tool} {
		if res := got.ExecCommands.Index.Decide(hookExec(t, a)); res.Outcome != execmatch.OutcomeAllowed {
			t.Errorf("%q: %+v", a, res)
		}
	}
	if res := rt.ExecCommands.Index.Decide(hookExec(t, argv)); res.Outcome == execmatch.OutcomeAllowed && res.Pattern != nil {
		t.Error("the compiled table's index holds the grant")
	}
	named, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, " + argv[0] + "]\n"))
	if HasErrors(ds) {
		t.Fatal(render(ds))
	}
	again, err := named.WithHarnessHook(argv)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Exec) != len(named.Exec) || again.HarnessHookRule() == "" {
		t.Errorf("an exec rule names the binary: %d rules, want %d, and the grant's command rule", len(again.Exec), len(named.Exec))
	}
}

// TestWithHarnessHookRefusesAnInexactGrant: no grant is made that could admit more than the hook's argv, or that names
// no ELF binary: a relative argv[0], a script, a set-id binary, a binary with a second hard link (another name the
// grant would admit, which nothing can enumerate), and a binary whose name a bare
// exec.allow entry or the contract's own command keeps unconstrained (any arguments).
func TestWithHarnessHookRefusesAnInexactGrant(t *testing.T) {
	f, rt, argv := hookFixture(t, "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n")
	setID := filepath.Join(f.bin, "tego-setuid")
	f.file(setID, string(elf64("", 2)), 0o755)
	if err := os.Chmod(setID, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(f.bin, "tego-linked")
	f.file(linked, string(elf64("", 2)), 0o755)
	if err := os.Link(linked, filepath.Join(t.TempDir(), "tego-copy")); err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string][]string{
		"a relative argv[0]":        {"tego", "hook"},
		"no argv":                   nil,
		"a script":                  {filepath.Join(f.bin, "tool.sh"), "hook"},
		"a set-id binary":           {setID, "hook"},
		"a binary with a hard link": {linked, "hook"},
	} {
		if _, err := rt.WithHarnessHook(a); !errors.Is(err, ErrHarnessHookGrant) {
			t.Errorf("%s: %v, want ErrHarnessHookGrant", name, err)
		}
	}
	for name, contract := range map[string]string{
		"a bare exec.allow name":       "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, tego]\n",
		"beside a worded entry":        "version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, tego, \"static-tool -v\"]\n",
		"the contract's command":       "version: 0\nname: a\ncommand: [tego, run]\nexec:\n  allow: [python]\n",
		"the command beside an entry:": "version: 0\nname: a\ncommand: [tego, run]\nexec:\n  allow: [python, \"static-tool -v\"]\n",
	} {
		lifted, ds := f.compile(f.load(contract))
		if HasErrors(ds) {
			t.Fatalf("%s: %s", name, render(ds))
		}
		if _, err := lifted.WithHarnessHook(argv); !errors.Is(err, ErrHarnessHookGrant) {
			t.Errorf("%s: %v, want ErrHarnessHookGrant (the binary's name keeps any arguments)", name, err)
		}
	}
}

// TestHarnessHookNote is the line compile prints under a granted hook (ADR 0064): best effort against a racing thread
// at tier landlock, where argv is a copied fact (ADR 0048 R5).
func TestHarnessHookNote(t *testing.T) {
	want := "harness hook: exact argv; best effort against a racing thread at tier landlock (ADR 0048 R5)"
	if got := (&RuleTable{Tier: backend.TierLandlock}).HarnessHookNote(); got != want {
		t.Errorf("landlock: %q", got)
	}
	if got := (&RuleTable{Tier: backend.TierBPFLSM}).HarnessHookNote(); got == want {
		t.Errorf("bpflsm: %q", got)
	}
	if (&RuleTable{}).HarnessHookRule() != "" {
		t.Error("a table with no grant names one")
	}
}

// TestWithHarnessHookSeesTheFence: an Adjustable table's exec fence entries joined exec.allow under an
// allow-list, so the grant's rebuilt index is built from them as from the compiled table's allow entries: an exec of a
// fenced program decides as it does for a contract that lists the same path in exec.allow.
func TestWithHarnessHookSeesTheFence(t *testing.T) {
	f := newFixture(t)
	tego := filepath.Join(f.bin, "tego")
	f.file(tego, string(elf64("", 2)), 0o755)
	argv := []string{tego, "hook", "claude-code"}
	decide := func(contract string) execmatch.Result {
		t.Helper()
		rt, ds := f.compile(f.load(contract))
		if HasErrors(ds) {
			t.Fatalf("compile: %s", render(ds))
		}
		if rt.ExecCommands != nil {
			t.Fatal("the table compiled command rules; the rebuild from the contract is not taken")
		}
		got, err := rt.WithHarnessHook(argv)
		if err != nil {
			t.Fatal(err)
		}
		return got.ExecCommands.Index.Decide(hookExec(t, []string{tego, "run", "c.yaml"}))
	}
	listed := decide("version: 0\nname: a\ncommand: [python]\ntier: cgroup\nexec:\n  allow: [python, " + tego + "]\n")
	fenced := decide("version: 0\nname: a\ncommand: [python]\ntier: cgroup\nexec:\n  allow: [python]\n" +
		"live:\n  mode: adjustable\n  fence:\n    exec: [" + tego + "]\n")
	if fenced.Outcome != listed.Outcome || fenced.Rule() != listed.Rule() {
		t.Fatalf("a fenced program decides %v (%s), the same path in exec.allow %v (%s)", fenced.Outcome, fenced.Rule(), listed.Outcome, listed.Rule())
	}
}
