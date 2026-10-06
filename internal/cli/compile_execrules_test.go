// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// execRulesDir writes a deny-list contract and a test table into a scratch directory and enters it.
func execRulesDir(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	dir := t.TempDir()
	contract := "version: 0\nname: rules\ncommand: [sh]\nexec:\n  deny: [git push, rm -r]\n  ask: [npm install]\n"
	table := `version: 0
tests:
  - {name: push behind -C, action: exec, argv: [git, -C, ., push], expect: refused, rule: "exec.deny[git push]"}
  - {name: autocorrected push, action: exec, argv: [git, psuh], expect: refused, rule: "exec.deny[git push]"}
  - {name: rm -fr, action: exec, argv: [rm, -fr, x], expect: refused, rule: "exec.deny[rm -r]"}
  - {name: npm i, action: exec, argv: [npm, i, x], expect: refused, rule: "exec.ask[npm install]"}
  - {name: status, action: exec, argv: [git, status], expect: allow}
  - {name: a script, action: exec, path: /opt/x/deploy, script: /usr/bin/env, script_arg: bash, argv: [deploy, prod], expect: allow}
`
	for name, body := range map[string]string{"agent.yaml": contract, "table.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
}

// TestCompileTestCommandRules: compile --test's exec rows run through the image floor, the command rules and the
// gate in every column (ADR 0048 (4)); a cell names the command rule, how it matched and where argv came from, a
// reserved ask is completion_unsupported, and script_arg is a row key.
func TestCompileTestCommandRules(t *testing.T) {
	execRulesDir(t)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "table.yaml", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var rep TestReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if rep.Failed != 0 || len(rep.Rows) != 6 {
		t.Fatalf("report %+v", rep)
	}
	for _, c := range rep.Rows[0].Columns {
		if c.CommandRule != "git push" || c.CommandMatch != "definite" || c.ArgvFacts != "test_row" || c.ArgvAssurance != "copied" {
			t.Errorf("push behind -C, %s: %+v", c.Tier, c)
		}
	}
	for _, c := range rep.Rows[1].Columns {
		if c.CommandMatch != "ambiguous" {
			t.Errorf("an autocorrected push is ambiguous, %s: %+v", c.Tier, c)
		}
	}
	for _, c := range rep.Rows[3].Columns {
		if !c.CompletionUnsupported || c.CommandList != "ask" {
			t.Errorf("npm i under exec.ask, %s: %+v", c.Tier, c)
		}
	}
}

// TestCompileExecOneLiner: compile --exec reads one command line with the pattern spelling and prints each
// interpretation with its readings, then the deciding rule per tier (ADR 0048 (4)), with no table.
func TestCompileExecOneLiner(t *testing.T) {
	execRulesDir(t)
	code, out, errs := run(t, "compile", "agent.yaml", "--exec", "git -C . push origin")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	for _, want := range []string{
		"exec git -C . push origin",
		"interpretation git via name",
		"reading: subcommand push",
		"landlock: refused exec.deny[git push] (deny, definite, via name)",
		"cgroup: refused exec.deny[git push]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--exec output lacks %q:\n%s", want, out)
		}
	}
	if code, _, errs := run(t, "compile", "agent.yaml", "--exec", "git 'push"); code != identity.ExitUsage || !strings.Contains(errs, "--exec") {
		t.Errorf("an unterminated quote: exit %d\n%s", code, errs)
	}
	// --exec prints text only: --json beside it is a usage error, as --test beside it is, never ignored.
	if code, out, errs := run(t, "compile", "agent.yaml", "--exec", "git push", "--json"); code != identity.ExitUsage || out != "" || !strings.Contains(errs, "--json") {
		t.Errorf("--exec with --json: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestCompileExecReadsShebang: compile --exec reads a script's #! line, as the supervisor reads every image's in a run
// with command rules (ADR 0048 (3)), and resolves its interpreter as a --test row's script: is resolved. Under deny:
// [rm -r], a script `#!<dir>/x -rf` with x a symlink to rm, run as `<script> out/tree`, is rm -rf and refused; it
// printed "allow unmatched" before. A relative interpreter is read from the cwd, as the kernel opens it.
func TestCompileExecReadsShebang(t *testing.T) {
	execRulesDir(t)
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm on PATH")
	}
	cwd, _ := os.Getwd()
	if err := os.Symlink(rm, filepath.Join(cwd, "x")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"run.sh": "#!" + filepath.Join(cwd, "x") + " -rf\n",
		"rel.sh": "#!./x -r\n",
		"ok.sh":  "#!" + filepath.Join(cwd, "x") + " -f\n",
	} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ line, want string }{
		{"./run.sh out/tree", "landlock: refused exec.deny[rm -r]"},
		{filepath.Join(cwd, "rel.sh") + " out/tree", "landlock: refused exec.deny[rm -r]"},
		{"./ok.sh out/tree", "landlock: allow unmatched"},
	} {
		code, out, errs := run(t, "compile", "agent.yaml", "--exec", c.line)
		if code != identity.ExitOK {
			t.Fatalf("%s: exit %d\nstdout %s\nstderr %s", c.line, code, out, errs)
		}
		if !strings.Contains(out, c.want) || !strings.Contains(out, "script: #!") {
			t.Errorf("%s: --exec output lacks %q or the script line:\n%s", c.line, c.want, out)
		}
	}
	code, out, _ := run(t, "compile", "agent.yaml", "--exec", "rm -f x")
	if code != identity.ExitOK || !strings.Contains(out, "a bare name is not looked up") {
		t.Errorf("a bare name: exit %d\n%s", code, out)
	}
}
